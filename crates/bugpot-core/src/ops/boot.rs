//! Boot-time orchestration: reattach surviving apps, sweep orphans,
//! eager-start always-on apps, and the matching shutdown path.

use std::sync::atomic::Ordering;
use std::time::Instant;

use anyhow::{Result, anyhow};
use bugpot_egress::{EgressOps, StartupClaims};
use bugpot_runtime::RuntimeOps;
use metrics::counter;
use tracing::{info, warn};

use crate::AppHost;
use crate::handle::{AppState, Slot, container_id};

impl<R: RuntimeOps, E: EgressOps> AppHost<R, E> {
    /// Reattach to containers that survived a previous bugpot process.
    /// Idempotent across calls (one-shot via [`AppHost::reattach_done`]);
    /// the second call warns and returns.
    ///
    /// For each known app whose container is still alive (running or
    /// paused), `claim` the matching endpoint from the supplied
    /// [`StartupClaims`], re-register it in egress, restore the in-
    /// memory state, and spawn fresh log-tail tasks. The handle's
    /// state is set directly (`AppState::Running` or `AppState::Frozen`);
    /// the previous bugpot's tail tasks died with the process, so the
    /// new process re-opens the on-disk log files via
    /// `RuntimeOps::ensure_log_tails`.
    pub async fn reattach_running(&self, claims: &mut StartupClaims) {
        if self.reattach_done.swap(true, Ordering::SeqCst) {
            warn!("reattach_running called more than once; ignoring subsequent calls");
            return;
        }
        for handle in self.list_handles().await {
            let name = &handle.identity.name;
            // Inspect both slots' on-disk libcontainer state. A
            // post-PR1 app has its live container under either
            // `name-a` or `name-b` (last successful rollover wins);
            // an app crashed mid-rollover has *both* slots present.
            let live_a = self.is_live_slot(name, Slot::A);
            let live_b = self.is_live_slot(name, Slot::B);

            let resolved = match (live_a, live_b) {
                (None, None) => continue,
                (Some(state), None) => Some((Slot::A, state)),
                (None, Some(state)) => Some((Slot::B, state)),
                (Some(_), Some(_)) => {
                    // Mid-rollover crash. Per the agreed recovery
                    // semantic we kill both and let the next request
                    // redo the rollout from Stopped; the new tag is
                    // already persisted by the prior `set_rollout`,
                    // so cold-start picks it up.
                    warn!(
                        app = %name,
                        "both slots present at reattach — mid-rollover crash, killing both",
                    );
                    self.purge_both_slots(name, claims).await;
                    None
                }
            };

            let Some((slot, is_paused)) = resolved else {
                continue;
            };
            let live_id = container_id(name, slot);
            let Some(ip) = claims.claim(&live_id) else {
                warn!(
                    app = %name,
                    container = %live_id,
                    "container alive but no netns IP discovered; leaving as Stopped",
                );
                continue;
            };
            self.reattach_one(&handle, slot, &live_id, ip, is_paused)
                .await;
        }
    }

    /// Probe one slot. Returns:
    /// - `Some(true)`: container is paused (= frozen across restart).
    /// - `Some(false)`: container is running.
    /// - `None`: no container in this slot.
    ///
    /// Encapsulates the "running or paused" disjunction so
    /// `reattach_running` reads as a flat decision tree.
    fn is_live_slot(&self, app_name: &str, slot: Slot) -> Option<bool> {
        let cid = container_id(app_name, slot);
        if self.runtime.is_container_paused(&cid) {
            Some(true)
        } else if self.runtime.is_container_running(&cid) {
            Some(false)
        } else {
            None
        }
    }

    /// Tear down both slots' containers and their netns when reattach
    /// detects a mid-rollover crash. Endpoints are drained from
    /// `claims` here so the subsequent `cleanup_orphans` pass doesn't
    /// also try to handle them (it would, harmlessly — but the log
    /// noise of "orphan cleaned" twice per app is worth avoiding).
    async fn purge_both_slots(&self, app_name: &str, claims: &mut StartupClaims) {
        for slot in [Slot::A, Slot::B] {
            let cid = container_id(app_name, slot);
            if let Err(e) = self.runtime.cleanup_container(&cid).await {
                warn!(app = %app_name, container = %cid, error = ?e, "purge: cleanup_container");
            }
            if let Some(ip) = claims.claim(&cid)
                && let Err(e) = self.egress.cleanup_orphan_endpoint(&cid, ip).await
            {
                warn!(app = %app_name, container = %cid, error = ?e, "purge: cleanup_orphan_endpoint");
            }
        }
    }

    /// Wire a single surviving container back into the in-memory
    /// state machine: egress re-registration, `state` /
    /// `current_slot` / `last_access` restoration, log-tail spawn.
    async fn reattach_one(
        &self,
        handle: &crate::handle::AppHandle,
        slot: Slot,
        live_id: &str,
        container_ip: std::net::Ipv4Addr,
        is_paused: bool,
    ) {
        let name = &handle.identity.name;
        let allowlist = handle.spec.read().await.egress.allow.clone();
        match self
            .egress
            .reattach_endpoint(live_id, container_ip, allowlist)
            .await
        {
            Ok(ep) => {
                {
                    let mut inner = handle.inner.lock().await;
                    inner.current_slot = slot;
                    inner.state = if is_paused {
                        AppState::Frozen {
                            container_ip: ep.container_ip,
                        }
                    } else {
                        AppState::Running {
                            container_ip: ep.container_ip,
                        }
                    };
                    inner.last_access = Instant::now();
                }
                // Log tails are keyed by app name (shared across
                // slots so post-mortem retention isn't fragmented
                // across rollovers). Tail opens at file start, so
                // bytes written during the interregnum replay once,
                // bounded by `MAX_LOG_BYTES`.
                self.runtime.ensure_log_tails(name);
                info!(
                    app = %name,
                    container = %live_id,
                    container_ip = %ep.container_ip,
                    slot = %slot.as_char(),
                    kind = if is_paused { "frozen" } else { "running" },
                    "reattached to surviving container",
                );
            }
            Err(e) => {
                warn!(app = %name, error = ?e, "reattach failed; leaving as Stopped");
            }
        }
    }

    /// Reap state left behind by apps whose `AppSpec` no longer exists.
    ///
    /// After `reattach_running` consumes endpoints for known apps, any
    /// `(name, ip)` still in egress's discovered set is an orphan:
    /// the TOML was deleted while bugpot was down, so the netns +
    /// container + IP allocation no longer have an owner. This call
    /// stops the container (if libcontainer state still exists), tears
    /// down the netns + nft entries, and returns the IP to the
    /// allocator. The per-app log directory is left alone — operators
    /// may still want to inspect it.
    ///
    /// Called once at startup after `reattach_running`. Safe to call
    /// when there are no orphans (no-op).
    pub async fn cleanup_orphans(&self, claims: StartupClaims) {
        // `name` here is whatever the egress layer discovered as a
        // netns suffix — a container ID. We have no reliable way to
        // recover the owning app name (the TOML is gone), so we
        // intentionally call only `cleanup_container`, not
        // `cleanup_app_assets`. The volume dir for the gone app
        // therefore lingers on disk; documented as a known
        // limitation for the rare "app removed while bugpot was down"
        // case (the operator can `rm -rf` the orphan volume dir by
        // hand). The alternative — strip a slot suffix to *guess* the
        // app name — used to bleed the slot convention into
        // bugpot-runtime, which we explicitly avoid.
        for (container_id, ip) in claims.drain() {
            info!(container = %container_id, %ip, "cleaning up orphan: TOML no longer present");
            if let Err(e) = self.runtime.cleanup_container(&container_id).await {
                warn!(container = %container_id, error = ?e, "cleanup orphan container failed");
            }
            if let Err(e) = self.egress.cleanup_orphan_endpoint(&container_id, ip).await {
                warn!(container = %container_id, error = ?e, "cleanup orphan endpoint failed");
            }
            counter!("bugpot_orphan_cleanups_total").increment(1);
        }
    }

    /// Eagerly start apps whose `idle_timeout` resolves to "always on".
    ///
    /// Concurrent: all qualifying apps' `ensure_running` futures are
    /// driven in parallel via [`futures::future::join_all`]. With N
    /// always-on apps that share an image, the first puller fills the
    /// cache and the rest hit it — startup is dominated by the slowest
    /// single cold-start instead of summing across all of them.
    ///
    /// **Error policy:** on per-app failure the future returns the
    /// error, but other futures continue. After all futures resolve, the
    /// **first** error is returned to the caller; successfully-started
    /// apps stay running. The caller (`cmd/bugpot::main`) rolls back via
    /// `teardown()` if it wants an all-or-nothing semantic.
    pub async fn deploy_always_on(&self) -> Result<()> {
        // Resolve idle_timeout up-front so a bad value fails fast before
        // any container is started.
        let handles = self.list_handles().await;
        let mut always_on = Vec::new();
        for handle in handles {
            let timeout = handle
                .spec
                .read()
                .await
                .scaling
                .resolve_idle_timeout()
                .map_err(|e| anyhow!("{}: {e}", handle.identity.name))?;
            if timeout.is_some() {
                continue;
            }
            // An always-on app that has never been rolled out can't be
            // started yet. Skip with a warning rather than failing the
            // entire bring-up — the operator will see the warning and
            // POST a rollout when ready.
            if handle.inner.lock().await.rollouts.is_empty() {
                warn!(
                    app = %handle.identity.name,
                    "eager start skipped: app has no rollout yet"
                );
                continue;
            }
            always_on.push(handle);
        }
        if always_on.is_empty() {
            return Ok(());
        }

        let starts = always_on.into_iter().map(|handle| {
            let name = handle.identity.name.clone();
            async move {
                info!(app = %name, "eager start (idle_timeout = 0)");
                match self.ensure_running(&handle).await {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        warn!(app = %name, error = ?e, "eager start failed");
                        Err(anyhow!("{name}: {e:#}"))
                    }
                }
            }
        });
        let results = futures::future::join_all(starts).await;
        for r in results {
            r?;
        }
        Ok(())
    }

    /// Stop every app that's currently running. Used on shutdown.
    pub async fn teardown(&self) {
        for handle in self.list_handles().await {
            let should_stop = {
                let inner = handle.inner.lock().await;
                // Frozen is deliberately excluded: on daemon shutdown
                // we leave paused containers paused so `reattach_running`
                // picks them back up after restart, rather than racing
                // a fresh stop.
                matches!(
                    inner.state,
                    AppState::Running { .. } | AppState::Starting { .. }
                )
            };
            if should_stop && let Err(e) = self.stop(&handle).await {
                warn!(app = %handle.identity.name, error = ?e, "stop failed during teardown");
            }
        }
    }
}
