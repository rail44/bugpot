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
use crate::handle::AppState;

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
            // Either Running or Paused (= frozen across the daemon
            // restart) counts as a live container worth reattaching to.
            // libcontainer persists `ContainerStatus::Paused` on disk
            // and the cgroup freezer state is kernel-side, so a frozen
            // container survives a bugpot crash transparently.
            let is_paused = self.runtime.is_container_paused(name);
            if !self.runtime.is_container_running(name) && !is_paused {
                continue;
            }
            let Some(container_ip) = claims.claim(name) else {
                warn!(
                    app = %name,
                    "container is running but no netns IP was discovered; \
                     leaving as Stopped — next request will cold-start"
                );
                continue;
            };
            let allowlist = handle.spec.read().await.egress.allow.clone();
            match self
                .egress
                .reattach_endpoint(name, container_ip, allowlist)
                .await
            {
                Ok(ep) => {
                    {
                        let mut inner = handle.inner.lock().await;
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
                    // The previous bugpot's tail tasks died with it.
                    // Spawn fresh ones so the new process's tracing
                    // pipeline (and `just logs`) keeps showing app
                    // output. The tail opens at the start of the
                    // file, so bytes the app wrote during the
                    // interregnum replay through tracing once
                    // (bounded by `MAX_LOG_BYTES`).
                    self.runtime.ensure_log_tails(name);
                    info!(
                        app = %name,
                        container_ip = %ep.container_ip,
                        kind = if is_paused { "frozen" } else { "running" },
                        "reattached to surviving container",
                    );
                }
                Err(e) => {
                    warn!(app = %name, error = ?e, "reattach failed; leaving as Stopped");
                }
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
        for (name, ip) in claims.drain() {
            info!(app = %name, %ip, "cleaning up orphan: TOML no longer present");
            if let Err(e) = self.runtime.cleanup_orphan_container(&name).await {
                warn!(app = %name, error = ?e, "cleanup orphan container failed");
            }
            if let Err(e) = self.egress.cleanup_orphan_endpoint(&name, ip).await {
                warn!(app = %name, error = ?e, "cleanup orphan endpoint failed");
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
