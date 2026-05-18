//! Image rollout pipeline: blue-green deployment with readiness
//! gate, atomic switch, drain, and auto-rollback on failure.
//!
//! Flow when the app is `Running` or `Frozen` (= has a *from*
//! container worth keeping live during the rollover):
//!
//! ```text
//!   set_rollout(tag)
//!     │
//!     ├─ pull(tag) ─ failures classified as ImageAuth / ImagePull
//!     ├─ record_rollout + persist (durable before any container work)
//!     ├─ enter_rolling_over (thaw if Frozen) → state := RollingOver{from_ip}
//!     │     (resolver keeps returning from_ip for the whole window
//!     │      below; see handle.rs::claim_start_slot)
//!     ├─ build_to_slot(to_id)
//!     │     ├─ allocate endpoint in opposite slot
//!     │     ├─ pull (cache-hit; digest already resolved above)
//!     │     ├─ start container
//!     │     └─ readiness probe
//!     ├─ on Ok(new_ip):
//!     │     ├─ state := Running{new_ip}; current_slot.flip
//!     │     ├─ drain active_upgrades (60 s cap)
//!     │     └─ teardown from-slot
//!     └─ on Err:
//!           ├─ state := Running{from_ip}  (rollback; current_slot unchanged)
//!           └─ teardown to-slot
//! ```
//!
//! The `Stopped` branch skips the blue-green path entirely and
//! delegates to the normal cold-start (`ensure_running` on the
//! current slot) — there's no "from" container to switch off of.
//!
//! `RollingOver`'s `from_ip` field is the single source of truth
//! for "where should the resolver send traffic right now": once it
//! flips back to `Running { container_ip }` (success) or
//! `Running { container_ip = from_ip }` (rollback), the resolver
//! reads whichever IP is in `state` on its next access. No
//! `Notify` is needed because there are no waiters — the resolver
//! never blocks during a rollover.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use anyhow::anyhow;
use bugpot_config::Rollout;
use bugpot_egress::EgressOps;
use bugpot_runtime::{ImageId, RuntimeOps};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::AppHost;
use crate::RolloutError;
use crate::error::classify_pull_error_for_rollout;
use crate::handle::{AppHandle, AppState, DigestCache, MAX_ROLLOUT_HISTORY, container_id};

/// Wall-clock cap on the post-switch drain: how long to wait for
/// in-flight WebSocket / SSE splices to finish on the *from* slot
/// before tearing it down. Defensive default; not user-configurable
/// by design — the app's own per-connection timeout is the
/// correctness mechanism, this is just a safety net so a misbehaving
/// upstream can't pin the old container indefinitely.
const DRAIN_TIMEOUT: Duration = Duration::from_mins(1);

/// Drain poll interval. Short enough that a sub-second-bursty upgrade
/// cliff finishes fast; long enough that an idle `active_upgrades`
/// stays in the cache without churning.
const DRAIN_POLL: Duration = Duration::from_millis(100);

/// Outcome of `enter_rolling_over` — tells `set_rollout` which
/// container-bring-up path applies for this state of the world.
enum RolloverEntry {
    /// No `from` container exists; treat the rollout as a normal
    /// cold start on the current slot. Resolver returns the new IP
    /// directly once `ensure_running` lands.
    ColdStart,
    /// `from` container is live (or just thawed). State has been
    /// transitioned to `RollingOver { from_ip }`; caller now owns
    /// the blue-green ladder.
    BlueGreen { from_ip: Ipv4Addr },
}

impl<R: RuntimeOps, E: EgressOps> AppHost<R, E> {
    /// Append a new rollout to the app's history and bring traffic to
    /// it. Blue-green when a from-side exists; otherwise a normal
    /// cold start.
    ///
    /// Error semantics:
    /// - [`RolloutError::EmptyTag`]: caller passed an empty tag.
    /// - [`RolloutError::Conflict`]: state is `Starting` /
    ///   `Stopping` / already `RollingOver`. Caller retries.
    /// - [`RolloutError::ImageAuth`] / [`RolloutError::ImagePull`]:
    ///   pull-side failures (classified pre-state-transition, no
    ///   cleanup needed).
    /// - [`RolloutError::StartFailed`]: container failed to start
    ///   or pass readiness on the *new* slot. The *from* side is
    ///   intact and serving — this is the auto-rollback case.
    pub async fn set_rollout(
        &self,
        handle: &Arc<AppHandle>,
        tag: String,
    ) -> std::result::Result<Rollout, RolloutError> {
        if tag.trim().is_empty() {
            return Err(RolloutError::EmptyTag);
        }
        let name = handle.name().to_owned();

        // Pre-flight conflict check. Done before pull so a doomed
        // call doesn't burn a registry round-trip. Re-verified inside
        // `enter_rolling_over` because state can drift across the
        // pull await.
        {
            let inner = handle.inner.lock().await;
            if inner.state.is_busy() {
                return Err(RolloutError::Conflict(name));
            }
        }

        // 1. Pull. Capture `repo` here so the digest we cache below
        // is paired with the exact value the pull resolved against —
        // a concurrent PATCH that changes `repo` mid-flight produces
        // a (new_repo, ?) on the spec side and our cache stays
        // (old_repo, old_digest), self-invalidating on next read.
        let repo = handle.spec.read().await.repo.clone();
        let resolved_digest = self.pull_for_rollout(handle, &repo, &tag).await?;

        // 2. Append to history and update the digest cache so the
        // next start (cold or blue-green) uses *this* rollout's
        // digest, not the previous rollout's.
        let rollout = Rollout {
            tag,
            created_at: SystemTime::now(),
        };
        record_rollout(handle, rollout.clone(), repo, resolved_digest).await;

        // 3. Persist before any container work — a crash mid-flight
        // must leave the new tag durable so reattach picks it up.
        if let Err(e) = self.store.persist_rollouts(handle).await {
            warn!(app = %name, error = ?e, "failed to persist rollouts");
        }

        // 4. Bring the container to the new state. Shared with the
        // `PATCH /apps/<name>` path so spec changes get the same
        // zero-gap deployment behaviour as tag changes.
        self.apply_change(handle).await?;
        Ok(rollout)
    }

    /// Bring a handle's live container(s) into alignment with whatever
    /// the spec + rollout history currently say. Shared by:
    /// - `set_rollout` after recording the new tag,
    /// - `update_app` after rewriting the spec.
    ///
    /// Dispatch:
    /// - `Stopped` → cold-start on `current_slot` (`ensure_running`).
    ///   Returns once readiness passes; on failure surfaces as
    ///   `RolloutError::StartFailed`.
    /// - `Running` / `Frozen` → blue-green to the opposite slot.
    ///   `Frozen` is thawed first inside `enter_rolling_over` so the
    ///   from-side serves traffic during the build window.
    /// - `Starting` / `Stopping` / `RollingOver` → `Conflict`.
    pub(crate) async fn apply_change(
        &self,
        handle: &Arc<AppHandle>,
    ) -> std::result::Result<(), RolloutError> {
        match self.enter_rolling_over(handle).await? {
            RolloverEntry::ColdStart => self
                .ensure_running(handle)
                .await
                .map(|_| ())
                .map_err(RolloutError::StartFailed),
            RolloverEntry::BlueGreen { from_ip } => self.do_blue_green(handle, from_ip).await,
        }
    }

    /// Atomic gate at the boundary between "rollout pipeline pulled
    /// and recorded the new tag" and "rollout pipeline starts touching
    /// containers". Resolves the race window across the pull await.
    ///
    /// - `Stopped`: trivial — no thaw, no transition, caller goes the
    ///   cold-start path.
    /// - `Frozen`: thaw to `Running` first so the from-side serves
    ///   any request that lands during the rollover window. (Without
    ///   this, the resolver returns a frozen IP and requests stall on
    ///   the paused container's listen socket.)
    /// - `Running`: transition to `RollingOver`; caller owns the
    ///   blue-green flow.
    /// - Other states (`Starting` / `Stopping` / `RollingOver`):
    ///   conflict — drifted in across the pull.
    async fn enter_rolling_over(
        &self,
        handle: &Arc<AppHandle>,
    ) -> std::result::Result<RolloverEntry, RolloutError> {
        let name = handle.name().to_owned();

        // Thaw step. Done outside the second lock because
        // `unfreeze_app` is a kernel write that can block on the
        // freezer file, and we don't want to hold the state lock
        // across it. The post-thaw lock acquisition re-verifies.
        let needs_thaw = handle.inner.lock().await.state.is_frozen();
        if needs_thaw {
            let cid = handle.current_id().await;
            if let Err(e) = self.runtime.unfreeze_app(&cid).await {
                return Err(RolloutError::StartFailed(anyhow!(
                    "unfreeze for rollover: {e:#}"
                )));
            }
            let mut inner = handle.inner.lock().await;
            if let AppState::Frozen { container_ip } = inner.state {
                inner.state = AppState::Running { container_ip };
            }
        }

        // Atomic transition. Lock scoped tightly: the guard releases
        // before the caller starts building the new slot, so the
        // resolver path (which also takes this lock) can't be blocked
        // by the build phase.
        let mut inner = handle.inner.lock().await;
        let outcome = match inner.state {
            AppState::Stopped => Ok(RolloverEntry::ColdStart),
            AppState::Running { container_ip } => {
                inner.state = AppState::RollingOver {
                    from_ip: container_ip,
                };
                Ok(RolloverEntry::BlueGreen {
                    from_ip: container_ip,
                })
            }
            AppState::Frozen { .. }
            | AppState::Starting { .. }
            | AppState::Stopping
            | AppState::RollingOver { .. } => Err(RolloutError::Conflict(name)),
        };
        drop(inner);
        outcome
    }

    /// Blue-green ladder: build the new slot, atomically switch, drain,
    /// tear down the old slot. On any build / readiness failure the
    /// from-side stays serving and we tear down the partial new slot
    /// — the caller (`set_rollout`) translates the error to
    /// `RolloutError::StartFailed`.
    pub(crate) async fn do_blue_green(
        &self,
        handle: &Arc<AppHandle>,
        from_ip: Ipv4Addr,
    ) -> std::result::Result<(), RolloutError> {
        let app_name = handle.identity.name.clone();
        let (from_slot, to_slot) = {
            let inner = handle.inner.lock().await;
            (inner.current_slot, inner.current_slot.other())
        };
        let to_id = container_id(&app_name, to_slot);

        info!(
            app = %app_name,
            from = %container_id(&app_name, from_slot),
            to = %to_id,
            "rollover: building new slot",
        );

        let build_result = self.build_to_slot(handle, &to_id).await;

        match build_result {
            Ok(new_ip) => {
                // Atomic switch — but only if state is *still*
                // `RollingOver`. A concurrent `stop` / `remove_app`
                // can flip state to `Stopping` and reap both slots
                // while we were busy building. In that case the
                // teardown has already happened; we must not
                // overwrite the operator's `Stopping` with a fresh
                // `Running` and revive a dead container in the
                // resolver's eyes.
                //
                // Pattern is "compare-and-swap on RollingOver": the
                // guard read + write live under one lock; if the
                // state slot drifted, we abandon the switch and
                // clean up the new container we just built.
                let switched = {
                    let mut inner = handle.inner.lock().await;
                    if matches!(inner.state, AppState::RollingOver { .. }) {
                        inner.state = AppState::Running {
                            container_ip: new_ip,
                        };
                        inner.current_slot = to_slot;
                        true
                    } else {
                        false
                    }
                };
                if !switched {
                    warn!(
                        app = %app_name,
                        "rollover: state drifted off RollingOver before switch \
                         (concurrent stop/remove?); tearing down new slot",
                    );
                    self.teardown_containers(&app_name, &[to_id]).await;
                    return Err(RolloutError::Conflict(app_name));
                }
                info!(
                    app = %app_name,
                    %from_ip,
                    %new_ip,
                    "rollover: switched",
                );

                drain_active_upgrades(&handle.active_upgrades, &app_name).await;

                let from_id = container_id(&app_name, from_slot);
                self.teardown_containers(&app_name, &[from_id]).await;
                Ok(())
            }
            Err(e) => {
                // Rollback: same compare-and-swap discipline. If state
                // drifted (concurrent stop/remove), don't restore
                // `Running{from_ip}` — the operator's transition wins.
                // We still reap the partial new slot unconditionally;
                // `teardown_containers` is idempotent so racing the
                // concurrent stop here is harmless.
                let restored = {
                    let mut inner = handle.inner.lock().await;
                    if matches!(inner.state, AppState::RollingOver { .. }) {
                        inner.state = AppState::Running {
                            container_ip: from_ip,
                        };
                        true
                    } else {
                        false
                    }
                };
                if restored {
                    warn!(
                        app = %app_name,
                        error = ?e,
                        "rollover: new-slot build failed; rolled back to from-side",
                    );
                } else {
                    warn!(
                        app = %app_name,
                        error = ?e,
                        "rollover: new-slot build failed and state drifted off \
                         RollingOver; not restoring from-side",
                    );
                }
                self.teardown_containers(&app_name, &[to_id]).await;
                Err(RolloutError::StartFailed(e))
            }
        }
    }

    /// Run the same phase sequence `do_start` uses, but parameterised
    /// by an explicit `container_id` (the to-slot's, not the
    /// handle's current). Each phase's error path is responsible for
    /// reverting its own side-effect (endpoint release, container
    /// stop) before returning — the caller (`do_blue_green`) layers a
    /// further sweep on top via `teardown_containers` to catch the
    /// edge where libcontainer state landed on disk but `start_app`
    /// returned `Err` after that.
    async fn build_to_slot(
        &self,
        handle: &Arc<AppHandle>,
        to_id: &str,
    ) -> anyhow::Result<Ipv4Addr> {
        let spec = handle.spec.read().await.clone();
        let plain_image_ref = self.resolve_image_ref(handle, &spec).await?;

        let endpoint = self.allocate_endpoint_phase(to_id, &spec).await?;

        let image_id = match self.pull_image_phase(handle, &spec, &plain_image_ref).await {
            Ok(id) => id,
            Err(e) => {
                let _ = self.egress.release_endpoint(to_id).await;
                return Err(e);
            }
        };

        if let Err(e) = self
            .start_container_phase(to_id, &spec, &image_id, &endpoint)
            .await
        {
            let _ = self.egress.release_endpoint(to_id).await;
            return Err(e);
        }

        if let Err(e) = self
            .readiness_phase(&handle.identity.name, endpoint.container_ip, &spec)
            .await
        {
            let _ = self.runtime.stop_app(to_id).await;
            let _ = self.egress.release_endpoint(to_id).await;
            return Err(e);
        }

        Ok(endpoint.container_ip)
    }

    /// Pull `{repo}:{tag}` for an in-flight `set_rollout`. Classifies
    /// auth-side failures into the dedicated [`RolloutError::ImageAuth`]
    /// variant so adapter crates can distinguish them from generic
    /// `ImagePull` errors.
    async fn pull_for_rollout(
        &self,
        handle: &AppHandle,
        repo: &str,
        tag: &str,
    ) -> std::result::Result<ImageId, RolloutError> {
        let name = &handle.identity.name;
        let image_ref = format!("{repo}:{tag}");
        self.runtime
            .pull_image(&image_ref, self.resolve_auth(repo))
            .await
            .map_err(|e| classify_pull_error_for_rollout(e, name, &image_ref))
    }

    /// Return a snapshot of the rollout history (front = oldest,
    /// back = current). Caller is responsible for proving the
    /// handle is registered — pass the value from `find_handle`.
    pub async fn list_rollouts(&self, handle: &Arc<AppHandle>) -> Vec<Rollout> {
        handle.inner.lock().await.rollouts.iter().cloned().collect()
    }
}

/// Wait for the from-slot's spliced upgrades (WebSocket / SSE) to
/// drain, capped at `DRAIN_TIMEOUT`. Polls every `DRAIN_POLL` rather
/// than subscribing because each splice updates the counter from its
/// own task and a notify-on-zero would race against the next
/// increment; the polling cost is negligible against the cap.
///
/// HTTP request/response is *not* drained here — the router's
/// `REQUEST_TIMEOUT` (30 s) bounds those independently, and starting
/// a teardown on the from-slot while a request is mid-flight only
/// returns whatever error the upstream chose; the new slot already
/// owns subsequent traffic.
async fn drain_active_upgrades(upgrades: &Arc<AtomicUsize>, app_name: &str) {
    let start = Instant::now();
    loop {
        let active = upgrades.load(Ordering::Relaxed);
        if active == 0 {
            return;
        }
        if start.elapsed() >= DRAIN_TIMEOUT {
            warn!(
                app = %app_name,
                active,
                "rollover drain: timeout — tearing down with upgrades still spliced",
            );
            return;
        }
        sleep(DRAIN_POLL).await;
    }
}

/// Append a freshly-minted rollout to the handle's history (popping
/// the oldest entry when the deque is full) and overwrite the
/// per-handle image-digest cache. Held under `inner` for a single
/// critical section so the rollouts + digest move atomically — a
/// concurrent `view_of` either sees both updates or neither.
async fn record_rollout(handle: &Arc<AppHandle>, rollout: Rollout, repo: String, digest: ImageId) {
    let mut inner = handle.inner.lock().await;
    while inner.rollouts.len() >= MAX_ROLLOUT_HISTORY {
        inner.rollouts.pop_front();
    }
    inner.rollouts.push_back(rollout);
    inner.image_digest = Some(DigestCache { repo, digest });
}
