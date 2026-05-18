//! Per-app lifecycle: state-machine coordination (`ensure_running`)
//! plus the cold-start orchestration it dispatches to (`do_start` and
//! its phases), the frozen-resume path (`do_resume`), and the
//! freeze / stop tear-down paths.
//!
//! Methods that are `pub(crate)` here (`ensure_running`, `freeze`,
//! `stop`) are called from sibling files in `ops/` (CRUD, rollout,
//! loops, boot). Cold-start phases (`do_start`, `pull_image_phase`,
//! etc.) stay private — they're internal to this module.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bugpot_config::AppSpec;
use bugpot_egress::EgressOps;
use bugpot_runtime::{ImageId, RuntimeOps};
use tracing::{debug, info, warn};

use crate::AppHost;
use crate::READINESS_TIMEOUT_DEFAULT;
use crate::handle::{AppHandle, AppState, DigestCache, StartClaim};
use crate::probe::wait_for_ready;

/// Time an expression returning `Result<_>` and record its duration to
/// a histogram **only on success**. Encodes the "completed phases
/// only" semantic of `bugpot_cold_start_seconds` / `bugpot_freeze_seconds`
/// / `bugpot_resume_seconds`: failure paths leave the distribution
/// untouched.
macro_rules! record_on_success {
    ($metric:literal $(, $k:literal => $v:expr)* ; $body:expr) => {{
        let __start = ::std::time::Instant::now();
        let __res = $body;
        if __res.is_ok() {
            ::metrics::histogram!($metric $(, $k => $v)*)
                .record(__start.elapsed().as_secs_f64());
        }
        __res
    }};
}

impl<R: RuntimeOps, E: EgressOps> AppHost<R, E> {
    /// Ensure the app is running, coalescing concurrent starts. Returns
    /// the container IP.
    pub(crate) async fn ensure_running(&self, handle: &Arc<AppHandle>) -> Result<Ipv4Addr> {
        loop {
            let claim = handle.inner.lock().await.claim_start_slot();
            match claim {
                StartClaim::Ready(ip) => return Ok(ip),
                StartClaim::Coalesce(notify) => {
                    debug!(app = %handle.identity.name, "awaiting concurrent start");
                    notify.notified().await;
                }
                StartClaim::WaitForStopping => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                StartClaim::Claimed {
                    notify: own_notify,
                    resume_from,
                } => {
                    let result = match resume_from {
                        Some(ip) => self.do_resume(handle, ip).await,
                        None => self.do_start(handle).await,
                    };
                    // Commit the result *before* waking waiters so the
                    // wake races against an observable state. `own_notify`
                    // keeps the channel alive across the transition that
                    // drops the in-state `Arc`.
                    handle.inner.lock().await.finish_start(&result);
                    own_notify.notify_waiters();
                    return result;
                }
            }
        }
    }

    /// Cold-start orchestration: allocate endpoint → pull image →
    /// start container → wait for readiness. Each phase contributes
    /// a single `bugpot_cold_start_seconds{phase=...}` sample on
    /// success; failure paths leave the histogram untouched so the
    /// distribution reflects completed starts.
    ///
    /// Error cleanup is the orchestrator's job: a failure mid-flight
    /// releases the endpoint (and stops the container, if the
    /// failure is post-start), but the per-phase helpers themselves
    /// stay cleanup-free — they return `Result` and let `do_start`
    /// decide how to unwind.
    async fn do_start(&self, handle: &AppHandle) -> Result<Ipv4Addr> {
        let name = &handle.identity.name;
        // Container ID for everything below the controller (runtime,
        // egress, libcontainer state, netns). `name` stays the
        // operator-facing identifier — log lines, persisted state,
        // metrics labels.
        let container_id = handle.current_id().await;
        let spec = handle.spec.read().await.clone();
        let plain_image_ref = self.resolve_image_ref(handle, &spec).await?;
        info!(app = %name, image = %plain_image_ref, "starting");

        let endpoint = self.allocate_endpoint_phase(&container_id, &spec).await?;

        let image_id = match self.pull_image_phase(handle, &spec, &plain_image_ref).await {
            Ok(id) => id,
            Err(e) => {
                let _ = self.egress.release_endpoint(&container_id).await;
                return Err(e);
            }
        };

        let running = match self
            .start_container_phase(&container_id, &spec, &image_id, &endpoint)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let _ = self.egress.release_endpoint(&container_id).await;
                return Err(e);
            }
        };
        info!(
            app = %name,
            pid = running.pid,
            container_ip = %endpoint.container_ip,
            "container running"
        );

        if let Err(e) = self
            .readiness_phase(name, endpoint.container_ip, &spec)
            .await
        {
            warn!(app = %name, error = %e, "readiness probe failed");
            let _ = self.runtime.stop_app(&container_id).await;
            let _ = self.egress.release_endpoint(&container_id).await;
            return Err(e);
        }
        Ok(endpoint.container_ip)
    }

    /// Form `repo:tag` for the cold start. Errors when the app has
    /// no rollout — there is no tag to pull.
    async fn resolve_image_ref(&self, handle: &AppHandle, spec: &AppSpec) -> Result<String> {
        let name = &handle.identity.name;
        let tag = handle
            .inner
            .lock()
            .await
            .rollouts
            .back()
            .map(|r| r.tag.clone())
            .ok_or_else(|| anyhow!("app '{name}' has no rollout; POST a rollout first"))?;
        Ok(format!("{repo}:{tag}", repo = spec.repo))
    }

    /// Phase 1 of `do_start`: claim a netns + container IP + DNS
    /// allowlist slot from `bugpot-egress`. Keyed by the slot-suffixed
    /// `container_id` so blue-green rollovers can hold two endpoints
    /// for the same app simultaneously.
    async fn allocate_endpoint_phase(
        &self,
        container_id: &str,
        spec: &AppSpec,
    ) -> Result<bugpot_egress::Endpoint> {
        record_on_success!(
            "bugpot_cold_start_seconds", "phase" => "endpoint";
            self.egress
                .allocate_endpoint(container_id, spec.egress.allow.clone())
                .await
                .with_context(|| format!("allocate endpoint for {container_id}"))
        )
    }

    /// Phase 2: pull, pinning to the cached digest if one was
    /// resolved on a previous start of this handle, then write the
    /// resolved digest back to the cache the first time.
    async fn pull_image_phase(
        &self,
        handle: &AppHandle,
        spec: &AppSpec,
        plain_image_ref: &str,
    ) -> Result<ImageId> {
        let name = &handle.identity.name;
        // If a prior pull on this handle resolved the tag to a digest
        // *for the same repo*, pin to it so the registry-side manifest
        // probe is skipped (`Puller::pull` short-circuits on digest
        // references). The freshness check on `cache.repo` means a
        // PATCH that changed `repo` since the cache was written
        // silently falls through to a full pull, no out-of-band
        // invalidation needed.
        let cached_digest = handle
            .inner
            .lock()
            .await
            .image_digest
            .as_ref()
            .filter(|cache| cache.repo == spec.repo)
            .map(|cache| cache.digest.clone());
        let image_ref = digest_pinned_ref(plain_image_ref, cached_digest.as_ref());
        let image_id = record_on_success!(
            "bugpot_cold_start_seconds", "phase" => "pull";
            self.runtime
                .pull_image(&image_ref, self.resolve_auth(&spec.repo))
                .await
                .with_context(|| format!("pull image for {name}"))
        )?;
        // Persist the resolved digest paired with the repo it was
        // resolved against. Future reads will only honour it while
        // the repo still matches.
        {
            let mut inner = handle.inner.lock().await;
            if inner.image_digest.is_none() {
                inner.image_digest = Some(DigestCache {
                    repo: spec.repo.clone(),
                    digest: image_id.clone(),
                });
            }
        }
        Ok(image_id)
    }

    /// Phase 3: hand off to libcontainer.
    async fn start_container_phase(
        &self,
        container_id: &str,
        spec: &AppSpec,
        image_id: &ImageId,
        endpoint: &bugpot_egress::Endpoint,
    ) -> Result<bugpot_runtime::RunningApp> {
        record_on_success!(
            "bugpot_cold_start_seconds", "phase" => "start";
            self.runtime
                .start_app(container_id, spec, image_id, Some(&endpoint.netns_path))
                .await
                .with_context(|| format!("start container for {container_id}"))
        )
    }

    /// Phase 4: TCP-bind or HTTP probe, until the app accepts traffic
    /// or the per-app `readiness.timeout` fires. Without this, the
    /// first proxied request would race ahead of the process's
    /// listener.
    async fn readiness_phase(
        &self,
        name: &str,
        container_ip: Ipv4Addr,
        spec: &AppSpec,
    ) -> Result<()> {
        let timeout = spec
            .readiness
            .resolve_timeout(READINESS_TIMEOUT_DEFAULT)
            .map_err(|e| anyhow!("{name}: {e}"))?;
        let upstream = SocketAddr::from((container_ip, spec.port));
        record_on_success!(
            "bugpot_cold_start_seconds", "phase" => "readiness";
            wait_for_ready(upstream, spec.readiness.path.as_deref(), timeout).await
        )
    }

    /// Unfreeze a paused container. The endpoint and listen socket
    /// survived the freeze, so this is cheap: a single cgroup write
    /// (via libcontainer) wakes the process.
    async fn do_resume(&self, handle: &AppHandle, container_ip: Ipv4Addr) -> Result<Ipv4Addr> {
        let name = &handle.identity.name;
        let container_id = handle.current_id().await;
        info!(app = %name, "resuming from frozen");
        record_on_success!(
            "bugpot_resume_seconds";
            self.runtime.unfreeze_app(&container_id).await
        )?;
        Ok(container_ip)
    }

    /// Suspend a running app via cgroup freezer. Returns Ok and leaves
    /// the handle in `Frozen { container_ip }` on success. No-op when
    /// the app isn't in a freezable state (Stopped / Stopping / already
    /// Frozen / Starting / has active upgraded connections).
    pub(crate) async fn freeze(&self, handle: &Arc<AppHandle>) -> Result<()> {
        let container_ip = {
            let inner = handle.inner.lock().await;
            match inner.state {
                AppState::Running { container_ip } => container_ip,
                _ => return Ok(()),
            }
        };
        // Skip if a WebSocket / SSE upgrade is mid-flight. Freezing
        // here would silently strand the connection (kernel keeps the
        // listen socket up, but the user-space process can't process
        // frames). The reaper will retry next tick.
        let active = handle.active_upgrades.load(Ordering::Relaxed);
        if active > 0 {
            debug!(
                app = %handle.identity.name,
                active,
                "skipping freeze: upgraded connections active",
            );
            return Ok(());
        }
        let name = &handle.identity.name;
        let container_id = handle.current_id().await;
        if let Err(e) = record_on_success!(
            "bugpot_freeze_seconds";
            self.runtime.freeze_app(&container_id).await
        ) {
            warn!(app = %name, error = %e, "freeze_app failed");
            return Err(e.into());
        }
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::Frozen { container_ip };
        }
        info!(app = %name, "frozen");
        Ok(())
    }

    pub(crate) async fn stop(&self, handle: &Arc<AppHandle>) -> Result<()> {
        {
            let mut inner = handle.inner.lock().await;
            if !inner.state.needs_teardown() {
                return Ok(());
            }
            inner.state = AppState::Stopping;
        }
        let res = self.do_stop(handle).await;
        let mut inner = handle.inner.lock().await;
        inner.state = AppState::Stopped;
        // Drop the CPU baseline so the next start of this app begins
        // from 0 rather than the (now-stale) last sample.
        inner.cpu_baseline = 0;
        res
    }

    async fn do_stop(&self, handle: &AppHandle) -> Result<()> {
        let name = &handle.identity.name;
        let container_id = handle.current_id().await;
        info!(app = %name, "stopping");
        if let Err(e) = self.runtime.stop_app(&container_id).await {
            warn!(app = %name, error = %e, "stop_app failed");
        }
        if let Err(e) = self.egress.release_endpoint(&container_id).await {
            warn!(app = %name, error = %e, "release_endpoint failed");
        }
        Ok(())
    }
}

/// If `digest` is `Some`, return an OCI reference pinned to that
/// digest so a subsequent pull skips the registry-side
/// `manifest_probe`. Returns the original reference unchanged when
/// `digest` is `None`, or when the reference already carries its
/// own `@sha256:…` suffix (constructing `repo:tag@d@d` would be
/// malformed and the existing reference is already digest-pinned).
pub(crate) fn digest_pinned_ref(image: &str, digest: Option<&ImageId>) -> String {
    match digest {
        Some(d) if !image.contains('@') => format!("{image}@{d}", d = d.as_str()),
        _ => image.to_owned(),
    }
}
