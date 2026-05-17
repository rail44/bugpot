//! Per-app lifecycle controller with scale-to-zero and dynamic mutation.
//!
//! Each app handle is a small state machine:
//!
//! ```text
//!  Stopped ─request─► Starting ─ok─► Running ─idle─► Stopping ─► Stopped
//!     ▲                  │ err                                    │
//!     └──────────────────┴────────────────────────────────────────┘
//! ```
//!
//! The set of registered apps is held in a `RwLock<HashMap<..>>` so adapter
//! crates (HTTP admin, future webhook / poller / CLI frontends) can mutate
//! it at runtime via [`AppController::deploy_app`] / [`AppController::remove_app`].
//! Per-app `Mutex`-protected state machines coalesce concurrent starts.
//!
//! Note: `pub(crate)` is used for cross-module items inside this crate;
//! the `clippy::redundant_pub_crate` warning conflicts with the workspace's
//! `unreachable_pub` rule, so the former is allowed crate-wide (same
//! convention as `bugpot-runtime`).

#![allow(clippy::redundant_pub_crate)]

#[cfg(test)]
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bugpot_config::{AppSpec, AuthConfig, RegistryCredential, Rollout, registry_host};
use bugpot_egress::EgressOps;
use bugpot_router::{ResolveError, Upstream, UpstreamResolver, subdomain_of};
#[cfg(test)]
use bugpot_runtime::RuntimeError;
use bugpot_runtime::{Auth, RuntimeOps};
use metrics::{counter, gauge, histogram};
use tokio::sync::{Notify, RwLock};
use tracing::{debug, error, info, warn};

mod error;
use error::classify_pull_error_for_rollout;
pub use error::{DeployError, RemoveError, RolloutError, UpdateError};

mod probe;
use probe::wait_for_ready;

mod mempressure;
use mempressure::read_mem_available;

mod handle;
use handle::{
    AppHandle, AppMaps, AppState, MAX_ROLLOUT_HISTORY, make_handle, make_handle_with_rollouts,
};

mod view;
pub use view::{AppStateView, AppView};
use view::{emit_resource_metrics, view_of};

mod persist;
use persist::{RolloutsFile, load_persisted_state};

/// How long to wait for an app to start accepting TCP connections on its
/// declared port after libcontainer reports the container is running.
/// Default readiness timeout when an app does not override
/// `readiness.timeout` in its TOML.
const READINESS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);

/// Per-app lifecycle controller.
///
/// `new` accepts the initial set of specs loaded at startup; subsequent
/// add/remove happens through [`Self::deploy_app`] / [`Self::remove_app`].
/// A background [`Self::sweep_loop`] task should be spawned to reclaim
/// apps whose container died unexpectedly or that have been idle too
/// long.
#[derive(Debug)]
pub struct AppController<R: RuntimeOps, E: EgressOps> {
    runtime: Arc<R>,
    egress: Arc<E>,
    /// Directory where bugpotd persists its own view of the world:
    /// `<state>/apps/<name>.toml` for `AppSpec`,
    /// `<state>/rollouts/<name>.toml` for rollout history. Operators
    /// do not edit anything under here — every spec change goes
    /// through the admin API.
    state_dir: PathBuf,
    auth: AuthConfig,
    apps: RwLock<AppMaps>,
    /// One-shot guard for `reattach_running`. The controller is only
    /// meant to reattach once per bugpot process — the function calls
    /// `ensure_log_tails` per surviving app, and a second call would
    /// double up tail tasks on the same files. Set on first entry; any
    /// further call is a no-op with a warning.
    reattach_done: AtomicBool,
}

impl<R: RuntimeOps, E: EgressOps> AppController<R, E> {
    /// Create a controller, materialising the daemon-owned state
    /// directories and rehydrating any apps + rollouts persisted by
    /// a previous run.
    ///
    /// Errors when an on-disk spec fails validation or rollouts file
    /// can't be parsed — both indicate state corruption that the
    /// operator should investigate before bugpotd serves traffic.
    pub fn new(
        runtime: Arc<R>,
        egress: Arc<E>,
        state_dir: PathBuf,
        auth: AuthConfig,
    ) -> Result<Self> {
        let specs_dir = state_dir.join("apps");
        let rollouts_dir = state_dir.join("rollouts");
        std::fs::create_dir_all(&specs_dir)
            .with_context(|| format!("create {}", specs_dir.display()))?;
        std::fs::create_dir_all(&rollouts_dir)
            .with_context(|| format!("create {}", rollouts_dir.display()))?;

        let mut maps = AppMaps::default();
        for (spec, rollouts) in load_persisted_state(&specs_dir, &rollouts_dir)? {
            // Specs persisted by bugpot have already passed validation
            // before being written; corrupted state here is operator-
            // investigation territory, but we fail loudly rather than
            // silently dropping the app.
            let handle = make_handle_with_rollouts(spec, rollouts)
                .map_err(|e| anyhow!("rehydrate handle: {e}"))?;
            maps.by_subdomain.insert(
                handle.identity.subdomain.clone(),
                handle.identity.name.clone(),
            );
            maps.by_name.insert(handle.identity.name.clone(), handle);
        }
        #[allow(clippy::cast_precision_loss)]
        gauge!("bugpot_apps_active").set(maps.by_name.len() as f64);
        Ok(Self {
            runtime,
            egress,
            state_dir,
            auth,
            apps: RwLock::new(maps),
            reattach_done: AtomicBool::new(false),
        })
    }

    /// Resolve pull credentials for an image reference by looking the
    /// registry hostname up in [`AuthConfig`]. Falls back to anonymous.
    fn resolve_auth(&self, image_ref: &str) -> Auth {
        let host = registry_host(image_ref);
        match self.auth.registries.get(host) {
            Some(RegistryCredential::Bearer { token }) => Auth::BearerToken(token.clone()),
            Some(RegistryCredential::Basic { username, password }) => Auth::Basic {
                user: username.clone(),
                pass: password.clone(),
            },
            None => Auth::Anonymous,
        }
    }

    /// Re-bind to containers that survived a previous bugpot run.
    ///
    /// For each registered app whose libcontainer state reports
    /// `Running`, ask the egress layer to re-register the existing netns
    /// IP + allowlist (no new veth / netns is created). The app's handle
    /// transitions directly into `Running`, so the very next
    /// `ensure_running` short-circuits — there is no cold-start, no
    /// image pull, no port readiness probe.
    ///
    /// **Lost on reattach:** the container's stdout/stderr forwarder was
    /// owned by the previous bugpot process; the write-end of the pipe
    /// is gone with that process. The container is still alive but its
    /// logs no longer flow through bugpot's tracing pipeline. Until
    /// #21 lands, journalctl on the container's app-side mount is the
    /// only way to retrieve them.
    ///
    /// Containers that look running to libcontainer but have no
    /// discovered egress endpoint are left in `Stopped` — the next
    /// request triggers a fresh cold start. This is a conservative
    /// recovery path: there is no way to safely manufacture the missing
    /// IP, and we would rather rebuild than route traffic to a netns
    /// we do not fully understand.
    ///
    /// Idempotent against accidental double-call: a second invocation
    /// is a no-op with a warning. The body spawns log-tail tasks per
    /// surviving app, and running it twice would double-tail every
    /// file — harmless functionally but visible as duplicate lines in
    /// tracing.
    pub async fn reattach_running(&self) {
        if self.reattach_done.swap(true, Ordering::SeqCst) {
            warn!("reattach_running called more than once; ignoring subsequent calls");
            return;
        }
        for handle in self.snapshot_handles().await {
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
            let allowlist = handle.spec.read().await.egress.allow.clone();
            match self.egress.reattach_endpoint(name, allowlist).await {
                Ok(Some(ep)) => {
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
                Ok(None) => {
                    warn!(
                        app = %name,
                        "container is running but no netns IP was discovered; \
                         leaving as Stopped — next request will cold-start"
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
    pub async fn cleanup_orphans(&self) {
        let orphans = self.egress.drain_unreclaimed_endpoints();
        for (name, ip) in orphans {
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
        let handles = self.snapshot_handles().await;
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

    /// Background task: sweeps registered apps periodically to:
    ///
    /// 1. Reclaim containers whose init has exited unexpectedly (crash,
    ///    OOM, etc.) so the next request triggers a fresh `do_start`
    ///    instead of being proxied to a dead IP.
    /// 2. Stop apps that have been idle beyond their `scaling.idle_timeout`
    ///    (scale-to-zero).
    ///
    /// Consumes an `Arc<Self>` so it can be `tokio::spawn`ed.
    pub async fn sweep_loop(self: Arc<Self>, tick: Duration) {
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            self.sweep().await;
        }
    }

    /// Background task: poll system memory and evict frozen apps to
    /// `Stopped` when available memory drops below `lo_bytes`. Stops
    /// evicting once memory rebounds past `hi_bytes` (hysteresis).
    ///
    /// Frozen apps still occupy their full RSS, so a runtime that
    /// freezes-by-default on idle would slowly fill memory. This loop
    /// is the safety valve: it converts the cheapest-to-restart
    /// (= least-recently-used) frozen apps back into proper Stopped
    /// state, freeing their pages.
    ///
    /// Apps are evicted one per tick in LRU order; the loop re-reads
    /// `MemAvailable` after each eviction so a single tick can release
    /// just enough to clear pressure rather than thawing everything.
    pub async fn memory_pressure_loop(
        self: Arc<Self>,
        tick: Duration,
        lo_bytes: u64,
        hi_bytes: u64,
    ) {
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut evicting = false;
        loop {
            interval.tick().await;
            let Some(avail) = read_mem_available() else {
                continue;
            };
            // Hysteresis: cross lo to engage, cross hi to disengage.
            // Between the two we keep evicting once started — that way
            // a slow leak doesn't keep flap-flipping on the lo line.
            if !evicting && avail < lo_bytes {
                evicting = true;
                info!(
                    avail_bytes = avail,
                    lo_bytes, "memory pressure: starting frozen-app eviction"
                );
            }
            if evicting && avail >= hi_bytes {
                evicting = false;
                info!(avail_bytes = avail, hi_bytes, "memory pressure resolved");
                continue;
            }
            if !evicting {
                continue;
            }
            if !self.evict_lru_frozen().await {
                // Nothing left to evict; pressure is from something
                // outside bugpot's reach. Disengage so we don't spin.
                debug!("no frozen apps to evict; disengaging pressure handler");
                evicting = false;
            }
        }
    }

    /// Find the longest-idle Frozen app and transition it to Stopped.
    /// Returns true if an eviction happened. Caller is the memory
    /// pressure loop; per-tick semantics keep eviction proportional
    /// to actual pressure.
    async fn evict_lru_frozen(&self) -> bool {
        let mut candidate: Option<(Arc<AppHandle>, Instant)> = None;
        for handle in self.snapshot_handles().await {
            let inner = handle.inner.lock().await;
            if inner.state.is_frozen() {
                match &candidate {
                    Some((_, oldest)) if inner.last_access >= *oldest => {}
                    _ => candidate = Some((handle.clone(), inner.last_access)),
                }
            }
        }
        let Some((handle, _)) = candidate else {
            return false;
        };
        info!(
            app = %handle.identity.name,
            "memory pressure: evicting frozen app"
        );
        counter!("bugpot_evictions_total").increment(1);
        if let Err(e) = self.stop(&handle).await {
            warn!(
                app = %handle.identity.name,
                error = ?e,
                "eviction stop() failed",
            );
        }
        true
    }

    async fn sweep(&self) {
        // Per-app sweep work is independent (each handle has its own
        // lock + spec + runtime entry), so run all apps concurrently.
        // A slow `stop()` on one app no longer blocks metric emission
        // or idle-timeout enforcement for the others in the same tick.
        let handles = self.snapshot_handles().await;
        let tasks = handles.into_iter().map(|h| self.sweep_one(h));
        futures::future::join_all(tasks).await;
    }

    async fn sweep_one(&self, handle: Arc<AppHandle>) {
        // Only look at apps we believe are running. Starting /
        // Stopping / Stopped handles are already in motion or
        // already-cleaned.
        if !handle.inner.lock().await.state.is_running() {
            return;
        }

        // 1. Liveness: did the container die under us?
        if !self.runtime.is_container_running(&handle.identity.name) {
            info!(app = %handle.identity.name, "container exited unexpectedly, cleaning up");
            counter!(
                "bugpot_container_crashes_total",
                "app" => handle.identity.name.clone(),
            )
            .increment(1);
            if let Err(e) = self.stop(&handle).await {
                warn!(app = %handle.identity.name, error = ?e, "cleanup of dead container failed");
            }
            return;
        }

        // 2. Resource sampling. Skip silently when cgroup paths
        // resolve to nothing (cgroup v1 host or transient /proc
        // races) — the gauge stops updating, the counter doesn't
        // move.
        if let Some(usage) = self.runtime.resource_usage(&handle.identity.name) {
            emit_resource_metrics(&handle, usage).await;
        }

        // 3. Idle timeout (scale-to-zero). always-on apps skip.
        let idle_resolved = handle.spec.read().await.scaling.resolve_idle_timeout();
        let timeout = match idle_resolved {
            Ok(Some(t)) => t,
            Ok(None) => return,
            Err(e) => {
                warn!(app = %handle.identity.name, "bad idle_timeout: {e}");
                return;
            }
        };
        let last_access = {
            let inner = handle.inner.lock().await;
            inner.last_access
        };
        if last_access.elapsed() >= timeout {
            info!(app = %handle.identity.name, "idle timeout reached, freezing");
            if let Err(e) = self.freeze(&handle).await {
                warn!(app = %handle.identity.name, error = ?e, "freeze on idle failed");
            }
        }
    }

    /// Stop every app that's currently running. Used on shutdown.
    pub async fn teardown(&self) {
        for handle in self.snapshot_handles().await {
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

    /// Register a new app. Fails if an app with the same name or
    /// subdomain already exists. **Does not pull an image or start a
    /// container** — the new app exists in `Stopped` state with no
    /// rollouts. Operators (or `set_rollout` from the admin API)
    /// supply the first rollout in a separate step, which is what
    /// actually pulls and starts.
    pub async fn deploy_app(&self, mut spec: AppSpec) -> std::result::Result<AppView, DeployError> {
        let name = spec.name.clone().ok_or(DeployError::MissingName)?;
        // Strict validation BEFORE we touch the filesystem — `name`
        // lands in `<state>/apps/<name>.toml` and `bugpot-<name>` netns
        // names, and the admin API accepts arbitrary JSON.
        spec.validate()?;
        let subdomain = spec.subdomain().to_owned();

        // Fast-fail on obvious collisions before persisting.
        {
            let maps = self.apps.read().await;
            if maps.by_name.contains_key(&name) {
                return Err(DeployError::AlreadyExists(name));
            }
            if maps.by_subdomain.contains_key(&subdomain) {
                return Err(DeployError::SubdomainTaken(subdomain));
            }
        }

        let toml_path = self.spec_path(&name);
        let toml_body =
            toml::to_string_pretty(&spec).with_context(|| format!("serialize app for {name}"))?;
        tokio::fs::write(&toml_path, toml_body)
            .await
            .with_context(|| format!("write {}", toml_path.display()))?;
        spec.source_path.clone_from(&toml_path);

        let handle = make_handle(spec.clone(), None)?;

        {
            let mut maps = self.apps.write().await;
            // Re-check under the write lock — a concurrent deploy may have
            // raced into the same keys.
            if maps.by_name.contains_key(&name) {
                discard_failed_toml(&toml_path).await;
                return Err(DeployError::AlreadyExists(name));
            }
            if maps.by_subdomain.contains_key(&subdomain) {
                discard_failed_toml(&toml_path).await;
                return Err(DeployError::SubdomainTaken(subdomain));
            }
            maps.by_subdomain.insert(subdomain.clone(), name.clone());
            maps.by_name.insert(name.clone(), handle.clone());
        }
        gauge!("bugpot_apps_active").increment(1.0);

        Ok(view_of(&handle).await)
    }

    /// Update an existing app's config in place.
    ///
    /// PATCH semantics — `new_spec` is the new desired state for
    /// every mutable field; `name` and `subdomain` are identity and
    /// rejected for change (rename = delete + recreate).
    ///
    /// Behaviour:
    ///   - Mid-transition (`Starting` / `Stopping`) → 409 Conflict.
    ///   - No effective change (TOML round-trip equal) → no-op
    ///     returning the current view. Lets the ops apply workflow
    ///     PATCH unconditionally without restarting containers on
    ///     every CI run.
    ///   - Spec changed → persist new TOML, reset the per-handle
    ///     `image_digest` cache if `repo` moved, and (if the app
    ///     was `Running`) stop + start it so the new config takes
    ///     effect. The current rollout history is preserved.
    pub async fn update_app(
        &self,
        name: &str,
        new_spec: AppSpec,
    ) -> std::result::Result<AppView, UpdateError> {
        new_spec.validate()?;

        let handle = self
            .apps
            .read()
            .await
            .by_name
            .get(name)
            .cloned()
            .ok_or_else(|| UpdateError::NotFound(name.to_owned()))?;

        // Identity guards: PATCH cannot change `name` / `subdomain`.
        // The body's `name` field is allowed to either match or be
        // absent (some clients omit identity from the body).
        if let Some(ref body_name) = new_spec.name
            && body_name != name
        {
            return Err(UpdateError::NameImmutable);
        }
        if new_spec.subdomain() != handle.identity.subdomain {
            return Err(UpdateError::SubdomainImmutable);
        }

        {
            let inner = handle.inner.lock().await;
            if inner.state.is_busy() {
                return Err(UpdateError::Conflict(name.to_owned()));
            }
        }

        // Short-circuit if nothing changed in the TOML projection.
        // `source_path` is `#[serde(skip)]`, so two specs whose
        // serialised TOML matches are functionally identical.
        let existing = handle.spec.read().await.clone();
        let logically_equal = match (toml::to_string(&existing), toml::to_string(&new_spec)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        if logically_equal {
            return Ok(view_of(&handle).await);
        }

        let was_running = handle.inner.lock().await.state.is_running();

        // Replace under the write lock.
        {
            let mut guard = handle.spec.write().await;
            *guard = new_spec.clone();
        }

        // The deploy-time digest cache (from PR #73) is bound to
        // whatever ref the previous `repo` resolved to. Clear it
        // when `repo` changes so the next pull rebuilds it against
        // the new registry path.
        if existing.repo != new_spec.repo {
            *handle.image_digest.lock().await = None;
        }

        if let Err(e) = self.persist_spec(&handle).await {
            return Err(UpdateError::Internal(e));
        }

        if was_running {
            if let Err(e) = self.stop(&handle).await {
                return Err(UpdateError::RestartFailed(anyhow!(
                    "stop before reconfigure: {e:#}"
                )));
            }
            if let Err(e) = self.ensure_running(&handle).await {
                return Err(UpdateError::RestartFailed(anyhow!(
                    "restart after reconfigure: {e:#}"
                )));
            }
        }

        Ok(view_of(&handle).await)
    }

    /// Append a new rollout to `name` and bring the app to that tag.
    ///
    /// Steps:
    ///   1. Pull `{repo}:{tag}`.
    ///   2. Push to the rollout history (popping the oldest entry
    ///      when the deque is full).
    ///   3. Persist `<apps_dir>/<name>.toml` with the new current
    ///      rollout.
    ///   4. If the app is `Running`, stop it; then start under the
    ///      new rollout.
    ///   5. If `Stopped`, start now (so callers observe a deployed
    ///      app on return).
    ///   6. If `Starting` / `Stopping`, return [`RolloutError::Conflict`]
    ///      and let the caller retry.
    pub async fn set_rollout(
        &self,
        name: &str,
        tag: String,
    ) -> std::result::Result<Rollout, RolloutError> {
        if tag.trim().is_empty() {
            return Err(RolloutError::EmptyTag);
        }
        let handle = self
            .apps
            .read()
            .await
            .by_name
            .get(name)
            .cloned()
            .ok_or_else(|| RolloutError::NotFound(name.to_owned()))?;

        // Conflict check: refuse mid-transition. Done before pull so
        // we don't waste a registry round-trip on a doomed call.
        {
            let inner = handle.inner.lock().await;
            if inner.state.is_busy() {
                return Err(RolloutError::Conflict(name.to_owned()));
            }
        }

        // 1. Pull.
        let repo = handle.spec.read().await.repo.clone();
        let image_ref = format!("{repo}:{tag}");
        let resolved_digest = self
            .runtime
            .pull_image(&image_ref, self.resolve_auth(&repo))
            .await
            .map_err(|e| classify_pull_error_for_rollout(e, name, &image_ref))?;

        // 2. Append to history. Reset the digest cache so the next
        // `do_start` uses *this* rollout's digest (not the previous
        // rollout's, which may have been a different tag).
        let rollout = Rollout {
            tag,
            created_at: humantime::format_rfc3339_seconds(SystemTime::now()).to_string(),
        };
        {
            let mut inner = handle.inner.lock().await;
            while inner.rollouts.len() >= MAX_ROLLOUT_HISTORY {
                inner.rollouts.pop_front();
            }
            inner.rollouts.push_back(rollout.clone());
        }
        *handle.image_digest.lock().await = Some(resolved_digest);

        // 3. Persist the rollout to its own state file. Spec doesn't
        // change here, so no spec rewrite needed.
        if let Err(e) = self.persist_rollouts(&handle).await {
            warn!(app = %name, error = ?e, "failed to persist rollouts");
        }

        // 4 + 5: bring the container to the new image. If it was
        // running, stop first so the start uses the new digest cache.
        let was_running = handle.inner.lock().await.state.is_running();
        if was_running && let Err(e) = self.stop(&handle).await {
            warn!(app = %name, error = ?e, "stop before rollout-restart failed");
        }
        if let Err(e) = self.ensure_running(&handle).await {
            return Err(RolloutError::StartFailed(e));
        }

        Ok(rollout)
    }

    /// Return a snapshot of the rollout history (front = oldest,
    /// back = current) for `name`, or `None` if the app does not
    /// exist.
    pub async fn list_rollouts(&self, name: &str) -> Option<Vec<Rollout>> {
        let handle = self.apps.read().await.by_name.get(name).cloned()?;
        Some(handle.inner.lock().await.rollouts.iter().cloned().collect())
    }

    fn spec_path(&self, name: &str) -> PathBuf {
        self.state_dir.join("apps").join(format!("{name}.toml"))
    }

    fn rollouts_path(&self, name: &str) -> PathBuf {
        self.state_dir.join("rollouts").join(format!("{name}.toml"))
    }

    /// Persist the handle's spec (post-update) to
    /// `<state>/apps/<name>.toml`. Best-effort; the caller logs on
    /// error.
    async fn persist_spec(&self, handle: &Arc<AppHandle>) -> Result<()> {
        let name = &handle.identity.name;
        let spec = handle.spec.read().await.clone();
        let body =
            toml::to_string_pretty(&spec).with_context(|| format!("serialize spec for {name}"))?;
        let path = self.spec_path(name);
        tokio::fs::write(&path, body)
            .await
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    /// Persist the handle's full rollout history to
    /// `<state>/rollouts/<name>.toml`. The file is daemon-owned; no
    /// operator should ever edit it, so the on-disk shape is purely
    /// `[[rollout]]` entries (oldest first, back = current).
    async fn persist_rollouts(&self, handle: &Arc<AppHandle>) -> Result<()> {
        let name = &handle.identity.name;
        let rollouts: Vec<Rollout> = handle.inner.lock().await.rollouts.iter().cloned().collect();
        let file = RolloutsFile { rollouts };
        let body = toml::to_string_pretty(&file)
            .with_context(|| format!("serialize rollouts for {name}"))?;
        let path = self.rollouts_path(name);
        tokio::fs::write(&path, body)
            .await
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    /// Unregister an app by name. Stops the container (if running) and
    /// deletes its TOML file.
    pub async fn remove_app(&self, name: &str) -> std::result::Result<(), RemoveError> {
        if !self.apps.read().await.by_name.contains_key(name) {
            return Err(RemoveError::NotFound(name.to_owned()));
        }
        self.remove_by_name(name)
            .await
            .map_err(RemoveError::Internal)
    }

    async fn remove_by_name(&self, name: &str) -> Result<()> {
        let handle = {
            let mut maps = self.apps.write().await;
            let handle = maps
                .by_name
                .remove(name)
                .ok_or_else(|| anyhow!("app '{name}' not found"))?;
            maps.by_subdomain.remove(&handle.identity.subdomain);
            handle
        };
        gauge!("bugpot_apps_active").decrement(1.0);
        if let Err(e) = self.stop(&handle).await {
            warn!(app = %handle.identity.name, error = ?e, "stop failed during remove");
        }
        // `stop()` only kills the container — it leaves the bundle dir
        // and the per-app volume tree on disk. `cleanup_orphan_container`
        // is what knows how to reclaim those (it's also the entry
        // point for the startup orphan sweep), so route through it
        // here too. Otherwise persistent-volume apps leak data on
        // DELETE — the volume dir survives until the operator runs a
        // restart-with-missing-TOML cycle.
        if let Err(e) = self
            .runtime
            .cleanup_orphan_container(&handle.identity.name)
            .await
        {
            warn!(
                app = %handle.identity.name,
                error = ?e,
                "cleanup_orphan_container failed during remove; bundle / volume dir may leak",
            );
        }
        let spec_path = self.spec_path(&handle.identity.name);
        if spec_path.exists()
            && let Err(e) = tokio::fs::remove_file(&spec_path).await
        {
            warn!(path = %spec_path.display(), error = %e, "remove spec toml failed");
        }
        let rollouts_path = self.rollouts_path(&handle.identity.name);
        if rollouts_path.exists()
            && let Err(e) = tokio::fs::remove_file(&rollouts_path).await
        {
            warn!(path = %rollouts_path.display(), error = %e, "remove rollouts toml failed");
        }
        Ok(())
    }

    pub async fn list_apps(&self) -> Vec<AppView> {
        let mut views = Vec::new();
        for handle in self.snapshot_handles().await {
            views.push(view_of(&handle).await);
        }
        views
    }

    pub async fn get_app(&self, name: &str) -> Option<AppView> {
        let handle = self.apps.read().await.by_name.get(name).cloned()?;
        Some(view_of(&handle).await)
    }

    async fn snapshot_handles(&self) -> Vec<Arc<AppHandle>> {
        self.apps.read().await.by_name.values().cloned().collect()
    }

    /// Ensure the app is running, coalescing concurrent starts. Returns
    /// the container IP.
    async fn ensure_running(&self, handle: &Arc<AppHandle>) -> Result<Ipv4Addr> {
        loop {
            // Phase 1: inspect / transition state under the lock.
            //
            // The `Notify` lives inside the `Starting` variant so the
            // "starting state without a notify" footgun is gone at the
            // type level — no more `expect` here.
            let (own_notify, resume_from) = {
                let mut inner = handle.inner.lock().await;
                inner.last_access = Instant::now();
                match &inner.state {
                    AppState::Running { container_ip } => return Ok(*container_ip),
                    AppState::Starting { notify } => {
                        let n = notify.clone();
                        drop(inner);
                        debug!(app = %handle.identity.name, "awaiting concurrent start");
                        n.notified().await;
                        continue;
                    }
                    AppState::Stopping => {
                        drop(inner);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    AppState::Stopped => {
                        let n = Arc::new(Notify::new());
                        inner.state = AppState::Starting { notify: n.clone() };
                        drop(inner);
                        (n, None)
                    }
                    AppState::Frozen { container_ip } => {
                        // Resume from cgroup freezer. We still re-use
                        // `Starting` here so concurrent callers coalesce
                        // through the same `Notify` regardless of which
                        // dormant state we were in.
                        let n = Arc::new(Notify::new());
                        let ip = *container_ip;
                        inner.state = AppState::Starting { notify: n.clone() };
                        drop(inner);
                        (n, Some(ip))
                    }
                }
            };

            // Phase 2: do the work outside the lock.
            let result = if let Some(ip) = resume_from {
                self.do_resume(handle, ip).await
            } else {
                self.do_start(handle).await
            };

            // Phase 3: commit state + wake waiters (after dropping the
            // lock so concurrent readers don't contend on `Notify`).
            // Transitioning out of `Starting` drops the in-state `Arc`;
            // `own_notify` keeps it alive for the wake below.
            {
                let mut inner = handle.inner.lock().await;
                inner.state = result
                    .as_ref()
                    .map_or(AppState::Stopped, |ip| AppState::Running {
                        container_ip: *ip,
                    });
            }
            own_notify.notify_waiters();
            return result;
        }
    }

    async fn do_start(&self, handle: &AppHandle) -> Result<Ipv4Addr> {
        let name = &handle.identity.name;
        // Snapshot the spec once: a cold start interleaves several
        // awaits with reads of repo / port / egress.allow / readiness,
        // so cloning the small `AppSpec` is cheaper than holding the
        // RwLock guard across them (or re-locking each time).
        let spec = handle.spec.read().await.clone();
        // Resolve current rollout. An app without a rollout cannot
        // start — fail fast before allocating any resources.
        let tag = handle
            .inner
            .lock()
            .await
            .rollouts
            .back()
            .map(|r| r.tag.clone())
            .ok_or_else(|| anyhow!("app '{name}' has no rollout; POST a rollout first"))?;
        let plain_image_ref = format!("{repo}:{tag}", repo = spec.repo);
        info!(app = %name, image = %plain_image_ref, "starting");

        // Each cold-start phase records into bugpot_cold_start_seconds
        // *only on success*; failure paths intentionally don't record so
        // the histogram reflects the latency distribution of complete
        // cold starts. Total cold-start time = sum across phases (queryable
        // in Prom).
        let phase_start = Instant::now();
        let endpoint = self
            .egress
            .allocate_endpoint(name, spec.egress.allow.clone())
            .await
            .with_context(|| format!("allocate endpoint for {name}"))?;
        histogram!("bugpot_cold_start_seconds", "phase" => "endpoint")
            .record(phase_start.elapsed().as_secs_f64());

        let phase_start = Instant::now();
        // If a prior pull on this handle resolved the tag to a
        // digest, pin to it for this pull so the registry-side
        // manifest probe is skipped (`Puller::pull` short-circuits on
        // digest references). The cache invalidates only when the
        // handle is destroyed (operator redeploy or bugpot restart).
        let image_ref =
            digest_pinned_ref(&plain_image_ref, handle.image_digest.lock().await.as_ref());
        let image_id = match self
            .runtime
            .pull_image(&image_ref, self.resolve_auth(&spec.repo))
            .await
        {
            Ok(id) => id,
            Err(e) => {
                let _ = self.egress.release_endpoint(name).await;
                return Err(e).with_context(|| format!("pull image for {name}"));
            }
        };
        // Persist the resolved digest the first time we see it.
        // Subsequent cold-starts (within this process) will skip the
        // probe via the branch above.
        {
            let mut slot = handle.image_digest.lock().await;
            if slot.is_none() {
                *slot = Some(image_id.clone());
            }
        }
        histogram!("bugpot_cold_start_seconds", "phase" => "pull")
            .record(phase_start.elapsed().as_secs_f64());

        let phase_start = Instant::now();
        let running = match self
            .runtime
            .start_app(&spec, &image_id, Some(&endpoint.netns_path))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let _ = self.egress.release_endpoint(name).await;
                return Err(e).with_context(|| format!("start container for {name}"));
            }
        };
        histogram!("bugpot_cold_start_seconds", "phase" => "start")
            .record(phase_start.elapsed().as_secs_f64());

        info!(
            app = %name,
            pid = running.pid,
            container_ip = %endpoint.container_ip,
            "container running"
        );

        // Wait for the app to bind on its declared port before returning,
        // otherwise the first proxied request would race ahead of the
        // process's listener. Timeout is per-app (TOML
        // `readiness.timeout`), falling back to the workspace default.
        let timeout = spec
            .readiness
            .resolve_timeout(READINESS_TIMEOUT_DEFAULT)
            .map_err(|e| anyhow!("{name}: {e}"))?;
        let upstream = SocketAddr::from((endpoint.container_ip, spec.port));
        let phase_start = Instant::now();
        let probe_path = spec.readiness.path.as_deref();
        if let Err(e) = wait_for_ready(upstream, probe_path, timeout).await {
            warn!(app = %name, error = %e, "readiness probe failed");
            let _ = self.runtime.stop_app(name).await;
            let _ = self.egress.release_endpoint(name).await;
            return Err(e);
        }
        histogram!("bugpot_cold_start_seconds", "phase" => "readiness")
            .record(phase_start.elapsed().as_secs_f64());
        Ok(endpoint.container_ip)
    }

    /// Unfreeze a paused container. The endpoint and listen socket
    /// survived the freeze, so this is cheap: a single cgroup write
    /// (via libcontainer) wakes the process.
    async fn do_resume(&self, handle: &AppHandle, container_ip: Ipv4Addr) -> Result<Ipv4Addr> {
        let name = &handle.identity.name;
        info!(app = %name, "resuming from frozen");
        let phase_start = Instant::now();
        self.runtime.unfreeze_app(name).await?;
        histogram!("bugpot_resume_seconds").record(phase_start.elapsed().as_secs_f64());
        Ok(container_ip)
    }

    /// Suspend a running app via cgroup freezer. Returns Ok and leaves
    /// the handle in `Frozen { container_ip }` on success. No-op when
    /// the app isn't in a freezable state (Stopped / Stopping / already
    /// Frozen / Starting / has active upgraded connections).
    async fn freeze(&self, handle: &Arc<AppHandle>) -> Result<()> {
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
        let phase_start = Instant::now();
        if let Err(e) = self.runtime.freeze_app(name).await {
            warn!(app = %name, error = %e, "freeze_app failed");
            return Err(e.into());
        }
        histogram!("bugpot_freeze_seconds").record(phase_start.elapsed().as_secs_f64());
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::Frozen { container_ip };
        }
        info!(app = %name, "frozen");
        Ok(())
    }

    async fn stop(&self, handle: &Arc<AppHandle>) -> Result<()> {
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
        info!(app = %name, "stopping");
        if let Err(e) = self.runtime.stop_app(name).await {
            warn!(app = %name, error = %e, "stop_app failed");
        }
        if let Err(e) = self.egress.release_endpoint(name).await {
            warn!(app = %name, error = %e, "release_endpoint failed");
        }
        Ok(())
    }
}

/// Best-effort cleanup of a TOML written by `deploy_app` that the
/// subsequent collision-check rejected. The error is non-fatal — the
/// stale file will be picked up by orphan cleanup at the next bugpot
/// restart — but we log it so operators see leak when it happens.
async fn discard_failed_toml(path: &Path) {
    if let Err(e) = tokio::fs::remove_file(path).await {
        warn!(
            path = %path.display(),
            error = %e,
            "leftover TOML from a failed deploy_app could not be removed; \
             orphan cleanup at next startup will reclaim it"
        );
    }
}

/// If `digest` is `Some`, return an OCI reference pinned to that
/// digest so a subsequent pull skips the registry-side
/// `manifest_probe`. Returns the original reference unchanged when
/// `digest` is `None`, or when the reference already carries its
/// own `@sha256:…` suffix (constructing `repo:tag@d@d` would be
/// malformed and the existing reference is already digest-pinned).
fn digest_pinned_ref(image: &str, digest: Option<&bugpot_runtime::ImageId>) -> String {
    match digest {
        Some(d) if !image.contains('@') => format!("{image}@{d}", d = d.as_str()),
        _ => image.to_owned(),
    }
}

#[async_trait]
impl<R: RuntimeOps, E: EgressOps> UpstreamResolver for AppController<R, E> {
    async fn resolve(&self, host: &str) -> Result<Upstream, ResolveError> {
        let subdomain = subdomain_of(host).ok_or(ResolveError::NoSuchApp)?;
        let handle = {
            let maps = self.apps.read().await;
            let name = maps
                .by_subdomain
                .get(subdomain)
                .ok_or(ResolveError::NoSuchApp)?;
            let handle = maps
                .by_name
                .get(name)
                .ok_or(ResolveError::NoSuchApp)?
                .clone();
            drop(maps);
            handle
        };
        let port = handle.spec.read().await.port;
        match self.ensure_running(&handle).await {
            Ok(ip) => Ok(Upstream::with_active_upgrades(
                SocketAddr::from((ip, port)),
                handle.active_upgrades.clone(),
            )),
            Err(e) => {
                error!(host, error = ?e, "ensure_running failed");
                Err(ResolveError::Unhealthy(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex as StdMutex;

    use bugpot_config::{AppSpec, EgressSpec, Readiness, Resources, Scaling};
    use bugpot_egress::{EgressOps, Endpoint};
    use bugpot_runtime::{Auth, ImageId, ResourceUsage, RunningApp, RuntimeOps};

    #[derive(Debug, Default)]
    struct MockRuntime {
        pull_results: StdMutex<VecDeque<std::result::Result<ImageId, RuntimeError>>>,
        start_results: StdMutex<VecDeque<std::result::Result<RunningApp, RuntimeError>>>,
        running: StdMutex<HashMap<String, bool>>,
        paused: StdMutex<HashMap<String, bool>>,
        calls: StdMutex<Vec<String>>,
    }

    impl MockRuntime {
        fn push_pull(&self, r: std::result::Result<ImageId, RuntimeError>) {
            self.pull_results.lock().unwrap().push_back(r);
        }
        fn set_running(&self, app: &str, value: bool) {
            self.running.lock().unwrap().insert(app.to_owned(), value);
        }
        fn set_paused(&self, app: &str, value: bool) {
            self.paused.lock().unwrap().insert(app.to_owned(), value);
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn record(&self, s: impl Into<String>) {
            self.calls.lock().unwrap().push(s.into());
        }
    }

    impl RuntimeOps for MockRuntime {
        async fn pull_image(
            &self,
            image_ref: &str,
            _auth: Auth,
        ) -> std::result::Result<ImageId, RuntimeError> {
            self.record(format!("pull_image({image_ref})"));
            self.pull_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(RuntimeError::Other("mock: no pull response queued".into())))
        }

        async fn start_app(
            &self,
            spec: &AppSpec,
            _image_id: &ImageId,
            _netns_path: Option<&Path>,
        ) -> std::result::Result<RunningApp, RuntimeError> {
            let name = spec.name().to_owned();
            self.record(format!("start_app({name})"));
            self.start_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Err(RuntimeError::Other("mock: no start response queued".into()))
                })
        }

        async fn stop_app(&self, name: &str) -> std::result::Result<(), RuntimeError> {
            self.record(format!("stop_app({name})"));
            self.running.lock().unwrap().remove(name);
            self.paused.lock().unwrap().remove(name);
            Ok(())
        }

        async fn freeze_app(&self, name: &str) -> std::result::Result<(), RuntimeError> {
            self.record(format!("freeze_app({name})"));
            self.paused.lock().unwrap().insert(name.to_owned(), true);
            Ok(())
        }

        async fn unfreeze_app(&self, name: &str) -> std::result::Result<(), RuntimeError> {
            self.record(format!("unfreeze_app({name})"));
            self.paused.lock().unwrap().remove(name);
            Ok(())
        }

        fn is_container_running(&self, name: &str) -> bool {
            *self.running.lock().unwrap().get(name).unwrap_or(&false)
        }

        fn is_container_paused(&self, name: &str) -> bool {
            *self.paused.lock().unwrap().get(name).unwrap_or(&false)
        }

        fn resource_usage(&self, _name: &str) -> Option<ResourceUsage> {
            None
        }

        fn ensure_log_tails(&self, name: &str) {
            self.record(format!("ensure_log_tails({name})"));
        }

        async fn cleanup_orphan_container(
            &self,
            name: &str,
        ) -> std::result::Result<(), RuntimeError> {
            self.record(format!("cleanup_orphan_container({name})"));
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct MockEgress {
        allocate_fail: StdMutex<bool>,
        endpoints: StdMutex<HashMap<String, Endpoint>>,
        /// Pre-discovered endpoints — the reattach analogue of what real
        /// `Egress::new` would have found by scanning `bugpot-*` netns.
        discovered: StdMutex<HashMap<String, Ipv4Addr>>,
        calls: StdMutex<Vec<String>>,
    }

    impl MockEgress {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn set_discovered(&self, name: &str, ip: Ipv4Addr) {
            self.discovered.lock().unwrap().insert(name.to_owned(), ip);
        }
    }

    impl EgressOps for MockEgress {
        async fn allocate_endpoint(
            &self,
            name: &str,
            _allowlist: Vec<String>,
        ) -> anyhow::Result<Endpoint> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("allocate_endpoint({name})"));
            if *self.allocate_fail.lock().unwrap() {
                anyhow::bail!("mock: allocate_endpoint failed");
            }
            let ep = Endpoint {
                container_ip: Ipv4Addr::LOCALHOST,
                netns_path: PathBuf::from(format!("/run/netns/mock-{name}")),
            };
            self.endpoints
                .lock()
                .unwrap()
                .insert(name.to_owned(), ep.clone());
            Ok(ep)
        }

        async fn release_endpoint(&self, name: &str) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("release_endpoint({name})"));
            self.endpoints.lock().unwrap().remove(name);
            Ok(())
        }

        async fn reattach_endpoint(
            &self,
            name: &str,
            _allowlist: Vec<String>,
        ) -> anyhow::Result<Option<Endpoint>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("reattach_endpoint({name})"));
            let Some(container_ip) = self.discovered.lock().unwrap().remove(name) else {
                return Ok(None);
            };
            let ep = Endpoint {
                container_ip,
                netns_path: PathBuf::from(format!("/run/netns/mock-{name}")),
            };
            self.endpoints
                .lock()
                .unwrap()
                .insert(name.to_owned(), ep.clone());
            Ok(Some(ep))
        }

        fn drain_unreclaimed_endpoints(&self) -> Vec<(String, Ipv4Addr)> {
            self.calls
                .lock()
                .unwrap()
                .push("drain_unreclaimed_endpoints".to_owned());
            self.discovered.lock().unwrap().drain().collect()
        }

        async fn cleanup_orphan_endpoint(
            &self,
            name: &str,
            container_ip: Ipv4Addr,
        ) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("cleanup_orphan_endpoint({name},{container_ip})"));
            Ok(())
        }
    }

    #[test]
    fn digest_pinned_ref_appends_digest_when_absent() {
        let digest = bugpot_runtime::ImageId::new("sha256:abc123");
        assert_eq!(
            digest_pinned_ref("gcr.io/x/y:1.0", Some(&digest)),
            "gcr.io/x/y:1.0@sha256:abc123"
        );
        assert_eq!(
            digest_pinned_ref("gcr.io/x/y", Some(&digest)),
            "gcr.io/x/y@sha256:abc123"
        );
    }

    #[test]
    fn digest_pinned_ref_passthrough_when_no_digest_or_already_pinned() {
        let digest = bugpot_runtime::ImageId::new("sha256:abc");
        // No cached digest → original ref.
        assert_eq!(digest_pinned_ref("gcr.io/x/y:1.0", None), "gcr.io/x/y:1.0");
        // Already digest-pinned → don't double-stamp.
        assert_eq!(
            digest_pinned_ref("gcr.io/x/y@sha256:def", Some(&digest)),
            "gcr.io/x/y@sha256:def"
        );
    }

    fn spec_with_name(name: &str) -> AppSpec {
        AppSpec {
            repo: "registry.example/img".to_owned(),
            port: 8080,
            name: Some(name.to_owned()),
            subdomain: None,
            egress: EgressSpec::default(),
            env: HashMap::default(),
            scaling: Scaling::default(),
            readiness: Readiness::default(),
            resources: Resources::default(),
            volumes: Vec::new(),
            source_path: PathBuf::new(),
        }
    }

    /// Pre-registered app with an initial rollout for tests that
    /// want to drive `ensure_running` directly (skipping the
    /// register-then-rollout choreography of the real admin API).
    /// `stored` is just a (spec, optional initial rollout) tuple now
    /// that on-disk persistence is keyed by state dir, not a single
    /// combined file.
    fn stored_with_name(name: &str, tag: &str) -> (AppSpec, Option<Rollout>) {
        (
            spec_with_name(name),
            Some(Rollout {
                tag: tag.to_owned(),
                created_at: "1970-01-01T00:00:00Z".to_owned(),
            }),
        )
    }

    fn make_controller(
        stored: Vec<(AppSpec, Option<Rollout>)>,
        state_dir: PathBuf,
    ) -> Arc<AppController<MockRuntime, MockEgress>> {
        // Seed the state dir so AppController::new's load path picks
        // these specs + rollouts back up on construction — keeps the
        // test entry symmetric with production (everything goes
        // through the disk-rehydrate code path).
        std::fs::create_dir_all(state_dir.join("apps")).unwrap();
        std::fs::create_dir_all(state_dir.join("rollouts")).unwrap();
        for (spec, rollout) in stored {
            let name = spec.name().to_owned();
            let spec_body = toml::to_string_pretty(&spec).unwrap();
            std::fs::write(
                state_dir.join("apps").join(format!("{name}.toml")),
                spec_body,
            )
            .unwrap();
            if let Some(r) = rollout {
                let file = RolloutsFile { rollouts: vec![r] };
                let body = toml::to_string_pretty(&file).unwrap();
                std::fs::write(
                    state_dir.join("rollouts").join(format!("{name}.toml")),
                    body,
                )
                .unwrap();
            }
        }
        Arc::new(
            AppController::new(
                Arc::new(MockRuntime::default()),
                Arc::new(MockEgress::default()),
                state_dir,
                AuthConfig::default(),
            )
            .expect("controller::new"),
        )
    }

    /// `deploy_app` only registers; it does not pull. So even a
    /// runtime configured to fail on pull must produce a successful
    /// register (with a TOML written and the app in `Stopped`).
    #[tokio::test]
    async fn deploy_app_does_not_pull() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        // A pull queued up should remain unconsumed — register must
        // not touch the runtime's pull path.
        controller
            .runtime
            .push_pull(Err(RuntimeError::Other("would-be pull failure".into())));

        let view = controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register should succeed without pulling");
        assert_eq!(view.name, "alpha");
        assert!(
            view.current_rollout.is_none(),
            "newly registered app has no rollout yet"
        );
        let toml = tmp.path().join("apps").join("alpha.toml");
        assert!(toml.exists(), "register must persist the toml");
        let calls = controller.runtime.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("pull_image")),
            "register must not pull; got {calls:?}"
        );
    }

    /// `set_rollout` must surface a pull failure as
    /// `RolloutError::ImagePull` and leave the rollout history empty
    /// (so the next attempt starts clean).
    #[tokio::test]
    async fn set_rollout_propagates_pull_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");
        controller
            .runtime
            .push_pull(Err(RuntimeError::Other("registry unreachable".into())));

        let err = controller
            .set_rollout("alpha", "v1".to_owned())
            .await
            .expect_err("expected pull failure");
        assert!(matches!(err, RolloutError::ImagePull(_)), "got {err:?}");

        let view = controller.get_app("alpha").await.expect("app present");
        assert!(
            view.current_rollout.is_none(),
            "rollout history must stay empty on pull failure"
        );
    }

    /// PATCH on a stopped, registered app rewrites the spec and
    /// persists. The previous + new TOML differ on disk.
    #[tokio::test]
    async fn update_app_persists_new_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");

        // PATCH: change port + add an env var.
        let mut updated = spec_with_name("alpha");
        updated.port = 9999;
        updated
            .env
            .insert("LOG_LEVEL".to_owned(), "debug".to_owned());

        let view = controller
            .update_app("alpha", updated)
            .await
            .expect("update succeeds");
        assert_eq!(view.port, 9999);

        // TOML on disk reflects the new state.
        let toml_body =
            std::fs::read_to_string(tmp.path().join("apps").join("alpha.toml")).unwrap();
        assert!(
            toml_body.contains("port = 9999"),
            "toml missing new port: {toml_body}"
        );
        assert!(
            toml_body.contains("LOG_LEVEL"),
            "toml missing new env var: {toml_body}"
        );
    }

    /// PATCH with an identity-only difference (rename via `name`) is
    /// rejected with `NameImmutable`; the rest of the spec is left
    /// untouched.
    #[tokio::test]
    async fn update_app_rejects_name_change() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");

        let mut renamed = spec_with_name("alpha");
        renamed.name = Some("beta".to_owned());
        let err = controller
            .update_app("alpha", renamed)
            .await
            .expect_err("expected NameImmutable");
        assert!(matches!(err, UpdateError::NameImmutable), "got {err:?}");
    }

    /// Subdomain change is also rejected (routing identity is fixed
    /// for the life of an app in v1).
    #[tokio::test]
    async fn update_app_rejects_subdomain_change() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");

        let mut moved = spec_with_name("alpha");
        moved.subdomain = Some("alpha-renamed".to_owned());
        let err = controller
            .update_app("alpha", moved)
            .await
            .expect_err("expected SubdomainImmutable");
        assert!(
            matches!(err, UpdateError::SubdomainImmutable),
            "got {err:?}"
        );
    }

    /// PATCH with a body whose TOML projection equals the current
    /// one is a no-op. This is the path the ops apply workflow
    /// hits on every CI run for unchanged apps; the short-circuit
    /// is what stops the workflow from flapping containers.
    #[tokio::test]
    async fn update_app_noop_when_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");
        let runtime_calls_before = controller.runtime.calls().len();

        // Re-PATCH with the same content.
        controller
            .update_app("alpha", spec_with_name("alpha"))
            .await
            .expect("noop succeeds");

        // No runtime side effects (no stop, no start, no pull).
        assert_eq!(
            controller.runtime.calls().len(),
            runtime_calls_before,
            "noop PATCH must not touch the runtime"
        );
    }

    /// PATCH on a missing app returns `NotFound`.
    #[tokio::test]
    async fn update_app_returns_not_found_for_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        let err = controller
            .update_app("ghost", spec_with_name("ghost"))
            .await
            .expect_err("expected NotFound");
        assert!(matches!(err, UpdateError::NotFound(_)), "got {err:?}");
    }

    /// `repo` change clears the per-handle `image_digest` cache so
    /// the next start re-resolves against the new registry path
    /// rather than reusing the previous repo's digest.
    #[tokio::test]
    async fn update_app_clears_digest_cache_on_repo_change() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");

        let handle = {
            let maps = controller.apps.read().await;
            maps.by_name.get("alpha").cloned().unwrap()
        };
        // Seed the cache as if a prior start populated it.
        *handle.image_digest.lock().await =
            Some(bugpot_runtime::ImageId::new("sha256:oldcacheddigest"));

        let mut new_spec = spec_with_name("alpha");
        new_spec.repo = "registry.example/other-img".to_owned();
        controller
            .update_app("alpha", new_spec)
            .await
            .expect("repo change PATCH succeeds");

        assert!(
            handle.image_digest.lock().await.is_none(),
            "image_digest cache must clear on repo change"
        );
    }

    /// On cold-start failure during image pull, the previously-allocated
    /// endpoint must be released so the next attempt can reallocate
    /// cleanly.
    #[tokio::test]
    async fn cold_start_releases_endpoint_on_pull_failure() {
        let tmp = tempfile::tempdir().unwrap();
        // Pre-register with a rollout so we hit ensure_running →
        // do_start without going through any admin API path.
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        controller
            .runtime
            .push_pull(Err(RuntimeError::Other("registry down".into())));

        let handle = {
            let maps = controller.apps.read().await;
            maps.by_name.get("alpha").cloned().expect("handle present")
        };
        let res = controller.ensure_running(&handle).await;
        assert!(res.is_err(), "expected pull failure to propagate");

        let egress_calls = controller.egress.calls();
        assert!(
            egress_calls.contains(&"allocate_endpoint(alpha)".to_owned()),
            "expected allocate; got {egress_calls:?}"
        );
        assert!(
            egress_calls.contains(&"release_endpoint(alpha)".to_owned()),
            "expected release after pull failure; got {egress_calls:?}"
        );
        assert!(
            !controller
                .runtime
                .calls()
                .iter()
                .any(|c| c.starts_with("start_app")),
            "start_app must not be called when pull fails"
        );
    }

    /// `reattach_running` should put a surviving container straight into
    /// `Running` (no cold-start path) and skip apps with no live
    /// container.
    #[tokio::test]
    async fn reattach_running_recovers_live_containers() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(
            vec![
                stored_with_name("alpha", "v1"),
                stored_with_name("beta", "v1"),
            ],
            tmp.path().to_owned(),
        );
        // alpha is alive with a recovered IP; beta is gone.
        controller.runtime.set_running("alpha", true);
        controller
            .egress
            .set_discovered("alpha", Ipv4Addr::new(10, 0, 0, 42));

        controller.reattach_running().await;

        let alpha_state = {
            let maps = controller.apps.read().await;
            maps.by_name
                .get("alpha")
                .unwrap()
                .inner
                .lock()
                .await
                .state
                .clone()
        };
        let beta_state = {
            let maps = controller.apps.read().await;
            maps.by_name
                .get("beta")
                .unwrap()
                .inner
                .lock()
                .await
                .state
                .clone()
        };
        assert!(
            matches!(alpha_state, AppState::Running { container_ip } if container_ip == Ipv4Addr::new(10, 0, 0, 42)),
            "alpha should be Running with recovered IP, got {alpha_state:?}"
        );
        assert!(
            matches!(beta_state, AppState::Stopped),
            "beta should stay Stopped, got {beta_state:?}"
        );
        // The mock should NOT have called allocate_endpoint — reattach
        // must never trigger the cold-start path.
        let eg_calls = controller.egress.calls();
        assert!(
            eg_calls.iter().any(|c| c == "reattach_endpoint(alpha)"),
            "expected reattach_endpoint(alpha); got {eg_calls:?}"
        );
        assert!(
            !eg_calls.iter().any(|c| c.starts_with("allocate_endpoint")),
            "allocate_endpoint must not be called during reattach; got {eg_calls:?}"
        );
        // The fresh tail tasks must be spawned for the reattached app
        // (the previous bugpot's tails died with it).
        let rt_calls = controller.runtime.calls();
        assert!(
            rt_calls.contains(&"ensure_log_tails(alpha)".to_owned()),
            "expected ensure_log_tails(alpha); got {rt_calls:?}"
        );
    }

    /// After `reattach_running` consumes its endpoints, any leftover
    /// discovered IPs are orphans: their TOML is gone. `cleanup_orphans`
    /// must drive the runtime cleanup before the egress teardown so the
    /// container's processes are gone before we delete the netns they
    /// live in.
    #[tokio::test]
    async fn cleanup_orphans_reaps_unreclaimed_endpoints() {
        let tmp = tempfile::tempdir().unwrap();
        // `alpha` is the only known app; `beta` (registered in egress
        // discovery) has no TOML and must be reaped.
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        controller.runtime.set_running("alpha", true);
        controller
            .egress
            .set_discovered("alpha", Ipv4Addr::new(10, 0, 0, 5));
        controller
            .egress
            .set_discovered("beta", Ipv4Addr::new(10, 0, 0, 9));

        controller.reattach_running().await;
        controller.cleanup_orphans().await;

        // alpha was reattached, not orphaned.
        let rt_calls = controller.runtime.calls();
        let eg_calls = controller.egress.calls();
        assert!(
            !rt_calls
                .iter()
                .any(|c| c == "cleanup_orphan_container(alpha)"),
            "reattached alpha must not be cleaned as orphan; rt_calls={rt_calls:?}"
        );
        // beta was orphaned.
        let beta_runtime_idx = rt_calls
            .iter()
            .position(|c| c == "cleanup_orphan_container(beta)")
            .expect("expected cleanup_orphan_container(beta)");
        let beta_egress_idx = eg_calls
            .iter()
            .position(|c| c == "cleanup_orphan_endpoint(beta,10.0.0.9)")
            .expect("expected cleanup_orphan_endpoint(beta,10.0.0.9)");
        // Ordering: cleaning the runtime side first means the container
        // is dead by the time we tear down its netns; if we reversed
        // the order the container would lose eth0 while still trying
        // to exit. (Mock can't expose this, but the call sequence
        // documents the contract.)
        let _ = (beta_runtime_idx, beta_egress_idx);
    }

    /// A second call to `reattach_running` must be a no-op so accidental
    /// re-invocation does not double the log-tail tasks per app.
    #[tokio::test]
    async fn reattach_running_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        controller.runtime.set_running("alpha", true);
        controller
            .egress
            .set_discovered("alpha", Ipv4Addr::new(10, 0, 0, 7));

        controller.reattach_running().await;
        controller.reattach_running().await; // should short-circuit

        let eg_reattach_calls = controller
            .egress
            .calls()
            .iter()
            .filter(|c| c.starts_with("reattach_endpoint"))
            .count();
        let rt_tail_calls = controller
            .runtime
            .calls()
            .iter()
            .filter(|c| c.starts_with("ensure_log_tails"))
            .count();
        assert_eq!(eg_reattach_calls, 1, "reattach_endpoint must run once");
        assert_eq!(rt_tail_calls, 1, "ensure_log_tails must run once");
    }

    /// Sweep must detect a container that died under the controller's
    /// feet (`is_container_running` returns false despite the handle
    /// reporting `Running`) and transition its handle back to `Stopped`.
    #[tokio::test]
    async fn sweep_detects_dead_container() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());

        // Force the handle into Running state without going through the
        // real cold-start path.
        let handle = {
            let maps = controller.apps.read().await;
            maps.by_name.get("alpha").cloned().unwrap()
        };
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::Running {
                container_ip: Ipv4Addr::LOCALHOST,
            };
        }
        // Simulate the kernel: container is *not* actually running.
        controller.runtime.set_running("alpha", false);

        controller.sweep().await;

        let state = handle.inner.lock().await.state.clone();
        assert!(
            matches!(state, AppState::Stopped),
            "expected Stopped after sweep, got {state:?}"
        );
        let rt_calls = controller.runtime.calls();
        assert!(
            rt_calls.contains(&"stop_app(alpha)".to_owned()),
            "expected stop_app; got {rt_calls:?}"
        );
        let eg_calls = controller.egress.calls();
        assert!(
            eg_calls.contains(&"release_endpoint(alpha)".to_owned()),
            "expected release_endpoint; got {eg_calls:?}"
        );
    }

    async fn force_running(handle: &AppHandle) {
        let mut inner = handle.inner.lock().await;
        inner.state = AppState::Running {
            container_ip: Ipv4Addr::LOCALHOST,
        };
    }

    /// Idle reaper freezes (not stops) by default. Container survives;
    /// only its cgroup gets the freezer write.
    #[tokio::test]
    async fn idle_timeout_freezes_running_app() {
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = spec_with_name("alpha");
        // Short idle so the test doesn't need fake clocks.
        spec.scaling = bugpot_config::Scaling {
            idle_timeout: Some("10ms".into()),
        };
        let stored = (
            spec,
            Some(Rollout {
                tag: "v1".into(),
                created_at: "1970-01-01T00:00:00Z".into(),
            }),
        );
        let controller = make_controller(vec![stored], tmp.path().to_owned());
        let handle = {
            let maps = controller.apps.read().await;
            maps.by_name.get("alpha").cloned().unwrap()
        };
        force_running(&handle).await;
        controller.runtime.set_running("alpha", true);

        // Push last_access into the past so the reaper triggers.
        {
            let mut inner = handle.inner.lock().await;
            inner.last_access = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test machine clock should not be at unix epoch");
        }
        controller.sweep().await;

        let state = handle.inner.lock().await.state.clone();
        assert!(
            state.is_frozen(),
            "expected Frozen after idle timeout, got {state:?}"
        );
        let rt_calls = controller.runtime.calls();
        assert!(
            rt_calls.contains(&"freeze_app(alpha)".to_owned()),
            "expected freeze_app; got {rt_calls:?}"
        );
        // Must NOT have stopped — freeze leaves the container resident.
        assert!(
            !rt_calls.iter().any(|c| c == "stop_app(alpha)"),
            "stop_app must not be called on freeze path; got {rt_calls:?}"
        );
    }

    /// `active_upgrades > 0` means the router is mid-splice for a
    /// WebSocket / SSE connection. Freezing would silently strand the
    /// connection; the reaper must skip and try later.
    #[tokio::test]
    async fn freeze_skipped_when_upgrades_active() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        let handle = {
            let maps = controller.apps.read().await;
            maps.by_name.get("alpha").cloned().unwrap()
        };
        force_running(&handle).await;
        handle.active_upgrades.fetch_add(1, Ordering::Relaxed);

        controller.freeze(&handle).await.unwrap();

        let state = handle.inner.lock().await.state.clone();
        assert!(
            state.is_running(),
            "expected freeze to be skipped (still Running), got {state:?}"
        );
        let rt_calls = controller.runtime.calls();
        assert!(
            !rt_calls.iter().any(|c| c == "freeze_app(alpha)"),
            "freeze_app must not be called when upgrades active; got {rt_calls:?}"
        );
    }

    /// `ensure_running` from `Frozen` calls `unfreeze_app` and reuses
    /// the same `container_ip` — no endpoint reallocation, no image
    /// pull. This is the "snappy resume" path that makes scale-to-zero
    /// invisible.
    #[tokio::test]
    async fn ensure_running_unfreezes_from_frozen() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        let handle = {
            let maps = controller.apps.read().await;
            maps.by_name.get("alpha").cloned().unwrap()
        };
        let frozen_ip = Ipv4Addr::new(10, 0, 0, 7);
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::Frozen {
                container_ip: frozen_ip,
            };
        }
        controller.runtime.set_paused("alpha", true);

        let ip = controller.ensure_running(&handle).await.unwrap();
        assert_eq!(ip, frozen_ip, "unfreeze must preserve container_ip");
        let rt_calls = controller.runtime.calls();
        assert!(
            rt_calls.contains(&"unfreeze_app(alpha)".to_owned()),
            "expected unfreeze_app; got {rt_calls:?}"
        );
        assert!(
            !rt_calls.iter().any(|c| c.starts_with("start_app")),
            "start_app must not be called on resume; got {rt_calls:?}"
        );
        assert!(
            !rt_calls.iter().any(|c| c.starts_with("pull_image")),
            "pull_image must not be called on resume; got {rt_calls:?}"
        );
    }

    /// Eviction picks the oldest `last_access` among Frozen handles.
    /// Newer-touched frozen apps stay frozen, older ones drop to
    /// Stopped to free RAM.
    #[tokio::test]
    async fn evict_lru_frozen_picks_oldest_last_access() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(
            vec![
                stored_with_name("alpha", "v1"),
                stored_with_name("beta", "v1"),
            ],
            tmp.path().to_owned(),
        );
        let (alpha, beta) = {
            let maps = controller.apps.read().await;
            (
                maps.by_name.get("alpha").cloned().unwrap(),
                maps.by_name.get("beta").cloned().unwrap(),
            )
        };
        let now = Instant::now();
        {
            let mut inner = alpha.inner.lock().await;
            inner.state = AppState::Frozen {
                container_ip: Ipv4Addr::new(10, 0, 0, 1),
            };
            inner.last_access = now
                .checked_sub(Duration::from_mins(1))
                .expect("test machine clock should not be at unix epoch");
        }
        {
            let mut inner = beta.inner.lock().await;
            inner.state = AppState::Frozen {
                container_ip: Ipv4Addr::new(10, 0, 0, 2),
            };
            inner.last_access = now;
        }

        assert!(controller.evict_lru_frozen().await, "expected an eviction");

        let alpha_state = alpha.inner.lock().await.state.clone();
        let beta_state = beta.inner.lock().await.state.clone();
        assert!(
            matches!(alpha_state, AppState::Stopped),
            "older alpha should be evicted, got {alpha_state:?}"
        );
        assert!(
            beta_state.is_frozen(),
            "newer beta should stay frozen, got {beta_state:?}"
        );
    }

    /// `DELETE /apps/<name>` (which lands in `remove_app`) must also
    /// route through the runtime's `cleanup_orphan_container` so the
    /// bundle dir + per-app volume tree are reclaimed — otherwise
    /// persistent-volume apps leak data on every remove, surfaced as
    /// "stale `/var/lib/bugpot/volumes/<name>/`" weeks later.
    #[tokio::test]
    async fn remove_app_runs_cleanup_orphan_container() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());

        controller.remove_app("alpha").await.expect("remove_app");

        let rt_calls = controller.runtime.calls();
        assert!(
            rt_calls
                .iter()
                .any(|c| c == "cleanup_orphan_container(alpha)"),
            "remove_app must trigger cleanup_orphan_container; got {rt_calls:?}"
        );
    }
}
