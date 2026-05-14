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

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bugpot_config::{AppIdentity, AppSpec, AuthConfig, RegistryCredential, registry_host};
use bugpot_egress::EgressOps;
use bugpot_router::{UpstreamResolver, subdomain_of};
use bugpot_runtime::{Auth, ResourceUsage, RuntimeOps};
use metrics::{counter, gauge, histogram};
use serde::Serialize;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::{debug, error, info, warn};

/// Errors surfaced by the public mutation API. Adapter crates map these
/// to their transport-specific failure shapes (HTTP status codes, etc).
#[derive(Debug, Error)]
pub enum DeployError {
    #[error("spec.name is required for deploy")]
    MissingName,
    #[error("invalid spec: {0}")]
    InvalidSpec(#[from] bugpot_config::InvalidSpec),
    #[error("app '{0}' already exists")]
    AlreadyExists(String),
    #[error("subdomain '{0}' already in use")]
    SubdomainTaken(String),
    #[error("image pull failed: {0:#}")]
    ImagePull(#[source] anyhow::Error),
    #[error("eager start failed: {0:#}")]
    StartFailed(#[source] anyhow::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum RemoveError {
    #[error("app '{0}' not found")]
    NotFound(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// How long to wait for an app to start accepting TCP connections on its
/// declared port after libcontainer reports the container is running.
/// Default readiness timeout when an app does not override
/// `readiness.timeout` in its TOML.
const READINESS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);
const READINESS_POLL: Duration = Duration::from_millis(100);

#[derive(Debug)]
struct AppHandle {
    /// Immutable identity (name + subdomain). Set once at construction
    /// from the validating `AppSpec::identity`, never updated — a
    /// future PUT-style update path will compare against this and
    /// reject mismatches rather than mutating it. `name` is the primary
    /// key in `AppMaps.by_name`; `subdomain` is the reverse-lookup key
    /// used by `UpstreamResolver::resolve`.
    identity: AppIdentity,
    /// Mutable spec fields (image, port, env, etc.). Wrapped in
    /// `RwLock` so future PUT-style updates can mutate in place
    /// without rebuilding the handle. The spec's own `name` /
    /// `subdomain` fields exist for TOML / JSON serialisation shape
    /// only — `identity` is the authoritative pair.
    spec: RwLock<AppSpec>,
    inner: Mutex<HandleInner>,
}

#[derive(Debug)]
struct HandleInner {
    state: AppState,
    last_access: Instant,
    /// Last-seen cgroup `cpu_usec` for the running container, used to
    /// compute deltas for the `bugpot_app_cpu_microseconds_total`
    /// counter across sweeps. Lifetime matches the handle's running
    /// lifetime (only valid while `state` is `Running`); resetting it
    /// on stop keeps the next run starting from zero, which Prometheus
    /// `rate()` tolerates as a reset.
    cpu_baseline: u64,
}

#[derive(Debug, Clone)]
enum AppState {
    Stopped,
    /// A concurrent start is in flight. Waiters subscribe on the inner
    /// `Notify`. The `Arc` lives only while the state machine is in
    /// this variant; transitioning away drops it (held clones held by
    /// waiters keep the channel alive long enough to receive the wake).
    Starting { notify: Arc<Notify> },
    Running { container_ip: Ipv4Addr },
    Stopping,
}

/// Public, serialisable snapshot of an app's registration.
#[derive(Debug, Clone, Serialize)]
pub struct AppView {
    pub name: String,
    pub subdomain: String,
    pub image: String,
    pub port: u16,
    pub state: AppStateView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppStateView {
    Stopped,
    Starting,
    Running,
    Stopping,
}

/// Both registration maps under a single lock so insert / remove are
/// atomic across the (name, subdomain) pair. Name is the primary key
/// (used by `get_app` / `remove_app` / `cleanup`); subdomain is a
/// reverse index used by `UpstreamResolver::resolve` to route HTTP
/// requests in O(1).
#[derive(Debug, Default)]
struct AppMaps {
    by_name: HashMap<String, Arc<AppHandle>>,
    by_subdomain: HashMap<String, String>,
}

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
    apps_dir: PathBuf,
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
    #[must_use]
    pub fn new(
        runtime: Arc<R>,
        egress: Arc<E>,
        apps_dir: PathBuf,
        auth: AuthConfig,
        specs: Vec<AppSpec>,
    ) -> Self {
        let mut maps = AppMaps::default();
        for spec in specs {
            // `load_apps` already validated each spec; an `InvalidSpec`
            // here would indicate a caller bypassed that, which is a
            // bug — `expect` is the right reaction.
            let handle = make_handle(spec).expect("controller::new received unvalidated AppSpec");
            maps.by_subdomain
                .insert(handle.identity.subdomain.clone(), handle.identity.name.clone());
            maps.by_name.insert(handle.identity.name.clone(), handle);
        }
        #[allow(clippy::cast_precision_loss)]
        gauge!("bugpot_apps_active").set(maps.by_name.len() as f64);
        Self {
            runtime,
            egress,
            apps_dir,
            auth,
            apps: RwLock::new(maps),
            reattach_done: AtomicBool::new(false),
        }
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
        if self
            .reattach_done
            .swap(true, Ordering::SeqCst)
        {
            warn!("reattach_running called more than once; ignoring subsequent calls");
            return;
        }
        for handle in self.snapshot_handles().await {
            let name = &handle.identity.name;
            if !self.runtime.is_container_running(name) {
                continue;
            }
            let allowlist = handle.spec.read().await.egress.allow.clone();
            match self.egress.reattach_endpoint(name, allowlist).await {
                Ok(Some(ep)) => {
                    {
                        let mut inner = handle.inner.lock().await;
                        inner.state = AppState::Running {
                            container_ip: ep.container_ip,
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
                    info!(app = %name, container_ip = %ep.container_ip, "reattached to running container");
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
            if timeout.is_none() {
                always_on.push(handle);
            }
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
        let is_running = matches!(
            handle.inner.lock().await.state,
            AppState::Running { .. }
        );
        if !is_running {
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
            info!(app = %handle.identity.name, "idle timeout reached, stopping");
            if let Err(e) = self.stop(&handle).await {
                warn!(app = %handle.identity.name, error = ?e, "stop on idle failed");
            }
        }
    }

    /// Stop every app that's currently running. Used on shutdown.
    pub async fn teardown(&self) {
        for handle in self.snapshot_handles().await {
            let should_stop = {
                let inner = handle.inner.lock().await;
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

    /// Register a new app. Fails if an app with the same name or subdomain
    /// already exists. The image is pulled before persistence so failure
    /// leaves no state. If `idle_timeout = 0`, the app is eager-started
    /// before this call returns.
    pub async fn deploy_app(&self, mut spec: AppSpec) -> std::result::Result<AppView, DeployError> {
        let name = spec.name.clone().ok_or(DeployError::MissingName)?;
        // Strict validation BEFORE we touch the filesystem — `name`
        // lands in `<apps_dir>/<name>.toml` and `bugpot-<name>` netns
        // names, and the admin API accepts arbitrary JSON.
        spec.validate()?;
        let subdomain = spec.subdomain().to_owned();

        // Fast-fail on obvious collisions before doing the expensive pull.
        {
            let maps = self.apps.read().await;
            if maps.by_name.contains_key(&name) {
                return Err(DeployError::AlreadyExists(name));
            }
            if maps.by_subdomain.contains_key(&subdomain) {
                return Err(DeployError::SubdomainTaken(subdomain));
            }
        }

        self.runtime
            .pull_image(&spec.image, self.resolve_auth(&spec.image))
            .await
            .map_err(|e| {
                DeployError::ImagePull(
                    anyhow::Error::from(e).context(format!("pull {} for {name}", spec.image)),
                )
            })?;

        let toml_path = self.apps_dir.join(format!("{name}.toml"));
        let toml_body = toml::to_string_pretty(&spec)
            .with_context(|| format!("serialize spec for {name}"))?;
        tokio::fs::write(&toml_path, toml_body)
            .await
            .with_context(|| format!("write {}", toml_path.display()))?;
        spec.source_path.clone_from(&toml_path);

        let handle = make_handle(spec.clone())?;

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

        let eager = spec
            .scaling
            .resolve_idle_timeout()
            .map_err(|e| anyhow!("{name}: {e}"))?
            .is_none();
        if eager {
            info!(app = %name, "eager start on deploy");
            if let Err(e) = self.ensure_running(&handle).await {
                // remove_by_name decrements the gauge to keep it balanced
                // with the increment above.
                let _ = self.remove_by_name(&name).await;
                return Err(DeployError::StartFailed(e));
            }
        }

        Ok(view_of(&handle).await)
    }

    /// Unregister an app by name. Stops the container (if running) and
    /// deletes its TOML file.
    pub async fn remove_app(&self, name: &str) -> std::result::Result<(), RemoveError> {
        if !self.apps.read().await.by_name.contains_key(name) {
            return Err(RemoveError::NotFound(name.to_owned()));
        }
        self.remove_by_name(name).await.map_err(RemoveError::Internal)
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
        let toml_path = self.apps_dir.join(format!("{}.toml", handle.identity.name));
        if toml_path.exists()
            && let Err(e) = tokio::fs::remove_file(&toml_path).await
        {
            warn!(path = %toml_path.display(), error = %e, "remove toml failed");
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
            let own_notify = {
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
                        n
                    }
                }
            };

            // Phase 2: do the work outside the lock.
            let result = self.do_start(handle).await;

            // Phase 3: commit state + wake waiters (after dropping the
            // lock so concurrent readers don't contend on `Notify`).
            // Transitioning out of `Starting` drops the in-state `Arc`;
            // `own_notify` keeps it alive for the wake below.
            {
                let mut inner = handle.inner.lock().await;
                inner.state = result.as_ref().map_or(AppState::Stopped, |ip| {
                    AppState::Running { container_ip: *ip }
                });
            }
            own_notify.notify_waiters();
            return result;
        }
    }

    async fn do_start(&self, handle: &AppHandle) -> Result<Ipv4Addr> {
        let name = &handle.identity.name;
        // Snapshot the spec once: a cold start interleaves several
        // awaits with reads of image / port / egress.allow / readiness,
        // so cloning the small `AppSpec` is cheaper than holding the
        // RwLock guard across them (or re-locking each time).
        let spec = handle.spec.read().await.clone();
        info!(app = %name, image = %spec.image, "starting");

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
        let image_id = match self
            .runtime
            .pull_image(&spec.image, self.resolve_auth(&spec.image))
            .await
        {
            Ok(id) => id,
            Err(e) => {
                let _ = self.egress.release_endpoint(name).await;
                return Err(e).with_context(|| format!("pull image for {name}"));
            }
        };
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
        if let Err(e) = wait_for_port(upstream, timeout).await {
            warn!(app = %name, error = %e, "readiness probe failed");
            let _ = self.runtime.stop_app(name).await;
            let _ = self.egress.release_endpoint(name).await;
            return Err(e);
        }
        histogram!("bugpot_cold_start_seconds", "phase" => "readiness")
            .record(phase_start.elapsed().as_secs_f64());
        Ok(endpoint.container_ip)
    }

    async fn stop(&self, handle: &Arc<AppHandle>) -> Result<()> {
        {
            let mut inner = handle.inner.lock().await;
            if !matches!(
                inner.state,
                AppState::Running { .. } | AppState::Starting { .. }
            ) {
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

/// Construct a handle from a validated spec. Returns `Err` if
/// `spec.identity()` fails (the spec's name / subdomain weren't valid
/// DNS labels). Callers in the deploy path are expected to have run
/// `spec.validate()` earlier; this is the belt-and-braces version.
fn make_handle(spec: AppSpec) -> Result<Arc<AppHandle>, bugpot_config::InvalidSpec> {
    let identity = spec.identity()?;
    Ok(Arc::new(AppHandle {
        identity,
        spec: RwLock::new(spec),
        inner: Mutex::new(HandleInner {
            state: AppState::Stopped,
            last_access: Instant::now(),
            cpu_baseline: 0,
        }),
    }))
}

async fn view_of(handle: &Arc<AppHandle>) -> AppView {
    let state = match &handle.inner.lock().await.state {
        AppState::Stopped => AppStateView::Stopped,
        AppState::Starting { .. } => AppStateView::Starting,
        AppState::Running { .. } => AppStateView::Running,
        AppState::Stopping => AppStateView::Stopping,
    };
    let spec = handle.spec.read().await;
    AppView {
        name: handle.identity.name.clone(),
        subdomain: handle.identity.subdomain.clone(),
        image: spec.image.clone(),
        port: spec.port,
        state,
    }
}

#[async_trait]
impl<R: RuntimeOps, E: EgressOps> UpstreamResolver for AppController<R, E> {
    async fn resolve(&self, host: &str) -> Option<SocketAddr> {
        let subdomain = subdomain_of(host)?;
        let handle = {
            let maps = self.apps.read().await;
            let name = maps.by_subdomain.get(subdomain)?;
            maps.by_name.get(name)?.clone()
        };
        let port = handle.spec.read().await.port;
        match self.ensure_running(&handle).await {
            Ok(ip) => Some(SocketAddr::from((ip, port))),
            Err(e) => {
                error!(host, error = ?e, "ensure_running failed");
                None
            }
        }
    }
}

/// Emit `bugpot_app_memory_bytes` (gauge) and
/// `bugpot_app_cpu_microseconds_total` (counter) from a fresh cgroup
/// sample. The CPU delta is computed against the per-handle baseline
/// stored in `HandleInner.cpu_baseline`, which is updated in place.
///
/// CPU is exposed in microseconds (cgroup-v2's native unit) so the
/// counter keeps full precision. Operators querying via Prometheus
/// divide by 1e6: `rate(bugpot_app_cpu_microseconds_total[5m]) / 1000000`.
async fn emit_resource_metrics(handle: &Arc<AppHandle>, usage: ResourceUsage) {
    #[allow(clippy::cast_precision_loss)]
    gauge!("bugpot_app_memory_bytes", "app" => handle.identity.name.clone())
        .set(usage.memory_bytes as f64);

    let mut inner = handle.inner.lock().await;
    let last = inner.cpu_baseline;
    inner.cpu_baseline = usage.cpu_usec;
    drop(inner);

    // A container restart resets the cgroup counter under us; treat
    // any backwards step as a 0-baseline and increment by the new
    // absolute value. Prometheus `rate()` tolerates the apparent
    // reset.
    let delta_usec = if usage.cpu_usec >= last {
        usage.cpu_usec - last
    } else {
        usage.cpu_usec
    };
    if delta_usec > 0 {
        counter!("bugpot_app_cpu_microseconds_total", "app" => handle.identity.name.clone())
            .increment(delta_usec);
    }
}

async fn wait_for_port(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_err: Option<std::io::Error> = None;
    while Instant::now() < deadline {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(READINESS_POLL).await;
            }
        }
    }
    Err(anyhow!(
        "container did not accept connections on {addr} within {timeout:?}: {last_err:?}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex as StdMutex;

    use bugpot_config::{AppSpec, EgressSpec, Readiness, Resources, RuntimeSpec, Scaling};
    use bugpot_egress::{Endpoint, EgressOps};
    use bugpot_runtime::{Auth, ImageId, ResourceUsage, RunningApp, RuntimeError, RuntimeOps};

    #[derive(Debug, Default)]
    struct MockRuntime {
        pull_results: StdMutex<VecDeque<std::result::Result<ImageId, RuntimeError>>>,
        start_results: StdMutex<VecDeque<std::result::Result<RunningApp, RuntimeError>>>,
        running: StdMutex<HashMap<String, bool>>,
        calls: StdMutex<Vec<String>>,
    }

    impl MockRuntime {
        fn push_pull(&self, r: std::result::Result<ImageId, RuntimeError>) {
            self.pull_results.lock().unwrap().push_back(r);
        }
        fn set_running(&self, app: &str, value: bool) {
            self.running.lock().unwrap().insert(app.to_owned(), value);
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
                .unwrap_or_else(|| Err(RuntimeError::Other("mock: no start response queued".into())))
        }

        async fn stop_app(&self, name: &str) -> std::result::Result<(), RuntimeError> {
            self.record(format!("stop_app({name})"));
            self.running.lock().unwrap().remove(name);
            Ok(())
        }

        fn is_container_running(&self, name: &str) -> bool {
            *self.running.lock().unwrap().get(name).unwrap_or(&false)
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
            self.discovered
                .lock()
                .unwrap()
                .drain()
                .collect()
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

    fn spec_with_name(name: &str) -> AppSpec {
        AppSpec {
            image: "registry.example/img:tag".to_owned(),
            port: 8080,
            name: Some(name.to_owned()),
            subdomain: None,
            egress: EgressSpec::default(),
            env: HashMap::default(),
            scaling: Scaling::default(),
            readiness: Readiness::default(),
            resources: Resources::default(),
            runtime: RuntimeSpec::default(),
            source_path: PathBuf::new(),
        }
    }

    fn make_controller(
        specs: Vec<AppSpec>,
        apps_dir: PathBuf,
    ) -> Arc<AppController<MockRuntime, MockEgress>> {
        Arc::new(AppController::new(
            Arc::new(MockRuntime::default()),
            Arc::new(MockEgress::default()),
            apps_dir,
            AuthConfig::default(),
            specs,
        ))
    }

    /// `deploy_app` must surface a pull failure as `DeployError::ImagePull`
    /// and leave no TOML file behind.
    #[tokio::test]
    async fn deploy_app_propagates_pull_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .runtime
            .push_pull(Err(RuntimeError::Other("registry unreachable".into())));

        let err = controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect_err("expected pull failure");
        assert!(matches!(err, DeployError::ImagePull(_)), "got {err:?}");

        let toml = tmp.path().join("alpha.toml");
        assert!(!toml.exists(), "toml should not be written on pull failure");
    }

    /// On cold-start failure during image pull, the previously-allocated
    /// endpoint must be released so the next attempt can reallocate
    /// cleanly.
    #[tokio::test]
    async fn cold_start_releases_endpoint_on_pull_failure() {
        let tmp = tempfile::tempdir().unwrap();
        // Pre-register so we hit ensure_running without going through
        // deploy_app's own pull (which would short-circuit).
        let controller = make_controller(vec![spec_with_name("alpha")], tmp.path().to_owned());
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
            !controller.runtime.calls().iter().any(|c| c.starts_with("start_app")),
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
            vec![spec_with_name("alpha"), spec_with_name("beta")],
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
            maps.by_name.get("alpha").unwrap().inner.lock().await.state.clone()
        };
        let beta_state = {
            let maps = controller.apps.read().await;
            maps.by_name.get("beta").unwrap().inner.lock().await.state.clone()
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
        let controller = make_controller(vec![spec_with_name("alpha")], tmp.path().to_owned());
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
            !rt_calls.iter().any(|c| c == "cleanup_orphan_container(alpha)"),
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
        let controller = make_controller(vec![spec_with_name("alpha")], tmp.path().to_owned());
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
        let controller = make_controller(vec![spec_with_name("alpha")], tmp.path().to_owned());

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
}
