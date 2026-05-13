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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bugpot_config::{AppSpec, AuthConfig, RegistryCredential, registry_host};
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
    name: String,
    spec: AppSpec,
    inner: Mutex<HandleInner>,
}

#[derive(Debug)]
struct HandleInner {
    state: AppState,
    last_access: Instant,
    /// `Some` while `state == Starting`. Waiters subscribe here.
    notify: Option<Arc<Notify>>,
}

#[derive(Debug, Clone, Copy)]
enum AppState {
    Stopped,
    Starting,
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
    /// Keyed by subdomain (= app name by default).
    apps: RwLock<HashMap<String, Arc<AppHandle>>>,
    /// Last-seen cgroup `cpu_usec` per app, used to compute deltas for
    /// the `bugpot_app_cpu_microseconds_total` counter across sweeps.
    /// Cleared when an app is stopped so the next run starts from 0 —
    /// Prometheus `rate()` handles the apparent reset.
    cpu_baselines: tokio::sync::Mutex<HashMap<String, u64>>,
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
        let mut apps = HashMap::with_capacity(specs.len());
        for spec in specs {
            let name = spec.name().to_owned();
            let key = spec.subdomain().to_owned();
            apps.insert(key, make_handle(name, spec));
        }
        #[allow(clippy::cast_precision_loss)]
        gauge!("bugpot_apps_active").set(apps.len() as f64);
        Self {
            runtime,
            egress,
            apps_dir,
            auth,
            apps: RwLock::new(apps),
            cpu_baselines: tokio::sync::Mutex::new(HashMap::new()),
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
    pub async fn reattach_running(&self) {
        for handle in self.snapshot_handles().await {
            let name = &handle.name;
            if !self.runtime.is_container_running(name) {
                continue;
            }
            match self
                .egress
                .reattach_endpoint(name, handle.spec.egress.allow.clone())
                .await
            {
                Ok(Some(ep)) => {
                    {
                        let mut inner = handle.inner.lock().await;
                        inner.state = AppState::Running {
                            container_ip: ep.container_ip,
                        };
                        inner.last_access = Instant::now();
                    }
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
                .scaling
                .resolve_idle_timeout()
                .map_err(|e| anyhow!("{}: {e}", handle.name))?;
            if timeout.is_none() {
                always_on.push(handle);
            }
        }
        if always_on.is_empty() {
            return Ok(());
        }

        let starts = always_on.into_iter().map(|handle| {
            let name = handle.name.clone();
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
        for handle in self.snapshot_handles().await {
            // Only look at apps we believe are running. Starting /
            // Stopping / Stopped handles are already in motion or
            // already-cleaned.
            let state_snapshot = {
                let inner = handle.inner.lock().await;
                inner.state
            };
            if !matches!(state_snapshot, AppState::Running { .. }) {
                continue;
            }

            // 1. Liveness: did the container die under us?
            if !self.runtime.is_container_running(&handle.name) {
                info!(app = %handle.name, "container exited unexpectedly, cleaning up");
                counter!(
                    "bugpot_container_crashes_total",
                    "app" => handle.name.clone(),
                )
                .increment(1);
                if let Err(e) = self.stop(&handle).await {
                    warn!(app = %handle.name, error = ?e, "cleanup of dead container failed");
                }
                continue;
            }

            // 2. Resource sampling. Skip silently when cgroup paths
            // resolve to nothing (cgroup v1 host or transient /proc
            // races) — the gauge stops updating, the counter doesn't
            // move.
            if let Some(usage) = self.runtime.resource_usage(&handle.name) {
                self.emit_resource_metrics(&handle.name, usage).await;
            }

            // 3. Idle timeout (scale-to-zero). always-on apps skip.
            let timeout = match handle.spec.scaling.resolve_idle_timeout() {
                Ok(Some(t)) => t,
                Ok(None) => continue,
                Err(e) => {
                    warn!(app = %handle.name, "bad idle_timeout: {e}");
                    continue;
                }
            };
            let last_access = {
                let inner = handle.inner.lock().await;
                inner.last_access
            };
            if last_access.elapsed() >= timeout {
                info!(app = %handle.name, "idle timeout reached, stopping");
                if let Err(e) = self.stop(&handle).await {
                    warn!(app = %handle.name, error = ?e, "stop on idle failed");
                }
            }
        }
    }

    /// Update memory gauge and CPU counter (via delta vs the per-app
    /// baseline) for `app` from a fresh cgroup sample.
    ///
    /// CPU is exposed in microseconds, the cgroup-v2 native unit, to
    /// preserve full precision through the integer-only counter API.
    /// Operators querying via Prometheus divide by 1e6 for seconds:
    /// `rate(bugpot_app_cpu_microseconds_total[5m]) / 1000000`.
    async fn emit_resource_metrics(&self, app: &str, usage: ResourceUsage) {
        #[allow(clippy::cast_precision_loss)]
        gauge!("bugpot_app_memory_bytes", "app" => app.to_owned())
            .set(usage.memory_bytes as f64);

        let last = {
            let mut baselines = self.cpu_baselines.lock().await;
            baselines.insert(app.to_owned(), usage.cpu_usec).unwrap_or(0)
        };
        // A container restart resets the cgroup counter under us;
        // treat any backwards step as a 0-baseline and increment by
        // the new absolute value. Prometheus `rate()` tolerates the
        // apparent reset.
        let delta_usec = if usage.cpu_usec >= last {
            usage.cpu_usec - last
        } else {
            usage.cpu_usec
        };
        if delta_usec > 0 {
            counter!("bugpot_app_cpu_microseconds_total", "app" => app.to_owned())
                .increment(delta_usec);
        }
    }

    async fn clear_cpu_baseline(&self, app: &str) {
        self.cpu_baselines.lock().await.remove(app);
    }

    /// Stop every app that's currently running. Used on shutdown.
    pub async fn teardown(&self) {
        for handle in self.snapshot_handles().await {
            let should_stop = {
                let inner = handle.inner.lock().await;
                matches!(inner.state, AppState::Running { .. } | AppState::Starting)
            };
            if should_stop && let Err(e) = self.stop(&handle).await {
                warn!(app = %handle.name, error = ?e, "stop failed during teardown");
            }
        }
    }

    /// Register a new app. Fails if an app with the same name or subdomain
    /// already exists. The image is pulled before persistence so failure
    /// leaves no state. If `idle_timeout = 0`, the app is eager-started
    /// before this call returns.
    pub async fn deploy_app(&self, mut spec: AppSpec) -> std::result::Result<AppView, DeployError> {
        let name = spec.name.clone().ok_or(DeployError::MissingName)?;
        let subdomain = spec.subdomain().to_owned();

        // Fast-fail on obvious collisions before doing the expensive pull.
        {
            let apps = self.apps.read().await;
            if apps.contains_key(&subdomain) {
                return Err(DeployError::SubdomainTaken(subdomain));
            }
            if apps.values().any(|h| h.name == name) {
                return Err(DeployError::AlreadyExists(name));
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

        let handle = make_handle(name.clone(), spec.clone());

        {
            let mut apps = self.apps.write().await;
            // Re-check under the write lock — a concurrent deploy may have
            // raced into the same key.
            if apps.contains_key(&subdomain) {
                let _ = tokio::fs::remove_file(&toml_path).await;
                return Err(DeployError::SubdomainTaken(subdomain));
            }
            apps.insert(subdomain.clone(), handle.clone());
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
                // remove_by_subdomain decrements the gauge to keep it
                // balanced with the increment above.
                let _ = self.remove_by_subdomain(&subdomain).await;
                return Err(DeployError::StartFailed(e));
            }
        }

        Ok(view_of(&handle).await)
    }

    /// Unregister an app by name. Stops the container (if running) and
    /// deletes its TOML file.
    pub async fn remove_app(&self, name: &str) -> std::result::Result<(), RemoveError> {
        let subdomain = {
            let apps = self.apps.read().await;
            apps.iter()
                .find(|(_, h)| h.name == name)
                .map(|(k, _)| k.clone())
                .ok_or_else(|| RemoveError::NotFound(name.to_owned()))?
        };
        self.remove_by_subdomain(&subdomain)
            .await
            .map_err(RemoveError::Internal)
    }

    async fn remove_by_subdomain(&self, subdomain: &str) -> Result<()> {
        let handle = {
            let mut apps = self.apps.write().await;
            apps.remove(subdomain)
                .ok_or_else(|| anyhow!("subdomain '{subdomain}' not found"))?
        };
        gauge!("bugpot_apps_active").decrement(1.0);
        if let Err(e) = self.stop(&handle).await {
            warn!(app = %handle.name, error = ?e, "stop failed during remove");
        }
        let toml_path = self.apps_dir.join(format!("{}.toml", handle.name));
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
        let handle = {
            let apps = self.apps.read().await;
            apps.values().find(|h| h.name == name).cloned()
        }?;
        Some(view_of(&handle).await)
    }

    async fn snapshot_handles(&self) -> Vec<Arc<AppHandle>> {
        self.apps.read().await.values().cloned().collect()
    }

    /// Ensure the app is running, coalescing concurrent starts. Returns
    /// the container IP.
    async fn ensure_running(&self, handle: &Arc<AppHandle>) -> Result<Ipv4Addr> {
        loop {
            // Phase 1: inspect / transition state under the lock.
            let own_notify = {
                let mut inner = handle.inner.lock().await;
                inner.last_access = Instant::now();
                match inner.state {
                    AppState::Running { container_ip } => return Ok(container_ip),
                    AppState::Starting => {
                        let n = inner
                            .notify
                            .clone()
                            .expect("Starting state must carry a notify");
                        drop(inner);
                        debug!(app = %handle.name, "awaiting concurrent start");
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
                        inner.state = AppState::Starting;
                        inner.notify = Some(n.clone());
                        n
                    }
                }
            };

            // Phase 2: do the work outside the lock.
            let result = self.do_start(handle).await;

            // Phase 3: commit state + wake waiters (after dropping the
            // lock so concurrent readers don't contend on `Notify`).
            {
                let mut inner = handle.inner.lock().await;
                inner.notify = None;
                inner.state = result.as_ref().map_or(AppState::Stopped, |ip| {
                    AppState::Running { container_ip: *ip }
                });
            }
            own_notify.notify_waiters();
            return result;
        }
    }

    async fn do_start(&self, handle: &AppHandle) -> Result<Ipv4Addr> {
        let name = &handle.name;
        info!(app = %name, image = %handle.spec.image, "starting");

        // Each cold-start phase records into bugpot_cold_start_seconds
        // *only on success*; failure paths intentionally don't record so
        // the histogram reflects the latency distribution of complete
        // cold starts. Total cold-start time = sum across phases (queryable
        // in Prom).
        let phase_start = Instant::now();
        let endpoint = self
            .egress
            .allocate_endpoint(name, handle.spec.egress.allow.clone())
            .await
            .with_context(|| format!("allocate endpoint for {name}"))?;
        histogram!("bugpot_cold_start_seconds", "phase" => "endpoint")
            .record(phase_start.elapsed().as_secs_f64());

        let phase_start = Instant::now();
        let image_id = match self
            .runtime
            .pull_image(&handle.spec.image, self.resolve_auth(&handle.spec.image))
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
            .start_app(&handle.spec, &image_id, Some(&endpoint.netns_path))
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
        let timeout = handle
            .spec
            .readiness
            .resolve_timeout(READINESS_TIMEOUT_DEFAULT)
            .map_err(|e| anyhow!("{name}: {e}"))?;
        let upstream = SocketAddr::from((endpoint.container_ip, handle.spec.port));
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
            if !matches!(inner.state, AppState::Running { .. } | AppState::Starting) {
                return Ok(());
            }
            inner.state = AppState::Stopping;
        }
        let res = self.do_stop(handle).await;
        // Drop the CPU baseline so the next start of this app begins
        // from 0 rather than the (now-stale) last sample.
        self.clear_cpu_baseline(&handle.name).await;
        let mut inner = handle.inner.lock().await;
        inner.state = AppState::Stopped;
        res
    }

    async fn do_stop(&self, handle: &AppHandle) -> Result<()> {
        let name = &handle.name;
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

fn make_handle(name: String, spec: AppSpec) -> Arc<AppHandle> {
    Arc::new(AppHandle {
        name,
        spec,
        inner: Mutex::new(HandleInner {
            state: AppState::Stopped,
            last_access: Instant::now(),
            notify: None,
        }),
    })
}

async fn view_of(handle: &Arc<AppHandle>) -> AppView {
    let snapshot = handle.inner.lock().await.state;
    let state = match snapshot {
        AppState::Stopped => AppStateView::Stopped,
        AppState::Starting => AppStateView::Starting,
        AppState::Running { .. } => AppStateView::Running,
        AppState::Stopping => AppStateView::Stopping,
    };
    AppView {
        name: handle.name.clone(),
        subdomain: handle.spec.subdomain().to_owned(),
        image: handle.spec.image.clone(),
        port: handle.spec.port,
        state,
    }
}

#[async_trait]
impl<R: RuntimeOps, E: EgressOps> UpstreamResolver for AppController<R, E> {
    async fn resolve(&self, host: &str) -> Option<SocketAddr> {
        let subdomain = subdomain_of(host)?;
        let handle = {
            let apps = self.apps.read().await;
            apps.get(subdomain)?.clone()
        };
        match self.ensure_running(&handle).await {
            Ok(ip) => Some(SocketAddr::from((ip, handle.spec.port))),
            Err(e) => {
                error!(host, error = ?e, "ensure_running failed");
                None
            }
        }
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

    use bugpot_config::{
        AppSpec, Egress as EgressSpec, Readiness, Resources, Runtime as RuntimeCfg, Scaling,
    };
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

        async fn stop_app(&self, id: &str) -> std::result::Result<(), RuntimeError> {
            self.record(format!("stop_app({id})"));
            self.running.lock().unwrap().remove(id);
            Ok(())
        }

        fn is_container_running(&self, id: &str) -> bool {
            *self.running.lock().unwrap().get(id).unwrap_or(&false)
        }

        fn resource_usage(&self, _id: &str) -> Option<ResourceUsage> {
            None
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
        fn set_discovered(&self, app_id: &str, ip: Ipv4Addr) {
            self.discovered.lock().unwrap().insert(app_id.to_owned(), ip);
        }
    }

    impl EgressOps for MockEgress {
        async fn allocate_endpoint(
            &self,
            app_id: &str,
            _allowlist: Vec<String>,
        ) -> anyhow::Result<Endpoint> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("allocate_endpoint({app_id})"));
            if *self.allocate_fail.lock().unwrap() {
                anyhow::bail!("mock: allocate_endpoint failed");
            }
            let ep = Endpoint {
                container_ip: Ipv4Addr::LOCALHOST,
                netns_path: PathBuf::from(format!("/run/netns/mock-{app_id}")),
            };
            self.endpoints
                .lock()
                .unwrap()
                .insert(app_id.to_owned(), ep.clone());
            Ok(ep)
        }

        async fn release_endpoint(&self, app_id: &str) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("release_endpoint({app_id})"));
            self.endpoints.lock().unwrap().remove(app_id);
            Ok(())
        }

        async fn reattach_endpoint(
            &self,
            app_id: &str,
            _allowlist: Vec<String>,
        ) -> anyhow::Result<Option<Endpoint>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("reattach_endpoint({app_id})"));
            let Some(container_ip) = self.discovered.lock().unwrap().remove(app_id) else {
                return Ok(None);
            };
            let ep = Endpoint {
                container_ip,
                netns_path: PathBuf::from(format!("/run/netns/mock-{app_id}")),
            };
            self.endpoints
                .lock()
                .unwrap()
                .insert(app_id.to_owned(), ep.clone());
            Ok(Some(ep))
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
            runtime: RuntimeCfg::default(),
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
            let apps = controller.apps.read().await;
            apps.get("alpha").cloned().expect("handle present")
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
            let apps = controller.apps.read().await;
            apps.get("alpha").unwrap().inner.lock().await.state
        };
        let beta_state = {
            let apps = controller.apps.read().await;
            apps.get("beta").unwrap().inner.lock().await.state
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
            let apps = controller.apps.read().await;
            apps.get("alpha").cloned().unwrap()
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

        let state = handle.inner.lock().await.state;
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
