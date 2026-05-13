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
use bugpot_egress::Egress;
use bugpot_router::{UpstreamResolver, subdomain_of};
use bugpot_runtime::{Auth, Runtime};
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
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
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
/// A background `idle_stopper_loop` task should be spawned to reclaim
/// apps that have been idle for too long.
#[derive(Debug)]
pub struct AppController {
    runtime: Arc<Runtime>,
    egress: Arc<Egress>,
    apps_dir: PathBuf,
    auth: AuthConfig,
    /// Keyed by subdomain (= app name by default).
    apps: RwLock<HashMap<String, Arc<AppHandle>>>,
}

impl AppController {
    #[must_use]
    pub fn new(
        runtime: Arc<Runtime>,
        egress: Arc<Egress>,
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
        Self {
            runtime,
            egress,
            apps_dir,
            auth,
            apps: RwLock::new(apps),
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

    /// Eagerly start apps whose `idle_timeout` resolves to "always on".
    pub async fn deploy_always_on(&self) -> Result<()> {
        let handles = self.snapshot_handles().await;
        for handle in handles {
            let timeout = handle
                .spec
                .scaling
                .resolve_idle_timeout()
                .map_err(|e| anyhow!("{}: {e}", handle.name))?;
            if timeout.is_none() {
                info!(app = %handle.name, "eager start (idle_timeout = 0)");
                self.ensure_running(&handle).await?;
            }
        }
        Ok(())
    }

    /// Background task: stop apps idle beyond their configured timeout.
    /// Consumes an `Arc<Self>` so it can be `tokio::spawn`ed.
    pub async fn idle_stopper_loop(self: Arc<Self>, tick: Duration) {
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            self.sweep_idle().await;
        }
    }

    async fn sweep_idle(&self) {
        for handle in self.snapshot_handles().await {
            let timeout = match handle.spec.scaling.resolve_idle_timeout() {
                Ok(Some(t)) => t,
                Ok(None) => continue, // always-on
                Err(e) => {
                    warn!(app = %handle.name, "bad idle_timeout: {e}");
                    continue;
                }
            };
            let should_stop = {
                let inner = handle.inner.lock().await;
                matches!(inner.state, AppState::Running { .. })
                    && inner.last_access.elapsed() >= timeout
            };
            if should_stop {
                info!(app = %handle.name, "idle timeout reached, stopping");
                if let Err(e) = self.stop(&handle).await {
                    warn!(app = %handle.name, error = ?e, "stop on idle failed");
                }
            }
        }
    }

    /// Stop every app that's currently running. Used on shutdown.
    pub async fn teardown(&self) {
        for handle in self.snapshot_handles().await {
            let should_stop = {
                let inner = handle.inner.lock().await;
                matches!(inner.state, AppState::Running { .. } | AppState::Starting)
            };
            if should_stop {
                if let Err(e) = self.stop(&handle).await {
                    warn!(app = %handle.name, error = ?e, "stop failed during teardown");
                }
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

        let eager = spec
            .scaling
            .resolve_idle_timeout()
            .map_err(|e| anyhow!("{name}: {e}"))?
            .is_none();
        if eager {
            info!(app = %name, "eager start on deploy");
            if let Err(e) = self.ensure_running(&handle).await {
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
        if let Err(e) = self.stop(&handle).await {
            warn!(app = %handle.name, error = ?e, "stop failed during remove");
        }
        let toml_path = self.apps_dir.join(format!("{}.toml", handle.name));
        if toml_path.exists() {
            if let Err(e) = tokio::fs::remove_file(&toml_path).await {
                warn!(path = %toml_path.display(), error = %e, "remove toml failed");
            }
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

        let endpoint = self
            .egress
            .allocate_endpoint(name, handle.spec.egress.allow.clone())
            .await
            .with_context(|| format!("allocate endpoint for {name}"))?;

        if let Err(e) = self
            .runtime
            .pull_image(&handle.spec.image, self.resolve_auth(&handle.spec.image))
            .await
        {
            let _ = self.egress.release_endpoint(name).await;
            return Err(e).with_context(|| format!("pull image for {name}"));
        }

        let running = match self
            .runtime
            .start_app(&handle.spec, Some(&endpoint.netns_path))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let _ = self.egress.release_endpoint(name).await;
                return Err(e).with_context(|| format!("start container for {name}"));
            }
        };
        info!(
            app = %name,
            pid = running.pid,
            container_ip = %endpoint.container_ip,
            "container running"
        );

        // Wait for the app to bind on its declared port before returning,
        // otherwise the first proxied request would race ahead of the
        // process's listener.
        let upstream = SocketAddr::from((endpoint.container_ip, handle.spec.port));
        if let Err(e) = wait_for_port(upstream).await {
            warn!(app = %name, error = %e, "readiness probe failed");
            let _ = self.runtime.stop_app(name).await;
            let _ = self.egress.release_endpoint(name).await;
            return Err(e);
        }
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
impl UpstreamResolver for AppController {
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

async fn wait_for_port(addr: SocketAddr) -> Result<()> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
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
        "container did not accept connections on {addr} within {READINESS_TIMEOUT:?}: {last_err:?}"
    ))
}
