//! Per-app lifecycle controller with scale-to-zero.
//!
//! Each app handle is a small state machine:
//!
//! ```text
//!  Stopped ─request─► Starting ─ok─► Running ─idle─► Stopping ─► Stopped
//!     ▲                  │ err                                    │
//!     └──────────────────┴────────────────────────────────────────┘
//! ```
//!
//! Concurrent starts on the same `Stopped` app are coalesced: the first
//! request transitions to `Starting` and performs the work; later requests
//! park on the per-app `Notify` until the transition lands as either
//! `Running` (return the upstream) or `Stopped` (start failed).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bugpot_config::AppSpec;
use bugpot_egress::Egress;
use bugpot_router::{UpstreamResolver, subdomain_of};
use bugpot_runtime::{Auth, Runtime};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tracing::{debug, error, info, warn};

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

/// Per-app lifecycle controller.
///
/// Created once during startup with every app spec. Hands out upstream
/// addresses on request (`UpstreamResolver`), starting stopped apps along
/// the way. A background `idle_stopper_loop` task should be spawned to
/// reclaim apps that have been idle for too long.
#[derive(Debug)]
pub struct AppController {
    runtime: Arc<Runtime>,
    egress: Arc<Egress>,
    /// Keyed by subdomain (= app name by default).
    apps: HashMap<String, Arc<AppHandle>>,
}

impl AppController {
    pub fn new(runtime: Arc<Runtime>, egress: Arc<Egress>, specs: Vec<AppSpec>) -> Self {
        let mut apps = HashMap::with_capacity(specs.len());
        for spec in specs {
            let name = spec.name().to_owned();
            let key = spec.subdomain().to_owned();
            let handle = Arc::new(AppHandle {
                name,
                spec,
                inner: Mutex::new(HandleInner {
                    state: AppState::Stopped,
                    last_access: Instant::now(),
                    notify: None,
                }),
            });
            apps.insert(key, handle);
        }
        Self {
            runtime,
            egress,
            apps,
        }
    }

    /// Eagerly start apps whose `idle_timeout` resolves to "always on".
    pub async fn deploy_always_on(&self) -> Result<()> {
        for handle in self.apps.values() {
            let timeout = handle
                .spec
                .scaling
                .resolve_idle_timeout()
                .map_err(|e| anyhow!("{}: {e}", handle.name))?;
            if timeout.is_none() {
                info!(app = %handle.name, "eager start (idle_timeout = 0)");
                self.ensure_running(handle).await?;
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
        for handle in self.apps.values() {
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
                if let Err(e) = self.stop(handle).await {
                    warn!(app = %handle.name, error = ?e, "stop on idle failed");
                }
            }
        }
    }

    /// Stop every app that's currently running. Used on shutdown.
    pub async fn teardown(&self) {
        for handle in self.apps.values() {
            let should_stop = {
                let inner = handle.inner.lock().await;
                matches!(inner.state, AppState::Running { .. } | AppState::Starting)
            };
            if should_stop {
                if let Err(e) = self.stop(handle).await {
                    warn!(app = %handle.name, error = ?e, "stop failed during teardown");
                }
            }
        }
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
            .pull_image(&handle.spec.image, Auth::Anonymous)
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

#[async_trait]
impl UpstreamResolver for AppController {
    async fn resolve(&self, host: &str) -> Option<SocketAddr> {
        let subdomain = subdomain_of(host)?;
        let handle = self.apps.get(subdomain)?.clone();
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
