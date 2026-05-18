//! `UpstreamResolver` impl — the router's hot path into `AppHost`.
//!
//! Resolution composes `Registry::find_by_subdomain` (one hash) with
//! `ensure_running` (cold-start if needed). Every HTTP request goes
//! through here, which is why the look-up is by reverse index (no
//! intermediate name string) and the lifecycle path is unified
//! whether the app is `Stopped`, `Frozen`, or `Running`.

use std::net::SocketAddr;

use bugpot_egress::EgressOps;
use bugpot_router::{ResolveError, Upstream, UpstreamResolver, subdomain_of};
use bugpot_runtime::RuntimeOps;
use tracing::error;

use crate::AppHost;

impl<R: RuntimeOps, E: EgressOps> UpstreamResolver for AppHost<R, E> {
    async fn resolve(&self, host: &str) -> Result<Upstream, ResolveError> {
        let subdomain = subdomain_of(host).ok_or(ResolveError::NoSuchApp)?;
        let handle = self
            .registry
            .find_by_subdomain(subdomain)
            .await
            .ok_or(ResolveError::NoSuchApp)?;
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
