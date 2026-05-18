//! Surface this crate's handlers need from the controller, expressed
//! as a `dyn`-safe trait so the HTTP layer can be generic-free.
//!
//! `AppController<R, E>` is parameterised so the controller's own
//! tests can swap in mocks; the HTTP layer doesn't share that need
//! and the parameterisation only shows up as `<R: RuntimeOps, E:
//! EgressOps>` noise on every handler / middleware / `serve`
//! signature. The trait below exposes exactly the methods this
//! crate calls; `AppController<R, E>` gets a blanket impl, so
//! `cmd/bugpotd` passes `controller` directly and the HTTP layer
//! holds an `Arc<dyn AdminBackend>`.
//!
//! Uses `#[async_trait]` rather than native AFIT because the values
//! travel as `dyn AdminBackend` — the workspace's other dyn-dispatch
//! trait (`bugpot_router::UpstreamResolver`) makes the same choice.

use std::sync::Arc;

use async_trait::async_trait;
use bugpot_config::{AppSpec, Rollout};
use bugpot_controller::{
    AppController, AppHandle, AppView, DeployError, RemoveError, RolloutError, UpdateError,
};
use bugpot_egress::EgressOps;
use bugpot_runtime::RuntimeOps;

#[async_trait]
pub trait AdminBackend: Send + Sync + 'static {
    async fn find_handle(&self, name: &str) -> Option<Arc<AppHandle>>;
    async fn get_app(&self, name: &str) -> Option<AppView>;
    async fn list_apps(&self) -> Vec<AppView>;
    async fn deploy_app(&self, spec: AppSpec) -> Result<AppView, DeployError>;
    async fn update_app(
        &self,
        handle: &Arc<AppHandle>,
        spec: AppSpec,
    ) -> Result<AppView, UpdateError>;
    async fn set_rollout(
        &self,
        handle: &Arc<AppHandle>,
        tag: String,
    ) -> Result<Rollout, RolloutError>;
    async fn list_rollouts(&self, handle: &Arc<AppHandle>) -> Vec<Rollout>;
    async fn remove_app(&self, handle: &Arc<AppHandle>) -> Result<(), RemoveError>;
}

#[async_trait]
impl<R, E> AdminBackend for AppController<R, E>
where
    R: RuntimeOps,
    E: EgressOps,
{
    async fn find_handle(&self, name: &str) -> Option<Arc<AppHandle>> {
        Self::find_handle(self, name).await
    }
    async fn get_app(&self, name: &str) -> Option<AppView> {
        Self::get_app(self, name).await
    }
    async fn list_apps(&self) -> Vec<AppView> {
        Self::list_apps(self).await
    }
    async fn deploy_app(&self, spec: AppSpec) -> Result<AppView, DeployError> {
        Self::deploy_app(self, spec).await
    }
    async fn update_app(
        &self,
        handle: &Arc<AppHandle>,
        spec: AppSpec,
    ) -> Result<AppView, UpdateError> {
        Self::update_app(self, handle, spec).await
    }
    async fn set_rollout(
        &self,
        handle: &Arc<AppHandle>,
        tag: String,
    ) -> Result<Rollout, RolloutError> {
        Self::set_rollout(self, handle, tag).await
    }
    async fn list_rollouts(&self, handle: &Arc<AppHandle>) -> Vec<Rollout> {
        Self::list_rollouts(self, handle).await
    }
    async fn remove_app(&self, handle: &Arc<AppHandle>) -> Result<(), RemoveError> {
        Self::remove_app(self, handle).await
    }
}
