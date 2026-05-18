//! Operator-facing snapshot types ([`AppView`] / [`AppStateView`])
//! and the per-handle projection that builds them. Pure serialisation
//! shape — no side effects. The matching Prometheus emission for
//! per-app resource usage lives next to its only caller, in
//! `ops/loops.rs`.
//!
//! These are what `bugpot-admin` serialises as JSON for
//! `GET /apps` / `GET /apps/<name>` and what the `bugpot` CLI
//! pretty-prints in its table output. The internal state machine
//! (in `handle.rs`) is the source of truth; `view_of` is the
//! one-way crystallisation step.

use std::sync::Arc;

use bugpot_config::Rollout;
use serde::Serialize;

use crate::handle::{AppHandle, AppState};

/// Public, serialisable snapshot of an app's registration.
#[derive(Debug, Clone, Serialize)]
pub struct AppView {
    pub name: String,
    pub subdomain: String,
    pub repo: String,
    pub port: u16,
    pub state: AppStateView,
    /// `None` when the app has never been rolled out (registered only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_rollout: Option<Rollout>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppStateView {
    Stopped,
    Starting,
    Running,
    /// Container is paused (cgroup freezer). RAM resident, CPU 0.
    /// Next request resumes it in sub-ms (no cold start).
    Frozen,
    /// Blue-green rollout in flight. The previously-running container
    /// is still serving traffic; a new container in the opposite slot
    /// is being built and readiness-probed in the background.
    RollingOver,
    Stopping,
}

pub(crate) async fn view_of(handle: &Arc<AppHandle>) -> AppView {
    let (state, current_rollout) = {
        let inner = handle.inner.lock().await;
        let state = match &inner.state {
            AppState::Stopped => AppStateView::Stopped,
            AppState::Starting { .. } => AppStateView::Starting,
            AppState::Running { .. } => AppStateView::Running,
            AppState::Frozen { .. } => AppStateView::Frozen,
            AppState::RollingOver { .. } => AppStateView::RollingOver,
            AppState::Stopping => AppStateView::Stopping,
        };
        (state, inner.rollouts.back().cloned())
    };
    let spec = handle.spec.read().await;
    AppView {
        name: handle.identity.name.clone(),
        subdomain: handle.identity.subdomain.clone(),
        repo: spec.repo.clone(),
        port: spec.port,
        state,
        current_rollout,
    }
}
