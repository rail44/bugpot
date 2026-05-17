//! Operator-facing snapshot types ([`AppView`] / [`AppStateView`])
//! and the per-handle projections that build them.
//!
//! These are what `bugpot-admin` serialises as JSON for
//! `GET /apps` / `GET /apps/<name>` and what the `bugpot` CLI
//! pretty-prints in its table output. The internal state machine
//! (in `handle.rs`) is the source of truth; `view_of` is the
//! one-way crystallisation step.

use std::sync::Arc;

use bugpot_config::Rollout;
use bugpot_runtime::ResourceUsage;
use metrics::{counter, gauge};
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

/// Emit `bugpot_app_memory_bytes` (gauge) and
/// `bugpot_app_cpu_microseconds_total` (counter) from a fresh cgroup
/// sample. The CPU delta is computed against the per-handle baseline
/// stored in `HandleInner.cpu_baseline`, which is updated in place.
///
/// CPU is exposed in microseconds (cgroup-v2's native unit) so the
/// counter keeps full precision. Operators querying via Prometheus
/// divide by 1e6: `rate(bugpot_app_cpu_microseconds_total[5m]) / 1000000`.
pub(crate) async fn emit_resource_metrics(handle: &Arc<AppHandle>, usage: ResourceUsage) {
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
