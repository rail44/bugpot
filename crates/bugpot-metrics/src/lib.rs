//! Prometheus-format metrics and a tiny health endpoint for bugpot.
//!
//! Install the recorder exactly once at startup with [`install_recorder`]
//! — the returned [`PrometheusHandle`] is the source of truth that
//! [`serve`] renders on each scrape. Instrumentation throughout the rest
//! of the workspace uses the `metrics` crate macros (`counter!`,
//! `gauge!`, `histogram!`); they are silently no-op until the recorder
//! is installed.
//!
//! # Routes (no auth)
//!
//! - `GET /metrics` — Prometheus exposition (text/plain).
//! - `GET /healthz` — `200 OK` while the listener is up.
//!
//! Auth is intentionally absent. The metrics listener should bind to a
//! trusted interface (loopback for dev, a Tailscale IP with ACL for
//! anything more).

use std::net::SocketAddr;

use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing::info;

/// Install the process-wide Prometheus recorder. Must be called exactly
/// once, before any metric macro fires. Subsequent metric emissions are
/// captured by the returned handle and rendered by [`serve`].
pub fn install_recorder() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("install metrics recorder: {e}"))?;
    Ok(handle)
}

/// Serve `/metrics` and `/healthz` at `addr` until the future is dropped.
pub async fn serve(addr: SocketAddr, handle: PrometheusHandle) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(healthz))
        .with_state(handle);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "bugpot-metrics listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn metrics_handler(
    axum::extract::State(handle): axum::extract::State<PrometheusHandle>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        handle.render(),
    )
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}
