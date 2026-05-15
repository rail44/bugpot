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
//! trusted interface (loopback for dev, or whatever private network the
//! operator scrapes from in production).

use std::net::SocketAddr;
use std::time::Duration;

use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use metrics::{counter, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio_metrics::RuntimeMonitor;
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
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        handle.render(),
    )
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// Spawn a long-lived background task that samples the tokio runtime
/// every `interval` and exposes the result as Prometheus metrics
/// under the `bugpot_tokio_*` prefix.
///
/// Caller must already be inside a running tokio runtime — the
/// function calls `Handle::current()` to find it. Pair this with
/// [`install_recorder`] earlier in startup. Setting `interval` too
/// tight (< 1s) adds runtime overhead without buying useful
/// resolution at Prometheus scrape cadence; 10s aligns with the
/// typical scrape interval.
///
/// Most of `tokio_metrics::RuntimeMetrics` is gated behind the
/// `tokio_unstable` cfg. The default emit set below is the stable
/// subset — saturation snapshots (worker count, queue depths,
/// blocking pool state). When the workspace is built with
/// `RUSTFLAGS="--cfg tokio_unstable"`, the richer throughput counters
/// (busy time, poll counts, steal events, budget yields, I/O driver
/// readiness) light up automatically via the
/// `#[cfg(tokio_unstable)]` block in `emit_runtime_metrics`.
pub fn spawn_runtime_monitor(interval: Duration) {
    let monitor = RuntimeMonitor::new(&tokio::runtime::Handle::current());
    tokio::spawn(async move {
        let mut intervals = monitor.intervals();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(m) = intervals.next() else {
                return;
            };
            emit_runtime_metrics(&m);
        }
    });
}

#[allow(clippy::cast_precision_loss)]
fn emit_runtime_metrics(m: &tokio_metrics::RuntimeMetrics) {
    // Stable subset of `tokio_metrics::RuntimeMetrics` (10 fields
    // total in 0.5; the rest are gated behind `tokio_unstable`).
    // Snapshot gauges (point-in-time):
    gauge!("bugpot_tokio_workers").set(m.workers_count as f64);
    gauge!("bugpot_tokio_live_tasks").set(m.live_tasks_count as f64);
    gauge!("bugpot_tokio_global_queue_depth").set(m.global_queue_depth as f64);

    // Delta counters: `intervals().next()` returns the delta since
    // the previous call, so increment the Prometheus counter by that
    // delta. Result: a monotonically increasing counter that
    // `rate()` consumes naturally. Busy duration is in microseconds
    // for full cgroup-style precision (operators divide by 1e6).
    counter!("bugpot_tokio_park_total").increment(m.total_park_count);
    counter!("bugpot_tokio_busy_microseconds_total")
        .increment(u64::try_from(m.total_busy_duration.as_micros()).unwrap_or(u64::MAX));

    // Richer signals require `--cfg tokio_unstable`. Compiled out by
    // default so the workspace stays buildable without that cfg; the
    // P3 follow-up enables the cfg behind a feature gate and lights
    // these up.
    #[cfg(tokio_unstable)]
    {
        gauge!("bugpot_tokio_local_queue_depth_max").set(m.max_local_queue_depth as f64);
        gauge!("bugpot_tokio_local_queue_depth_total").set(m.total_local_queue_depth as f64);
        gauge!("bugpot_tokio_blocking_threads").set(m.blocking_threads_count as f64);
        gauge!("bugpot_tokio_idle_blocking_threads").set(m.idle_blocking_threads_count as f64);
        gauge!("bugpot_tokio_blocking_queue_depth").set(m.blocking_queue_depth as f64);
        gauge!("bugpot_tokio_mean_poll_duration_seconds").set(m.mean_poll_duration.as_secs_f64());

        counter!("bugpot_tokio_noop_total").increment(m.total_noop_count);
        counter!("bugpot_tokio_steal_total").increment(m.total_steal_count);
        counter!("bugpot_tokio_steal_operations_total").increment(m.total_steal_operations);
        counter!("bugpot_tokio_polls_total").increment(m.total_polls_count);
        counter!("bugpot_tokio_remote_schedules_total").increment(m.num_remote_schedules);
        counter!("bugpot_tokio_local_schedules_total").increment(m.total_local_schedule_count);
        counter!("bugpot_tokio_local_overflow_total").increment(m.total_overflow_count);
        counter!("bugpot_tokio_budget_forced_yields_total").increment(m.budget_forced_yield_count);
        counter!("bugpot_tokio_io_driver_ready_total").increment(m.io_driver_ready_count);
    }
}
