//! Background timer-driven loops: per-app sweep (crash detection +
//! idle-freeze) and host-wide memory-pressure eviction.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bugpot_egress::EgressOps;
use bugpot_runtime::{ResourceUsage, RuntimeOps};
use metrics::{counter, gauge};
use tracing::{debug, info, warn};

use crate::AppHost;
use crate::handle::AppHandle;
use crate::mempressure::read_mem_available;

impl<R: RuntimeOps, E: EgressOps> AppHost<R, E> {
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

    /// Background task: poll system memory and evict frozen apps to
    /// `Stopped` when available memory drops below `lo_bytes`. Stops
    /// evicting once memory rebounds past `hi_bytes` (hysteresis).
    ///
    /// Frozen apps still occupy their full RSS, so a runtime that
    /// freezes-by-default on idle would slowly fill memory. This loop
    /// is the safety valve: it converts the cheapest-to-restart
    /// (= least-recently-used) frozen apps back into proper Stopped
    /// state, freeing their pages.
    ///
    /// Apps are evicted one per tick in LRU order; the loop re-reads
    /// `MemAvailable` after each eviction so a single tick can release
    /// just enough to clear pressure rather than thawing everything.
    pub async fn memory_pressure_loop(
        self: Arc<Self>,
        tick: Duration,
        lo_bytes: u64,
        hi_bytes: u64,
    ) {
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut evicting = false;
        loop {
            interval.tick().await;
            let Some(avail) = read_mem_available() else {
                continue;
            };
            // Hysteresis: cross lo to engage, cross hi to disengage.
            // Between the two we keep evicting once started — that way
            // a slow leak doesn't keep flap-flipping on the lo line.
            if !evicting && avail < lo_bytes {
                evicting = true;
                info!(
                    avail_bytes = avail,
                    lo_bytes, "memory pressure: starting frozen-app eviction"
                );
            }
            if evicting && avail >= hi_bytes {
                evicting = false;
                info!(avail_bytes = avail, hi_bytes, "memory pressure resolved");
                continue;
            }
            if !evicting {
                continue;
            }
            if !self.evict_lru_frozen().await {
                // Nothing left to evict; pressure is from something
                // outside bugpot's reach. Disengage so we don't spin.
                debug!("no frozen apps to evict; disengaging pressure handler");
                evicting = false;
            }
        }
    }

    /// Find the longest-idle Frozen app and transition it to Stopped.
    /// Returns true if an eviction happened. Caller is the memory
    /// pressure loop; per-tick semantics keep eviction proportional
    /// to actual pressure.
    pub(crate) async fn evict_lru_frozen(&self) -> bool {
        let mut candidate: Option<(Arc<AppHandle>, Instant)> = None;
        for handle in self.list_handles().await {
            let inner = handle.inner.lock().await;
            if inner.state.is_frozen() {
                match &candidate {
                    Some((_, oldest)) if inner.last_access >= *oldest => {}
                    _ => candidate = Some((handle.clone(), inner.last_access)),
                }
            }
        }
        let Some((handle, _)) = candidate else {
            return false;
        };
        info!(
            app = %handle.identity.name,
            "memory pressure: evicting frozen app"
        );
        counter!("bugpot_evictions_total").increment(1);
        if let Err(e) = self.stop(&handle).await {
            warn!(
                app = %handle.identity.name,
                error = ?e,
                "eviction stop() failed",
            );
        }
        true
    }

    pub(crate) async fn sweep(&self) {
        // Per-app sweep work is independent (each handle has its own
        // lock + spec + runtime entry), so run all apps concurrently.
        // A slow `stop()` on one app no longer blocks metric emission
        // or idle-timeout enforcement for the others in the same tick.
        let handles = self.list_handles().await;
        let tasks = handles.into_iter().map(|h| self.sweep_one(h));
        futures::future::join_all(tasks).await;
    }

    async fn sweep_one(&self, handle: Arc<AppHandle>) {
        // Only look at apps we believe are running. Starting /
        // Stopping / Stopped handles are already in motion or
        // already-cleaned.
        if !handle.inner.lock().await.state.is_running() {
            return;
        }

        let container_id = handle.current_id().await;

        // 1. Liveness: did the container die under us?
        if !self.runtime.is_container_running(&container_id) {
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
        if let Some(usage) = self.runtime.resource_usage(&container_id) {
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
            info!(app = %handle.identity.name, "idle timeout reached, freezing");
            if let Err(e) = self.freeze(&handle).await {
                warn!(app = %handle.identity.name, error = ?e, "freeze on idle failed");
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
///
/// Co-located with its only caller (the sweep loop) rather than living
/// in `view.rs` — projection types belong with the serialisable shape;
/// side-effecting Prometheus emission belongs with the timer-driven
/// loop that decides when to sample.
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
