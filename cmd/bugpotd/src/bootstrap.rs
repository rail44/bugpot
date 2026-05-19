//! Daemon-wide bring-up and tear-down.
//!
//! [`Bootstrap`] is the single object that owns every long-lived
//! handle the daemon spawns at start: the controller, every
//! `JoinHandle` for background tasks, and the metrics-listener
//! task if it's enabled. `build` runs the synchronous bring-up
//! sequence (egress → runtime → image GC → controller →
//! reattach / orphan-cleanup → eager-start → spawn tasks).
//! `run` blocks on SIGINT, aborts every spawned task, and tears
//! down the controller.
//!
//! Splitting bring-up from `main` keeps the orchestration linear
//! and lets the cleanup paths share the same teardown surface
//! regardless of which phase failed.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bugpot_admin::AdminAuth;
use bugpot_core::AppHost;
use bugpot_egress::Egress;
use bugpot_metrics::PrometheusHandle;
use bugpot_runtime::Runtime;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::{Config, parse_router_config};
use crate::secrets::{read_admin_token, read_deploy_secret};

/// Cadence for the controller's lifecycle sweep (crash detection +
/// scale-to-zero idle stop). 30 s strikes the balance for a 1 vCPU
/// host: granular enough that idle-stop happens within a minute of
/// the configured timeout, but not so aggressive that the sweep
/// itself wakes the CPU twelve times a minute for nothing.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// How often the memory-pressure handler polls `MemAvailable`. 500 ms
/// is the sweet spot between "fast enough to evict before OOM on a
/// 1 GiB VM" and "noise floor on `/proc/meminfo` read cost".
const MEM_PRESSURE_POLL: Duration = Duration::from_millis(500);

/// Memory-pressure thresholds are derived from `MemTotal` at startup
/// rather than configured: `lo = 15% of total`, `hi = 25% of total`,
/// with absolute caps so the eviction window doesn't grow boundlessly
/// on a large host. The 15/25 split matches the historical `e2-micro`
/// defaults (150 MiB / 256 MiB on a 1 GiB host) and is the ratio that
/// was already in production use before this auto-derive landed.
const MEM_PRESSURE_LO_RATIO: u64 = 15;
const MEM_PRESSURE_HI_RATIO: u64 = 25;
const MEM_PRESSURE_LO_CAP: u64 = 1024 * 1024 * 1024; // 1 GiB
const MEM_PRESSURE_HI_CAP: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
/// Fallback `MemTotal` when `/proc/meminfo` is unreadable or missing
/// the `MemTotal:` line (the latter shouldn't happen on Linux but the
/// helper has to return *something*). 1 GiB matches the e2-micro
/// reference target.
const MEM_TOTAL_FALLBACK: u64 = 1024 * 1024 * 1024;

/// How often the in-process tokio runtime monitor samples and emits
/// `bugpot_tokio_*` gauges / counters. Unconditional — the cost is
/// negligible and the metrics are no-op when the listener is off.
const RUNTIME_MONITOR_INTERVAL: Duration = Duration::from_secs(10);

/// Live state of a started daemon: the controller plus every task
/// spawned by `build`. `run` consumes the value, aborts the tasks,
/// and tears the controller down — there is no other safe way to
/// shut down.
pub(crate) struct Bootstrap {
    controller: Arc<AppHost<Runtime, Egress>>,
    listen: SocketAddr,
    admin_listen: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl Bootstrap {
    /// Bring up egress, runtime, controller, and every background
    /// task. On any post-controller failure (e.g. `deploy_always_on`)
    /// the partially-built controller is torn down before the error
    /// propagates, so the host nft / netns state stays consistent.
    pub(crate) async fn build(cfg: Config, metrics_handle: PrometheusHandle) -> Result<Self> {
        let auth_file = Config::auth_file();
        let auth = bugpot_config::load_auth(auth_file).context("load auth.toml")?;
        info!(
            file = %auth_file.display(),
            registries = auth.registries.len(),
            "loaded registry auth",
        );

        info!(
            bridge = %bugpot_egress::BRIDGE_NAME,
            subnet = %bugpot_egress::subnet(),
            bridge_ip = %bugpot_egress::bridge_ip(),
            "bringing up egress"
        );
        let (egress, mut startup_claims) = Egress::new(cfg.egress)
            .await
            .context("init egress (bridge/DNS/nftables)")?;
        let egress = Arc::new(egress);

        let state_dir = Runtime::default_state_dir();
        info!(state_dir = %state_dir.display(), "init runtime");
        let runtime = Arc::new(Runtime::new(state_dir.clone()).context("init runtime")?);

        gc_image_cache(&runtime);

        let controller =
            Arc::new(AppHost::new(runtime, egress, state_dir, auth).context("init controller")?);
        controller.reattach_running(&mut startup_claims).await;
        controller.cleanup_orphans(startup_claims).await;

        if let Err(e) = controller.deploy_always_on().await {
            error!(error = ?e, "eager-start failed; rolling back");
            controller.teardown().await;
            return Err(e);
        }

        let mut tasks = Vec::new();
        tasks.push(spawn_sweep(&controller));
        tasks.push(spawn_memory_pressure(&controller));
        tasks.push(spawn_router(cfg.listen, &controller)?);

        bugpot_metrics::spawn_runtime_monitor(RUNTIME_MONITOR_INTERVAL);

        if let Some(t) = spawn_metrics(metrics_handle)? {
            tasks.push(t);
        }
        tasks.push(spawn_admin(cfg.admin_listen, &controller)?);

        Ok(Self {
            controller,
            listen: cfg.listen,
            admin_listen: cfg.admin_listen,
            tasks,
        })
    }

    /// Block on SIGINT, then abort every spawned task and tear the
    /// controller down. Consuming `self` makes the post-shutdown
    /// state unrepresentable.
    pub(crate) async fn run(self) {
        info!(
            listen = %self.listen,
            admin_listen = %self.admin_listen,
            "bugpot up; press Ctrl+C to shut down",
        );
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!(error = %e, "failed to wait for SIGINT");
        }
        info!("shutdown signal received; tearing down");

        for t in &self.tasks {
            t.abort();
        }
        self.controller.teardown().await;
    }
}

/// Returns `true` iff the current process has `CAP_NET_ADMIN` in its
/// effective set. Covers both the "running as root" path and the
/// "non-root with ambient cap" path (`AmbientCapabilities` in a
/// systemd unit).
pub(crate) fn has_cap_net_admin() -> bool {
    bugpot_runtime::caps::has_effective_cap(bugpot_runtime::caps::CAP_NET_ADMIN)
}

/// Reclaim image cache dirs whose digest no bundle references and
/// any orphan `.tmp.*` / incomplete-pull dirs. Best-effort: a
/// failure logs and continues — startup is not aborted because the
/// cost is at most one re-pull on next start.
fn gc_image_cache(runtime: &Runtime) {
    match runtime.gc_unused_images() {
        Ok(removed) if removed > 0 => {
            info!(removed, "image cache GC");
            metrics::counter!("bugpot_images_gc_total").increment(removed as u64);
        }
        Ok(_) => {}
        Err(e) => warn!(error = ?e, "image cache GC failed (continuing)"),
    }
}

fn spawn_sweep(controller: &Arc<AppHost<Runtime, Egress>>) -> JoinHandle<()> {
    let c = Arc::clone(controller);
    tokio::spawn(c.sweep_loop(SWEEP_INTERVAL))
}

/// Spawn the memory-pressure loop with thresholds auto-derived from
/// `/proc/meminfo`. Unconditional now (freeze is always on): the loop
/// is cheap when there are no Frozen apps to evict, and the
/// "stop-on-idle" pre-freeze fallback is gone.
fn spawn_memory_pressure(controller: &Arc<AppHost<Runtime, Egress>>) -> JoinHandle<()> {
    let (lo, hi) = derive_mem_pressure_thresholds();
    info!(
        lo_bytes = lo,
        hi_bytes = hi,
        "memory-pressure handler enabled (auto-derived from MemTotal)"
    );
    let c = Arc::clone(controller);
    tokio::spawn(c.memory_pressure_loop(MEM_PRESSURE_POLL, lo, hi))
}

/// Compute `(lo, hi)` byte thresholds for the memory-pressure handler
/// from the host's `MemTotal`. 15% / 25% of total, capped at 1 GiB /
/// 2 GiB so the eviction window doesn't widen unboundedly on a host
/// where almost all the RAM is for other things anyway.
fn derive_mem_pressure_thresholds() -> (u64, u64) {
    let total = read_mem_total().unwrap_or(MEM_TOTAL_FALLBACK);
    let lo = (total * MEM_PRESSURE_LO_RATIO / 100).min(MEM_PRESSURE_LO_CAP);
    let hi = (total * MEM_PRESSURE_HI_RATIO / 100).min(MEM_PRESSURE_HI_CAP);
    (lo, hi)
}

/// Parse `MemTotal` (bytes) from `/proc/meminfo`. Mirrors
/// `bugpot_core::mempressure::read_mem_available` in shape — kept here
/// because `bugpot-core` doesn't expose its parser and the daemon only
/// needs this once at startup.
fn read_mem_total() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())?;
            return Some(kb * 1024);
        }
    }
    None
}

fn spawn_router(
    listen: SocketAddr,
    controller: &Arc<AppHost<Runtime, Egress>>,
) -> Result<JoinHandle<()>> {
    let resolver = Arc::clone(controller);
    let router_cfg = parse_router_config()?;
    Ok(tokio::spawn(async move {
        if let Err(e) = bugpot_router::serve(listen, resolver, router_cfg).await {
            error!(error = %e, "router exited with error");
        }
    }))
}

/// Metrics HTTP listener (optional). Recorder installation is
/// unconditional in `main` so emission paths stay no-op-safe even
/// when this listener is disabled; only the HTTP surface is gated.
fn spawn_metrics(handle: PrometheusHandle) -> Result<Option<JoinHandle<()>>> {
    let Ok(raw) = std::env::var("BUGPOT_METRICS_LISTEN") else {
        info!("BUGPOT_METRICS_LISTEN unset; /metrics endpoint disabled");
        drop(handle);
        return Ok(None);
    };
    let addr: SocketAddr = raw.parse().context("parse BUGPOT_METRICS_LISTEN")?;
    Ok(Some(tokio::spawn(async move {
        if let Err(e) = bugpot_metrics::serve(addr, handle).await {
            error!(error = %e, "metrics endpoint exited with error");
        }
    })))
}

fn spawn_admin(
    admin_listen: SocketAddr,
    controller: &Arc<AppHost<Runtime, Egress>>,
) -> Result<JoinHandle<()>> {
    let token = read_admin_token()?;
    let admin_auth = Arc::new(AdminAuth::from_token(token));
    info!("admin API bearer token loaded");
    let deploy_secret = Arc::new(read_deploy_secret()?);
    info!("deploy-key secret loaded");
    let admin_controller = Arc::clone(controller);
    Ok(tokio::spawn(async move {
        if let Err(e) =
            bugpot_admin::serve(admin_listen, admin_controller, admin_auth, deploy_secret).await
        {
            error!(error = %e, "admin api exited with error");
        }
    }))
}
