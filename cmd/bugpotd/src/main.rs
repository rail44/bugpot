//! `bugpot` entrypoint.
//!
//! Loads `apps/*.toml`, brings up the egress stack (bridge / DNS / nftables),
//! initialises the runtime, and starts the router. Apps are deployed
//! lazily by the [`AppController`] on first request, except those that
//! explicitly opt out of scale-to-zero (`scaling.idle_timeout = "0"`),
//! which are started eagerly on bring-up.
//!
//! On SIGINT, every running app is stopped and its endpoint released. The
//! bridge / nftables ruleset persist across runs; `Egress::new` re-applies
//! them atomically.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bugpot_admin::AdminAuth;
use bugpot_controller::AppController;
use bugpot_egress::{Egress, EgressConfig, EgressOps};
use bugpot_router::UpstreamResolver;
use bugpot_runtime::{Runtime, RuntimeOps};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:8081";
const DEFAULT_AUTH_FILE: &str = "/etc/bugpot/auth.toml";
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

/// Default low-water mark for memory pressure (bytes of `MemAvailable`).
/// Below this, the controller starts evicting frozen apps LRU-first.
/// 150 MiB is comfortable for an e2-micro (1 GiB); operators on a
/// larger VM can override via `BUGPOT_FREEZE_MEM_LO`.
const MEM_PRESSURE_LO_DEFAULT: u64 = 150 * 1024 * 1024;

/// Default high-water mark (bytes). Eviction halts once `MemAvailable`
/// rises back to this level — the hysteresis gap keeps the handler
/// from flap-flipping at the threshold edge. Override via
/// `BUGPOT_FREEZE_MEM_HI`.
const MEM_PRESSURE_HI_DEFAULT: u64 = 250 * 1024 * 1024;

// Metrics: the Prometheus recorder is *always* installed so callsites
// emit successfully; the HTTP listener is only spawned when
// `BUGPOT_METRICS_LISTEN` is set, keeping the surface area opt-in.

#[derive(Debug)]
struct Config {
    listen: SocketAddr,
    admin_listen: SocketAddr,
    auth_file: PathBuf,
    egress: EgressConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let metrics_handle = bugpot_metrics::install_recorder().context("install metrics recorder")?;

    // Capability-based start gate. bugpot doesn't actually require
    // uid=0 — only `CAP_NET_ADMIN` (bridge / veth / nftables) plus
    // a handful of others libcontainer needs. The shipped systemd
    // unit (examples/bugpotd.service) grants exactly that set via
    // `AmbientCapabilities` to an unprivileged `bugpot` user.
    if !has_cap_net_admin() {
        anyhow::bail!(
            "bugpot needs CAP_NET_ADMIN (and the libcontainer set) — \
             bridge / veth / netns / nftables setup will fail without it.\n\
             Install via the shipped systemd unit (examples/bugpotd.service) \
             or, for development, run under `sudo`. See docs/deploy.md."
        );
    }

    let cfg = parse_config()?;

    let auth = bugpot_config::load_auth(&cfg.auth_file).context("load auth.toml")?;
    info!(
        file = %cfg.auth_file.display(),
        registries = auth.registries.len(),
        "loaded registry auth",
    );

    // Egress (bridge + DNS + nftables): idempotent across runs.
    info!(
        bridge = %bugpot_egress::BRIDGE_NAME,
        subnet = %bugpot_egress::subnet(),
        bridge_ip = %bugpot_egress::bridge_ip(),
        "bringing up egress"
    );
    let egress = Arc::new(
        Egress::new(cfg.egress)
            .await
            .context("init egress (bridge/DNS/nftables)")?,
    );

    // Runtime (image cache + libcontainer state).
    let state_dir = Runtime::default_state_dir();
    info!(state_dir = %state_dir.display(), "init runtime");
    let runtime = Arc::new(Runtime::new(state_dir.clone()).context("init runtime")?);

    // Reclaim image cache dirs whose digest no bundle references and
    // any orphan `.tmp.*` / incomplete-pull dirs. Safe before pulls
    // because nothing else has started yet.
    match runtime.gc_unused_images() {
        Ok(removed) if removed > 0 => {
            info!(removed, "image cache GC");
            metrics::counter!("bugpot_images_gc_total").increment(removed as u64);
        }
        Ok(_) => {}
        Err(e) => warn!(error = ?e, "image cache GC failed (continuing)"),
    }

    // Controller owns per-app lifecycle. It rehydrates AppSpecs and
    // rollouts from its own state directory (`<state>/apps/` and
    // `<state>/rollouts/`) — operators do not feed it specs from a
    // separate directory; admin API is the only entry point.
    let controller = Arc::new(
        AppController::new(runtime, egress, state_dir.clone(), auth).context("init controller")?,
    );
    // Reclaim any containers + endpoints that survived a previous bugpot
    // process (e.g. a crash, or a planned binary upgrade in a later
    // version). Done before deploy_always_on so eager-start sees these
    // apps already Running and skips them.
    controller.reattach_running().await;

    // Anything left in egress's discovered set has no current TOML —
    // tear it down so its IP doesn't sit allocated forever and the
    // netns / nft entries don't linger.
    controller.cleanup_orphans().await;

    if let Err(e) = controller.deploy_always_on().await {
        error!(error = ?e, "eager-start failed; rolling back");
        controller.teardown().await;
        return Err(e);
    }

    let sweep_task = spawn_sweep(&controller);
    let pressure_task = spawn_memory_pressure(&controller)?;
    let serve_task = spawn_router(cfg.listen, &controller)?;

    // Sample the tokio runtime every 10s and emit `bugpot_tokio_*`
    // gauges / counters. Unconditional — the cost is negligible
    // (a single background task with one `Handle::current()`
    // snapshot per tick) and the metrics are no-op when the
    // recorder's listener is disabled, just like every other
    // emission point.
    bugpot_metrics::spawn_runtime_monitor(std::time::Duration::from_secs(10));

    // Metrics HTTP listener (optional). The recorder is installed
    // unconditionally above so emission paths stay no-op-safe even when
    // the listener is disabled.
    let metrics_task = if let Ok(raw) = std::env::var("BUGPOT_METRICS_LISTEN") {
        let addr: SocketAddr = raw.parse().context("parse BUGPOT_METRICS_LISTEN")?;
        Some(tokio::spawn(async move {
            if let Err(e) = bugpot_metrics::serve(addr, metrics_handle).await {
                error!(error = %e, "metrics endpoint exited with error");
            }
        }))
    } else {
        info!("BUGPOT_METRICS_LISTEN unset; /metrics endpoint disabled");
        drop(metrics_handle);
        None
    };

    let admin_task = spawn_admin(cfg.admin_listen, &controller)?;

    info!(listen = %cfg.listen, admin_listen = %cfg.admin_listen, "bugpot up; press Ctrl+C to shut down");
    if let Err(e) = tokio::signal::ctrl_c().await {
        error!(error = %e, "failed to wait for SIGINT");
    }
    info!("shutdown signal received; tearing down");

    serve_task.abort();
    admin_task.abort();
    if let Some(t) = metrics_task {
        t.abort();
    }
    sweep_task.abort();
    if let Some(t) = pressure_task {
        t.abort();
    }
    controller.teardown().await;

    Ok(())
}

fn parse_config() -> Result<Config> {
    let listen: SocketAddr = std::env::var("BUGPOT_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
        .parse()
        .context("parse BUGPOT_LISTEN")?;

    let admin_listen: SocketAddr = std::env::var("BUGPOT_ADMIN_LISTEN")
        .unwrap_or_else(|_| DEFAULT_ADMIN_LISTEN.to_owned())
        .parse()
        .context("parse BUGPOT_ADMIN_LISTEN")?;

    let auth_file = std::env::var("BUGPOT_AUTH_FILE")
        .map_or_else(|_| PathBuf::from(DEFAULT_AUTH_FILE), PathBuf::from);

    let egress = parse_egress_config()?;

    Ok(Config {
        listen,
        admin_listen,
        auth_file,
        egress,
    })
}

/// Build an `EgressConfig` from env. The only deployment-variable knob
/// left is the upstream DNS server list (corporate networks routinely
/// run their own resolver); the bridge address / subnet / nft table are
/// fixed at the type level — see `bugpot_egress::{BRIDGE_NAME, subnet,
/// bridge_ip, NFT_TABLE, DNS_PORT, ALLOW_TTL_SECS}`.
///
/// Recognised env vars:
///   - `BUGPOT_EGRESS_DNS_UPSTREAM` — comma-separated socket addrs
///     (default `1.1.1.1:53,8.8.8.8:53`)
fn parse_egress_config() -> Result<EgressConfig> {
    let mut cfg = EgressConfig::default();
    if let Ok(raw) = std::env::var("BUGPOT_EGRESS_DNS_UPSTREAM") {
        cfg.dns_upstream =
            bugpot_egress::parse_dns_upstream(&raw).context("parse BUGPOT_EGRESS_DNS_UPSTREAM")?;
    }
    cfg.validate().context("validate egress config")?;
    Ok(cfg)
}

fn spawn_sweep<R: RuntimeOps, E: EgressOps>(
    controller: &Arc<AppController<R, E>>,
) -> JoinHandle<()> {
    let c = Arc::clone(controller);
    tokio::spawn(c.sweep_loop(SWEEP_INTERVAL))
}

/// Memory-pressure loop runs only when freeze is enabled. With freeze
/// disabled there are no Frozen apps to evict and the loop would just
/// burn cycles reading `/proc/meminfo`. Returns `Ok(None)` (a
/// suppressed task) when disabled so the main waitlist still type-checks.
///
/// `BUGPOT_FREEZE_ENABLED` (default `true`) is the kill switch:
/// flipping it off restores pre-freeze scale-to-zero behavior
/// (idle apps stop, no RAM-resident pool).
fn spawn_memory_pressure<R: RuntimeOps, E: EgressOps>(
    controller: &Arc<AppController<R, E>>,
) -> Result<Option<JoinHandle<()>>> {
    if !parse_env_bool("BUGPOT_FREEZE_ENABLED", true)? {
        info!("BUGPOT_FREEZE_ENABLED=false; memory-pressure handler disabled");
        return Ok(None);
    }
    let lo = parse_env_bytes("BUGPOT_FREEZE_MEM_LO", MEM_PRESSURE_LO_DEFAULT)?;
    let hi = parse_env_bytes("BUGPOT_FREEZE_MEM_HI", MEM_PRESSURE_HI_DEFAULT)?;
    if hi <= lo {
        anyhow::bail!(
            "BUGPOT_FREEZE_MEM_HI ({hi}) must be greater than BUGPOT_FREEZE_MEM_LO ({lo})",
        );
    }
    info!(
        lo_bytes = lo,
        hi_bytes = hi,
        "memory-pressure handler enabled"
    );
    let c = Arc::clone(controller);
    Ok(Some(tokio::spawn(c.memory_pressure_loop(
        MEM_PRESSURE_POLL,
        lo,
        hi,
    ))))
}

fn parse_env_bool(key: &str, default: bool) -> Result<bool> {
    match std::env::var(key) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" | "" => Ok(false),
            other => anyhow::bail!("{key}: expected boolean, got '{other}'"),
        },
        Err(_) => Ok(default),
    }
}

fn parse_env_bytes(key: &str, default: u64) -> Result<u64> {
    std::env::var(key).map_or(Ok(default), |raw| {
        raw.trim()
            .parse::<u64>()
            .with_context(|| format!("parse {key}"))
    })
}

fn spawn_router<R: RuntimeOps, E: EgressOps>(
    listen: SocketAddr,
    controller: &Arc<AppController<R, E>>,
) -> Result<JoinHandle<()>> {
    let resolver: Arc<dyn UpstreamResolver> = controller.clone();
    let router_cfg = parse_router_config()?;
    Ok(tokio::spawn(async move {
        if let Err(e) = bugpot_router::serve(listen, resolver, router_cfg).await {
            error!(error = %e, "router exited with error");
        }
    }))
}

/// Build a `bugpot_router::RouterConfig` from optional env vars.
///
/// `BUGPOT_TRUSTED_PROXIES` is a comma-separated CIDR list. Peers
/// outside this set have their incoming `X-Forwarded-For` discarded
/// so an attacker cannot spoof an upstream chain. Empty / unset →
/// behave as the historical proxy (always append).
///
/// `BUGPOT_FORWARDED_PROTO` overrides the value bugpot writes into
/// `X-Forwarded-Proto`. Set to `https` when bugpot sits behind a
/// TLS-terminating front; default is `http`.
fn parse_router_config() -> Result<bugpot_router::RouterConfig> {
    let mut cfg = bugpot_router::RouterConfig::defaults();
    if let Ok(raw) = std::env::var("BUGPOT_TRUSTED_PROXIES") {
        for token in raw.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            let net: ipnet::IpNet = trimmed
                .parse()
                .with_context(|| format!("parse BUGPOT_TRUSTED_PROXIES entry '{trimmed}'"))?;
            cfg.trusted_proxies.push(net);
        }
    }
    if let Ok(raw) = std::env::var("BUGPOT_FORWARDED_PROTO") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            trimmed.clone_into(&mut cfg.forwarded_proto);
        }
    }
    Ok(cfg)
}

fn spawn_admin<R: RuntimeOps, E: EgressOps>(
    admin_listen: SocketAddr,
    controller: &Arc<AppController<R, E>>,
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

/// Read the admin token from env or file. A token is required —
/// the admin API has no "trust the listener" path (that turned out
/// to be too easy to defeat by an accidental `0.0.0.0` bind).
///
/// Precedence: `BUGPOT_ADMIN_TOKEN_FILE` first, then `BUGPOT_ADMIN_TOKEN`
/// as a fallback. The file path is preferred — its strict mode
/// requirement (`chmod 600`) keeps the secret out of `/proc/PID/environ`,
/// `ps auxe`, and shell history. The env-var path remains for dev
/// convenience but logs a warning.
fn read_admin_token() -> Result<String> {
    if let Ok(path) = std::env::var("BUGPOT_ADMIN_TOKEN_FILE") {
        return read_admin_token_from_file(&path);
    }
    if let Ok(raw) = std::env::var("BUGPOT_ADMIN_TOKEN") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            warn!(
                "admin token loaded from BUGPOT_ADMIN_TOKEN; the env-var \
                 path is visible in /proc/<pid>/environ. Prefer \
                 BUGPOT_ADMIN_TOKEN_FILE for production deployments.",
            );
            return Ok(trimmed.to_owned());
        }
    }
    anyhow::bail!(
        "admin token is required: set BUGPOT_ADMIN_TOKEN_FILE (preferred) or BUGPOT_ADMIN_TOKEN"
    );
}

/// Read the admin token from `path` after asserting it (and all of
/// its ancestor directories) is accessible only by the bugpot owner.
/// Delegates the permissions check to `bugpot_config::require_owner_only`
/// so both the admin token and `auth.toml` share one enforcement path.
fn read_admin_token_from_file(path: &str) -> Result<String> {
    bugpot_config::require_owner_only(std::path::Path::new(path))?;
    let body =
        std::fs::read_to_string(path).with_context(|| format!("read admin token from {path}"))?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        anyhow::bail!("admin token file {path} is empty");
    }
    Ok(trimmed.to_owned())
}

/// Read the HMAC secret used to derive per-app deploy tokens. Same
/// shape as the admin token: a file path (preferred) or an env var
/// fallback that logs a warning. The secret is purely a server-side
/// derivation key — leaking it lets an attacker mint a deploy token
/// for any app, so the same `chmod 600` + ancestor-permission rules
/// apply.
fn read_deploy_secret() -> Result<bugpot_admin::DeployKeySecret> {
    if let Ok(path) = std::env::var("BUGPOT_DEPLOY_SECRET_FILE") {
        return read_deploy_secret_from_file(&path);
    }
    if let Ok(raw) = std::env::var("BUGPOT_DEPLOY_SECRET") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            warn!(
                "deploy-key secret loaded from BUGPOT_DEPLOY_SECRET; the \
                 env-var path is visible in /proc/<pid>/environ. Prefer \
                 BUGPOT_DEPLOY_SECRET_FILE for production deployments.",
            );
            return Ok(bugpot_admin::DeployKeySecret::from_bytes(
                trimmed.as_bytes().to_vec(),
            ));
        }
    }
    anyhow::bail!(
        "deploy-key secret is required: set BUGPOT_DEPLOY_SECRET_FILE (preferred) or BUGPOT_DEPLOY_SECRET"
    );
}

fn read_deploy_secret_from_file(path: &str) -> Result<bugpot_admin::DeployKeySecret> {
    bugpot_config::require_owner_only(std::path::Path::new(path))?;
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read deploy-key secret from {path}"))?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        anyhow::bail!("deploy-key secret file {path} is empty");
    }
    Ok(bugpot_admin::DeployKeySecret::from_bytes(
        trimmed.as_bytes().to_vec(),
    ))
}

/// Returns `true` iff the current process has `CAP_NET_ADMIN` in its
/// effective set. Reads `/proc/self/status` so it covers both the
/// "running as root" path and the "non-root with ambient cap" path
/// (`AmbientCapabilities` in a systemd unit).
fn has_cap_net_admin() -> bool {
    // include/uapi/linux/capability.h: CAP_NET_ADMIN = 12
    const CAP_NET_ADMIN_BIT: u64 = 1 << 12;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let Some(hex) = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:").map(str::trim))
    else {
        return false;
    };
    u64::from_str_radix(hex, 16).is_ok_and(|bits| bits & CAP_NET_ADMIN_BIT != 0)
}

fn init_tracing() {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "bugpot=info,bugpot_admin=info,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info,bugpot_controller=info",
        )
    });
    let fmt_layer = tracing_subscriber::fmt::layer().with_filter(filter);

    // When the `tokio-console` cargo feature is on, also wire up
    // console-subscriber's `Console` layer so `tokio-console
    // http://127.0.0.1:6669` can attach. The console layer
    // deliberately has no `EnvFilter` — it watches
    // `tokio::task` / `runtime::resource` targets directly and
    // filtering them out would break the UI.
    #[cfg(feature = "tokio-console")]
    let console_layer = console_subscriber::spawn();

    let registry = tracing_subscriber::registry().with(fmt_layer);
    #[cfg(feature = "tokio-console")]
    let registry = registry.with(console_layer);
    registry.init();
}
