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
const DEFAULT_APPS_DIR: &str = "./apps";
const DEFAULT_AUTH_FILE: &str = "/etc/bugpot/auth.toml";
/// Cadence for the controller's lifecycle sweep (crash detection +
/// scale-to-zero idle stop).
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

// Metrics: the Prometheus recorder is *always* installed so callsites
// emit successfully; the HTTP listener is only spawned when
// `BUGPOT_METRICS_LISTEN` is set, keeping the surface area opt-in.

#[derive(Debug)]
struct Config {
    apps_dir: PathBuf,
    listen: SocketAddr,
    admin_listen: SocketAddr,
    auth_file: PathBuf,
    egress: EgressConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let metrics_handle = bugpot_metrics::install_recorder().context("install metrics recorder")?;

    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!(
            "bugpot must run as root: bridge/netns/nftables setup requires CAP_NET_ADMIN.\n\
             Try `sudo -E ./target/debug/bugpot`."
        );
    }

    let cfg = parse_config()?;

    let apps = bugpot_config::load_apps(&cfg.apps_dir)?;
    info!(count = apps.len(), dir = %cfg.apps_dir.display(), "loaded apps");

    let auth = bugpot_config::load_auth(&cfg.auth_file).context("load auth.toml")?;
    info!(
        file = %cfg.auth_file.display(),
        registries = auth.registries.len(),
        "loaded registry auth",
    );

    // Egress (bridge + DNS + nftables): idempotent across runs.
    info!(
        bridge = %cfg.egress.bridge_name,
        subnet = %cfg.egress.subnet,
        bridge_ip = %cfg.egress.bridge_ip,
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
    let runtime = Arc::new(Runtime::new(state_dir).context("init runtime")?);

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

    // Controller owns per-app lifecycle.
    let controller = Arc::new(AppController::new(
        runtime,
        egress,
        cfg.apps_dir.clone(),
        auth,
        apps,
    ));
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
    controller.teardown().await;

    Ok(())
}

fn parse_config() -> Result<Config> {
    let apps_dir = std::env::var("BUGPOT_APPS_DIR")
        .map_or_else(|_| PathBuf::from(DEFAULT_APPS_DIR), PathBuf::from);

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
        apps_dir,
        listen,
        admin_listen,
        auth_file,
        egress,
    })
}

/// Build an `EgressConfig`, layering env-var overrides on top of defaults.
///
/// Recognised env vars:
///
/// - `BUGPOT_EGRESS_SUBNET` (e.g. `10.10.0.0/24`)
/// - `BUGPOT_EGRESS_BRIDGE_IP` (e.g. `10.10.0.1`)
/// - `BUGPOT_EGRESS_DNS_UPSTREAM` (comma-separated socket addrs)
///
/// When only the subnet is set, the bridge IP defaults to the first host
/// of that subnet — so a single override changes both consistently.
/// Setting the bridge IP without the subnet, or any inconsistent
/// combination, fails `EgressConfig::validate`.
fn parse_egress_config() -> Result<EgressConfig> {
    let mut cfg = EgressConfig::default();

    let subnet_env = std::env::var("BUGPOT_EGRESS_SUBNET").ok();
    let bridge_ip_env = std::env::var("BUGPOT_EGRESS_BRIDGE_IP").ok();

    if let Some(s) = subnet_env {
        cfg.subnet = s.parse().context("parse BUGPOT_EGRESS_SUBNET")?;
        if bridge_ip_env.is_none() {
            cfg.bridge_ip = bugpot_egress::derive_bridge_ip(cfg.subnet);
        }
    }
    if let Some(ip) = bridge_ip_env {
        cfg.bridge_ip = ip.parse().context("parse BUGPOT_EGRESS_BRIDGE_IP")?;
    }

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
    let admin_controller = Arc::clone(controller);
    Ok(tokio::spawn(async move {
        if let Err(e) = bugpot_admin::serve(admin_listen, admin_controller, admin_auth).await {
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
