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
use bugpot_egress::{Egress, EgressConfig};
use bugpot_router::UpstreamResolver;
use bugpot_runtime::Runtime;
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

    // Controller owns per-app lifecycle.
    let controller = Arc::new(AppController::new(
        runtime,
        egress,
        cfg.apps_dir.clone(),
        auth,
        apps,
    ));
    if let Err(e) = controller.deploy_always_on().await {
        error!(error = ?e, "eager-start failed; rolling back");
        controller.teardown().await;
        return Err(e);
    }

    let sweep_task = spawn_sweep(&controller);
    let serve_task = spawn_router(cfg.listen, &controller);

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
        cfg.dns_upstream = bugpot_egress::parse_dns_upstream(&raw)
            .context("parse BUGPOT_EGRESS_DNS_UPSTREAM")?;
    }

    cfg.validate().context("validate egress config")?;
    Ok(cfg)
}

fn spawn_sweep(controller: &Arc<AppController>) -> JoinHandle<()> {
    let c = Arc::clone(controller);
    tokio::spawn(c.sweep_loop(SWEEP_INTERVAL))
}

fn spawn_router(listen: SocketAddr, controller: &Arc<AppController>) -> JoinHandle<()> {
    let resolver: Arc<dyn UpstreamResolver> = controller.clone();
    tokio::spawn(async move {
        if let Err(e) = bugpot_router::serve(listen, resolver).await {
            error!(error = %e, "router exited with error");
        }
    })
}

fn spawn_admin(
    admin_listen: SocketAddr,
    controller: &Arc<AppController>,
) -> Result<JoinHandle<()>> {
    let admin_auth = Arc::new(AdminAuth::from_token(read_admin_token()?));
    if admin_auth.is_enforced() {
        info!("admin API requires bearer token");
    } else {
        warn!(
            "admin API has no token configured \
             (BUGPOT_ADMIN_TOKEN / BUGPOT_ADMIN_TOKEN_FILE unset); \
             trust is delegated to the listener binding",
        );
    }
    let admin_controller = Arc::clone(controller);
    Ok(tokio::spawn(async move {
        if let Err(e) = bugpot_admin::serve(admin_listen, admin_controller, admin_auth).await {
            error!(error = %e, "admin api exited with error");
        }
    }))
}

/// Read the admin token from env or file.
///
/// Precedence: `BUGPOT_ADMIN_TOKEN` (env, raw value) > `BUGPOT_ADMIN_TOKEN_FILE`
/// (path to a file whose trimmed contents are the token). Returns `Ok(None)`
/// when neither is set, which leaves the admin API unauthenticated.
fn read_admin_token() -> Result<Option<String>> {
    if let Ok(raw) = std::env::var("BUGPOT_ADMIN_TOKEN") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_owned()));
        }
    }
    if let Ok(path) = std::env::var("BUGPOT_ADMIN_TOKEN_FILE") {
        let body =
            std::fs::read_to_string(&path).with_context(|| format!("read admin token from {path}"))?;
        let trimmed = body.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_owned()));
        }
    }
    Ok(None)
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new(
                    "bugpot=info,bugpot_admin=info,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info,bugpot_controller=info",
                )
            }),
        )
        .init();
}
