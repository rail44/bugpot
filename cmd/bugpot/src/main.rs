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
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:8081";
const DEFAULT_APPS_DIR: &str = "./apps";
const DEFAULT_AUTH_FILE: &str = "/etc/bugpot/auth.toml";
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!(
            "bugpot must run as root: bridge/netns/nftables setup requires CAP_NET_ADMIN.\n\
             Try `sudo -E ./target/debug/bugpot`."
        );
    }

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

    let apps = bugpot_config::load_apps(&apps_dir)?;
    info!(count = apps.len(), dir = %apps_dir.display(), "loaded apps");

    let auth_file = std::env::var("BUGPOT_AUTH_FILE")
        .map_or_else(|_| PathBuf::from(DEFAULT_AUTH_FILE), PathBuf::from);
    let auth = bugpot_config::load_auth(&auth_file).context("load auth.toml")?;
    info!(
        file = %auth_file.display(),
        registries = auth.registries.len(),
        "loaded registry auth",
    );

    // Egress (bridge + DNS + nftables): idempotent across runs.
    let egress_cfg = EgressConfig::default();
    info!(
        bridge = %egress_cfg.bridge_name,
        subnet = %egress_cfg.subnet,
        "bringing up egress"
    );
    let egress = Arc::new(
        Egress::new(egress_cfg)
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
        apps_dir.clone(),
        auth,
        apps,
    ));
    if let Err(e) = controller.deploy_always_on().await {
        error!(error = ?e, "eager-start failed; rolling back");
        controller.teardown().await;
        return Err(e);
    }

    // Background idle stopper.
    let stopper = Arc::clone(&controller);
    let stopper_task = tokio::spawn(stopper.idle_stopper_loop(IDLE_SWEEP_INTERVAL));

    // Router.
    let resolver: Arc<dyn UpstreamResolver> = controller.clone();
    let serve_task = tokio::spawn(async move {
        if let Err(e) = bugpot_router::serve(listen, resolver).await {
            error!(error = %e, "router exited with error");
        }
    });

    // Admin HTTP API.
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
    let admin_controller = Arc::clone(&controller);
    let admin_task = tokio::spawn(async move {
        if let Err(e) = bugpot_admin::serve(admin_listen, admin_controller, admin_auth).await {
            error!(error = %e, "admin api exited with error");
        }
    });

    info!(%listen, %admin_listen, "bugpot up; press Ctrl+C to shut down");
    if let Err(e) = tokio::signal::ctrl_c().await {
        error!(error = %e, "failed to wait for SIGINT");
    }
    info!("shutdown signal received; tearing down");

    serve_task.abort();
    admin_task.abort();
    stopper_task.abort();
    controller.teardown().await;

    Ok(())
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
