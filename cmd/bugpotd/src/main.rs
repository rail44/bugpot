//! `bugpot` entrypoint.
//!
//! Loads `apps/*.toml`, brings up the egress stack (bridge / DNS / nftables),
//! initialises the runtime, and starts the router. Apps are deployed
//! lazily by the [`bugpot_core::AppHost`] on first request,
//! except those that explicitly opt out of scale-to-zero
//! (`scaling.idle_timeout = "0"`), which are started eagerly on bring-up.
//!
//! On SIGINT, every running app is stopped and its endpoint released. The
//! bridge / nftables ruleset persist across runs; `Egress::new` re-applies
//! them atomically.
//!
//! Note: `pub(crate)` is used for cross-module items inside this binary;
//! the `clippy::redundant_pub_crate` warning conflicts with the workspace's
//! `unreachable_pub` rule, so the former is allowed crate-wide.

#![allow(clippy::redundant_pub_crate)]

mod bootstrap;
mod config;
mod secrets;

use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;

use crate::bootstrap::{Bootstrap, has_cap_net_admin};
use crate::config::Config;

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

    let cfg = Config::from_env()?;
    let bootstrap = Bootstrap::build(cfg, metrics_handle).await?;
    bootstrap.run().await;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "bugpot=info,bugpot_admin=info,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info,bugpot_core=info",
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
