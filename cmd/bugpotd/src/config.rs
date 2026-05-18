//! Environment-variable configuration for `bugpotd`.
//!
//! Every operator-visible knob the daemon reads at startup is
//! resolved here so the rest of the binary deals in plain values
//! and concrete types instead of `std::env` lookups. The split
//! also keeps `main` short and makes "which env var is this?"
//! answerable by grepping one file.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use bugpot_egress::EgressConfig;

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:8081";
const DEFAULT_AUTH_FILE: &str = "/etc/bugpot/auth.toml";

/// Resolved startup configuration. Constructed once at process
/// start; never re-read while the daemon runs (the systemd unit
/// is the live-reload mechanism — `systemctl restart bugpotd`).
#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) listen: SocketAddr,
    pub(crate) admin_listen: SocketAddr,
    pub(crate) auth_file: PathBuf,
    pub(crate) egress: EgressConfig,
}

impl Config {
    pub(crate) fn from_env() -> Result<Self> {
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

        Ok(Self {
            listen,
            admin_listen,
            auth_file,
            egress,
        })
    }
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
pub(crate) fn parse_router_config() -> Result<bugpot_router::RouterConfig> {
    let mut cfg = bugpot_router::RouterConfig::default();
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

pub(crate) fn parse_env_bool(key: &str, default: bool) -> Result<bool> {
    match std::env::var(key) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" | "" => Ok(false),
            other => anyhow::bail!("{key}: expected boolean, got '{other}'"),
        },
        Err(_) => Ok(default),
    }
}

pub(crate) fn parse_env_bytes(key: &str, default: u64) -> Result<u64> {
    std::env::var(key).map_or(Ok(default), |raw| {
        raw.trim()
            .parse::<u64>()
            .with_context(|| format!("parse {key}"))
    })
}
