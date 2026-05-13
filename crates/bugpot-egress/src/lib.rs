//! Per-app network isolation and egress allowlist enforcement.
//!
//! # Layout
//!
//! On host bring-up [`Egress::new`] sets up:
//!   - bridge `bugpot0` (configurable) with `172.20.0.1/24` (configurable),
//!   - nftables table `bugpot` with a default-drop forward chain and a
//!     timeout-bounded `(src, dst)` allow set,
//!   - a hickory DNS server bound on the bridge IP (UDP+TCP) that identifies
//!     callers by peer IP and consults a per-app allowlist.
//!
//! Per-app, [`Egress::allocate_endpoint`] creates a network namespace + veth
//! pair, plugs the host side into the bridge, assigns the next free IP from
//! the subnet, and registers the app in the in-memory `(src_ip → allowlist)`
//! table that the DNS handler reads on every query.
//!
//! When the DNS handler resolves an allowed domain it inserts every answer
//! `(src_ip, resolved_ip)` into the allow set with a configurable TTL — that
//! is the only mechanism by which packets are permitted to leave the bridge.
//! Direct-IP egress, `DoH`, `DoT`, and queries to external resolvers are all
//! blocked by the chain rules emitted in [`nft::render_bootstrap`].
//!
//! # References
//!
//!   - Whalewall (Go): per-container nftables ruleset shape and the
//!     `(src, dst)` allow-set idea.
//!   - dnsmasq `--ipset`: DNS-driven set population, simpler precursor.
//!   - Cilium FQDN policy: source-aware allowlist semantics (bare domain
//!     covers subdomains; explicit `*.` wildcard for strict-sub only).
//!
//! # Status
//!
//! - Pure logic (allowlist, allocator, nft text, netns command list, DNS
//!   handler) is implemented and unit-tested.
//! - The host side ([`Egress::new`], [`Egress::allocate_endpoint`]) shells
//!   out to `nft` and `ip` — these paths require root and are gated behind
//!   `#[ignore]`-able integration tests (not included here).

#![allow(clippy::module_name_repetitions)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_server::server::Server as DnsServer;
use ipnet::Ipv4Net;
use parking_lot::Mutex;
use tokio::net::{TcpListener, UdpSocket};

pub mod allocator;
pub mod allowlist;
pub mod dns;
pub mod netns;
pub mod nft;

use allocator::IpAllocator;
use allowlist::Allowlist;
use dns::{AllowSet, AppEntry, AppRegistry, EgressDnsHandler, Upstream};
use netns::EndpointPlan;
use nft::NftConfig;

#[derive(Debug, Clone)]
pub struct EgressConfig {
    pub bridge_name: String,
    pub subnet: Ipv4Net,
    pub bridge_ip: Ipv4Addr,
    pub dns_upstream: Vec<SocketAddr>,
    pub dns_port: u16,
    pub allow_ttl_secs: u32,
    pub nft_table: String,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            bridge_name: "bugpot0".to_string(),
            subnet: "172.20.0.0/24".parse().expect("const subnet parses"),
            bridge_ip: "172.20.0.1".parse().expect("const ip parses"),
            dns_upstream: vec![
                "1.1.1.1:53".parse().expect("const sockaddr parses"),
                "8.8.8.8:53".parse().expect("const sockaddr parses"),
            ],
            dns_port: 53,
            allow_ttl_secs: 60,
            nft_table: "bugpot".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub container_ip: Ipv4Addr,
    pub netns_path: PathBuf,
}

/// In-memory record so we can free addresses on release and apply allowlist
/// updates without re-allocating.
#[derive(Debug)]
struct AllocatedApp {
    container_ip: Ipv4Addr,
    plan: EndpointPlan,
}

/// Internal state that the DNS handler shares with the public surface.
pub struct Egress {
    config: EgressConfig,
    allocator: Mutex<IpAllocator>,
    apps: Mutex<std::collections::HashMap<String, AllocatedApp>>,
    registry: Arc<AppRegistry>,
    nft_table: String,
    // Holding the server keeps the DNS task alive for the lifetime of Egress.
    _dns_server: Option<DnsServer<EgressDnsHandler<HickoryUpstream, NftAllowSet>>>,
}

impl std::fmt::Debug for Egress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Egress")
            .field("config", &self.config)
            .field("nft_table", &self.nft_table)
            .finish_non_exhaustive()
    }
}

impl Egress {
    /// Bring up the bridge, install the nftables ruleset, and start the DNS
    /// server. Requires root.
    pub async fn new(config: EgressConfig) -> anyhow::Result<Self> {
        // 1. bridge + sysctl
        let bridge_cmds = netns::render_setup_bridge(
            &config.bridge_name,
            config.bridge_ip,
            config.subnet,
        );
        // Best-effort: ignore "already exists" by re-running individually.
        for cmd in bridge_cmds {
            let _ = netns::run_cmds(vec![cmd]).await;
        }

        // 2. nftables ruleset
        let nft_cfg = NftConfig {
            table: config.nft_table.clone(),
            bridge: config.bridge_name.clone(),
            subnet: config.subnet,
            bridge_ip: config.bridge_ip,
            dns_port: config.dns_port,
            allow_ttl_secs: config.allow_ttl_secs,
        };
        nft::run_script(&nft::render_bootstrap(&nft_cfg))
            .await
            .context("install nft ruleset")?;

        // 3. DNS handler + server
        let registry = Arc::new(AppRegistry::new());
        let upstream = Arc::new(HickoryUpstream::new(&config.dns_upstream)?);
        let allow_set = Arc::new(NftAllowSet {
            table: config.nft_table.clone(),
        });
        let handler = EgressDnsHandler::new(
            registry.clone(),
            upstream,
            allow_set,
            config.allow_ttl_secs,
        );
        let mut server = DnsServer::new(handler);
        let bind_addr = SocketAddr::from((config.bridge_ip, config.dns_port));
        let udp = UdpSocket::bind(bind_addr).await.with_context(|| {
            format!("bind DNS UDP {bind_addr}")
        })?;
        server.register_socket(udp);
        let tcp = TcpListener::bind(bind_addr).await.with_context(|| {
            format!("bind DNS TCP {bind_addr}")
        })?;
        server.register_listener(tcp, std::time::Duration::from_secs(5), 4096);

        let mut allocator = IpAllocator::new(config.subnet, config.bridge_ip)?;
        // Sanity allocate-and-release to prove the subnet works.
        let probe = allocator.allocate()?;
        allocator.release(probe);

        Ok(Self {
            nft_table: config.nft_table.clone(),
            config,
            allocator: Mutex::new(allocator),
            apps: Mutex::new(std::collections::HashMap::new()),
            registry,
            _dns_server: Some(server),
        })
    }

    /// Allocate veth + netns + container IP, register the app's allowlist.
    pub async fn allocate_endpoint(
        &self,
        app_id: &str,
        allowlist: Vec<String>,
    ) -> anyhow::Result<Endpoint> {
        let parsed = Allowlist::parse(allowlist)?;
        let container_ip = self.allocator.lock().allocate()?;
        let plan = EndpointPlan::new(app_id, container_ip, self.config.subnet);

        if let Err(e) = netns::run_cmds(netns::render_attach_endpoint(
            &self.config.bridge_name,
            &plan,
        ))
        .await
        {
            // Roll back IP allocation on failure.
            self.allocator.lock().release(container_ip);
            return Err(e).context("attach endpoint");
        }

        self.registry.insert(
            container_ip,
            AppEntry {
                app_id: app_id.to_string(),
                allowlist: parsed,
            },
        );
        let ep = Endpoint {
            container_ip,
            netns_path: plan.ns_path.clone(),
        };
        self.apps.lock().insert(
            app_id.to_string(),
            AllocatedApp { container_ip, plan },
        );
        Ok(ep)
    }

    pub async fn release_endpoint(&self, app_id: &str) -> anyhow::Result<()> {
        let Some(app) = self.apps.lock().remove(app_id) else {
            return Ok(());
        };
        self.registry.remove(app.container_ip);
        // Flush this src's entries from the allow set (best-effort; entries
        // expire via TTL anyway).
        let _ = nft::run_script(&nft::render_flush_src(
            &self.nft_table,
            app.container_ip,
        ))
        .await;
        netns::run_cmds(netns::render_detach_endpoint(&app.plan)).await?;
        self.allocator.lock().release(app.container_ip);
        Ok(())
    }

    #[allow(clippy::unused_async)] // matches the public spec; future versions may push to nft.
    pub async fn update_allowlist(
        &self,
        app_id: &str,
        allowlist: Vec<String>,
    ) -> anyhow::Result<()> {
        let parsed = Allowlist::parse(allowlist)?;
        let ip = self
            .apps
            .lock()
            .get(app_id)
            .map(|a| a.container_ip)
            .ok_or_else(|| anyhow::anyhow!("unknown app {app_id}"))?;
        anyhow::ensure!(
            self.registry.update_allowlist(ip, parsed),
            "registry desync for {app_id}"
        );
        Ok(())
    }
}

/// Thin adapter from `hickory_resolver` to our [`Upstream`] trait.
#[derive(Debug)]
struct HickoryUpstream {
    resolver: TokioResolver,
}

impl HickoryUpstream {
    fn new(upstreams: &[SocketAddr]) -> anyhow::Result<Self> {
        anyhow::ensure!(!upstreams.is_empty(), "at least one upstream required");
        let mut cfg = ResolverConfig::from_parts(None, vec![], vec![]);
        for sa in upstreams {
            cfg.add_name_server(NameServerConfig::udp_and_tcp(sa.ip()));
        }
        let resolver =
            TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default()).build()?;
        Ok(Self { resolver })
    }
}

#[async_trait::async_trait]
impl Upstream for HickoryUpstream {
    async fn resolve_a(&self, name: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
        use hickory_proto::rr::RData;
        let lookup = self.resolver.ipv4_lookup(name).await?;
        let ips = lookup
            .answers()
            .iter()
            .filter_map(|r| match r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect();
        Ok(ips)
    }
}

/// Adapter that pushes allow-set entries to the running `nft` binary.
#[derive(Debug)]
struct NftAllowSet {
    table: String,
}

#[async_trait::async_trait]
impl AllowSet for NftAllowSet {
    async fn register(&self, src: Ipv4Addr, dst: Ipv4Addr) -> anyhow::Result<()> {
        nft::add_allow(&self.table, src, dst).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_sane() {
        let c = EgressConfig::default();
        assert_eq!(c.bridge_name, "bugpot0");
        assert!(c.subnet.contains(&c.bridge_ip));
        assert_eq!(c.allow_ttl_secs, 60);
        assert!(!c.dns_upstream.is_empty());
    }
}
