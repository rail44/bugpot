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

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

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
use netns::EndpointLayout;
use nft::NftConfig;

// ---- Host-fixed parameters (one bugpot per host, scenario "small VM"). ----
//
// Originally `EgressConfig` made these tunable — none of them actually
// varied between deployments in practice, every test/script hardcoded the
// same values, and most weren't even reachable from env. Folded down to
// constants so the surface area matches reality. Re-introduce a knob
// only when a second concrete deployment actually needs a different value.

/// Linux bridge interface name on the host.
pub const BRIDGE_NAME: &str = "bugpot0";
/// nftables table name. Survives bugpot restarts (re-installed atomically).
pub const NFT_TABLE: &str = "bugpot";
/// DNS server listen port on the bridge IP.
pub const DNS_PORT: u16 = 53;
/// TTL (seconds) for entries in the nft `allow4` set. Determines how long
/// after a DNS resolve a container has to actually reach the resolved IP.
pub const ALLOW_TTL_SECS: u32 = 60;

static SUBNET_NET: LazyLock<Ipv4Net> =
    LazyLock::new(|| "172.20.0.0/24".parse().expect("const subnet parses"));
static BRIDGE_IP_ADDR: LazyLock<Ipv4Addr> =
    LazyLock::new(|| "172.20.0.1".parse().expect("const bridge ip parses"));

/// Bridge subnet (CIDR). Backed by [`LazyLock`] because `Ipv4Net::new`
/// isn't `const`.
#[must_use]
pub fn subnet() -> Ipv4Net {
    *SUBNET_NET
}

/// Bridge IP (host side of the bridge — the DNS server binds here).
#[must_use]
pub fn bridge_ip() -> Ipv4Addr {
    *BRIDGE_IP_ADDR
}

/// Per-deployment knobs the operator may want to override via env.
///
/// Currently the only such knob is the DNS upstream list — corporate
/// networks routinely run their own resolver, but the bridge address /
/// nft table / port aren't worth exposing.
#[derive(Debug, Clone)]
pub struct EgressConfig {
    pub dns_upstream: Vec<SocketAddr>,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            dns_upstream: vec![
                "1.1.1.1:53".parse().expect("const sockaddr parses"),
                "8.8.8.8:53".parse().expect("const sockaddr parses"),
            ],
        }
    }
}

impl EgressConfig {
    /// Reject obviously-broken configs. Currently only checks that the
    /// upstream resolver list is non-empty; the host-fixed parameters
    /// (`subnet`, `bridge_ip`, etc.) are validated at the type level
    /// because they're consts.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.dns_upstream.is_empty(), "dns_upstream is empty");
        Ok(())
    }
}

/// Parse a comma-separated list of `SocketAddr`s (e.g.
/// `"1.1.1.1:53,8.8.8.8:53"`). Whitespace and empty entries are
/// tolerated; invalid entries propagate as errors.
pub fn parse_dns_upstream(s: &str) -> anyhow::Result<Vec<SocketAddr>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            p.parse::<SocketAddr>()
                .with_context(|| format!("parse dns upstream entry {p:?}"))
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub container_ip: Ipv4Addr,
    pub netns_path: PathBuf,
}

/// Trait surface used by callers (the controller) to allocate and release
/// per-app network endpoints.
///
/// Static dispatch only — no `dyn`. Native AFIT to avoid the
/// `Pin<Box<dyn Future>>` allocation `#[async_trait]` would introduce;
/// explicit `+ Send` because callers `tokio::spawn` over these futures.
pub trait EgressOps: Send + Sync + std::fmt::Debug + 'static {
    fn allocate_endpoint(
        &self,
        name: &str,
        allowlist: Vec<String>,
    ) -> impl Future<Output = anyhow::Result<Endpoint>> + Send;
    fn release_endpoint(&self, name: &str) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// Re-register an endpoint that was already provisioned by a previous
    /// bugpot run. Returns `Ok(None)` when no live netns matches `name`
    /// (no IP was discovered for it at startup), `Ok(Some(_))` when the
    /// app has been re-bound to its existing IP + allowlist without
    /// touching netns/veth/nft. Does not allocate or release host
    /// resources.
    fn reattach_endpoint(
        &self,
        name: &str,
        allowlist: Vec<String>,
    ) -> impl Future<Output = anyhow::Result<Option<Endpoint>>> + Send;
    /// Drain the set of endpoints that were discovered at startup but
    /// never claimed by `reattach_endpoint` (i.e. their `AppSpec` is no
    /// longer present). The returned entries must be passed to
    /// `cleanup_orphan_endpoint` to release the kernel resources.
    fn drain_unreclaimed_endpoints(&self) -> Vec<(String, Ipv4Addr)>;
    /// Tear down an orphan endpoint discovered at startup: delete the
    /// netns + host-side veth, flush its nft allow-set entries, and
    /// release its IP back to the allocator. Idempotent.
    fn cleanup_orphan_endpoint(
        &self,
        name: &str,
        container_ip: Ipv4Addr,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// In-memory record so we can free addresses on release and apply allowlist
/// updates without re-allocating.
#[derive(Debug)]
struct AllocatedApp {
    container_ip: Ipv4Addr,
    plan: EndpointLayout,
}

/// Internal state that the DNS handler shares with the public surface.
pub struct Egress {
    allocator: Mutex<IpAllocator>,
    apps: Mutex<std::collections::HashMap<String, AllocatedApp>>,
    /// IPs recovered from live `bugpot-*` netns at startup. Drained by
    /// `reattach_endpoint` as each app gets reclaimed by the controller;
    /// anything left over after reattach is an orphan netns (see #35).
    discovered_endpoints: Mutex<std::collections::HashMap<String, Ipv4Addr>>,
    registry: Arc<AppRegistry>,
    // Holding the server keeps the DNS task alive for the lifetime of Egress.
    _dns_server: Option<DnsServer<EgressDnsHandler<HickoryUpstream, NftAllowSet>>>,
}

impl std::fmt::Debug for Egress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Egress")
            .field("bridge", &BRIDGE_NAME)
            .field("subnet", &subnet())
            .field("nft_table", &NFT_TABLE)
            .finish_non_exhaustive()
    }
}

impl Egress {
    /// Bring up the bridge, install the nftables ruleset, and start the DNS
    /// server. Requires root.
    pub async fn new(config: EgressConfig) -> anyhow::Result<Self> {
        let subnet = subnet();
        let bridge_ip = bridge_ip();

        // 1. bridge + sysctl
        let bridge_cmds = netns::render_setup_bridge(BRIDGE_NAME, bridge_ip, subnet);
        // Best-effort: ignore "already exists" by re-running individually.
        for cmd in bridge_cmds {
            let _ = netns::run_cmds(vec![cmd]).await;
        }

        // 2. nftables ruleset
        let nft_cfg = NftConfig {
            table: NFT_TABLE.to_owned(),
            bridge: BRIDGE_NAME.to_owned(),
            subnet,
            bridge_ip,
            dns_port: DNS_PORT,
            allow_ttl_secs: ALLOW_TTL_SECS,
        };
        nft::run_script(&nft::render_bootstrap(&nft_cfg))
            .await
            .context("install nft ruleset")?;

        // 3. DNS handler + server
        let registry = Arc::new(AppRegistry::new());
        let upstream = Arc::new(HickoryUpstream::new(&config.dns_upstream)?);
        let allow_set = Arc::new(NftAllowSet {
            table: NFT_TABLE.to_owned(),
        });
        let handler = EgressDnsHandler::new(registry.clone(), upstream, allow_set, ALLOW_TTL_SECS);
        let mut server = DnsServer::new(handler);
        let bind_addr = SocketAddr::from((bridge_ip, DNS_PORT));
        let udp = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("bind DNS UDP {bind_addr}"))?;
        server.register_socket(udp);
        let tcp = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("bind DNS TCP {bind_addr}"))?;
        server.register_listener(tcp, std::time::Duration::from_secs(5), 4096);

        let mut allocator = IpAllocator::new(subnet, bridge_ip)?;
        // Sanity allocate-and-release to prove the subnet works.
        let probe = allocator.allocate()?;
        allocator.release(probe);

        // Discover endpoints left behind by a previous bugpot run so
        // their IPs don't get re-allocated under another app. The
        // controller drains this map via `reattach_endpoint` for apps
        // that are still actually running; the rest remain orphans
        // (#35).
        let discovered = discover_endpoints().await;
        for (name, ip) in &discovered {
            tracing::info!(app = %name, %ip, "discovered existing endpoint");
            allocator.mark_used(*ip);
        }

        Ok(Self {
            allocator: Mutex::new(allocator),
            apps: Mutex::new(std::collections::HashMap::new()),
            discovered_endpoints: Mutex::new(discovered),
            registry,
            _dns_server: Some(server),
        })
    }
}

impl EgressOps for Egress {
    /// Allocate veth + netns + container IP, register the app's allowlist.
    async fn allocate_endpoint(
        &self,
        name: &str,
        allowlist: Vec<String>,
    ) -> anyhow::Result<Endpoint> {
        let parsed = Allowlist::parse(allowlist)?;
        let container_ip = self.allocator.lock().allocate()?;
        let plan = EndpointLayout::new(name, container_ip, subnet());

        // Defensive pre-detach: a prior `release_endpoint` may have
        // bailed mid-way and left a netns + veth named the way we're
        // about to use. The detach is idempotent — no-ops when nothing
        // exists — so this only does anything on the leaked-state path.
        netns::force_detach_endpoint(&plan).await;

        if let Err(e) =
            netns::run_cmds(netns::render_attach_endpoint(BRIDGE_NAME, &plan)).await
        {
            // Roll back: tear down any partial state from a failed
            // attach (e.g. netns add succeeded but veth move failed),
            // then return the IP to the allocator.
            netns::force_detach_endpoint(&plan).await;
            self.allocator.lock().release(container_ip);
            return Err(e).context("attach endpoint");
        }

        self.registry.insert(
            container_ip,
            AppEntry {
                name: name.to_string(),
                allowlist: parsed,
            },
        );
        let ep = Endpoint {
            container_ip,
            netns_path: plan.ns_path.clone(),
        };
        self.apps
            .lock()
            .insert(name.to_string(), AllocatedApp { container_ip, plan });
        Ok(ep)
    }

    async fn reattach_endpoint(
        &self,
        name: &str,
        allowlist: Vec<String>,
    ) -> anyhow::Result<Option<Endpoint>> {
        let Some(container_ip) = self.discovered_endpoints.lock().remove(name) else {
            return Ok(None);
        };
        let parsed = Allowlist::parse(allowlist)?;
        let plan = EndpointLayout::new(name, container_ip, subnet());
        let ep = Endpoint {
            container_ip,
            netns_path: plan.ns_path.clone(),
        };
        self.registry.insert(
            container_ip,
            AppEntry {
                name: name.to_string(),
                allowlist: parsed,
            },
        );
        self.apps
            .lock()
            .insert(name.to_string(), AllocatedApp { container_ip, plan });
        Ok(Some(ep))
    }

    fn drain_unreclaimed_endpoints(&self) -> Vec<(String, Ipv4Addr)> {
        self.discovered_endpoints.lock().drain().collect()
    }

    async fn cleanup_orphan_endpoint(
        &self,
        name: &str,
        container_ip: Ipv4Addr,
    ) -> anyhow::Result<()> {
        // Best-effort: drop any allow-set entries left over from the
        // previous bugpot run for *this* container IP. Entries also
        // TTL out, so a failure here is non-fatal.
        let _ = nft::flush_src(NFT_TABLE,container_ip).await;
        // Use force-detach so a missing veth (e.g. host side already
        // gone) doesn't prevent deleting the netns. The netns name +
        // host veth name derive deterministically from the app name,
        // so this works even though we never called
        // `allocate_endpoint` for this app in this process.
        let plan = netns::EndpointLayout::new(name, container_ip, subnet());
        netns::force_detach_endpoint(&plan).await;
        self.allocator.lock().release(container_ip);
        Ok(())
    }

    async fn release_endpoint(&self, name: &str) -> anyhow::Result<()> {
        let Some(app) = self.apps.lock().remove(name) else {
            return Ok(());
        };
        // In-memory state is authoritative: drop the app from every
        // bookkeeping structure before touching the kernel. A failure
        // in the netns / nft path is logged by the caller and the
        // next `discover_endpoints` at startup will reap any leaked
        // kernel resources, but the allocator must not stay marked
        // in_use just because `ip netns del` returned an error.
        self.registry.remove(app.container_ip);
        self.allocator.lock().release(app.container_ip);
        // Flush this src's entries from the allow set (best-effort; the
        // 60s TTL is a backstop). Only entries matching *this* src IP
        // are removed — previous behaviour flushed the whole set, which
        // briefly broke egress for every other running app.
        let _ = nft::flush_src(NFT_TABLE,app.container_ip).await;
        netns::run_cmds(netns::render_detach_endpoint(&app.plan)).await?;
        Ok(())
    }
}

/// Scan `bugpot-*` netns left over from a prior bugpot instance and
/// recover the IP of each one's `eth0`. Failures (missing `ip`,
/// half-deleted netns, no inet on eth0) are logged and skipped — they
/// must not block startup.
async fn discover_endpoints() -> std::collections::HashMap<String, Ipv4Addr> {
    let mut out = std::collections::HashMap::new();
    let ns_list = match netns::list_app_namespaces().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "list bugpot netns failed; reattach disabled this run");
            return out;
        }
    };
    for name in ns_list {
        match netns::read_eth0_ipv4(&name).await {
            Ok(Some(ip)) => {
                out.insert(name, ip);
            }
            Ok(None) => {
                tracing::warn!(app = %name, "existing netns has no inet address on eth0; skipping");
            }
            Err(e) => {
                tracing::warn!(app = %name, error = %e, "read eth0 ip failed; skipping");
            }
        }
    }
    out
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

impl AllowSet for NftAllowSet {
    async fn register(&self, src: Ipv4Addr, dst: Ipv4Addr) -> anyhow::Result<()> {
        nft::add_allow(&self.table, src, dst).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_constants_are_consistent() {
        // Bridge IP must live inside the bridge subnet; this is the one
        // invariant that used to be checked by `EgressConfig::validate`
        // and is now enforced by the type-level constants.
        assert!(subnet().contains(&bridge_ip()));
        assert_eq!(BRIDGE_NAME, "bugpot0");
        assert_eq!(NFT_TABLE, "bugpot");
        assert_eq!(DNS_PORT, 53);
        assert_eq!(ALLOW_TTL_SECS, 60);
    }

    #[test]
    fn default_config_is_sane() {
        let c = EgressConfig::default();
        assert!(!c.dns_upstream.is_empty());
        c.validate().expect("default config validates");
    }

    #[test]
    fn validate_rejects_empty_dns_upstream() {
        let c = EgressConfig {
            dns_upstream: vec![],
        };
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("dns_upstream"), "got: {err}");
    }

    #[test]
    fn parse_dns_upstream_single() {
        let v = parse_dns_upstream("1.1.1.1:53").unwrap();
        assert_eq!(v, vec!["1.1.1.1:53".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn parse_dns_upstream_multi_with_whitespace() {
        let v = parse_dns_upstream("1.1.1.1:53, 8.8.8.8:53 , 9.9.9.9:53").unwrap();
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn parse_dns_upstream_skips_empty_entries() {
        let v = parse_dns_upstream("1.1.1.1:53,,8.8.8.8:53").unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn parse_dns_upstream_rejects_garbage() {
        assert!(parse_dns_upstream("not-a-sockaddr").is_err());
        // No port: rejected (SocketAddr requires :port)
        assert!(parse_dns_upstream("1.1.1.1").is_err());
    }

}
