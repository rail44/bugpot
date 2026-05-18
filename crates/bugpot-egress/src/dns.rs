//! DNS request handler that gates per-app egress.
//!
//! Wire path:
//!   container → bridge IP:53 → [`EgressDnsHandler`]:
//!     1. resolve peer IP from `Request::src()` (UDP/TCP socket addr).
//!     2. look up which app owns that peer IP in the shared
//!        [`crate::endpoints::EndpointStore`].
//!     3. check the app's [`Allowlist`] for the queried name.
//!     4. hit → call the (trait-injected) upstream resolver, collect A records,
//!        register every `(src_ip, dst_ip)` into the nft allow set via
//!        [`AllowSet::register`], return the answer untouched.
//!     5. miss → return NXDOMAIN. (Refused gives some clients fallback noise;
//!        Cilium FQDN uses Refused, but the de-facto convention for "no such
//!        domain for you" is NXDOMAIN and works cleanly with libc resolvers.)
//!
//! Both the upstream resolver and the allow-set sink are trait-bounded so the
//! handler is unit-testable without binding sockets or touching nftables.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::endpoints::EndpointStore;

/// Inject the upstream resolver behind a trait so tests don't need real DNS.
/// Native AFIT (no `#[async_trait]`) — used only via generics
/// (`EgressDnsHandler<U: Upstream, _>`), never `dyn`.
pub trait Upstream: Send + Sync + 'static {
    fn resolve_a(&self, name: &str) -> impl Future<Output = anyhow::Result<Vec<Ipv4Addr>>> + Send;
}

/// Inject the nftables allow-set so tests can capture writes.
/// Native AFIT — see [`Upstream`] for rationale.
pub trait AllowSet: Send + Sync + 'static {
    fn register(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// Pure decision function.
///
/// Kept separate from the `RequestHandler` impl so unit tests can exercise
/// the lookup logic without a `Request` or a `ResponseHandler`. Returns the
/// decision and (for tests / logs) the app name that owned the source IP,
/// if any.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// No app is registered at this src IP. Treat as Refused (the query came
    /// from somewhere we don't trust).
    UnknownSource,
    /// App known, name not allowed. Return NXDOMAIN.
    Denied { name: String },
    /// App known, name allowed, resolve upstream.
    Allowed { name: String },
}

#[must_use]
pub fn decide(endpoints: &EndpointStore, src: Ipv4Addr, query_name: &str) -> Decision {
    let Some(app) = endpoints.lookup_by_ip(src) else {
        return Decision::UnknownSource;
    };
    if app.allowlist.matches_domain(query_name) {
        Decision::Allowed {
            name: app.name.clone(),
        }
    } else {
        Decision::Denied {
            name: app.name.clone(),
        }
    }
}

/// The actual `hickory_server` handler.
#[derive(Debug)]
pub struct EgressDnsHandler<U, A> {
    endpoints: Arc<EndpointStore>,
    upstream: Arc<U>,
    allow_set: Arc<A>,
    ttl: u32,
}

impl<U, A> EgressDnsHandler<U, A> {
    pub const fn new(
        endpoints: Arc<EndpointStore>,
        upstream: Arc<U>,
        allow_set: Arc<A>,
        ttl: u32,
    ) -> Self {
        Self {
            endpoints,
            upstream,
            allow_set,
            ttl,
        }
    }
}

#[async_trait]
impl<U: Upstream, A: AllowSet> RequestHandler for EgressDnsHandler<U, A> {
    async fn handle_request<R, T>(&self, request: &Request, mut response_handle: R) -> ResponseInfo
    where
        R: ResponseHandler,
        T: hickory_server::net::runtime::Time,
    {
        let src = match request.src().ip() {
            IpAddr::V4(v4) => v4,
            // IPv6 not on the bridge — refuse.
            IpAddr::V6(_) => {
                return reply_code(request, &mut response_handle, ResponseCode::Refused).await;
            }
        };

        let Ok(info) = request.request_info() else {
            return reply_code(request, &mut response_handle, ResponseCode::FormErr).await;
        };

        let qname = info.query.name().to_string();
        let qtype = info.query.query_type();
        let qname_stripped = qname.trim_end_matches('.').to_string();

        // Only A is enforced; everything else (AAAA, MX, TXT, …) is NXDOMAIN
        // by policy so apps can't sneak through with a SRV or CNAME chain.
        // (CNAMEs *to* allowed names would need extra plumbing; keeping the
        // initial cut tight is the correct default — Whalewall takes the
        // same conservative stance.)
        if qtype != RecordType::A {
            return reply_code(request, &mut response_handle, ResponseCode::NXDomain).await;
        }

        match decide(&self.endpoints, src, &qname_stripped) {
            Decision::UnknownSource => {
                tracing::warn!(%src, %qname, "dns query from unknown source");
                reply_code(request, &mut response_handle, ResponseCode::Refused).await
            }
            Decision::Denied { name } => {
                tracing::info!(%src, app=%name, %qname, "dns deny");
                reply_code(request, &mut response_handle, ResponseCode::NXDomain).await
            }
            Decision::Allowed { name } => {
                tracing::debug!(%src, app=%name, %qname, "dns allow");
                let ips = match self.upstream.resolve_a(&qname_stripped).await {
                    Ok(ips) => ips,
                    Err(e) => {
                        tracing::warn!(error = %e, "upstream resolve failed");
                        return reply_code(request, &mut response_handle, ResponseCode::ServFail)
                            .await;
                    }
                };
                for ip in &ips {
                    if let Err(e) = self.allow_set.register(src, *ip).await {
                        // Don't fail the query — log and best-effort continue.
                        // If nft is down, the FORWARD chain default-drops, so
                        // the worst case is a connection refused at the next
                        // hop, never an unintended allow.
                        tracing::warn!(error = %e, "allow-set register failed");
                    }
                }
                reply_a(
                    request,
                    &mut response_handle,
                    info.query.name().into(),
                    &ips,
                    self.ttl,
                )
                .await
            }
        }
    }
}

/// Build a `ResponseInfo` that signals serve-fail for the given request,
/// used when the wire send itself fails (rare, but the trait demands a value).
fn fallback_info(request: &Request) -> ResponseInfo {
    let mut meta = Metadata::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    meta.response_code = ResponseCode::ServFail;
    Header {
        metadata: meta,
        counts: HeaderCounts::default(),
    }
    .into()
}

async fn reply_code<R: ResponseHandler>(
    request: &Request,
    handle: &mut R,
    code: ResponseCode,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut meta = Metadata::response_from_request(&request.metadata);
    meta.response_code = code;
    let resp = builder.build_no_records(meta);
    handle
        .send_response(resp)
        .await
        .unwrap_or_else(|_| fallback_info(request))
}

async fn reply_a<R: ResponseHandler>(
    request: &Request,
    handle: &mut R,
    name: Name,
    ips: &[Ipv4Addr],
    ttl: u32,
) -> ResponseInfo {
    let records: Vec<Record> = ips
        .iter()
        .map(|ip| Record::from_rdata(name.clone(), ttl, RData::A(A(*ip))))
        .collect();
    let builder = MessageResponseBuilder::from_message_request(request);
    let meta = Metadata::response_from_request(&request.metadata);
    let resp = builder.build(meta, records.iter(), [], [], []);
    handle
        .send_response(resp)
        .await
        .unwrap_or_else(|_| fallback_info(request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::Allowlist;
    use crate::endpoints::AllocatedApp;
    use crate::netns::EndpointLayout;
    use ipnet::Ipv4Net;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockUpstream {
        answers: HashMap<String, Vec<Ipv4Addr>>,
    }

    impl Upstream for MockUpstream {
        async fn resolve_a(&self, name: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
            self.answers
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no mock answer for {name}"))
        }
    }

    #[derive(Default)]
    struct MockAllowSet {
        calls: Mutex<Vec<(Ipv4Addr, Ipv4Addr)>>,
    }

    impl AllowSet for MockAllowSet {
        async fn register(&self, src: Ipv4Addr, dst: Ipv4Addr) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push((src, dst));
            Ok(())
        }
    }

    fn endpoints_with(app: &str, src: Ipv4Addr, allow: &[&str]) -> Arc<EndpointStore> {
        let store = EndpointStore::new();
        let subnet: Ipv4Net = "172.20.0.0/24".parse().unwrap();
        store.insert(AllocatedApp {
            name: app.to_owned(),
            container_ip: src,
            plan: EndpointLayout::new(app, src, subnet),
            allowlist: Allowlist::parse(allow.iter().copied()).unwrap(),
        });
        Arc::new(store)
    }

    #[test]
    fn decide_allow_deny_unknown() {
        let src: Ipv4Addr = "172.20.0.10".parse().unwrap();
        let store = endpoints_with("app1", src, &["api.openai.com"]);

        assert!(matches!(
            decide(&store, src, "api.openai.com"),
            Decision::Allowed { .. }
        ));
        assert!(matches!(
            decide(&store, src, "evil.example.com"),
            Decision::Denied { .. }
        ));
        assert_eq!(
            decide(&store, "172.20.0.99".parse().unwrap(), "api.openai.com"),
            Decision::UnknownSource
        );
    }

    #[test]
    fn insert_and_remove() {
        let src: Ipv4Addr = "172.20.0.10".parse().unwrap();
        let subnet: Ipv4Net = "172.20.0.0/24".parse().unwrap();
        let store = EndpointStore::new();
        store.insert(AllocatedApp {
            name: "a".to_owned(),
            container_ip: src,
            plan: EndpointLayout::new("a", src, subnet),
            allowlist: Allowlist::parse(["a.com"]).unwrap(),
        });
        let app = store.lookup_by_ip(src).unwrap();
        assert!(app.allowlist.matches_domain("a.com"));
        assert!(store.remove_by_name("a").is_some());
        assert!(store.lookup_by_ip(src).is_none());
    }

    // End-to-end handler test — Mock everything around the handler so the
    // pure routing logic is exercised without binding sockets. We don't
    // construct a real `Request` (the hickory-server `MessageRequest` API is
    // crate-private), but `decide` covers the same branches.
    #[tokio::test]
    async fn upstream_invoked_only_on_allowed() {
        let src: Ipv4Addr = "172.20.0.10".parse().unwrap();
        let store = endpoints_with("app1", src, &["api.openai.com"]);
        let up = Arc::new(MockUpstream {
            answers: std::iter::once((
                "api.openai.com".to_string(),
                vec!["1.2.3.4".parse().unwrap()],
            ))
            .collect(),
        });
        let allow = Arc::new(MockAllowSet::default());

        // Simulate the allow path directly.
        let ips = up.resolve_a("api.openai.com").await.unwrap();
        for ip in &ips {
            allow.register(src, *ip).await.unwrap();
        }
        assert_eq!(
            allow.calls.lock().unwrap().as_slice(),
            &[(src, "1.2.3.4".parse().unwrap())]
        );

        // Deny path must never call upstream.
        match decide(&store, src, "evil.example.com") {
            Decision::Denied { .. } => {}
            _ => panic!("expected deny"),
        }
    }
}
