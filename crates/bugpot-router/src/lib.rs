use anyhow::Result;
use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode, Uri,
        header::{CONNECTION, HOST, UPGRADE},
        uri::PathAndQuery,
    },
    response::Response,
    routing::any,
};
use bugpot_config::AppSpec;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use metrics::counter;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tracing::{debug, info, warn};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_mins(1);

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");

type ProxyClient = Client<HttpConnector, Body>;

/// One registered app paired with the concrete upstream to forward to.
///
/// Production deployments point this at the app's container IP (allocated by
/// `bugpot-egress`). Tests and host-network setups can use
/// [`Deployment::localhost`] to keep things on `127.0.0.1`.
#[derive(Debug, Clone)]
pub struct Deployment {
    pub spec: AppSpec,
    pub upstream: SocketAddr,
}

impl Deployment {
    #[must_use]
    pub const fn new(spec: AppSpec, upstream: SocketAddr) -> Self {
        Self { spec, upstream }
    }

    /// Convenience for tests and host-network deployments: point the upstream
    /// at `127.0.0.1:<spec.port>`.
    #[must_use]
    pub fn localhost(spec: AppSpec) -> Self {
        let port = spec.port;
        Self {
            spec,
            upstream: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }
}

/// Pluggable upstream resolver.
///
/// The router calls this on every request to find out where to forward.
/// Implementations may take meaningful time (e.g. waiting for a cold-start
/// container to come up) but should respect cancellation if the caller
/// drops the future.
#[async_trait]
pub trait UpstreamResolver: Send + Sync + std::fmt::Debug {
    async fn resolve(&self, host: &str) -> Option<SocketAddr>;
}

/// Convenience extractor used by both [`AppRouter`] and any custom
/// resolver implementation.
#[must_use]
pub fn subdomain_of(host: &str) -> Option<&str> {
    host.split(':').next()?.split('.').next()
}

#[derive(Debug)]
pub struct AppRouter {
    deployments: Vec<Deployment>,
}

impl AppRouter {
    #[must_use]
    pub const fn new(deployments: Vec<Deployment>) -> Self {
        Self { deployments }
    }

    /// Resolve a host header (e.g. `myapp.bugpot.ts.net` or `myapp.bugpot.ts.net:443`)
    /// to a registered deployment by matching the first DNS label against the
    /// app's subdomain.
    #[must_use]
    pub fn resolve(&self, host: &str) -> Option<&Deployment> {
        let subdomain = subdomain_of(host)?;
        self.deployments
            .iter()
            .find(|d| d.spec.subdomain() == subdomain)
    }
}

#[async_trait]
impl UpstreamResolver for AppRouter {
    async fn resolve(&self, host: &str) -> Option<SocketAddr> {
        self.resolve(host).map(|d| d.upstream)
    }
}

/// Shared state passed to every handler invocation.
#[derive(Clone)]
struct ProxyState {
    resolver: Arc<dyn UpstreamResolver>,
    client: ProxyClient,
}

impl std::fmt::Debug for ProxyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyState")
            .field("resolver", &self.resolver)
            .finish_non_exhaustive()
    }
}

fn build_client() -> ProxyClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(CONNECT_TIMEOUT));
    connector.set_nodelay(true);
    // HttpConnector defaults to enforcing http scheme; that's what we want.
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(IDLE_TIMEOUT)
        .build(connector)
}

pub async fn serve(addr: SocketAddr, resolver: Arc<dyn UpstreamResolver>) -> Result<()> {
    let state = ProxyState {
        resolver,
        client: build_client(),
    };
    let app = Router::new().fallback(any(handler)).with_state(state);
    info!(%addr, "bugpot-router listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn handler(State(state): State<ProxyState>, req: Request) -> Response {
    let host = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let app_label = subdomain_of(&host)
        .unwrap_or("unknown")
        .to_owned();

    let response = match state.resolver.resolve(&host).await {
        None => {
            warn!(host = %host, "no app matched");
            error_response(StatusCode::NOT_FOUND, format!("no app matched host '{host}'\n"))
        }
        Some(upstream) => {
            info!(host = %host, %upstream, "matched route");
            forward(state.client, req, upstream, &host).await
        }
    };
    counter!(
        "bugpot_router_requests_total",
        "app" => app_label,
        "status" => response.status().as_u16().to_string(),
    )
    .increment(1);
    response
}

/// Forward a request to the resolved upstream socket.
///
/// Handles HTTP and HTTP/1.1 Upgrade (e.g. WebSocket) transparently.
async fn forward(
    client: ProxyClient,
    mut req: Request,
    upstream: SocketAddr,
    original_host: &str,
) -> Response {
    let is_upgrade = is_upgrade_request(req.headers());

    // Connection info (peer address) is injected by axum's
    // `into_make_service_with_connect_info`; it may be absent in tests that
    // don't use that wrapper, in which case X-Forwarded-For falls back to the
    // existing chain only.
    let peer_addr = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string());

    // Rewrite URI to point at the upstream.
    let new_uri = match rewrite_uri(req.uri(), upstream) {
        Ok(u) => u,
        Err(e) => {
            warn!(error = %e, "failed to rewrite request URI");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "upstream URI rewrite failed\n".to_owned(),
            );
        }
    };
    *req.uri_mut() = new_uri;

    inject_forwarded_headers(req.headers_mut(), peer_addr.as_deref(), original_host);

    if is_upgrade {
        return forward_upgrade(client, req).await;
    }

    let pending = client.request(req);
    let result = tokio::time::timeout(REQUEST_TIMEOUT, pending).await;
    match result {
        Ok(Ok(res)) => res.map(Body::new),
        Ok(Err(e)) => {
            warn!(error = %e, "upstream request failed");
            error_response(StatusCode::BAD_GATEWAY, "upstream connection failed\n".to_owned())
        }
        Err(_) => {
            warn!(timeout_secs = REQUEST_TIMEOUT.as_secs(), "upstream request timed out");
            error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream request timed out\n".to_owned(),
            )
        }
    }
}

/// Forward an HTTP/1.1 upgrade request (e.g. WebSocket) by splicing the two
/// upgraded byte streams together.
async fn forward_upgrade(client: ProxyClient, mut req: Request) -> Response {
    // Capture the inbound upgrade future *before* sending the response. Hyper
    // will resolve it once the response (with 101) is flushed.
    let client_upgrade = hyper::upgrade::on(&mut req);

    let pending = client.request(req);
    let mut upstream_res = match tokio::time::timeout(REQUEST_TIMEOUT, pending).await {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => {
            warn!(error = %e, "upstream upgrade request failed");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "upstream connection failed\n".to_owned(),
            );
        }
        Err(_) => {
            warn!("upstream upgrade request timed out");
            return error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream request timed out\n".to_owned(),
            );
        }
    };

    if upstream_res.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Upstream refused to upgrade — just forward whatever response it sent
        // (including its body). The client never sees an upgrade.
        return upstream_res.map(Body::new);
    }

    // Capture the outbound upgrade future and detach a task that splices the
    // two halves once both are available.
    let server_upgrade = hyper::upgrade::on(&mut upstream_res);
    tokio::spawn(async move {
        match tokio::try_join!(client_upgrade, server_upgrade) {
            Ok((client_io, server_io)) => {
                let mut client_io = TokioIo::new(client_io);
                let mut server_io = TokioIo::new(server_io);
                if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut server_io).await
                {
                    debug!(error = %e, "upgraded stream closed with error");
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to complete upgrade handshake");
            }
        }
    });

    upstream_res.map(Body::new)
}

/// Build a new URI pointing at the given upstream socket address, preserving
/// the request's path and query.
fn rewrite_uri(orig: &Uri, upstream: SocketAddr) -> Result<Uri, axum::http::Error> {
    let path_and_query = orig
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    Uri::builder()
        .scheme("http")
        .authority(upstream.to_string())
        .path_and_query(path_and_query)
        .build()
}

fn is_upgrade_request(headers: &HeaderMap) -> bool {
    if !headers.contains_key(UPGRADE) {
        return false;
    }
    headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
}

fn inject_forwarded_headers(
    headers: &mut HeaderMap,
    peer_ip: Option<&str>,
    original_host: &str,
) {
    if let Some(ip) = peer_ip {
        append_forwarded_for(headers, ip);
    }
    // bugpot terminates plain HTTP (TLS is handled upstream of the router, by
    // tailscale/the load balancer); from the upstream app's perspective the
    // proto is whatever the client originally requested. We don't have that
    // information here, so we always advertise http. When TLS termination
    // lands inside bugpot-router this should be revised.
    if !headers.contains_key(&X_FORWARDED_PROTO) {
        headers.insert(
            X_FORWARDED_PROTO,
            HeaderValue::from_static("http"),
        );
    }
    if !headers.contains_key(&X_FORWARDED_HOST)
        && let Ok(v) = HeaderValue::from_str(original_host)
    {
        headers.insert(X_FORWARDED_HOST, v);
    }
}

fn append_forwarded_for(headers: &mut HeaderMap, peer_ip: &str) {
    let new_value = headers
        .get(&X_FORWARDED_FOR)
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| peer_ip.to_owned(), |s| format!("{s}, {peer_ip}"));
    if let Ok(v) = HeaderValue::from_str(&new_value) {
        headers.insert(X_FORWARDED_FOR, v);
    }
}

fn error_response(status: StatusCode, body: String) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(body))
        .expect("static response build never fails")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fake_app(name: &str) -> AppSpec {
        AppSpec {
            image: format!("ghcr.io/test/{name}:latest"),
            port: 3000,
            name: None,
            subdomain: None,
            egress: bugpot_config::Egress::default(),
            env: std::collections::HashMap::default(),
            scaling: bugpot_config::Scaling::default(),
            readiness: bugpot_config::Readiness::default(),
            resources: bugpot_config::Resources::default(),
            runtime: bugpot_config::Runtime::default(),
            source_path: PathBuf::from(format!("/apps/{name}.toml")),
        }
    }

    #[test]
    fn resolves_by_subdomain() {
        let router = AppRouter::new(vec![
            Deployment::localhost(fake_app("alpha")),
            Deployment::localhost(fake_app("beta")),
        ]);
        assert_eq!(
            router
                .resolve("alpha.bugpot.ts.net")
                .map(|d| d.spec.name()),
            Some("alpha")
        );
        assert_eq!(
            router
                .resolve("beta.bugpot.ts.net:443")
                .map(|d| d.spec.name()),
            Some("beta")
        );
        assert!(router.resolve("gamma.bugpot.ts.net").is_none());
        assert!(router.resolve("").is_none());
    }

    #[test]
    fn detects_upgrade_request() {
        let mut h = HeaderMap::new();
        h.insert(UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        assert!(is_upgrade_request(&h));

        let mut h2 = HeaderMap::new();
        h2.insert(UPGRADE, HeaderValue::from_static("websocket"));
        h2.insert(CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
        assert!(is_upgrade_request(&h2));

        let mut h3 = HeaderMap::new();
        h3.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        assert!(!is_upgrade_request(&h3));
    }

    #[test]
    fn appends_forwarded_for() {
        let mut h = HeaderMap::new();
        append_forwarded_for(&mut h, "10.0.0.1");
        assert_eq!(
            h.get(&X_FORWARDED_FOR).and_then(|v| v.to_str().ok()),
            Some("10.0.0.1")
        );
        append_forwarded_for(&mut h, "10.0.0.2");
        assert_eq!(
            h.get(&X_FORWARDED_FOR).and_then(|v| v.to_str().ok()),
            Some("10.0.0.1, 10.0.0.2")
        );
    }

    #[test]
    fn rewrites_uri_keeping_path_and_query() {
        let uri: Uri = "/foo/bar?x=1".parse().unwrap();
        let upstream = SocketAddr::from(([172, 20, 0, 5], 8123));
        let rewritten = rewrite_uri(&uri, upstream).unwrap();
        assert_eq!(rewritten.scheme_str(), Some("http"));
        assert_eq!(rewritten.host(), Some("172.20.0.5"));
        assert_eq!(rewritten.port_u16(), Some(8123));
        assert_eq!(rewritten.path(), "/foo/bar");
        assert_eq!(rewritten.query(), Some("x=1"));
    }
}
