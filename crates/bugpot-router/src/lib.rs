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
use http_body_util::Limited;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
    service::TowerToHyperService,
};
use ipnet::IpNet;
use metrics::counter;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant as StdInstant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
};
use tower::Service;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    limit::RequestBodyLimitLayer,
    timeout::{TimeoutBody, TimeoutLayer},
};
use tracing::{debug, info, warn};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Total per-request timeout enforced at the tower layer. Caps any single
/// request including slow body uploads and slow upstream responses.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_mins(1);
/// Slowloris guard: how long the HTTP/1 reader will wait for the full
/// request headers before tearing down the connection.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard upper bound on a single request body. Larger bodies are
/// rejected with 413 by `tower_http::limit::RequestBodyLimitLayer`.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
/// Maximum simultaneous in-flight requests. Excess requests queue at
/// the tower layer; combined with `REQUEST_TIMEOUT` they cannot pile
/// up unboundedly.
const MAX_CONCURRENT_REQUESTS: usize = 1024;
/// Per-frame idle timeout on the response body once we start
/// streaming it back to the client. `REQUEST_TIMEOUT` only covers the
/// time until the response head is received; a slow-read attacker can
/// stall body delivery beyond it.
const RESPONSE_FRAME_TIMEOUT: Duration = Duration::from_mins(1);
/// Hard ceiling on the total response body bytes a single request may
/// stream. Stops a buggy / malicious upstream from monopolising a
/// router connection (and host bandwidth) with multi-GB payloads.
const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024 * 1024;
/// Maximum simultaneous Upgrade (WebSocket) connections. Each upgrade
/// detaches a spliced byte-pump task that the `MAX_CONCURRENT_REQUESTS`
/// limit cannot bound; without an explicit cap an attacker could
/// detach thousands of idle splices and pressure the tokio runtime.
const MAX_CONCURRENT_UPGRADES: usize = 256;
/// Idle (no traffic in either direction) timeout for an upgraded
/// connection. Splices that exceed it are torn down.
const UPGRADE_IDLE_TIMEOUT: Duration = Duration::from_mins(5);
/// HTTP/2 max concurrent streams per connection. The hyper default
/// (200) lets a small handful of h2 clients exhaust the global
/// `MAX_CONCURRENT_REQUESTS` ceiling; pin it tighter so abusive
/// clients don't starve the tower concurrency layer.
const H2_MAX_CONCURRENT_STREAMS: u32 = 64;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");

/// RFC 7230 §6.1 hop-by-hop headers. Stored as lowercase strings so we
/// can store them in a `const` (compound `HeaderName` arrays don't
/// survive `const` because of interior mutability) and parsed at call
/// time via `HeaderMap::remove(&str)`. `Upgrade` is in the list but
/// the WebSocket path runs *before* the strip and keeps it.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

type ProxyClient = Client<HttpConnector, Body>;

/// Per-deployment knobs the router reads from env at startup.
///
/// Kept separate from `serve()` so callers can build it from anywhere
/// (`cmd/bugpot::parse_router_config`, tests, etc.) and so the
/// defaults stay in one place.
#[derive(Debug, Clone, Default)]
pub struct RouterConfig {
    /// IPv4/IPv6 networks whose `X-Forwarded-For` is honoured. Requests
    /// from any other peer have their incoming XFF discarded — the
    /// peer's IP becomes the head of a fresh chain. Empty (default)
    /// means trust the existing chain (current behaviour); set to
    /// loopback / Tailscale tailnet ranges in real deployments.
    pub trusted_proxies: Vec<IpNet>,
    /// Value to set in `X-Forwarded-Proto` when the upstream request
    /// doesn't already carry one. Defaults to `http`. Set to `https`
    /// when bugpot sits behind a TLS-terminating front (Tailscale
    /// Services, an external LB, etc.).
    pub forwarded_proto: String,
}

impl RouterConfig {
    /// Hard-coded sensible defaults: trust nothing, advertise `http`.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            forwarded_proto: "http".to_owned(),
        }
    }
}

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
///
/// `host` is the literal `Host` header value, optionally with a
/// trailing `:port`. Returns the first DNS label of the hostname, or
/// `None` for IPv6 literals (`[::1]:8080`) — bugpot routes by
/// subdomain, so an IPv6 literal can't ever match an app.
#[must_use]
pub fn subdomain_of(host: &str) -> Option<&str> {
    // IPv6 literal in URL form: `[::1]` or `[::1]:8080`. Reject early
    // so the `:port` splitter below doesn't trip on the address
    // separator.
    if host.starts_with('[') {
        return None;
    }
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
    config: Arc<RouterConfig>,
    /// Caps the number of simultaneously-spliced Upgrade connections.
    /// `forward_upgrade` acquires a permit before detaching its splice
    /// task; if no permits are available the upgrade is rejected with
    /// 503. Counts only successfully-spliced upgrades.
    upgrade_slots: Arc<Semaphore>,
}

impl std::fmt::Debug for ProxyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyState")
            .field("resolver", &self.resolver)
            .field("config", &self.config)
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

/// Run the bugpot proxy.
///
/// Drops down to `hyper_util::server::conn::auto::Builder` directly
/// (rather than `axum::serve`) because we need
/// `http1.header_read_timeout` for slowloris protection, and axum 0.8
/// doesn't expose that knob through its `Serve` wrapper.
pub async fn serve(
    addr: SocketAddr,
    resolver: Arc<dyn UpstreamResolver>,
    config: RouterConfig,
) -> Result<()> {
    let state = ProxyState {
        resolver,
        client: build_client(),
        config: Arc::new(config),
        upgrade_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_UPGRADES)),
    };
    let app = Router::new()
        .fallback(any(handler))
        .with_state(state)
        // Tower layers — applied to every request the service sees,
        // including upgrades. The body limit only counts bytes that
        // pass through the proxy before an upgrade, which is exactly
        // what we want (WebSocket frame bytes are not "body").
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS));

    info!(%addr, "bugpot-router listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Per-connection hyper builder, configured once and cloned for each
    // accepted connection. `_with_upgrades` keeps the WebSocket splice
    // path working. `header_read_timeout` requires a timer; the global
    // builder timer needs `TokioTimer`.
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);

    // `into_make_service_with_connect_info` returns a `MakeService` that
    // takes a `SocketAddr` and produces a per-connection service whose
    // request extensions include `ConnectInfo(SocketAddr)`. We call it
    // with the peer addr on each accept.
    let mut make_svc = app.into_make_service_with_connect_info::<SocketAddr>();

    loop {
        let (socket, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "accept failed; continuing");
                continue;
            }
        };
        let svc = match make_svc.call(peer_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "make_service failed; dropping connection");
                continue;
            }
        };
        let svc = TowerToHyperService::new(svc);
        let io = TokioIo::new(socket);
        let builder = builder.clone();
        tokio::spawn(async move {
            if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
                debug!(error = %e, "connection closed with error");
            }
        });
    }
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
            forward(&state, req, upstream, &host).await
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
    state: &ProxyState,
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
        .map(|c| c.0.ip());

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

    inject_forwarded_headers(req.headers_mut(), peer_addr, original_host, &state.config);

    if is_upgrade {
        // The Upgrade path needs `Connection: Upgrade` and the
        // `Upgrade:` token to flow through to the upstream so it
        // returns 101. Skip the hop-by-hop strip here; the splice
        // takes over once both sides agree.
        return forward_upgrade(state, req).await;
    }

    strip_hop_by_hop_headers(req.headers_mut());

    let pending = state.client.request(req);
    let result = tokio::time::timeout(REQUEST_TIMEOUT, pending).await;
    match result {
        Ok(Ok(mut res)) => {
            strip_hop_by_hop_headers(res.headers_mut());
            // Bound the streaming half (per-frame idle + total bytes).
            // `TimeoutLayer` only covers time-to-headers; without this
            // wrap, slow-reading clients and runaway upstream bodies
            // are unconstrained. Composed from two upstream layers:
            // `Limited` enforces the byte ceiling and `TimeoutBody`
            // enforces the per-frame idle timeout — same semantics
            // we had with the home-grown wrapper, just delegated.
            res.map(|body| {
                let limited = Limited::new(body, MAX_RESPONSE_BODY_BYTES);
                let timed = TimeoutBody::new(RESPONSE_FRAME_TIMEOUT, limited);
                Body::new(timed)
            })
        }
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
async fn forward_upgrade(state: &ProxyState, mut req: Request) -> Response {
    // Reserve a slot before promising the client we'll splice. If the
    // global cap is saturated we surface 503 instead of detaching yet
    // another task into the background.
    let Ok(permit) = Arc::clone(&state.upgrade_slots).try_acquire_owned() else {
        warn!(cap = MAX_CONCURRENT_UPGRADES, "upgrade limit reached");
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "upgrade limit reached; retry later\n".to_owned(),
        );
    };

    // Capture the inbound upgrade future *before* sending the response. Hyper
    // will resolve it once the response (with 101) is flushed.
    let client_upgrade = hyper::upgrade::on(&mut req);

    let pending = state.client.request(req);
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
        // Upstream refused to upgrade — forward whatever response it
        // sent (including its body). The client never sees an upgrade,
        // so this is a normal HTTP/1.1 response: strip hop-by-hop
        // headers like the non-upgrade path does, otherwise an
        // upstream `Connection: close` or `Transfer-Encoding: chunked`
        // leaks to the client.
        strip_hop_by_hop_headers(upstream_res.headers_mut());
        return upstream_res.map(Body::new);
    }

    // Capture the outbound upgrade future and detach a task that splices the
    // two halves once both are available.
    let server_upgrade = hyper::upgrade::on(&mut upstream_res);
    tokio::spawn(async move {
        // `permit` is moved into this task; dropping it on exit
        // releases the upgrade slot.
        let _permit = permit;
        match tokio::try_join!(client_upgrade, server_upgrade) {
            Ok((client_io, server_io)) => {
                let client_io = TokioIo::new(client_io);
                let server_io = TokioIo::new(server_io);
                if let Err(e) =
                    splice_with_idle(client_io, server_io, UPGRADE_IDLE_TIMEOUT).await
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

/// Bidirectional copy with shared idle timeout and proper half-close
/// semantics. Equivalent to `tokio::io::copy_bidirectional` but tears
/// the splice down when no bytes have moved in either direction for
/// `idle`. When one direction reaches EOF, that side's write half is
/// shut down explicitly so the peer observes a clean half-close; the
/// other direction is allowed to drain. Both must finish (or the
/// watchdog must fire) before the splice task returns.
async fn splice_with_idle<C, S>(client: C, server: S, idle: Duration) -> std::io::Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut sr, mut sw) = tokio::io::split(server);
    let last = Arc::new(Mutex::new(StdInstant::now()));

    let last_c = Arc::clone(&last);
    let c_to_s = async move {
        // Read from the client until EOF, write to the server, then
        // shut down the server-side write half so the upstream sees a
        // clean close on its read side. Errors propagate up.
        let mut buf = vec![0u8; 8192];
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            *last_c.lock().expect("splice activity lock poisoned") = StdInstant::now();
            sw.write_all(&buf[..n]).await?;
        }
        sw.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    let last_s = Arc::clone(&last);
    let s_to_c = async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = sr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            *last_s.lock().expect("splice activity lock poisoned") = StdInstant::now();
            cw.write_all(&buf[..n]).await?;
        }
        cw.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    let watchdog_last = Arc::clone(&last);
    let watchdog = async move {
        let tick = idle / 2;
        loop {
            tokio::time::sleep(tick).await;
            let elapsed = watchdog_last
                .lock()
                .expect("splice activity lock poisoned")
                .elapsed();
            if elapsed >= idle {
                return;
            }
        }
    };

    // Wait for both directions to complete (proper half-close) or the
    // idle watchdog to fire. `try_join` cancels the still-running
    // direction on error so we don't keep a corrupt half alive.
    tokio::select! {
        r = futures::future::try_join(c_to_s, s_to_c) => r.map(|_| ()),
        () = watchdog => {
            debug!(?idle, "upgraded stream idle, closing");
            Ok(())
        }
    }
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
    peer_ip: Option<IpAddr>,
    original_host: &str,
    config: &RouterConfig,
) {
    if let Some(ip) = peer_ip {
        rewrite_forwarded_for(headers, ip, &config.trusted_proxies);
    }
    if !headers.contains_key(&X_FORWARDED_PROTO)
        && let Ok(v) = HeaderValue::from_str(&config.forwarded_proto)
    {
        headers.insert(X_FORWARDED_PROTO, v);
    }
    if !headers.contains_key(&X_FORWARDED_HOST)
        && let Ok(v) = HeaderValue::from_str(original_host)
    {
        headers.insert(X_FORWARDED_HOST, v);
    }
}

/// Append the peer's IP to `X-Forwarded-For` when the peer is in
/// `trusted_proxies`; otherwise reset XFF to just the peer's IP so an
/// attacker can't spoof an upstream chain.
///
/// `trusted_proxies` empty (default) preserves the historical
/// behaviour of unconditionally appending — operators who haven't
/// configured trust boundaries see no behaviour change.
fn rewrite_forwarded_for(headers: &mut HeaderMap, peer_ip: IpAddr, trusted: &[IpNet]) {
    let peer_str = peer_ip.to_string();
    let trust_peer = trusted.is_empty() || trusted.iter().any(|n| n.contains(&peer_ip));
    let new_value = if trust_peer {
        headers
            .get(&X_FORWARDED_FOR)
            .and_then(|v| v.to_str().ok())
            .map_or_else(|| peer_str.clone(), |s| format!("{s}, {peer_str}"))
    } else {
        peer_str
    };
    if let Ok(v) = HeaderValue::from_str(&new_value) {
        headers.insert(X_FORWARDED_FOR, v);
    }
}

/// RFC 7230 §6.1: drop the static hop-by-hop set plus any header
/// listed in `Connection`. Run before forwarding to the upstream and
/// on the way back to the client.
fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    // Collect Connection-listed extras first; HeaderMap doesn't let us
    // iterate while we mutate.
    let extras: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|name| HeaderName::try_from(name.trim()).ok())
        .collect();
    for h in HOP_BY_HOP_HEADERS {
        headers.remove(*h);
    }
    for h in extras {
        headers.remove(&h);
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
    fn appends_forwarded_for_with_empty_trust_list() {
        // Empty trust list = trust everyone (back-compat).
        let mut h = HeaderMap::new();
        rewrite_forwarded_for(&mut h, "10.0.0.1".parse().unwrap(), &[]);
        assert_eq!(
            h.get(&X_FORWARDED_FOR).and_then(|v| v.to_str().ok()),
            Some("10.0.0.1")
        );
        rewrite_forwarded_for(&mut h, "10.0.0.2".parse().unwrap(), &[]);
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

    #[test]
    fn subdomain_of_rejects_ipv6_literal() {
        // IPv6 literals in Host headers wrap the address in `[...]`.
        // They never match a bugpot subdomain — and the naive
        // `split(':').next()` would have returned `"[" ...` which is
        // not a valid label.
        assert_eq!(subdomain_of("[::1]"), None);
        assert_eq!(subdomain_of("[::1]:8080"), None);
        assert_eq!(subdomain_of("[2001:db8::1]:443"), None);
        // Regression: regular host:port still works.
        assert_eq!(subdomain_of("alpha.bugpot.ts.net:443"), Some("alpha"));
    }

    #[test]
    fn strip_hop_by_hop_removes_static_set() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("close"));
        h.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        h.insert(
            HeaderName::from_static("transfer-encoding"),
            HeaderValue::from_static("chunked"),
        );
        h.insert(
            HeaderName::from_static("x-bugpot-app"),
            HeaderValue::from_static("alpha"),
        );
        strip_hop_by_hop_headers(&mut h);
        assert!(!h.contains_key(CONNECTION));
        assert!(!h.contains_key("keep-alive"));
        assert!(!h.contains_key("transfer-encoding"));
        // Non-hop-by-hop headers must survive.
        assert!(h.contains_key("x-bugpot-app"));
    }

    #[test]
    fn strip_hop_by_hop_removes_connection_extras() {
        // Headers named in `Connection` should also be stripped.
        let mut h = HeaderMap::new();
        h.insert(
            CONNECTION,
            HeaderValue::from_static("close, x-internal-token"),
        );
        h.insert(
            HeaderName::from_static("x-internal-token"),
            HeaderValue::from_static("secret"),
        );
        h.insert(
            HeaderName::from_static("x-bugpot-app"),
            HeaderValue::from_static("alpha"),
        );
        strip_hop_by_hop_headers(&mut h);
        assert!(!h.contains_key("x-internal-token"));
        assert!(h.contains_key("x-bugpot-app"));
    }

    #[test]
    fn xff_appends_when_trusted_or_empty() {
        // Empty trusted list = trust everything (historical behaviour).
        let mut h = HeaderMap::new();
        h.insert(X_FORWARDED_FOR, HeaderValue::from_static("1.2.3.4"));
        rewrite_forwarded_for(&mut h, "5.6.7.8".parse().unwrap(), &[]);
        assert_eq!(h.get(X_FORWARDED_FOR).unwrap(), "1.2.3.4, 5.6.7.8");

        // Trusted peer: append.
        let mut h = HeaderMap::new();
        h.insert(X_FORWARDED_FOR, HeaderValue::from_static("1.2.3.4"));
        let trusted: Vec<IpNet> = vec!["5.6.7.0/24".parse().unwrap()];
        rewrite_forwarded_for(&mut h, "5.6.7.8".parse().unwrap(), &trusted);
        assert_eq!(h.get(X_FORWARDED_FOR).unwrap(), "1.2.3.4, 5.6.7.8");
    }

    #[test]
    fn xff_resets_when_peer_not_trusted() {
        // Untrusted peer: drop the spoofed chain and use peer IP only.
        let mut h = HeaderMap::new();
        h.insert(X_FORWARDED_FOR, HeaderValue::from_static("evil-spoof"));
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        rewrite_forwarded_for(&mut h, "5.6.7.8".parse().unwrap(), &trusted);
        assert_eq!(h.get(X_FORWARDED_FOR).unwrap(), "5.6.7.8");
    }

}
