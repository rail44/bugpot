use anyhow::Result;
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
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
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
/// Sized for the "many small apps on a cheap VM" scenario: total
/// bookkeeping floor is `MAX_BODY_BYTES * MAX_CONCURRENT_REQUESTS`
/// (4 MiB × 64 = 256 MiB), which leaves room on a 1 GiB host.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum simultaneous in-flight requests. Excess requests queue at
/// the tower layer; combined with `REQUEST_TIMEOUT` they cannot pile
/// up unboundedly. 64 fits 1 vCPU / 1 GiB hosts; higher numbers
/// (e.g. the previous 1024) trip the bookkeeping invariant above.
const MAX_CONCURRENT_REQUESTS: usize = 64;
/// Per-frame idle timeout on the response body once we start
/// streaming it back to the client. `REQUEST_TIMEOUT` only covers the
/// time until the response head is received; a slow-read attacker can
/// stall body delivery beyond it.
const RESPONSE_FRAME_TIMEOUT: Duration = Duration::from_mins(1);
/// Hard ceiling on the total response body bytes a single request may
/// stream. 64 MiB is generous for the "internal apps on a cheap VM"
/// scenario; larger responses should stream out-of-band (e.g.
/// presigned URLs) rather than through the router.
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Maximum simultaneous Upgrade (WebSocket) connections. Each upgrade
/// detaches a spliced byte-pump task that the `MAX_CONCURRENT_REQUESTS`
/// limit cannot bound; without an explicit cap an attacker could
/// detach thousands of idle splices and pressure the tokio runtime.
const MAX_CONCURRENT_UPGRADES: usize = 32;
/// Idle (no traffic in either direction) timeout for an upgraded
/// connection. Splices that exceed it are torn down.
const UPGRADE_IDLE_TIMEOUT: Duration = Duration::from_mins(5);
/// HTTP/2 max concurrent streams per connection. Pinned well below
/// `MAX_CONCURRENT_REQUESTS` so a single h2 client can't exhaust the
/// global ceiling with one connection.
const H2_MAX_CONCURRENT_STREAMS: u32 = 16;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");

/// RFC 7230 §6.1 hop-by-hop headers. Pre-parsed once into typed
/// `HeaderName`s so the per-request strip path does eight pointer
/// comparisons instead of eight `&str → HeaderName` parses. The
/// `HeaderName` type has interior mutability (atomic refcount on the
/// inner `Bytes`) so a compound `const [HeaderName; N]` will not
/// compile, hence the `LazyLock`. `Upgrade` is in the list but the
/// WebSocket path runs *before* the strip and keeps it.
static HOP_BY_HOP_HEADERS: LazyLock<[HeaderName; 8]> = LazyLock::new(|| {
    [
        HeaderName::from_static("connection"),
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-authenticate"),
        HeaderName::from_static("proxy-authorization"),
        HeaderName::from_static("te"),
        HeaderName::from_static("trailer"),
        HeaderName::from_static("transfer-encoding"),
        HeaderName::from_static("upgrade"),
    ]
});

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
    /// means trust the existing chain (current behaviour); set to the
    /// IP ranges of whichever reverse proxy / private network sits in
    /// front of bugpot in real deployments.
    pub trusted_proxies: Vec<IpNet>,
    /// Value to set in `X-Forwarded-Proto` when the upstream request
    /// doesn't already carry one. Defaults to `http`. Set to `https`
    /// when bugpot sits behind a TLS-terminating front (reverse proxy,
    /// external LB, etc.).
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

/// What `UpstreamResolver::resolve` returns for a successfully-resolved
/// host: the upstream address plus an optional per-app counter the
/// router will increment when it spawns a long-lived upgrade splice.
///
/// Resolvers that don't care about per-app upgrade tracking can leave
/// `active_upgrades` set to `None` (e.g. the static resolver in this
/// crate's integration test); the in-bugpot `AppController` impl
/// returns the `AppHandle`'s counter so the controller's idle reaper
/// can defer freezing while an upgrade is mid-flight.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub addr: SocketAddr,
    pub active_upgrades: Option<Arc<AtomicUsize>>,
}

impl Upstream {
    #[must_use]
    pub const fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            active_upgrades: None,
        }
    }

    #[must_use]
    pub const fn with_active_upgrades(addr: SocketAddr, counter: Arc<AtomicUsize>) -> Self {
        Self {
            addr,
            active_upgrades: Some(counter),
        }
    }
}

/// Why a host couldn't be resolved to a live upstream. Distinguishes
/// the two operator-visible failure modes so the router can return
/// different HTTP status codes:
///
/// - [`ResolveError::NoSuchApp`] → `404 Not Found`. The subdomain
///   never matched a registered app; the request is for something
///   that doesn't exist.
/// - [`ResolveError::Unhealthy`] → `502 Bad Gateway`. The app **is**
///   registered, but bringing it up to serve this request failed
///   (image pull, readiness probe, etc.). The error chain is logged
///   server-side; clients see only the status code.
///
/// Without this split a deployed-but-failing app and an unregistered
/// subdomain look identical to operators, which is exactly the
/// "Linkding is broken vs I never deployed it" gotcha.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("no app registered for this host")]
    NoSuchApp,
    #[error("upstream is registered but failed to come up: {0}")]
    Unhealthy(#[source] anyhow::Error),
}

/// Pluggable upstream resolver.
///
/// The router calls this on every request to find out where to forward.
/// Implementations may take meaningful time (e.g. waiting for a cold-start
/// container to come up) but should respect cancellation if the caller
/// drops the future.
/// Native AFIT — `serve` is generic over the concrete resolver type
/// (controller in production, a test fixture in `tests/proxy.rs`),
/// so no `dyn` and no `#[async_trait]` allocation per request.
pub trait UpstreamResolver: Send + Sync + std::fmt::Debug {
    fn resolve(&self, host: &str) -> impl Future<Output = Result<Upstream, ResolveError>> + Send;
}

/// Convenience extractor used by `UpstreamResolver` implementations.
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

/// Shared state passed to every handler invocation.
struct ProxyState<R: UpstreamResolver + 'static> {
    resolver: Arc<R>,
    client: ProxyClient,
    config: Arc<RouterConfig>,
    /// Caps the number of simultaneously-spliced Upgrade connections.
    /// `forward_upgrade` acquires a permit before detaching its splice
    /// task; if no permits are available the upgrade is rejected with
    /// 503. Counts only successfully-spliced upgrades.
    upgrade_slots: Arc<Semaphore>,
}

// Derive-style `Clone` would require `R: Clone`, which we don't need
// (the `Arc<R>` is what gets cloned). Hand-write the impl.
impl<R: UpstreamResolver + 'static> Clone for ProxyState<R> {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            client: self.client.clone(),
            config: Arc::clone(&self.config),
            upgrade_slots: Arc::clone(&self.upgrade_slots),
        }
    }
}

impl<R: UpstreamResolver + 'static> std::fmt::Debug for ProxyState<R> {
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
pub async fn serve<R: UpstreamResolver + 'static>(
    addr: SocketAddr,
    resolver: Arc<R>,
    config: RouterConfig,
) -> Result<()> {
    let state = ProxyState {
        resolver,
        client: build_client(),
        config: Arc::new(config),
        upgrade_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_UPGRADES)),
    };
    let app = Router::new()
        .fallback(any(handler::<R>))
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

async fn handler<R: UpstreamResolver + 'static>(
    State(state): State<ProxyState<R>>,
    req: Request,
) -> Response {
    let host = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let app_label = subdomain_of(&host).unwrap_or("unknown").to_owned();

    let response = match state.resolver.resolve(&host).await {
        Err(ResolveError::NoSuchApp) => {
            warn!(host = %host, "no app matched");
            error_response(
                StatusCode::NOT_FOUND,
                format!("no app matched host '{host}'\n"),
            )
        }
        Err(ResolveError::Unhealthy(err)) => {
            // The app is registered but couldn't be made ready —
            // cold start failure, readiness probe fail, etc. 502 so
            // operators can tell this case apart from "you never
            // deployed me" (404). The detail is in the daemon log;
            // we don't echo it to the client because it can leak
            // internal hostnames / pull errors.
            warn!(host = %host, error = ?err, "upstream unhealthy");
            error_response(
                StatusCode::BAD_GATEWAY,
                format!("upstream for '{host}' failed to come up\n"),
            )
        }
        Ok(upstream) => {
            // Per-request route confirmation. At info-level this
            // showed up as ~33μs/req (≈ 2.7× total router throughput
            // hit at the default level). Route hits are not
            // actionable operational signal — `bugpot_router_requests_total`
            // covers the same fact with no allocations per call.
            debug!(host = %host, addr = %upstream.addr, "matched route");
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
async fn forward<R: UpstreamResolver + 'static>(
    state: &ProxyState<R>,
    mut req: Request,
    upstream: Upstream,
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
    let new_uri = match rewrite_uri(req.uri(), upstream.addr) {
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
        return forward_upgrade(state, req, upstream.active_upgrades).await;
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
            error_response(
                StatusCode::BAD_GATEWAY,
                "upstream connection failed\n".to_owned(),
            )
        }
        Err(_) => {
            warn!(
                timeout_secs = REQUEST_TIMEOUT.as_secs(),
                "upstream request timed out"
            );
            error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream request timed out\n".to_owned(),
            )
        }
    }
}

/// Forward an HTTP/1.1 upgrade request (e.g. WebSocket) by splicing the two
/// upgraded byte streams together.
///
/// `active_upgrades` (if provided) is an upstream-side counter the
/// router increments when a successful upgrade enters splice and
/// decrements when the splice task exits. The controller reads this
/// counter to defer freezing while an upgrade is mid-flight.
async fn forward_upgrade<R: UpstreamResolver + 'static>(
    state: &ProxyState<R>,
    mut req: Request,
    active_upgrades: Option<Arc<AtomicUsize>>,
) -> Response {
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
    // Increment the per-app upgrade counter *before* the splice task is
    // detached, so a freeze decision racing with this upgrade observes
    // the increment instead of an empty counter. The drop guard inside
    // the task decrements on exit (normal close / error / panic), so
    // the counter is balanced.
    let upgrade_guard = active_upgrades.map(ActiveUpgradeGuard::new);
    tokio::spawn(async move {
        // `permit` is moved into this task; dropping it on exit
        // releases the upgrade slot. `_guard` mirrors that for the
        // per-app counter.
        let _permit = permit;
        let _guard = upgrade_guard;
        match tokio::try_join!(client_upgrade, server_upgrade) {
            Ok((client_io, server_io)) => {
                let client_io = TokioIo::new(client_io);
                let server_io = TokioIo::new(server_io);
                if let Err(e) = splice_with_idle(client_io, server_io, UPGRADE_IDLE_TIMEOUT).await {
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

/// RAII guard around the per-app `active_upgrades` counter. Construction
/// increments; drop decrements. Held inside the splice task so the
/// counter naturally reaches zero on normal exit, panic, or runtime
/// shutdown — there's no separate "splice finished" callback to wire.
#[derive(Debug)]
struct ActiveUpgradeGuard(Arc<AtomicUsize>);

impl ActiveUpgradeGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for ActiveUpgradeGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
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
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
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
    for h in HOP_BY_HOP_HEADERS.iter() {
        headers.remove(h);
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

    #[test]
    fn subdomain_of_extracts_first_label() {
        assert_eq!(subdomain_of("alpha.bugpot.example"), Some("alpha"));
        // The `:port` suffix is stripped before label extraction so
        // routing works regardless of how the client wrote the Host.
        assert_eq!(subdomain_of("beta.bugpot.example:443"), Some("beta"));
        // Single label with no dot is its own subdomain (matches the
        // `*.localhost` dev-loopback case).
        assert_eq!(subdomain_of("alpha:8080"), Some("alpha"));
    }

    #[test]
    fn subdomain_of_empty_returns_empty_label() {
        // No special-casing for empty Host — it falls out as an empty
        // first label, which the resolver compares against registered
        // subdomains and (correctly) fails to match anything.
        assert_eq!(subdomain_of(""), Some(""));
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
        assert_eq!(subdomain_of("alpha.bugpot.example:443"), Some("alpha"));
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
