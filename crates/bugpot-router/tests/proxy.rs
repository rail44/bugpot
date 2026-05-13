//! End-to-end tests for `bugpot-router` as a reverse proxy.
//!
//! Each test starts:
//!
//! 1. a small backend `axum` server on a random port (the "app"), and
//! 2. the router itself on another random port,
//!
//! then drives requests through the router and asserts behaviour.

use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::any,
};
use bugpot_config::{AppSpec, Egress, Readiness, Resources, Runtime, Scaling};
use bugpot_router::{AppRouter, Deployment, serve};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use tokio::{net::TcpListener, time::timeout};

/// Spin up an axum backend that echoes its request as JSON-ish text and returns
/// the bound port.
async fn start_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().fallback(any(echo_handler));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

async fn echo_handler(req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let headers_summary = summarize_headers(req.headers());
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let body_text = String::from_utf8_lossy(&body_bytes).into_owned();
    let payload = format!("METHOD={method}\nPATH={path}\n{headers_summary}\nBODY={body_text}\n");
    Response::builder()
        .status(StatusCode::OK)
        .header("x-backend", "yes")
        .body(Body::from(payload))
        .unwrap()
}

fn summarize_headers(h: &HeaderMap) -> String {
    let mut keys: Vec<_> = h.iter().collect();
    keys.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    keys.into_iter()
        .map(|(k, v)| format!("H:{}={}", k.as_str(), v.to_str().unwrap_or("<binary>")))
        .collect::<Vec<_>>()
        .join("\n")
}

fn fake_app(name: &str, port: u16) -> AppSpec {
    AppSpec {
        image: "ghcr.io/test/app:latest".to_owned(),
        port,
        name: Some(name.to_owned()),
        subdomain: Some(name.to_owned()),
        egress: Egress::default(),
        env: HashMap::default(),
        scaling: Scaling::default(),
        readiness: Readiness::default(),
        resources: Resources::default(),
        runtime: Runtime::default(),
        source_path: PathBuf::from(format!("/apps/{name}.toml")),
    }
}

/// Bind the router on an ephemeral port and return its address. The supplied
/// apps are deployed against `127.0.0.1:<app.port>` (the test backend).
async fn start_router(apps: Vec<AppSpec>) -> SocketAddr {
    let deployments = apps.into_iter().map(Deployment::localhost).collect();
    let app_router = Arc::new(AppRouter::new(deployments));
    // Reserve a port, then immediately release the listener so `serve` can
    // re-bind. There's a small TOCTOU window but it's acceptable for tests.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    tokio::spawn(async move {
        serve(addr, app_router).await.unwrap();
    });
    // Wait until the router accepts connections.
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("router did not start in time");
}

#[tokio::test]
async fn forwards_http_request_and_injects_forwarded_headers() {
    let backend_port = start_backend().await;
    let router_addr = start_router(vec![fake_app("hello", backend_port)]).await;

    let stream = tokio::net::TcpStream::connect(router_addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("POST")
        .uri("/some/path?x=1")
        .header("host", "hello.bugpot.ts.net")
        .header("x-custom", "alpha")
        .body(Full::new(Bytes::from_static(b"ping")))
        .unwrap();
    let res = timeout(Duration::from_secs(5), sender.send_request(req))
        .await
        .expect("router responded in time")
        .expect("router returned ok");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("x-backend").and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("METHOD=POST"), "body was: {text}");
    assert!(text.contains("PATH=/some/path"), "body was: {text}");
    assert!(text.contains("BODY=ping"), "body was: {text}");
    assert!(
        text.contains("H:x-forwarded-for=127.0.0.1"),
        "missing X-Forwarded-For; body was: {text}"
    );
    assert!(
        text.contains("H:x-forwarded-proto=http"),
        "missing X-Forwarded-Proto; body was: {text}"
    );
    assert!(
        text.contains("H:x-forwarded-host=hello.bugpot.ts.net"),
        "missing X-Forwarded-Host; body was: {text}"
    );
    assert!(
        text.contains("H:host=hello.bugpot.ts.net"),
        "Host header should be preserved verbatim; body was: {text}"
    );
    assert!(
        text.contains("H:x-custom=alpha"),
        "arbitrary headers should pass through; body was: {text}"
    );
}

#[tokio::test]
async fn returns_502_when_upstream_is_unreachable() {
    // Point the app at a port nothing is listening on.
    let unused_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let router_addr = start_router(vec![fake_app("dead", unused_port)]).await;

    let stream = tokio::net::TcpStream::connect(router_addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("GET")
        .uri("/")
        .header("host", "dead.bugpot.ts.net")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = timeout(Duration::from_secs(10), sender.send_request(req))
        .await
        .expect("router responded in time")
        .expect("router returned ok");
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn returns_404_for_unknown_host() {
    let backend_port = start_backend().await;
    let router_addr = start_router(vec![fake_app("hello", backend_port)]).await;

    let stream = tokio::net::TcpStream::connect(router_addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("GET")
        .uri("/")
        .header("host", "unknown.bugpot.ts.net")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = timeout(Duration::from_secs(5), sender.send_request(req))
        .await
        .expect("router responded in time")
        .expect("router returned ok");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// Drive a raw HTTP/1.1 Upgrade through the router and assert that the bytes
/// after the handshake are spliced end-to-end.
///
/// We don't speak the real WebSocket framing protocol because the router never
/// inspects the upgraded stream — it only proxies bytes — so a fake protocol
/// is sufficient to exercise the code path.
#[tokio::test]
async fn proxies_http1_upgrade_transparently() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Backend: minimal HTTP/1.1 server that accepts an Upgrade request, sends
    // 101, then echoes whatever bytes the client writes.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // Drain request headers.
        let mut buf = [0u8; 4096];
        let mut total = 0;
        loop {
            let n = sock.read(&mut buf[total..]).await.unwrap();
            assert!(n > 0, "client closed before headers were complete");
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        sock.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              \r\n",
        )
        .await
        .unwrap();
        // Echo loop until EOF.
        loop {
            let mut b = [0u8; 1024];
            let n = sock.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            sock.write_all(&b[..n]).await.unwrap();
        }
    });

    let router_addr = start_router(vec![fake_app("ws", backend_port)]).await;

    let mut stream = tokio::net::TcpStream::connect(router_addr).await.unwrap();
    stream
        .write_all(
            b"GET /chat HTTP/1.1\r\n\
              Host: ws.bugpot.ts.net\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              \r\n",
        )
        .await
        .unwrap();

    // Read response headers.
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "router closed before sending 101");
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let header_text = std::str::from_utf8(&buf).unwrap();
    assert!(
        header_text.starts_with("HTTP/1.1 101"),
        "expected 101, got: {header_text}"
    );

    // Now write some bytes and expect them back (echo through the spliced
    // upgrade).
    stream.write_all(b"hello-upgrade").await.unwrap();
    let mut got = [0u8; 13];
    let read = timeout(Duration::from_secs(5), stream.read_exact(&mut got))
        .await
        .expect("read timed out")
        .expect("read failed");
    assert_eq!(read, 13);
    assert_eq!(&got, b"hello-upgrade");
}
