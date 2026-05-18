//! Readiness probing for the cold-start path.
//!
//! Used by `AppHost::do_start` after libcontainer reports the
//! container is running but before the controller declares the start
//! successful. Two modes selected by the app's TOML:
//!
//! * **TCP-bind** (default) — a successful `TcpStream::connect` is
//!   enough. Fast, no expectations on the upstream's HTTP shape.
//! * **HTTP** (`[readiness] path = "..."`) — bugpot sends `GET <path>`
//!   and waits for a 2xx. Catches the Rails / Django pattern where the
//!   listener binds early but the app is still warming up its DB pool.
//!
//! The HTTP probe is hand-rolled `tokio::net::TcpStream` plus the
//! smallest possible HTTP/1.1 request (`Connection: close`, 256-byte
//! response head cap) so this crate doesn't take a hyper / reqwest
//! dependency for one GET per cold start.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use tokio::net::TcpStream;

/// Inter-attempt delay while the probe is polling. Smaller = faster
/// detection of the upstream becoming ready, but more wasted syscalls
/// when the upstream is sluggish. 100 ms is the median Rails-class
/// startup-tail granularity.
const READINESS_POLL: Duration = Duration::from_millis(100);

/// Poll the container's port until it's ready, on the cadence of
/// `READINESS_POLL` and up to `timeout`.
///
/// When `path` is `None`, "ready" = a successful `TcpStream::connect`
/// — sufficient for plain-TCP apps and the cheap path for HTTP apps
/// whose handlers come up the moment they bind. When `path` is
/// `Some(p)`, "ready" = the upstream replies to `GET p` with a 2xx
/// status; this catches the common Rails / Django startup pattern
/// where the listener binds early but the app responds 500 until
/// its DB pool is connected.
pub(crate) async fn wait_for_ready(
    addr: SocketAddr,
    path: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_err: Option<anyhow::Error> = None;
    while Instant::now() < deadline {
        let attempt = match path {
            None => tcp_probe(addr).await,
            Some(p) => http_probe(addr, p).await,
        };
        match attempt {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(READINESS_POLL).await;
            }
        }
    }
    let kind = path.map_or("TCP", |_| "HTTP");
    Err(anyhow!(
        "{kind} readiness probe of {addr} timed out after {timeout:?}: {last_err:?}"
    ))
}

async fn tcp_probe(addr: SocketAddr) -> Result<()> {
    TcpStream::connect(addr)
        .await
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

/// One-shot HTTP/1.1 GET probe. Returns `Ok(())` on 2xx, `Err` on
/// connect failure / write failure / non-2xx status.
async fn http_probe(addr: SocketAddr, path: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(addr).await?;
    // `Host` carries the literal upstream address — bugpot's apps
    // bind a single virtual host inside their netns, so the value
    // doesn't matter for routing, only for HTTP/1.1 compliance.
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: bugpot-readiness\r\nConnection: close\r\nAccept: */*\r\n\r\n",
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // We only need the status line. 256 bytes is enough for any
    // reasonable HTTP/1.1 status line + the start of the headers,
    // and capping the read keeps a wedged upstream from streaming
    // megabytes into our probe.
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Err(anyhow!("upstream closed before sending any bytes"));
    }
    let head = std::str::from_utf8(&buf[..n])
        .map_err(|e| anyhow!("non-UTF-8 in HTTP status line: {e}"))?;
    let status = parse_http_status_code(head)
        .ok_or_else(|| anyhow!("could not parse HTTP status from {head:?}"))?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(anyhow!("upstream returned HTTP {status} on {path}"))
    }
}

/// Extract the integer status code from an HTTP/1.x response head.
/// Returns `None` if the first line doesn't look like
/// `HTTP/<version> <code> <reason>`.
fn parse_http_status_code(head: &str) -> Option<u16> {
    let first_line = head.split("\r\n").next()?;
    let mut parts = first_line.split(' ');
    // Skip "HTTP/1.1" or similar.
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let code = parts.next()?;
    code.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_status_code_handles_typical_responses() {
        assert_eq!(parse_http_status_code("HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(
            parse_http_status_code("HTTP/1.0 503 Service Unavailable\r\nServer: x\r\n"),
            Some(503),
        );
        // Tolerant of HTTP/2 framing should it ever land here (would
        // require a downstream that speaks h2 on the same socket — not
        // bugpot's case today, but cheap to handle).
        assert_eq!(
            parse_http_status_code("HTTP/2 204 No Content\r\n"),
            Some(204)
        );
    }

    #[test]
    fn parse_http_status_code_rejects_garbage() {
        assert!(parse_http_status_code("").is_none());
        assert!(parse_http_status_code("hello world").is_none());
        assert!(parse_http_status_code("HTTP/1.1\r\n").is_none());
        assert!(parse_http_status_code("HTTP/1.1 oops OK\r\n").is_none());
    }

    /// End-to-end smoke for `http_probe`: spin up a tiny in-process
    /// listener that hand-rolls one response per connection, then
    /// confirm `http_probe` distinguishes 2xx from non-2xx.
    #[tokio::test]
    async fn http_probe_accepts_2xx_rejects_5xx() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        async fn run_once(response: &'static str) -> std::result::Result<(), anyhow::Error> {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf).await;
                sock.write_all(response.as_bytes()).await.unwrap();
                sock.shutdown().await.ok();
            });
            let res = http_probe(addr, "/health").await;
            server.await.unwrap();
            res
        }

        run_once("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("2xx must be ready");
        let err = run_once("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect_err("5xx must not be ready");
        assert!(err.to_string().contains("503"), "got {err}");
    }
}
