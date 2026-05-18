//! Trait + value types that define the boundary between bugpot's
//! HTTP router and whatever decides which upstream a request goes to.
//!
//! This crate exists purely to slim the dependency surface:
//! `bugpot-core` (the controller) implements [`UpstreamResolver`] to
//! plug `AppHost` into the router, and on the consumer side
//! `bugpot-router` calls it. Both used to pull in each other's
//! transitive deps via the trait alone; lifting the trait into a
//! tiny port crate lets `bugpot-core` build against just the
//! interface (~100 LOC, no axum / hyper) instead of all of
//! `bugpot-router`.
//!
//! Naming follows the ports & adapters pattern: the "port" is the
//! shape the consumer (router) requires; "adapters" (the core's
//! `AppHost`, the static fixture in `bugpot-router/tests/proxy.rs`)
//! implement that shape.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

/// What [`UpstreamResolver::resolve`] returns for a
/// successfully-resolved host.
///
/// `addr` is where the router forwards to; `active_upgrades` is an
/// optional per-app counter the router increments when it spawns a
/// long-lived upgrade splice. Resolvers that don't care about
/// per-app upgrade tracking can leave it `None` (e.g. a static
/// resolver in tests); the in-bugpot `AppHost` impl returns the
/// `AppHandle`'s counter so the controller's idle reaper can defer
/// freezing while an upgrade is mid-flight.
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
/// The router calls this on every request to find out where to
/// forward. Implementations may take meaningful time (e.g. waiting
/// for a cold-start container to come up) but should respect
/// cancellation if the caller drops the future.
///
/// Native AFIT — `serve` is generic over the concrete resolver type
/// (controller in production, a test fixture in `tests/proxy.rs`),
/// so no `dyn` and no `#[async_trait]` allocation per request.
pub trait UpstreamResolver: Send + Sync + std::fmt::Debug {
    fn resolve(&self, host: &str) -> impl Future<Output = Result<Upstream, ResolveError>> + Send;
}

/// Convenience extractor used by [`UpstreamResolver`]
/// implementations.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomain_of_extracts_first_label() {
        assert_eq!(subdomain_of("alpha.bugpot.example"), Some("alpha"));
        assert_eq!(subdomain_of("alpha.bugpot.example:443"), Some("alpha"));
        assert_eq!(subdomain_of("beta.bugpot.example"), Some("beta"));
        assert_eq!(subdomain_of("beta.bugpot.example:443"), Some("beta"));
        // No `.` after the label: the whole thing is the label.
        assert_eq!(subdomain_of("alpha:8080"), Some("alpha"));
        assert_eq!(subdomain_of("alpha"), Some("alpha"));
    }

    #[test]
    fn subdomain_of_empty_returns_empty_label() {
        // Empty host → empty label. Caller decides whether to treat
        // that as a 404; resolution is the resolver's job, not this
        // helper's.
        assert_eq!(subdomain_of(""), Some(""));
    }

    #[test]
    fn subdomain_of_rejects_ipv6_literal() {
        // `[::1]:8080` and `[::1]` both should not match anything
        // sensible — bugpot routes by subdomain only.
        assert_eq!(subdomain_of("[::1]:8080"), None);
        assert_eq!(subdomain_of("[::1]"), None);
    }
}
