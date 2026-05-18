//! In-memory store of every live per-app endpoint.
//!
//! One [`AllocatedApp`] per registered app — the same value is
//! reachable by name (control-path: `release_endpoint`) and by
//! container IP (DNS hot path: `decide`). Both indexes live under a
//! single [`RwLock`], so an `insert` / `remove_by_name` is atomic
//! across the two views and the DNS-side read is consistent with
//! whatever the control-path last committed.
//!
//! Replaces an earlier shape that kept two independent maps —
//! `Mutex<HashMap<String, AllocatedApp>>` plus a separate
//! `Arc<AppRegistry>` — and required every mutating method to write
//! to both, by hand, in the right order. The shared-data, indexed
//! shape removes that footgun: callers commit one value, both
//! indexes update together.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::allowlist::Allowlist;
use crate::netns::EndpointLayout;

/// Everything we need to know about a live per-app endpoint.
///
/// `name` + `container_ip` are the two index keys; `plan` is used by
/// the control path during teardown; `allowlist` is used by the DNS
/// handler on every query. The value is shared via `Arc` so both
/// indexes can point at the same allocation.
#[derive(Debug)]
pub struct AllocatedApp {
    pub name: String,
    pub container_ip: Ipv4Addr,
    pub plan: EndpointLayout,
    pub allowlist: Allowlist,
}

/// Two-index endpoint store backed by a single lock.
#[derive(Debug, Default)]
pub struct EndpointStore {
    inner: RwLock<EndpointStoreInner>,
}

#[derive(Debug, Default)]
struct EndpointStoreInner {
    by_name: HashMap<String, Arc<AllocatedApp>>,
    by_ip: HashMap<Ipv4Addr, Arc<AllocatedApp>>,
}

impl EndpointStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `app` under both indexes atomically. If an entry for
    /// the same `name` or `container_ip` is already present it is
    /// overwritten — callers that need collision detection should
    /// check first (e.g. via the allocator).
    pub fn insert(&self, app: AllocatedApp) {
        let app = Arc::new(app);
        let mut inner = self.inner.write();
        inner.by_name.insert(app.name.clone(), Arc::clone(&app));
        inner.by_ip.insert(app.container_ip, app);
    }

    /// Drop the entry keyed by `name` from both indexes. Returns the
    /// removed value so callers can recover its `container_ip` /
    /// `plan` for kernel teardown without a second lookup.
    pub fn remove_by_name(&self, name: &str) -> Option<Arc<AllocatedApp>> {
        let mut inner = self.inner.write();
        let app = inner.by_name.remove(name)?;
        inner.by_ip.remove(&app.container_ip);
        drop(inner);
        Some(app)
    }

    /// DNS hot-path lookup. Returns `None` for unrecognised IPs (the
    /// DNS handler maps that to `Refused`).
    #[must_use]
    pub fn lookup_by_ip(&self, ip: Ipv4Addr) -> Option<Arc<AllocatedApp>> {
        self.inner.read().by_ip.get(&ip).cloned()
    }
}
