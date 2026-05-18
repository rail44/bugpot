//! Atomic ownership of bugpot's set of registered apps.
//!
//! Wraps the dual-indexed `AppMaps` (`by_name` + `by_subdomain`)
//! behind a narrow API so the rest of `bugpot-core` can't accidentally
//! desync the two indexes — insert / remove are atomic across both
//! views under a single lock. The router's hot path
//! ([`Registry::find_by_subdomain`]) and the admin path
//! ([`Registry::find_by_name`]) both resolve in one hash and one
//! `read()`.
//!
//! Lookups return `Arc<AppHandle>` clones (not borrows) so callers
//! don't hold the read lock across `.await`. Handles outlive the
//! registry entry by Arc refcount — a concurrent `remove` doesn't
//! invalidate an in-flight Arc, only future lookups.

use std::sync::Arc;

use tokio::sync::RwLock;

use crate::handle::{AppHandle, AppMaps};

/// Why a `try_insert` was rejected. Mapped to the corresponding admin
/// error (409 Conflict, distinguished by which key collided).
pub(crate) enum InsertCollision {
    NameTaken,
    SubdomainTaken,
}

#[derive(Debug, Default)]
pub(crate) struct Registry {
    apps: RwLock<AppMaps>,
}

impl Registry {
    /// Synchronous bulk-construction from an already-validated set of
    /// handles. Used during `AppHost::new` (rehydration from disk)
    /// where the async lock would force `new` to become async or do a
    /// `block_on` dance inside a tokio runtime.
    pub(crate) fn from_handles<I: IntoIterator<Item = Arc<AppHandle>>>(handles: I) -> Self {
        let mut maps = AppMaps::default();
        for handle in handles {
            maps.by_subdomain
                .insert(handle.subdomain().to_owned(), Arc::clone(&handle));
            maps.by_name.insert(handle.name().to_owned(), handle);
        }
        Self {
            apps: RwLock::new(maps),
        }
    }

    /// Synchronous count for `AppHost::new`'s startup metric. The
    /// async variants are still preferred from runtime code.
    pub(crate) fn len_blocking(&self) -> usize {
        // `try_read` won't block here — `from_handles` only ever
        // builds a registry that's never been published yet.
        self.apps.try_read().map_or(0, |m| m.by_name.len())
    }

    /// Primary lookup. Used by admin reads and by every operation
    /// method that takes a `&str` name before delegating internally.
    pub(crate) async fn find_by_name(&self, name: &str) -> Option<Arc<AppHandle>> {
        self.apps.read().await.by_name.get(name).cloned()
    }

    /// Reverse lookup. Used by the router's `UpstreamResolver` impl
    /// on every HTTP request.
    pub(crate) async fn find_by_subdomain(&self, subdomain: &str) -> Option<Arc<AppHandle>> {
        self.apps.read().await.by_subdomain.get(subdomain).cloned()
    }

    /// Snapshot of every registered handle. Ordering is undefined.
    pub(crate) async fn list(&self) -> Vec<Arc<AppHandle>> {
        self.apps.read().await.by_name.values().cloned().collect()
    }

    /// Fast-fail pre-check before doing disk I/O for a new registration.
    /// Holds only the read lock; the authoritative collision detection
    /// happens in [`Self::try_insert`] under the write lock.
    pub(crate) async fn would_collide(
        &self,
        name: &str,
        subdomain: &str,
    ) -> Option<InsertCollision> {
        let maps = self.apps.read().await;
        if maps.by_name.contains_key(name) {
            Some(InsertCollision::NameTaken)
        } else if maps.by_subdomain.contains_key(subdomain) {
            Some(InsertCollision::SubdomainTaken)
        } else {
            None
        }
    }

    /// Atomic check-and-insert under the write lock. Both `by_name`
    /// and `by_subdomain` are populated together so the dual-index
    /// invariant is never observable mid-write.
    pub(crate) async fn try_insert(&self, handle: Arc<AppHandle>) -> Result<(), InsertCollision> {
        let mut maps = self.apps.write().await;
        if maps.by_name.contains_key(handle.name()) {
            return Err(InsertCollision::NameTaken);
        }
        if maps.by_subdomain.contains_key(handle.subdomain()) {
            return Err(InsertCollision::SubdomainTaken);
        }
        maps.by_subdomain
            .insert(handle.subdomain().to_owned(), Arc::clone(&handle));
        maps.by_name.insert(handle.name().to_owned(), handle);
        drop(maps);
        Ok(())
    }

    /// Drop the entry keyed by `(name, subdomain)` from both indexes.
    /// Idempotent: removing an absent entry is a no-op.
    pub(crate) async fn remove(&self, name: &str, subdomain: &str) {
        let mut maps = self.apps.write().await;
        maps.by_name.remove(name);
        maps.by_subdomain.remove(subdomain);
    }
}
