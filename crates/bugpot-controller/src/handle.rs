//! Per-app handle and state machine types.
//!
//! These are the building blocks the `AppController` operates on:
//! a long-lived [`AppHandle`] per registered app, an [`AppState`]
//! enum capturing the lifecycle, and [`AppMaps`] for the
//! registration index. The transition logic that mutates them
//! lives in `AppController`'s methods (in `lib.rs`); this module
//! is the *types and their construction*.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;

use bugpot_config::{AppIdentity, AppSpec, Rollout};
use tokio::sync::{Mutex, Notify, RwLock};

/// Cap on the per-app rollout history retained in memory + on disk.
/// Older rollouts are dropped (popped from the front of the deque) as
/// new ones land. Two = live rollout + one immediate-rollback target,
/// which matches the realistic recovery window for an internal-tool
/// deployment cadence and keeps stale image references from defeating
/// the image GC on cheap-VM hosts.
pub(crate) const MAX_ROLLOUT_HISTORY: usize = 2;

#[derive(Debug)]
pub(crate) struct AppHandle {
    /// Immutable identity (name + subdomain). Set once at construction
    /// from the validating `AppSpec::identity`, never updated — a
    /// future PUT-style update path will compare against this and
    /// reject mismatches rather than mutating it. `name` is the primary
    /// key in `AppMaps.by_name`; `subdomain` is the reverse-lookup key
    /// used by `UpstreamResolver::resolve`.
    pub(crate) identity: AppIdentity,
    /// Mutable spec fields (image, port, env, etc.). Wrapped in
    /// `RwLock` so future PUT-style updates can mutate in place
    /// without rebuilding the handle. The spec's own `name` /
    /// `subdomain` fields exist for TOML / JSON serialisation shape
    /// only — `identity` is the authoritative pair.
    pub(crate) spec: RwLock<AppSpec>,
    /// Per-app counter of HTTP/1.1 upgrades (WebSocket / SSE) currently
    /// spliced through the router. Incremented by the router on splice
    /// spawn, decremented when the splice task exits. The idle reaper
    /// reads this **without taking `inner`'s lock** to decide whether
    /// to freeze: freezing an app mid-WebSocket would silently strand
    /// the connection, since the kernel keeps the listen socket up but
    /// the user-space process can't process frames.
    pub(crate) active_upgrades: Arc<AtomicUsize>,
    pub(crate) inner: Mutex<HandleInner>,
}

#[derive(Debug)]
pub(crate) struct HandleInner {
    pub(crate) state: AppState,
    pub(crate) last_access: Instant,
    /// Bounded rollout history, co-located with `state` because the
    /// two move together: a rollout push advances both the rollout
    /// list and the state (Stopped → Running, or Running → Stopping →
    /// Running with the new image). The back of the deque is the
    /// current rollout (the tag bugpot pulls and runs). Empty = the
    /// app is registered but not yet deployed, in which case
    /// `ensure_running` will fail.
    pub(crate) rollouts: VecDeque<Rollout>,
    /// Resolved image digest from the first successful pull. Pinning
    /// at the handle level means subsequent cold-starts for this app
    /// skip the `manifest_probe` round-trip (~1s on a remote registry)
    /// and go straight to the cache-hit path inside `Puller::pull`.
    ///
    /// Lives in `HandleInner` because invalidation is part of the
    /// lifecycle: `update_app` clears it on `repo` change, and a
    /// successful pull writes it. Mutable tags (`:latest` etc.)
    /// therefore behave the way Kubernetes' `imagePullPolicy:
    /// IfNotPresent` does — an operator-side redeploy is required
    /// to pick up an upstream retag. No TTL.
    pub(crate) image_digest: Option<bugpot_runtime::ImageId>,
    /// Last-seen cgroup `cpu_usec` for the running container, used to
    /// compute deltas for the `bugpot_app_cpu_microseconds_total`
    /// counter across sweeps. Lifetime matches the handle's running
    /// lifetime (only valid while `state` is `Running`); resetting it
    /// on stop keeps the next run starting from zero, which Prometheus
    /// `rate()` tolerates as a reset.
    pub(crate) cpu_baseline: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum AppState {
    Stopped,
    /// A concurrent start is in flight. Waiters subscribe on the inner
    /// `Notify`. The `Arc` lives only while the state machine is in
    /// this variant; transitioning away drops it (held clones held by
    /// waiters keep the channel alive long enough to receive the wake).
    Starting {
        notify: Arc<Notify>,
    },
    Running {
        container_ip: Ipv4Addr,
    },
    /// Container is suspended via cgroup freezer; netns + listen
    /// socket are still alive. The `container_ip` is reused on resume —
    /// no endpoint re-allocation needed. `ensure_running` transitions
    /// Frozen → Starting → Running by unfreezing.
    Frozen {
        container_ip: Ipv4Addr,
    },
    Stopping,
}

impl AppState {
    /// `Running` — the container is up and accepting traffic. Distinct
    /// from "has a live container" (`needs_teardown`); this is the
    /// strict "ready to serve" state.
    pub(crate) const fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// `Frozen` — paused via cgroup freezer. RAM-resident, CPU 0.
    pub(crate) const fn is_frozen(&self) -> bool {
        matches!(self, Self::Frozen { .. })
    }

    /// Mid-transition (`Starting` or `Stopping`). Callers that need a
    /// settled state typically return a 409-style "retry later"
    /// rather than blocking.
    pub(crate) const fn is_busy(&self) -> bool {
        matches!(self, Self::Starting { .. } | Self::Stopping)
    }

    /// There is (or is about to be) a container associated with this
    /// handle that bugpot is responsible for tearing down. Covers the
    /// three variants whose teardown actually frees resources:
    /// `Running`, `Frozen`, and `Starting` (a cold start in flight
    /// must be interrupted).
    pub(crate) const fn needs_teardown(&self) -> bool {
        matches!(
            self,
            Self::Running { .. } | Self::Frozen { .. } | Self::Starting { .. }
        )
    }
}

/// Both registration maps under a single lock so insert / remove are
/// atomic across the (name, subdomain) pair. Name is the primary key
/// (used by `get_app` / `remove_app` / `cleanup`); subdomain is a
/// reverse index used by `UpstreamResolver::resolve` to route HTTP
/// requests in O(1).
#[derive(Debug, Default)]
pub(crate) struct AppMaps {
    pub(crate) by_name: HashMap<String, Arc<AppHandle>>,
    pub(crate) by_subdomain: HashMap<String, String>,
}

/// Construct a handle from a validated spec. Returns `Err` if
/// `spec.identity()` fails (the spec's name / subdomain weren't valid
/// DNS labels). Callers in the deploy path are expected to have run
/// `spec.validate()` earlier; this is the belt-and-braces version.
pub(crate) fn make_handle(
    spec: AppSpec,
    initial_rollout: Option<Rollout>,
) -> Result<Arc<AppHandle>, bugpot_config::InvalidSpec> {
    let mut rollouts = VecDeque::with_capacity(MAX_ROLLOUT_HISTORY);
    if let Some(r) = initial_rollout {
        rollouts.push_back(r);
    }
    make_handle_with_rollouts(spec, rollouts)
}

/// Build a handle from a spec + a pre-populated rollout history.
/// Used by the rehydrate-from-disk path; preserves the order callers
/// (and the on-disk file) maintain — back of the queue = current
/// rollout.
pub(crate) fn make_handle_with_rollouts(
    spec: AppSpec,
    rollouts: VecDeque<Rollout>,
) -> Result<Arc<AppHandle>, bugpot_config::InvalidSpec> {
    let identity = spec.identity()?;
    Ok(Arc::new(AppHandle {
        identity,
        spec: RwLock::new(spec),
        active_upgrades: Arc::new(AtomicUsize::new(0)),
        inner: Mutex::new(HandleInner {
            state: AppState::Stopped,
            last_access: Instant::now(),
            rollouts,
            image_digest: None,
            cpu_baseline: 0,
        }),
    }))
}
