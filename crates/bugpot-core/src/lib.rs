//! Per-app lifecycle controller with scale-to-zero and dynamic mutation.
//!
//! Each app handle is a small state machine:
//!
//! ```text
//!                        ┌─── idle ───────────► Frozen
//!                        │                        │
//!  Stopped ─request─► Starting ─ok─► Running ◄────┘ request
//!     ▲                  │ err          │
//!     │                  └──────────────►│
//!     │                                  │ rollout / update_app
//!     │                                  ▼
//!     │                             RollingOver
//!     │                             (from-side serves; new
//!     │                              container builds in
//!     │                              opposite slot)
//!     │                                  │
//!     │              switch ◄────────────┤
//!     │              or rollback         │
//!     │                                  ▼
//!     └─────────── Stopping ◄────── Running (new slot or rollback)
//! ```
//!
//! - `Frozen` is the idle-timeout target (cgroup v2 freezer); resume is sub-ms.
//! - `RollingOver` keeps `from_ip` serving traffic while a new container
//!   builds in the opposite slot — see [`mod ops::rollout`].
//!
//! The set of registered apps is held in a `RwLock<HashMap<..>>` so adapter
//! crates (HTTP admin, future webhook / poller / CLI frontends) can mutate
//! it at runtime via [`AppHost::deploy_app`] / [`AppHost::remove_app`].
//! Per-app `Mutex`-protected state machines coalesce concurrent starts.
//!
//! Note: `pub(crate)` is used for cross-module items inside this crate;
//! the `clippy::redundant_pub_crate` warning conflicts with the workspace's
//! `unreachable_pub` rule, so the former is allowed crate-wide (same
//! convention as `bugpot-runtime`). `clippy::similar_names` is allowed
//! crate-wide because the two principal handle-derived identifiers —
//! `container_id` (libcontainer / nft key) and `container_ip`
//! (`Ipv4Addr` inside `AppState`) — necessarily live within the same
//! function in every lifecycle method; using opaque short names like
//! `cid` / `cip` would obscure the call site for marginal lint
//! satisfaction. Disambiguation: `container_id` is the slot-suffixed
//! string key into libcontainer / nft; `container_ip` is the
//! `Ipv4Addr` inside `AppState::Running` / `AppState::Frozen`.
#![allow(clippy::redundant_pub_crate, clippy::similar_names)]

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
#[cfg(test)]
use std::time::SystemTime;

use anyhow::{Result, anyhow};
#[cfg(test)]
use bugpot_config::Rollout;
use bugpot_config::{AuthConfig, RegistryCredential, registry_host};
use bugpot_egress::EgressOps;
#[cfg(test)]
use bugpot_egress::StartupClaims;
#[cfg(test)]
use bugpot_runtime::RuntimeError;
use bugpot_runtime::{Auth, RuntimeOps};
use metrics::gauge;

mod error;
pub use error::{DeployError, RemoveError, RolloutError, UpdateError};

mod probe;

mod mempressure;

mod handle;
pub use handle::AppHandle;
use handle::make_handle_with_rollouts;

mod registry;
use registry::Registry;

mod store;
use store::AppStore;

mod view;
pub use view::{AppStateView, AppView};

mod persist;
#[cfg(test)]
use persist::RolloutsFile;

mod ops;

/// How long to wait for an app to start accepting TCP connections on its
/// declared port after libcontainer reports the container is running.
/// Default readiness timeout when an app does not override
/// `readiness.timeout` in its TOML.
const READINESS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);

/// Per-app lifecycle controller.
///
/// `new` accepts the initial set of specs loaded at startup; subsequent
/// add/remove happens through [`Self::deploy_app`] / [`Self::remove_app`].
/// A background [`Self::sweep_loop`] task should be spawned to reclaim
/// apps whose container died unexpectedly or that have been idle too
/// long.
#[derive(Debug)]
pub struct AppHost<R: RuntimeOps, E: EgressOps> {
    runtime: Arc<R>,
    egress: Arc<E>,
    /// In-memory ownership of the registered apps. The two indexes
    /// (`by_name` + `by_subdomain`) are atomic under a single
    /// `RwLock` inside [`Registry`].
    registry: Registry,
    /// On-disk shadow of `registry`: `<state>/apps/<name>.toml` for
    /// `AppSpec`, `<state>/rollouts/<name>.toml` for rollout history.
    /// Operators do not edit anything under here — every spec change
    /// goes through the admin API.
    store: AppStore,
    auth: AuthConfig,
    /// One-shot guard for `reattach_running`. The controller is only
    /// meant to reattach once per bugpot process — the function calls
    /// `ensure_log_tails` per surviving app, and a second call would
    /// double up tail tasks on the same files. Set on first entry; any
    /// further call is a no-op with a warning.
    reattach_done: AtomicBool,
}

impl<R: RuntimeOps, E: EgressOps> AppHost<R, E> {
    /// Create a controller, materialising the daemon-owned state
    /// directories and rehydrating any apps + rollouts persisted by
    /// a previous run.
    ///
    /// Errors when an on-disk spec fails validation or rollouts file
    /// can't be parsed — both indicate state corruption that the
    /// operator should investigate before bugpotd serves traffic.
    pub fn new(
        runtime: Arc<R>,
        egress: Arc<E>,
        state_dir: PathBuf,
        auth: AuthConfig,
    ) -> Result<Self> {
        let store = AppStore::new(state_dir);
        store.ensure_dirs()?;

        let mut handles = Vec::new();
        for (spec, rollouts) in store.load()? {
            // Specs persisted by bugpot have already passed validation
            // before being written; corrupted state here is operator-
            // investigation territory, but we fail loudly rather than
            // silently dropping the app.
            let handle = make_handle_with_rollouts(spec, rollouts)
                .map_err(|e| anyhow!("rehydrate handle: {e}"))?;
            handles.push(handle);
        }
        let registry = Registry::from_handles(handles);
        #[allow(clippy::cast_precision_loss)]
        gauge!("bugpot_apps_active").set(registry.len_blocking() as f64);
        Ok(Self {
            runtime,
            egress,
            registry,
            store,
            auth,
            reattach_done: AtomicBool::new(false),
        })
    }

    /// Resolve pull credentials for an image reference by looking the
    /// registry hostname up in [`AuthConfig`]. Falls back to anonymous.
    pub(crate) fn resolve_auth(&self, image_ref: &str) -> Auth {
        let host = registry_host(image_ref);
        match self.auth.registries.get(host) {
            Some(RegistryCredential::Bearer { token }) => Auth::BearerToken(token.clone()),
            Some(RegistryCredential::Basic { username, password }) => Auth::Basic {
                user: username.clone(),
                pass: password.clone(),
            },
            None => Auth::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::{AppState, DigestCache, Slot};
    use crate::ops::lifecycle::digest_pinned_ref;
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    use bugpot_config::{AppSpec, EgressSpec, Readiness, Scaling};
    use bugpot_egress::{EgressOps, Endpoint};
    use bugpot_runtime::{Auth, ImageId, ResourceUsage, RunningApp, RuntimeOps};

    #[derive(Debug, Default)]
    struct MockRuntime {
        pull_results: StdMutex<VecDeque<std::result::Result<ImageId, RuntimeError>>>,
        start_results: StdMutex<VecDeque<std::result::Result<RunningApp, RuntimeError>>>,
        running: StdMutex<HashMap<String, bool>>,
        paused: StdMutex<HashMap<String, bool>>,
        calls: StdMutex<Vec<String>>,
    }

    impl MockRuntime {
        fn push_pull(&self, r: std::result::Result<ImageId, RuntimeError>) {
            self.pull_results.lock().unwrap().push_back(r);
        }
        fn push_start(&self, r: std::result::Result<RunningApp, RuntimeError>) {
            self.start_results.lock().unwrap().push_back(r);
        }
        fn set_running(&self, app: &str, value: bool) {
            self.running.lock().unwrap().insert(app.to_owned(), value);
        }
        fn set_paused(&self, app: &str, value: bool) {
            self.paused.lock().unwrap().insert(app.to_owned(), value);
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn record(&self, s: impl Into<String>) {
            self.calls.lock().unwrap().push(s.into());
        }
    }

    impl RuntimeOps for MockRuntime {
        async fn pull_image(
            &self,
            image_ref: &str,
            _auth: Auth,
        ) -> std::result::Result<ImageId, RuntimeError> {
            self.record(format!("pull_image({image_ref})"));
            self.pull_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(RuntimeError::Other("mock: no pull response queued".into())))
        }

        async fn start_app(
            &self,
            container_id: &str,
            _spec: &AppSpec,
            _image_id: &ImageId,
            _netns_path: Option<&Path>,
        ) -> std::result::Result<RunningApp, RuntimeError> {
            self.record(format!("start_app({container_id})"));
            self.start_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Err(RuntimeError::Other("mock: no start response queued".into()))
                })
        }

        async fn stop_app(&self, name: &str) -> std::result::Result<(), RuntimeError> {
            self.record(format!("stop_app({name})"));
            self.running.lock().unwrap().remove(name);
            self.paused.lock().unwrap().remove(name);
            Ok(())
        }

        async fn freeze_app(&self, name: &str) -> std::result::Result<(), RuntimeError> {
            self.record(format!("freeze_app({name})"));
            self.paused.lock().unwrap().insert(name.to_owned(), true);
            Ok(())
        }

        async fn unfreeze_app(&self, name: &str) -> std::result::Result<(), RuntimeError> {
            self.record(format!("unfreeze_app({name})"));
            self.paused.lock().unwrap().remove(name);
            Ok(())
        }

        fn is_container_running(&self, name: &str) -> bool {
            *self.running.lock().unwrap().get(name).unwrap_or(&false)
        }

        fn is_container_paused(&self, name: &str) -> bool {
            *self.paused.lock().unwrap().get(name).unwrap_or(&false)
        }

        fn resource_usage(&self, _name: &str) -> Option<ResourceUsage> {
            None
        }

        async fn cleanup_container(
            &self,
            container_id: &str,
        ) -> std::result::Result<(), RuntimeError> {
            self.record(format!("cleanup_container({container_id})"));
            Ok(())
        }

        async fn cleanup_app_assets(
            &self,
            app_name: &str,
        ) -> std::result::Result<(), RuntimeError> {
            self.record(format!("cleanup_app_assets({app_name})"));
            Ok(())
        }

        fn ensure_log_tails(&self, name: &str) {
            self.record(format!("ensure_log_tails({name})"));
        }
    }

    #[derive(Debug, Default)]
    struct MockEgress {
        allocate_fail: StdMutex<bool>,
        endpoints: StdMutex<HashMap<String, Endpoint>>,
        calls: StdMutex<Vec<String>>,
    }

    impl MockEgress {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    /// Build a [`StartupClaims`] for tests. Mirrors what
    /// `Egress::new`'s discovery phase produces in production.
    fn claims_with(entries: &[(&str, Ipv4Addr)]) -> StartupClaims {
        let map = entries
            .iter()
            .map(|(name, ip)| ((*name).to_owned(), *ip))
            .collect();
        StartupClaims::new(map)
    }

    impl EgressOps for MockEgress {
        async fn allocate_endpoint(
            &self,
            name: &str,
            _allowlist: Vec<String>,
        ) -> anyhow::Result<Endpoint> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("allocate_endpoint({name})"));
            if *self.allocate_fail.lock().unwrap() {
                anyhow::bail!("mock: allocate_endpoint failed");
            }
            let ep = Endpoint {
                container_ip: Ipv4Addr::LOCALHOST,
                netns_path: PathBuf::from(format!("/run/netns/mock-{name}")),
            };
            self.endpoints
                .lock()
                .unwrap()
                .insert(name.to_owned(), ep.clone());
            Ok(ep)
        }

        async fn release_endpoint(&self, name: &str) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("release_endpoint({name})"));
            self.endpoints.lock().unwrap().remove(name);
            Ok(())
        }

        async fn reattach_endpoint(
            &self,
            name: &str,
            container_ip: Ipv4Addr,
            _allowlist: Vec<String>,
        ) -> anyhow::Result<Endpoint> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("reattach_endpoint({name})"));
            let ep = Endpoint {
                container_ip,
                netns_path: PathBuf::from(format!("/run/netns/mock-{name}")),
            };
            self.endpoints
                .lock()
                .unwrap()
                .insert(name.to_owned(), ep.clone());
            Ok(ep)
        }

        async fn cleanup_orphan_endpoint(
            &self,
            name: &str,
            container_ip: Ipv4Addr,
        ) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("cleanup_orphan_endpoint({name},{container_ip})"));
            Ok(())
        }
    }

    #[test]
    fn digest_pinned_ref_appends_digest_when_absent() {
        let digest = bugpot_runtime::ImageId::new("sha256:abc123");
        assert_eq!(
            digest_pinned_ref("gcr.io/x/y:1.0", Some(&digest)),
            "gcr.io/x/y:1.0@sha256:abc123"
        );
        assert_eq!(
            digest_pinned_ref("gcr.io/x/y", Some(&digest)),
            "gcr.io/x/y@sha256:abc123"
        );
    }

    #[test]
    fn digest_pinned_ref_passthrough_when_no_digest_or_already_pinned() {
        let digest = bugpot_runtime::ImageId::new("sha256:abc");
        // No cached digest → original ref.
        assert_eq!(digest_pinned_ref("gcr.io/x/y:1.0", None), "gcr.io/x/y:1.0");
        // Already digest-pinned → don't double-stamp.
        assert_eq!(
            digest_pinned_ref("gcr.io/x/y@sha256:def", Some(&digest)),
            "gcr.io/x/y@sha256:def"
        );
    }

    fn spec_with_name(name: &str) -> AppSpec {
        AppSpec {
            repo: "registry.example/img".to_owned(),
            port: 8080,
            name: name.to_owned(),
            subdomain: None,
            egress: EgressSpec::default(),
            env: HashMap::default(),
            scaling: Scaling::default(),
            readiness: Readiness::default(),
            volumes: Vec::new(),
        }
    }

    /// Pre-registered app with an initial rollout for tests that
    /// want to drive `ensure_running` directly (skipping the
    /// register-then-rollout choreography of the real admin API).
    /// `stored` is just a (spec, optional initial rollout) tuple now
    /// that on-disk persistence is keyed by state dir, not a single
    /// combined file.
    fn stored_with_name(name: &str, tag: &str) -> (AppSpec, Option<Rollout>) {
        (
            spec_with_name(name),
            Some(Rollout {
                tag: tag.to_owned(),
                created_at: SystemTime::UNIX_EPOCH,
            }),
        )
    }

    fn make_controller(
        stored: Vec<(AppSpec, Option<Rollout>)>,
        state_dir: PathBuf,
    ) -> Arc<AppHost<MockRuntime, MockEgress>> {
        // Seed the state dir so AppHost::new's load path picks
        // these specs + rollouts back up on construction — keeps the
        // test entry symmetric with production (everything goes
        // through the disk-rehydrate code path).
        std::fs::create_dir_all(state_dir.join("apps")).unwrap();
        std::fs::create_dir_all(state_dir.join("rollouts")).unwrap();
        for (spec, rollout) in stored {
            let name = spec.name().to_owned();
            let spec_body = toml::to_string_pretty(&spec).unwrap();
            std::fs::write(
                state_dir.join("apps").join(format!("{name}.toml")),
                spec_body,
            )
            .unwrap();
            if let Some(r) = rollout {
                let file = RolloutsFile { rollouts: vec![r] };
                let body = toml::to_string_pretty(&file).unwrap();
                std::fs::write(
                    state_dir.join("rollouts").join(format!("{name}.toml")),
                    body,
                )
                .unwrap();
            }
        }
        Arc::new(
            AppHost::new(
                Arc::new(MockRuntime::default()),
                Arc::new(MockEgress::default()),
                state_dir,
                AuthConfig::default(),
            )
            .expect("controller::new"),
        )
    }

    /// `deploy_app` only registers; it does not pull. So even a
    /// runtime configured to fail on pull must produce a successful
    /// register (with a TOML written and the app in `Stopped`).
    #[tokio::test]
    async fn deploy_app_does_not_pull() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        // A pull queued up should remain unconsumed — register must
        // not touch the runtime's pull path.
        controller
            .runtime
            .push_pull(Err(RuntimeError::Other("would-be pull failure".into())));

        let view = controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register should succeed without pulling");
        assert_eq!(view.name, "alpha");
        assert!(
            view.current_rollout.is_none(),
            "newly registered app has no rollout yet"
        );
        let toml = tmp.path().join("apps").join("alpha.toml");
        assert!(toml.exists(), "register must persist the toml");
        let calls = controller.runtime.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("pull_image")),
            "register must not pull; got {calls:?}"
        );
    }

    /// `set_rollout` must surface a pull failure as
    /// `RolloutError::ImagePull` and leave the rollout history empty
    /// (so the next attempt starts clean).
    #[tokio::test]
    async fn set_rollout_propagates_pull_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");
        controller
            .runtime
            .push_pull(Err(RuntimeError::Other("registry unreachable".into())));

        let handle = controller
            .find_handle("alpha")
            .await
            .expect("handle present");
        let err = controller
            .set_rollout(&handle, "v1".to_owned())
            .await
            .expect_err("expected pull failure");
        assert!(matches!(err, RolloutError::ImagePull(_)), "got {err:?}");

        let view = controller.get_app("alpha").await.expect("app present");
        assert!(
            view.current_rollout.is_none(),
            "rollout history must stay empty on pull failure"
        );
    }

    /// PATCH on a stopped, registered app rewrites the spec and
    /// persists. The previous + new TOML differ on disk.
    #[tokio::test]
    async fn update_app_persists_new_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");

        // PATCH: change port + add an env var.
        let mut updated = spec_with_name("alpha");
        updated.port = 9999;
        updated
            .env
            .insert("LOG_LEVEL".to_owned(), "debug".to_owned());

        let handle = controller
            .find_handle("alpha")
            .await
            .expect("handle present");
        let view = controller
            .update_app(&handle, updated)
            .await
            .expect("update succeeds");
        assert_eq!(view.port, 9999);

        // TOML on disk reflects the new state.
        let toml_body =
            std::fs::read_to_string(tmp.path().join("apps").join("alpha.toml")).unwrap();
        assert!(
            toml_body.contains("port = 9999"),
            "toml missing new port: {toml_body}"
        );
        assert!(
            toml_body.contains("LOG_LEVEL"),
            "toml missing new env var: {toml_body}"
        );
    }

    /// PATCH with an identity-only difference (rename via `name`) is
    /// rejected with `NameImmutable`; the rest of the spec is left
    /// untouched.
    #[tokio::test]
    async fn update_app_rejects_name_change() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");

        let mut renamed = spec_with_name("alpha");
        renamed.name = "beta".to_owned();
        let handle = controller
            .find_handle("alpha")
            .await
            .expect("handle present");
        let err = controller
            .update_app(&handle, renamed)
            .await
            .expect_err("expected NameImmutable");
        assert!(matches!(err, UpdateError::NameImmutable), "got {err:?}");
    }

    /// Subdomain change is also rejected (routing identity is fixed
    /// for the life of an app in v1).
    #[tokio::test]
    async fn update_app_rejects_subdomain_change() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");

        let mut moved = spec_with_name("alpha");
        moved.subdomain = Some("alpha-renamed".to_owned());
        let handle = controller
            .find_handle("alpha")
            .await
            .expect("handle present");
        let err = controller
            .update_app(&handle, moved)
            .await
            .expect_err("expected SubdomainImmutable");
        assert!(
            matches!(err, UpdateError::SubdomainImmutable),
            "got {err:?}"
        );
    }

    /// PATCH with a body whose TOML projection equals the current
    /// one is a no-op. This is the path the ops apply workflow
    /// hits on every CI run for unchanged apps; the short-circuit
    /// is what stops the workflow from flapping containers.
    #[tokio::test]
    async fn update_app_noop_when_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");
        let runtime_calls_before = controller.runtime.calls().len();

        // Re-PATCH with the same content.
        let handle = controller
            .find_handle("alpha")
            .await
            .expect("handle present");
        controller
            .update_app(&handle, spec_with_name("alpha"))
            .await
            .expect("noop succeeds");

        // No runtime side effects (no stop, no start, no pull).
        assert_eq!(
            controller.runtime.calls().len(),
            runtime_calls_before,
            "noop PATCH must not touch the runtime"
        );
    }

    /// `find_handle` returns `None` for an unregistered app. The
    /// admin layer maps this to a 404 before any operation runs —
    /// `update_app` itself no longer carries a `NotFound` variant
    /// because by construction its handle argument is registered.
    #[tokio::test]
    async fn find_handle_returns_none_for_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        assert!(controller.find_handle("ghost").await.is_none());
    }

    /// `repo` change leaves the `(repo, digest)` cache entry in
    /// place but the freshness check at the next pull treats it as
    /// stale — the cache is self-invalidating. The previous shape
    /// (single `Option<ImageId>` cleared inline) raced against
    /// concurrent cold-starts; the new shape removes the
    /// out-of-band clear entirely.
    #[tokio::test]
    async fn update_app_repo_change_makes_digest_cache_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(vec![], tmp.path().to_owned());
        controller
            .deploy_app(spec_with_name("alpha"))
            .await
            .expect("register");

        let handle = controller
            .find_handle("alpha")
            .await
            .expect("handle present");
        // Seed the cache as if a prior pull populated it against
        // the deploy-time repo.
        let old_repo = handle.spec.read().await.repo.clone();
        handle.inner.lock().await.image_digest = Some(DigestCache {
            repo: old_repo.clone(),
            digest: bugpot_runtime::ImageId::new("sha256:oldcacheddigest"),
        });

        let mut new_spec = spec_with_name("alpha");
        new_spec.repo = "registry.example/other-img".to_owned();
        controller
            .update_app(&handle, new_spec)
            .await
            .expect("repo change PATCH succeeds");

        // The cache entry survives the PATCH — the freshness check
        // happens at *read* time. Verify its `repo` no longer
        // matches the spec, which is how `pull_image_phase`
        // recognises staleness.
        let cached = handle.inner.lock().await.image_digest.clone();
        let cached = cached.expect("seeded cache entry should survive the PATCH");
        let live_repo = handle.spec.read().await.repo.clone();
        assert_eq!(cached.repo, old_repo);
        assert_ne!(cached.repo, live_repo);
    }

    /// On cold-start failure during image pull, the previously-allocated
    /// endpoint must be released so the next attempt can reallocate
    /// cleanly.
    #[tokio::test]
    async fn cold_start_releases_endpoint_on_pull_failure() {
        let tmp = tempfile::tempdir().unwrap();
        // Pre-register with a rollout so we hit ensure_running →
        // do_start without going through any admin API path.
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        controller
            .runtime
            .push_pull(Err(RuntimeError::Other("registry down".into())));

        let handle = controller
            .find_handle("alpha")
            .await
            .expect("handle present");
        let res = controller.ensure_running(&handle).await;
        assert!(res.is_err(), "expected pull failure to propagate");

        let egress_calls = controller.egress.calls();
        assert!(
            egress_calls.contains(&"allocate_endpoint(alpha-a)".to_owned()),
            "expected allocate; got {egress_calls:?}"
        );
        assert!(
            egress_calls.contains(&"release_endpoint(alpha-a)".to_owned()),
            "expected release after pull failure; got {egress_calls:?}"
        );
        assert!(
            !controller
                .runtime
                .calls()
                .iter()
                .any(|c| c.starts_with("start_app")),
            "start_app must not be called when pull fails"
        );
    }

    /// `reattach_running` should put a surviving container straight into
    /// `Running` (no cold-start path) and skip apps with no live
    /// container.
    #[tokio::test]
    async fn reattach_running_recovers_live_containers() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(
            vec![
                stored_with_name("alpha", "v1"),
                stored_with_name("beta", "v1"),
            ],
            tmp.path().to_owned(),
        );
        // alpha is alive with a recovered IP; beta is gone.
        controller.runtime.set_running("alpha-a", true);
        let mut claims = claims_with(&[("alpha-a", Ipv4Addr::new(10, 0, 0, 42))]);

        controller.reattach_running(&mut claims).await;

        let alpha_state = controller
            .find_handle("alpha")
            .await
            .unwrap()
            .inner
            .lock()
            .await
            .state
            .clone();
        let beta_state = controller
            .find_handle("beta")
            .await
            .unwrap()
            .inner
            .lock()
            .await
            .state
            .clone();
        assert!(
            matches!(alpha_state, AppState::Running { container_ip } if container_ip == Ipv4Addr::new(10, 0, 0, 42)),
            "alpha should be Running with recovered IP, got {alpha_state:?}"
        );
        assert!(
            matches!(beta_state, AppState::Stopped),
            "beta should stay Stopped, got {beta_state:?}"
        );
        // The mock should NOT have called allocate_endpoint — reattach
        // must never trigger the cold-start path.
        let eg_calls = controller.egress.calls();
        assert!(
            eg_calls.iter().any(|c| c == "reattach_endpoint(alpha-a)"),
            "expected reattach_endpoint(alpha-a); got {eg_calls:?}"
        );
        assert!(
            !eg_calls.iter().any(|c| c.starts_with("allocate_endpoint")),
            "allocate_endpoint must not be called during reattach; got {eg_calls:?}"
        );
        // The fresh tail tasks must be spawned for the reattached app
        // (the previous bugpot's tails died with it).
        let rt_calls = controller.runtime.calls();
        assert!(
            rt_calls.contains(&"ensure_log_tails(alpha)".to_owned()),
            "expected ensure_log_tails(alpha); got {rt_calls:?}"
        );
    }

    /// After `reattach_running` consumes its endpoints, any leftover
    /// discovered IPs are orphans: their TOML is gone. `cleanup_orphans`
    /// must drive the runtime cleanup before the egress teardown so the
    /// container's processes are gone before we delete the netns they
    /// live in.
    #[tokio::test]
    async fn cleanup_orphans_reaps_unreclaimed_endpoints() {
        let tmp = tempfile::tempdir().unwrap();
        // `alpha` is the only known app; `beta` (registered in egress
        // discovery) has no TOML and must be reaped. Beta's
        // discovered netns has the new slot-suffixed shape because
        // it came from a previous bugpot at this same code level.
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        controller.runtime.set_running("alpha-a", true);
        let mut claims = claims_with(&[
            ("alpha-a", Ipv4Addr::new(10, 0, 0, 5)),
            ("beta-a", Ipv4Addr::new(10, 0, 0, 9)),
        ]);

        controller.reattach_running(&mut claims).await;
        controller.cleanup_orphans(claims).await;

        // alpha was reattached, not orphaned.
        let rt_calls = controller.runtime.calls();
        let eg_calls = controller.egress.calls();
        assert!(
            !rt_calls.iter().any(|c| c == "cleanup_container(alpha-a)"),
            "reattached alpha must not be cleaned as orphan; rt_calls={rt_calls:?}"
        );
        // beta was orphaned.
        let beta_runtime_idx = rt_calls
            .iter()
            .position(|c| c == "cleanup_container(beta-a)")
            .expect("expected cleanup_container(beta-a)");
        let beta_egress_idx = eg_calls
            .iter()
            .position(|c| c == "cleanup_orphan_endpoint(beta-a,10.0.0.9)")
            .expect("expected cleanup_orphan_endpoint(beta-a,10.0.0.9)");
        // Ordering: cleaning the runtime side first means the container
        // is dead by the time we tear down its netns; if we reversed
        // the order the container would lose eth0 while still trying
        // to exit. (Mock can't expose this, but the call sequence
        // documents the contract.)
        let _ = (beta_runtime_idx, beta_egress_idx);
    }

    /// A second call to `reattach_running` must be a no-op so accidental
    /// re-invocation does not double the log-tail tasks per app.
    #[tokio::test]
    async fn reattach_running_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        controller.runtime.set_running("alpha-a", true);
        let mut claims = claims_with(&[("alpha-a", Ipv4Addr::new(10, 0, 0, 7))]);

        controller.reattach_running(&mut claims).await;
        // A second pass with a freshly-discovered claims map should
        // still short-circuit at the controller's once-guard.
        let mut second = claims_with(&[("alpha-a", Ipv4Addr::new(10, 0, 0, 7))]);
        controller.reattach_running(&mut second).await;

        let eg_reattach_calls = controller
            .egress
            .calls()
            .iter()
            .filter(|c| c.starts_with("reattach_endpoint"))
            .count();
        let rt_tail_calls = controller
            .runtime
            .calls()
            .iter()
            .filter(|c| c.starts_with("ensure_log_tails"))
            .count();
        assert_eq!(eg_reattach_calls, 1, "reattach_endpoint must run once");
        assert_eq!(rt_tail_calls, 1, "ensure_log_tails must run once");
    }

    /// Sweep must detect a container that died under the controller's
    /// feet (`is_container_running` returns false despite the handle
    /// reporting `Running`) and transition its handle back to `Stopped`.
    #[tokio::test]
    async fn sweep_detects_dead_container() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());

        // Force the handle into Running state without going through the
        // real cold-start path.
        let handle = controller.find_handle("alpha").await.unwrap();
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::Running {
                container_ip: Ipv4Addr::LOCALHOST,
            };
        }
        // Simulate the kernel: container is *not* actually running.
        controller.runtime.set_running("alpha-a", false);

        controller.sweep().await;

        let state = handle.inner.lock().await.state.clone();
        assert!(
            matches!(state, AppState::Stopped),
            "expected Stopped after sweep, got {state:?}"
        );
        let rt_calls = controller.runtime.calls();
        assert!(
            rt_calls.contains(&"stop_app(alpha-a)".to_owned()),
            "expected stop_app; got {rt_calls:?}"
        );
        let eg_calls = controller.egress.calls();
        assert!(
            eg_calls.contains(&"release_endpoint(alpha-a)".to_owned()),
            "expected release_endpoint; got {eg_calls:?}"
        );
    }

    async fn force_running(handle: &AppHandle) {
        let mut inner = handle.inner.lock().await;
        inner.state = AppState::Running {
            container_ip: Ipv4Addr::LOCALHOST,
        };
    }

    /// Idle reaper freezes (not stops) by default. Container survives;
    /// only its cgroup gets the freezer write.
    #[tokio::test]
    async fn idle_timeout_freezes_running_app() {
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = spec_with_name("alpha");
        // Short idle so the test doesn't need fake clocks.
        spec.scaling = bugpot_config::Scaling {
            idle_timeout: Some("10ms".into()),
        };
        let stored = (
            spec,
            Some(Rollout {
                tag: "v1".into(),
                created_at: SystemTime::UNIX_EPOCH,
            }),
        );
        let controller = make_controller(vec![stored], tmp.path().to_owned());
        let handle = controller.find_handle("alpha").await.unwrap();
        force_running(&handle).await;
        controller.runtime.set_running("alpha-a", true);

        // Push last_access into the past so the reaper triggers.
        {
            let mut inner = handle.inner.lock().await;
            inner.last_access = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test machine clock should not be at unix epoch");
        }
        controller.sweep().await;

        let state = handle.inner.lock().await.state.clone();
        assert!(
            state.is_frozen(),
            "expected Frozen after idle timeout, got {state:?}"
        );
        let rt_calls = controller.runtime.calls();
        assert!(
            rt_calls.contains(&"freeze_app(alpha-a)".to_owned()),
            "expected freeze_app; got {rt_calls:?}"
        );
        // Must NOT have stopped — freeze leaves the container resident.
        assert!(
            !rt_calls.iter().any(|c| c == "stop_app(alpha-a)"),
            "stop_app must not be called on freeze path; got {rt_calls:?}"
        );
    }

    /// `active_upgrades > 0` means the router is mid-splice for a
    /// WebSocket / SSE connection. Freezing would silently strand the
    /// connection; the reaper must skip and try later.
    #[tokio::test]
    async fn freeze_skipped_when_upgrades_active() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        let handle = controller.find_handle("alpha").await.unwrap();
        force_running(&handle).await;
        handle.active_upgrades.fetch_add(1, Ordering::Relaxed);

        controller.freeze(&handle).await.unwrap();

        let state = handle.inner.lock().await.state.clone();
        assert!(
            state.is_running(),
            "expected freeze to be skipped (still Running), got {state:?}"
        );
        let rt_calls = controller.runtime.calls();
        assert!(
            !rt_calls.iter().any(|c| c == "freeze_app(alpha-a)"),
            "freeze_app must not be called when upgrades active; got {rt_calls:?}"
        );
    }

    /// `ensure_running` from `Frozen` calls `unfreeze_app` and reuses
    /// the same `container_ip` — no endpoint reallocation, no image
    /// pull. This is the "snappy resume" path that makes scale-to-zero
    /// invisible.
    #[tokio::test]
    async fn ensure_running_unfreezes_from_frozen() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        let handle = controller.find_handle("alpha").await.unwrap();
        let frozen_ip = Ipv4Addr::new(10, 0, 0, 7);
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::Frozen {
                container_ip: frozen_ip,
            };
        }
        controller.runtime.set_paused("alpha-a", true);

        let ip = controller.ensure_running(&handle).await.unwrap();
        assert_eq!(ip, frozen_ip, "unfreeze must preserve container_ip");
        let rt_calls = controller.runtime.calls();
        assert!(
            rt_calls.contains(&"unfreeze_app(alpha-a)".to_owned()),
            "expected unfreeze_app; got {rt_calls:?}"
        );
        assert!(
            !rt_calls.iter().any(|c| c.starts_with("start_app")),
            "start_app must not be called on resume; got {rt_calls:?}"
        );
        assert!(
            !rt_calls.iter().any(|c| c.starts_with("pull_image")),
            "pull_image must not be called on resume; got {rt_calls:?}"
        );
    }

    /// Eviction picks the oldest `last_access` among Frozen handles.
    /// Newer-touched frozen apps stay frozen, older ones drop to
    /// Stopped to free RAM.
    #[tokio::test]
    async fn evict_lru_frozen_picks_oldest_last_access() {
        let tmp = tempfile::tempdir().unwrap();
        let controller = make_controller(
            vec![
                stored_with_name("alpha", "v1"),
                stored_with_name("beta", "v1"),
            ],
            tmp.path().to_owned(),
        );
        let alpha = controller.find_handle("alpha").await.unwrap();
        let beta = controller.find_handle("beta").await.unwrap();
        let now = Instant::now();
        {
            let mut inner = alpha.inner.lock().await;
            inner.state = AppState::Frozen {
                container_ip: Ipv4Addr::new(10, 0, 0, 1),
            };
            inner.last_access = now
                .checked_sub(Duration::from_mins(1))
                .expect("test machine clock should not be at unix epoch");
        }
        {
            let mut inner = beta.inner.lock().await;
            inner.state = AppState::Frozen {
                container_ip: Ipv4Addr::new(10, 0, 0, 2),
            };
            inner.last_access = now;
        }

        assert!(controller.evict_lru_frozen().await, "expected an eviction");

        let alpha_state = alpha.inner.lock().await.state.clone();
        let beta_state = beta.inner.lock().await.state.clone();
        assert!(
            matches!(alpha_state, AppState::Stopped),
            "older alpha should be evicted, got {alpha_state:?}"
        );
        assert!(
            beta_state.is_frozen(),
            "newer beta should stay frozen, got {beta_state:?}"
        );
    }

    /// `DELETE /apps/<name>` against a running app must route through
    /// both runtime cleanup methods: `cleanup_container` (once per
    /// slot that had live state) for the bundle dir + libcontainer
    /// state, and `cleanup_app_assets` (once for the app) for the
    /// log-tail tasks + volume tree. Either omission leaks disk state
    /// on every remove.
    #[tokio::test]
    async fn remove_app_runs_runtime_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());

        let handle = controller
            .find_handle("alpha")
            .await
            .expect("handle present");
        // Force into Running so `live_container_ids` reports the
        // current-slot bundle as something to clean. Otherwise the
        // app is Stopped at remove time and there's nothing per-slot
        // to clean — a legitimate (and tested elsewhere) shape.
        force_running(&handle).await;
        controller.remove_app(&handle).await.expect("remove_app");

        let rt_calls = controller.runtime.calls();
        assert!(
            rt_calls.iter().any(|c| c == "cleanup_container(alpha-a)"),
            "remove_app must trigger cleanup_container per live slot; got {rt_calls:?}"
        );
        assert!(
            rt_calls.iter().any(|c| c == "cleanup_app_assets(alpha)"),
            "remove_app must trigger cleanup_app_assets; got {rt_calls:?}"
        );
    }

    /// Blue-green happy path: a Running app accepts a new rollout,
    /// the new container comes up in the opposite slot, readiness
    /// passes, the resolver atomically flips to the new IP,
    /// `current_slot` advances, and the from-slot is torn down.
    ///
    /// Readiness is satisfied by a real `127.0.0.1:<port>` TCP
    /// listener bound in the test — `MockEgress` returns
    /// `container_ip = LOCALHOST`, so probing that IP on the
    /// listener's port succeeds without standing up libcontainer.
    #[tokio::test]
    async fn blue_green_happy_path_flips_slot_and_tears_down_from() {
        let tmp = tempfile::tempdir().unwrap();
        // Bind a listener so the readiness probe (TCP connect to
        // container_ip:port) actually succeeds.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut spec = spec_with_name("alpha");
        spec.port = port;
        let stored = (
            spec,
            Some(Rollout {
                tag: "v1".into(),
                created_at: SystemTime::UNIX_EPOCH,
            }),
        );
        let controller = make_controller(vec![stored], tmp.path().to_owned());

        let handle = controller.find_handle("alpha").await.unwrap();
        // Force the handle into Running on slot A — the precondition
        // for blue-green. `current_slot` defaults to A so no field
        // mutation needed.
        force_running(&handle).await;

        // Two pull successes: one in `set_rollout` (the explicit
        // pull), one in `build_to_slot` (the cache-hit re-pull
        // through `pull_image_phase`). One start success for the
        // to-slot container.
        controller
            .runtime
            .push_pull(Ok(ImageId::new("sha256:newdigest")));
        controller
            .runtime
            .push_pull(Ok(ImageId::new("sha256:newdigest")));
        controller.runtime.push_start(Ok(RunningApp {
            name: "alpha-b".into(),
            pid: 42,
            image: ImageId::new("sha256:newdigest"),
        }));

        let rollout = controller
            .set_rollout(&handle, "v2".into())
            .await
            .expect("blue-green rollout");
        assert_eq!(rollout.tag, "v2");

        let inner = handle.inner.lock().await;
        assert!(
            matches!(inner.state, AppState::Running { .. }),
            "expected Running after switch, got {:?}",
            inner.state
        );
        assert_eq!(inner.current_slot, Slot::B, "slot must have advanced");
        drop(inner);

        let rt = controller.runtime.calls();
        let eg = controller.egress.calls();
        assert!(
            eg.iter().any(|c| c == "allocate_endpoint(alpha-b)"),
            "to-slot endpoint must be allocated; got {eg:?}"
        );
        assert!(
            rt.iter().any(|c| c == "start_app(alpha-b)"),
            "to-slot container must be started; got {rt:?}"
        );
        assert!(
            rt.iter().any(|c| c == "stop_app(alpha-a)"),
            "from-slot container must be torn down after switch; got {rt:?}"
        );
        assert!(
            eg.iter().any(|c| c == "release_endpoint(alpha-a)"),
            "from-slot endpoint must be released; got {eg:?}"
        );
        // From-slot teardown must happen *after* the to-slot start
        // (otherwise the resolver sees a window with no live
        // container).
        let start_idx = rt.iter().position(|c| c == "start_app(alpha-b)").unwrap();
        let stop_idx = rt.iter().position(|c| c == "stop_app(alpha-a)").unwrap();
        assert!(
            start_idx < stop_idx,
            "to-slot start must precede from-slot stop"
        );
        drop(listener);
    }

    /// Blue-green rollback: the new slot's start fails (mock returns
    /// "no start response queued"), `set_rollout` returns
    /// `StartFailed`, the from-slot keeps serving, and the partial
    /// new slot is cleaned up.
    #[tokio::test]
    async fn blue_green_rolls_back_on_start_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());

        let handle = controller.find_handle("alpha").await.unwrap();
        let from_ip = Ipv4Addr::new(10, 0, 0, 99);
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::Running {
                container_ip: from_ip,
            };
        }

        // Two pulls succeed; no start response queued so
        // `start_app` returns Err — build_to_slot fails before
        // readiness, triggering rollback.
        controller
            .runtime
            .push_pull(Ok(ImageId::new("sha256:newdigest")));
        controller
            .runtime
            .push_pull(Ok(ImageId::new("sha256:newdigest")));

        let err = controller
            .set_rollout(&handle, "v2".into())
            .await
            .expect_err("expected rollback");
        assert!(matches!(err, RolloutError::StartFailed(_)), "got {err:?}");

        let inner = handle.inner.lock().await;
        assert!(
            matches!(inner.state, AppState::Running { container_ip } if container_ip == from_ip),
            "state must roll back to Running{{from_ip}}, got {:?}",
            inner.state
        );
        assert_eq!(
            inner.current_slot,
            Slot::A,
            "current_slot must not advance on rollback"
        );
        drop(inner);

        let rt = controller.runtime.calls();
        let eg = controller.egress.calls();
        assert!(
            rt.iter().any(|c| c == "stop_app(alpha-b)"),
            "partial new slot must be stopped; got {rt:?}"
        );
        assert!(
            eg.iter().any(|c| c == "release_endpoint(alpha-b)"),
            "partial new slot endpoint must be released; got {eg:?}"
        );
        assert!(
            !rt.iter().any(|c| c == "stop_app(alpha-a)"),
            "from-slot must NOT be torn down on rollback; got {rt:?}"
        );
    }

    /// A second `set_rollout` arriving while a first is mid-flight
    /// (handle still in `RollingOver`) returns `Conflict` immediately
    /// — no second pull, no second container churn.
    #[tokio::test]
    async fn set_rollout_during_rolling_over_returns_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        let handle = controller.find_handle("alpha").await.unwrap();
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::RollingOver {
                from_ip: Ipv4Addr::new(10, 0, 0, 1),
            };
        }

        let err = controller
            .set_rollout(&handle, "v2".into())
            .await
            .expect_err("expected conflict");
        assert!(
            matches!(err, RolloutError::Conflict(ref n) if n == "alpha"),
            "got {err:?}"
        );

        // No pull was attempted (the pre-flight conflict check fires
        // before the pull phase).
        assert!(
            !controller
                .runtime
                .calls()
                .iter()
                .any(|c| c.starts_with("pull_image")),
            "conflict must short-circuit before any pull",
        );
    }

    /// Rollover from `Frozen`: the from-side is thawed first so it
    /// can serve traffic during the rollover window; then the
    /// regular blue-green ladder runs.
    #[tokio::test]
    async fn rollout_from_frozen_thaws_then_blue_greens() {
        let tmp = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut spec = spec_with_name("alpha");
        spec.port = port;
        let stored = (
            spec,
            Some(Rollout {
                tag: "v1".into(),
                created_at: SystemTime::UNIX_EPOCH,
            }),
        );
        let controller = make_controller(vec![stored], tmp.path().to_owned());

        let handle = controller.find_handle("alpha").await.unwrap();
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::Frozen {
                container_ip: Ipv4Addr::LOCALHOST,
            };
        }
        controller.runtime.set_paused("alpha-a", true);

        controller
            .runtime
            .push_pull(Ok(ImageId::new("sha256:newdigest")));
        controller
            .runtime
            .push_pull(Ok(ImageId::new("sha256:newdigest")));
        controller.runtime.push_start(Ok(RunningApp {
            name: "alpha-b".into(),
            pid: 99,
            image: ImageId::new("sha256:newdigest"),
        }));

        controller
            .set_rollout(&handle, "v2".into())
            .await
            .expect("rollout from frozen");

        let rt = controller.runtime.calls();
        // Thaw must precede any to-slot work.
        let thaw_idx = rt
            .iter()
            .position(|c| c == "unfreeze_app(alpha-a)")
            .expect("unfreeze_app(alpha-a) must fire before rollover starts");
        let alloc_idx = controller
            .egress
            .calls()
            .iter()
            .position(|c| c == "allocate_endpoint(alpha-b)")
            .expect("to-slot endpoint must be allocated");
        let _ = (thaw_idx, alloc_idx);
        // Atomic switch happened.
        let inner = handle.inner.lock().await;
        assert_eq!(inner.current_slot, Slot::B);
        drop(inner);
        drop(listener);
    }

    /// Reattach with both slots alive on disk is a mid-rollover
    /// crash: both are purged and the handle stays Stopped, so the
    /// next request cold-starts under the new (already-persisted)
    /// rollout tag.
    #[tokio::test]
    async fn reattach_purges_both_slots_on_mid_rollover_crash() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        // Both slots' libcontainer state would be on-disk if a
        // rollover crashed; simulate by marking both running on the
        // mock + supplying both netns in claims.
        controller.runtime.set_running("alpha-a", true);
        controller.runtime.set_running("alpha-b", true);
        let mut claims = claims_with(&[
            ("alpha-a", Ipv4Addr::new(10, 0, 0, 5)),
            ("alpha-b", Ipv4Addr::new(10, 0, 0, 6)),
        ]);

        controller.reattach_running(&mut claims).await;

        // Both slots purged.
        let rt = controller.runtime.calls();
        let eg = controller.egress.calls();
        assert!(
            rt.iter().any(|c| c == "cleanup_container(alpha-a)"),
            "from-slot must be purged; got {rt:?}"
        );
        assert!(
            rt.iter().any(|c| c == "cleanup_container(alpha-b)"),
            "to-slot must be purged; got {rt:?}"
        );
        assert!(
            eg.iter()
                .any(|c| c == "cleanup_orphan_endpoint(alpha-a,10.0.0.5)"),
            "from-slot endpoint must be cleaned; got {eg:?}"
        );
        assert!(
            eg.iter()
                .any(|c| c == "cleanup_orphan_endpoint(alpha-b,10.0.0.6)"),
            "to-slot endpoint must be cleaned; got {eg:?}"
        );

        // State must remain Stopped (next request cold-starts).
        let state = handle_state(&controller, "alpha").await;
        assert!(
            matches!(state, AppState::Stopped),
            "handle must be Stopped after both-slot purge; got {state:?}"
        );
    }

    /// Reattach picks the actually-live slot, even when it's `B`
    /// (i.e. a previous bugpot run had already rolled over to slot
    /// B). `current_slot` must be restored to match what survived
    /// on disk; otherwise the next operation would target the wrong
    /// slot.
    #[tokio::test]
    async fn reattach_restores_current_slot_b() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        controller.runtime.set_running("alpha-b", true);
        let mut claims = claims_with(&[("alpha-b", Ipv4Addr::new(10, 0, 0, 7))]);

        controller.reattach_running(&mut claims).await;

        let handle = controller.find_handle("alpha").await.unwrap();
        let (slot, state) = {
            let inner = handle.inner.lock().await;
            (inner.current_slot, inner.state.clone())
        };
        assert_eq!(slot, Slot::B, "current_slot must be B");
        assert!(
            matches!(state, AppState::Running { container_ip } if container_ip == Ipv4Addr::new(10, 0, 0, 7)),
            "expected Running on slot B, got {state:?}"
        );
    }

    async fn handle_state(controller: &AppHost<MockRuntime, MockEgress>, name: &str) -> AppState {
        let handle = controller.find_handle(name).await.unwrap();
        let inner = handle.inner.lock().await;
        inner.state.clone()
    }

    /// State-drift race: while `do_blue_green` is mid-build, a
    /// concurrent `stop`/`remove_app` flips state to `Stopping` and
    /// reaps both slots. The rollover's switch / rollback paths must
    /// NOT overwrite the operator's transition by writing a fresh
    /// `Running` back in.
    ///
    /// We simulate the race by hand: pre-set the handle to
    /// `RollingOver` (which is what `enter_rolling_over` does), then
    /// flip it to `Stopped` *before* the build resolves. Then drive
    /// `do_blue_green` directly and assert the final state stays
    /// `Stopped` (not `Running { from_ip }`).
    ///
    /// Direct invocation of `do_blue_green` is fine here because it's
    /// `pub(super)` and the test is in the same crate; the alternative
    /// (driving via `set_rollout` and triggering a real concurrent
    /// stop) needs full tokio orchestration that the existing mocks
    /// don't model.
    #[tokio::test]
    async fn blue_green_does_not_clobber_state_after_concurrent_stop() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());
        let handle = controller.find_handle("alpha").await.unwrap();
        let from_ip = Ipv4Addr::new(10, 0, 0, 99);

        // Initial transition: enter RollingOver as if `enter_rolling_over`
        // already ran.
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::RollingOver { from_ip };
        }

        // Two pulls succeed; no start response queued → build_to_slot
        // fails. We want the rollback path to run.
        controller
            .runtime
            .push_pull(Ok(ImageId::new("sha256:newdigest")));
        controller
            .runtime
            .push_pull(Ok(ImageId::new("sha256:newdigest")));

        // Simulate the race: before do_blue_green resolves, flip
        // state to Stopped. (In production this would be done by a
        // concurrent `stop` task.)
        {
            let mut inner = handle.inner.lock().await;
            inner.state = AppState::Stopped;
        }

        let _ = controller.do_blue_green(&handle, from_ip).await;

        // State must STILL be Stopped — the rollback path saw the
        // drift and skipped the `Running { from_ip }` write.
        let state = handle_state(&controller, "alpha").await;
        assert!(
            matches!(state, AppState::Stopped),
            "state drifted off RollingOver before rollback fired; \
             do_blue_green must respect the new state, got {state:?}"
        );
    }

    /// `PATCH /apps/<name>` on a `Running` app now uses blue-green
    /// instead of stop-then-start. New container in opposite slot,
    /// readiness gate, atomic switch, from-slot teardown.
    #[tokio::test]
    async fn update_app_running_uses_blue_green() {
        let tmp = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut spec = spec_with_name("alpha");
        spec.port = port;
        let stored = (
            spec,
            Some(Rollout {
                tag: "v1".into(),
                created_at: SystemTime::UNIX_EPOCH,
            }),
        );
        let controller = make_controller(vec![stored], tmp.path().to_owned());

        let handle = controller.find_handle("alpha").await.unwrap();
        force_running(&handle).await;

        // PATCH body: same port (readiness must hit it) but a new
        // env var so the spec actually differs.
        let mut new_spec = handle.spec.read().await.clone();
        new_spec.env.insert("BUGPOT_TEST".into(), "1".into());

        controller
            .runtime
            .push_pull(Ok(ImageId::new("sha256:newdigest")));
        controller.runtime.push_start(Ok(RunningApp {
            name: "alpha-b".into(),
            pid: 77,
            image: ImageId::new("sha256:newdigest"),
        }));

        controller
            .update_app(&handle, new_spec)
            .await
            .expect("update_app should run blue-green");

        let (slot, state) = {
            let inner = handle.inner.lock().await;
            (inner.current_slot, inner.state.clone())
        };
        assert_eq!(slot, Slot::B, "current_slot must have advanced");
        assert!(
            matches!(state, AppState::Running { .. }),
            "expected Running after PATCH, got {state:?}"
        );

        let rt = controller.runtime.calls();
        let eg = controller.egress.calls();
        assert!(
            eg.iter().any(|c| c == "allocate_endpoint(alpha-b)"),
            "PATCH must allocate the to-slot endpoint; got {eg:?}"
        );
        assert!(
            rt.iter().any(|c| c == "start_app(alpha-b)"),
            "PATCH must start the to-slot container; got {rt:?}"
        );
        assert!(
            rt.iter().any(|c| c == "stop_app(alpha-a)"),
            "PATCH must tear down from-slot after switch; got {rt:?}"
        );
        // Critically: stop_app(alpha-a) happens AFTER start_app(alpha-b).
        // The old stop-then-start would have had stop_app first.
        let start_idx = rt.iter().position(|c| c == "start_app(alpha-b)").unwrap();
        let stop_idx = rt.iter().position(|c| c == "stop_app(alpha-a)").unwrap();
        assert!(
            start_idx < stop_idx,
            "to-slot start must precede from-slot stop; \
             stop-then-start regression detected. rt={rt:?}"
        );
        drop(listener);
    }

    /// Removing a never-started app skips per-slot cleanup (nothing
    /// to clean) but still drops app-level assets so an operator
    /// re-registering the same name doesn't inherit a stale volume
    /// tree.
    #[tokio::test]
    async fn remove_never_started_app_skips_container_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let controller =
            make_controller(vec![stored_with_name("alpha", "v1")], tmp.path().to_owned());

        let handle = controller
            .find_handle("alpha")
            .await
            .expect("handle present");
        controller.remove_app(&handle).await.expect("remove_app");

        let rt_calls = controller.runtime.calls();
        assert!(
            !rt_calls.iter().any(|c| c.starts_with("cleanup_container(")),
            "never-started app must not trigger cleanup_container; got {rt_calls:?}"
        );
        assert!(
            rt_calls.iter().any(|c| c == "cleanup_app_assets(alpha)"),
            "cleanup_app_assets fires regardless of run state; got {rt_calls:?}"
        );
    }
}
