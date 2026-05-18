//! Registry-facing CRUD: register / update / unregister / list / get
//! / lookup. These methods compose [`Registry`] (in-memory ownership)
//! and [`AppStore`] (TOML persistence) with the lifecycle methods
//! (`stop`, `ensure_running`, etc.) defined in `ops/lifecycle.rs`.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use bugpot_config::AppSpec;
use bugpot_egress::EgressOps;
use bugpot_runtime::RuntimeOps;
use metrics::gauge;
use tracing::warn;

use crate::handle::{AppHandle, make_handle};
use crate::registry::InsertCollision;
use crate::view::view_of;
use crate::{AppHost, AppView, DeployError, RemoveError, UpdateError};

impl<R: RuntimeOps, E: EgressOps> AppHost<R, E> {
    /// Register a new app. Fails if an app with the same name or
    /// subdomain already exists. **Does not pull an image or start a
    /// container** — the new app exists in `Stopped` state with no
    /// rollouts. Operators (or `set_rollout` from the admin API)
    /// supply the first rollout in a separate step, which is what
    /// actually pulls and starts.
    pub async fn deploy_app(&self, spec: AppSpec) -> std::result::Result<AppView, DeployError> {
        // Strict validation BEFORE we touch the filesystem — `name`
        // lands in `<state>/apps/<name>.toml` and `bugpot-<name>` netns
        // names, and the admin API accepts arbitrary JSON.
        spec.validate()?;
        let name = spec.name.clone();
        let subdomain = spec.subdomain().to_owned();

        // Fast-fail on obvious collisions before doing disk I/O. The
        // authoritative check is the `try_insert` below, under the
        // write lock; this just saves a TOML write on the rare
        // race-loser case.
        if let Some(collision) = self.registry.would_collide(&name, &subdomain).await {
            return Err(match collision {
                InsertCollision::NameTaken => DeployError::AlreadyExists(name),
                InsertCollision::SubdomainTaken => DeployError::SubdomainTaken(subdomain),
            });
        }

        let toml_path = self.store.spec_path(&name);
        let toml_body =
            toml::to_string_pretty(&spec).with_context(|| format!("serialize app for {name}"))?;
        tokio::fs::write(&toml_path, toml_body)
            .await
            .with_context(|| format!("write {}", toml_path.display()))?;

        let handle = make_handle(spec.clone(), None)?;

        if let Err(collision) = self.registry.try_insert(Arc::clone(&handle)).await {
            self.store.discard_failed_spec(&name).await;
            return Err(match collision {
                InsertCollision::NameTaken => DeployError::AlreadyExists(name),
                InsertCollision::SubdomainTaken => DeployError::SubdomainTaken(subdomain),
            });
        }
        gauge!("bugpot_apps_active").increment(1.0);

        Ok(view_of(&handle).await)
    }

    /// Update an existing app's config in place.
    ///
    /// PATCH semantics — `new_spec` is the new desired state for
    /// every mutable field; `name` and `subdomain` are identity and
    /// rejected for change (rename = delete + recreate).
    ///
    /// Behaviour:
    ///   - Mid-transition (`Starting` / `Stopping`) → 409 Conflict.
    ///   - No effective change (TOML round-trip equal) → no-op
    ///     returning the current view. Lets the ops apply workflow
    ///     PATCH unconditionally without restarting containers on
    ///     every CI run.
    ///   - Spec changed → persist new TOML and (if the app was
    ///     `Running`) stop + start it so the new config takes
    ///     effect. The current rollout history is preserved. The
    ///     per-handle `image_digest` cache (a `DigestCache` that
    ///     records the `repo` it was resolved against) needs no
    ///     explicit invalidation — `pull_image_phase`'s freshness
    ///     check ignores entries whose `repo` no longer matches
    ///     `spec.repo`.
    pub async fn update_app(
        &self,
        handle: &Arc<AppHandle>,
        new_spec: AppSpec,
    ) -> std::result::Result<AppView, UpdateError> {
        new_spec.validate()?;

        let name = handle.name();

        // Identity guards: PATCH cannot change `name` / `subdomain`.
        // The body must carry a `name` field (required by `AppSpec`)
        // and it must equal the URL path's app name.
        if new_spec.name != name {
            return Err(UpdateError::NameImmutable);
        }
        if new_spec.subdomain() != handle.identity.subdomain {
            return Err(UpdateError::SubdomainImmutable);
        }

        {
            let inner = handle.inner.lock().await;
            if inner.state.is_busy() {
                return Err(UpdateError::Conflict(name.to_owned()));
            }
        }

        // Short-circuit if nothing changed in the TOML projection.
        // `source_path` is `#[serde(skip)]`, so two specs whose
        // serialised TOML matches are functionally identical.
        let existing = handle.spec.read().await.clone();
        let logically_equal = match (toml::to_string(&existing), toml::to_string(&new_spec)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        if logically_equal {
            return Ok(view_of(handle).await);
        }

        let was_running = handle.inner.lock().await.state.is_running();

        // Replace under the write lock. The digest cache doesn't
        // need an explicit clear — `DigestCache` carries the `repo`
        // it was resolved against, so a subsequent pull-phase
        // freshness check ignores any cache entry whose `repo` no
        // longer matches `spec.repo`. That removes the
        // "update + concurrent cold-start races and persists a
        // stale (new_repo, old_digest) pair" window the old
        // out-of-band invalidation allowed.
        {
            let mut guard = handle.spec.write().await;
            *guard = new_spec.clone();
        }

        if let Err(e) = self.store.persist_spec(handle).await {
            return Err(UpdateError::Internal(e));
        }

        if was_running {
            self.restart_after_spec_change(handle).await?;
        }

        Ok(view_of(handle).await)
    }

    /// Stop + start cycle for an app whose spec was just rewritten.
    /// Errors map to [`UpdateError::RestartFailed`] with a phase
    /// label so operators can tell whether the failure was on the
    /// way down or on the way back up.
    async fn restart_after_spec_change(
        &self,
        handle: &Arc<AppHandle>,
    ) -> std::result::Result<(), UpdateError> {
        if let Err(e) = self.stop(handle).await {
            return Err(UpdateError::RestartFailed(anyhow!(
                "stop before reconfigure: {e:#}"
            )));
        }
        self.ensure_running(handle)
            .await
            .map(|_| ())
            .map_err(|e| UpdateError::RestartFailed(anyhow!("restart after reconfigure: {e:#}")))
    }

    /// Unregister an app. Stops the container (if running), drops
    /// the registry entries, and deletes the on-disk spec + rollouts
    /// files. Caller proves the handle is registered (by passing the
    /// value from `find_handle`); concurrent removes of the same
    /// app collapse harmlessly to a single registry mutation.
    pub async fn remove_app(
        &self,
        handle: &Arc<AppHandle>,
    ) -> std::result::Result<(), RemoveError> {
        self.do_remove(handle).await.map_err(RemoveError::Internal)
    }

    async fn do_remove(&self, handle: &Arc<AppHandle>) -> Result<()> {
        let name = handle.name();
        // Snapshot the live containers *before* `stop()` flips state
        // to Stopping (after which `live_container_ids` would shrink
        // to just the current slot and we'd lose a mid-rollover
        // off-slot bundle to leak).
        let live_ids = handle.inner.lock().await.live_container_ids(name);
        self.registry.remove(name, handle.subdomain()).await;
        gauge!("bugpot_apps_active").decrement(1.0);
        if let Err(e) = self.stop(handle).await {
            warn!(app = %name, error = ?e, "stop failed during remove");
        }
        // Per-container teardown: bundle dir + libcontainer state for
        // every slot that had live state at remove time. `stop()`
        // already killed the processes; this reclaims their on-disk
        // bookkeeping.
        for cid in &live_ids {
            if let Err(e) = self.runtime.cleanup_container(cid).await {
                warn!(
                    app = %name,
                    container = %cid,
                    error = ?e,
                    "cleanup_container failed during remove; bundle dir may leak",
                );
            }
        }
        // App-level: log-tail tasks + the volume host dir. Once per
        // remove, regardless of slot count.
        if let Err(e) = self.runtime.cleanup_app_assets(name).await {
            warn!(
                app = %name,
                error = ?e,
                "cleanup_app_assets failed during remove; volume dir may leak",
            );
        }
        self.store.remove(name).await;
        Ok(())
    }

    pub async fn list_apps(&self) -> Vec<AppView> {
        let mut views = Vec::new();
        for handle in self.list_handles().await {
            views.push(view_of(&handle).await);
        }
        views
    }

    pub async fn get_app(&self, name: &str) -> Option<AppView> {
        let handle = self.find_handle(name).await?;
        Some(view_of(&handle).await)
    }

    /// The single read-side lookup: `name → Arc<AppHandle>`. All other
    /// callers (admin auth middleware, operation methods, view
    /// builders) compose on top of this so the registry's read
    /// access path lives in exactly one place.
    pub async fn find_handle(&self, name: &str) -> Option<Arc<AppHandle>> {
        self.registry.find_by_name(name).await
    }

    /// Snapshot of every registered handle. Ordering is undefined —
    /// callers that need a stable presentation order sort downstream.
    pub async fn list_handles(&self) -> Vec<Arc<AppHandle>> {
        self.registry.list().await
    }
}
