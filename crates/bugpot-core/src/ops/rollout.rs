//! Image rollout pipeline: pull → record → restart.
//!
//! Sequenced with the lifecycle methods (`stop`, `ensure_running`)
//! defined in `lifecycle.rs` and the digest-cache update co-located
//! with the rollouts deque so the two stay atomic.

use std::sync::Arc;
use std::time::SystemTime;

use bugpot_config::Rollout;
use bugpot_egress::EgressOps;
use bugpot_runtime::{ImageId, RuntimeOps};
use tracing::warn;

use crate::AppHost;
use crate::RolloutError;
use crate::error::classify_pull_error_for_rollout;
use crate::handle::{AppHandle, DigestCache, MAX_ROLLOUT_HISTORY};

impl<R: RuntimeOps, E: EgressOps> AppHost<R, E> {
    /// Append a new rollout to `name` and bring the app to that tag.
    ///
    /// Steps:
    ///   1. Pull `{repo}:{tag}`.
    ///   2. Push to the rollout history (popping the oldest entry
    ///      when the deque is full).
    ///   3. Persist `<apps_dir>/<name>.toml` with the new current
    ///      rollout.
    ///   4. If the app is `Running`, stop it; then start under the
    ///      new rollout.
    ///   5. If `Stopped`, start now (so callers observe a deployed
    ///      app on return).
    ///   6. If `Starting` / `Stopping`, return [`RolloutError::Conflict`]
    ///      and let the caller retry.
    pub async fn set_rollout(
        &self,
        handle: &Arc<AppHandle>,
        tag: String,
    ) -> std::result::Result<Rollout, RolloutError> {
        if tag.trim().is_empty() {
            return Err(RolloutError::EmptyTag);
        }
        let name = handle.name().to_owned();

        // Conflict check: refuse mid-transition. Done before pull so
        // we don't waste a registry round-trip on a doomed call.
        {
            let inner = handle.inner.lock().await;
            if inner.state.is_busy() {
                return Err(RolloutError::Conflict(name));
            }
        }

        // 1. Pull. Capture `repo` here so the digest we cache below
        // is paired with the exact value the pull resolved against —
        // a concurrent PATCH that changes `repo` mid-flight produces
        // a (new_repo, ?) on the spec side and our cache stays
        // (old_repo, old_digest), self-invalidating on next read.
        let repo = handle.spec.read().await.repo.clone();
        let resolved_digest = self.pull_for_rollout(handle, &repo, &tag).await?;

        // 2. Append to history and update the digest cache so the
        // next `do_start` uses *this* rollout's digest, not the
        // previous rollout's (which may have been a different tag).
        let rollout = Rollout {
            tag,
            created_at: SystemTime::now(),
        };
        record_rollout(handle, rollout.clone(), repo, resolved_digest).await;

        // 3. Persist the rollout to its own state file. Spec doesn't
        // change here, so no spec rewrite needed.
        if let Err(e) = self.store.persist_rollouts(handle).await {
            warn!(app = %name, error = ?e, "failed to persist rollouts");
        }

        // 4 + 5: bring the container to the new image. If it was
        // running, stop first so the start uses the new digest cache.
        let was_running = handle.inner.lock().await.state.is_running();
        if was_running && let Err(e) = self.stop(handle).await {
            warn!(app = %name, error = ?e, "stop before rollout-restart failed");
        }
        if let Err(e) = self.ensure_running(handle).await {
            return Err(RolloutError::StartFailed(e));
        }

        Ok(rollout)
    }

    /// Pull `{repo}:{tag}` for an in-flight `set_rollout`. Classifies
    /// auth-side failures into the dedicated [`RolloutError::ImageAuth`]
    /// variant so adapter crates can distinguish them from generic
    /// `ImagePull` errors.
    async fn pull_for_rollout(
        &self,
        handle: &AppHandle,
        repo: &str,
        tag: &str,
    ) -> std::result::Result<ImageId, RolloutError> {
        let name = &handle.identity.name;
        let image_ref = format!("{repo}:{tag}");
        self.runtime
            .pull_image(&image_ref, self.resolve_auth(repo))
            .await
            .map_err(|e| classify_pull_error_for_rollout(e, name, &image_ref))
    }

    /// Return a snapshot of the rollout history (front = oldest,
    /// back = current). Caller is responsible for proving the
    /// handle is registered — pass the value from `find_handle`.
    pub async fn list_rollouts(&self, handle: &Arc<AppHandle>) -> Vec<Rollout> {
        handle.inner.lock().await.rollouts.iter().cloned().collect()
    }
}

/// Append a freshly-minted rollout to the handle's history (popping
/// the oldest entry when the deque is full) and overwrite the
/// per-handle image-digest cache. Held under `inner` for a single
/// critical section so the rollouts + digest move atomically — a
/// concurrent `view_of` either sees both updates or neither.
async fn record_rollout(handle: &Arc<AppHandle>, rollout: Rollout, repo: String, digest: ImageId) {
    let mut inner = handle.inner.lock().await;
    while inner.rollouts.len() >= MAX_ROLLOUT_HISTORY {
        inner.rollouts.pop_front();
    }
    inner.rollouts.push_back(rollout);
    inner.image_digest = Some(DigestCache { repo, digest });
}
