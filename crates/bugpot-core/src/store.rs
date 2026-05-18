//! On-disk shadow of `bugpot-core`'s in-memory state.
//!
//! Each registered app has up to two TOML files under
//! `<state>/apps/<name>.toml` (the `AppSpec`) and
//! `<state>/rollouts/<name>.toml` (the rollout history). Both are
//! bugpot-written; operators never edit them directly (every spec
//! mutation goes through the admin API).
//!
//! `AppStore` is a thin I/O wrapper — no in-memory caching, no
//! invariants beyond "write what the caller gives". The registry
//! owns the in-memory truth; the store mirrors it.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bugpot_config::{AppSpec, Rollout};
use tracing::warn;

use crate::handle::AppHandle;
use crate::persist::{RolloutsFile, load_persisted_state};

#[derive(Debug)]
pub(crate) struct AppStore {
    state_dir: PathBuf,
}

impl AppStore {
    pub(crate) const fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }

    pub(crate) fn specs_dir(&self) -> PathBuf {
        self.state_dir.join("apps")
    }

    pub(crate) fn rollouts_dir(&self) -> PathBuf {
        self.state_dir.join("rollouts")
    }

    pub(crate) fn spec_path(&self, name: &str) -> PathBuf {
        self.specs_dir().join(format!("{name}.toml"))
    }

    pub(crate) fn rollouts_path(&self, name: &str) -> PathBuf {
        self.rollouts_dir().join(format!("{name}.toml"))
    }

    /// Ensure the on-disk layout exists. Idempotent across restarts.
    pub(crate) fn ensure_dirs(&self) -> Result<()> {
        let specs = self.specs_dir();
        std::fs::create_dir_all(&specs).with_context(|| format!("create {}", specs.display()))?;
        let rollouts = self.rollouts_dir();
        std::fs::create_dir_all(&rollouts)
            .with_context(|| format!("create {}", rollouts.display()))?;
        Ok(())
    }

    /// Read every persisted spec + its rollout history at startup.
    /// Failures here indicate state corruption — we bubble them so
    /// `AppHost::new` can refuse to come up rather than silently
    /// dropping apps.
    pub(crate) fn load(&self) -> Result<Vec<(AppSpec, VecDeque<Rollout>)>> {
        load_persisted_state(&self.specs_dir(), &self.rollouts_dir())
    }

    /// Persist the handle's current spec.
    pub(crate) async fn persist_spec(&self, handle: &AppHandle) -> Result<()> {
        let name = handle.name();
        let spec = handle.spec.read().await.clone();
        self.persist_toml(&self.spec_path(name), &spec, "spec", name)
            .await
    }

    /// Persist the handle's full rollout history.
    pub(crate) async fn persist_rollouts(&self, handle: &AppHandle) -> Result<()> {
        let name = handle.name();
        let rollouts: Vec<Rollout> = handle.inner.lock().await.rollouts.iter().cloned().collect();
        let file = RolloutsFile { rollouts };
        self.persist_toml(&self.rollouts_path(name), &file, "rollouts", name)
            .await
    }

    /// Serialise `value` as pretty-printed TOML and write it to `path`.
    /// Shared by `persist_spec` and `persist_rollouts`; `what` and
    /// `name` flow into the error envelopes so a failure tells the
    /// operator which app's which file failed.
    async fn persist_toml<T: serde::Serialize + Sync>(
        &self,
        path: &Path,
        value: &T,
        what: &str,
        name: &str,
    ) -> Result<()> {
        let body = toml::to_string_pretty(value)
            .with_context(|| format!("serialize {what} for {name}"))?;
        tokio::fs::write(path, body)
            .await
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    /// Remove an app's on-disk state. Best-effort: each file is
    /// removed if present; absence is treated as success.
    pub(crate) async fn remove(&self, name: &str) {
        try_remove_file(&self.spec_path(name)).await;
        try_remove_file(&self.rollouts_path(name)).await;
    }

    /// Discard a TOML written by a deploy whose subsequent
    /// collision-check rejected the registration. Logs on failure
    /// because the file becomes an orphan that the next bugpot start
    /// has to reap.
    pub(crate) async fn discard_failed_spec(&self, name: &str) {
        let path = self.spec_path(name);
        if let Err(e) = tokio::fs::remove_file(&path).await {
            warn!(
                path = %path.display(),
                error = %e,
                "leftover TOML from a failed deploy_app could not be removed; \
                 orphan cleanup at next startup will reclaim it"
            );
        }
    }
}

/// Best-effort `remove_file` that treats `NotFound` as success.
async fn try_remove_file(path: &Path) {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(path = %path.display(), error = %e, "remove file failed"),
    }
}
