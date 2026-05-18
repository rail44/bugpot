//! On-disk persistence of `AppSpec` + rollout state.
//!
//! Two daemon-owned directories under `<state>/`:
//!
//! * `<state>/apps/<name>.toml` — `AppSpec`, written by
//!   `deploy_app` / `update_app` and read at boot to rehydrate the
//!   in-memory app map.
//! * `<state>/rollouts/<name>.toml` — `[[rollout]]` history, written
//!   by `set_rollout` and read at boot to repopulate per-handle
//!   `VecDeque<Rollout>` queues.
//!
//! Operators never touch either directory — the admin API is the
//! single entry point for spec mutations. These functions only
//! handle the "load at startup" half; the write half lives on
//! `AppController` (in `lib.rs`) so it can hold the right locks.

use std::collections::VecDeque;
use std::path::Path;

use anyhow::{Context, Result};
use bugpot_config::{AppSpec, Rollout};

/// On-disk shape of the rollouts file. Wrapped in a top-level table
/// so it can grow extra fields later without breaking the format.
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
pub(crate) struct RolloutsFile {
    #[serde(default, rename = "rollout", skip_serializing_if = "Vec::is_empty")]
    pub(crate) rollouts: Vec<Rollout>,
}

/// Walk the spec and rollouts state directories, returning one
/// `(spec, rollouts)` pair per registered app. Specs that fail
/// validation surface as an error — corrupted bugpot state should
/// stop the daemon coming up, not silently drop an app.
pub(crate) fn load_persisted_state(
    specs_dir: &Path,
    rollouts_dir: &Path,
) -> Result<Vec<(AppSpec, VecDeque<Rollout>)>> {
    let mut out = Vec::new();
    let entries =
        std::fs::read_dir(specs_dir).with_context(|| format!("read {}", specs_dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("read {}", specs_dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let body =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let spec: AppSpec =
            toml::from_str(&body).with_context(|| format!("parse {}", path.display()))?;
        spec.validate()
            .with_context(|| format!("validate {}", path.display()))?;
        // Defensive: the file's name (set by `persist_spec`) should
        // always match the spec body's `name`. A mismatch means
        // someone edited the file out-of-band — refuse to load it
        // rather than registering an app under a name that disagrees
        // with its on-disk home.
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if stem != spec.name {
            anyhow::bail!(
                "spec file {} declares name = {:?}, expected {:?}",
                path.display(),
                spec.name,
                stem
            );
        }
        let name = spec.name.clone();
        let rollouts = read_rollouts_file(rollouts_dir, &name)?;
        out.push((spec, rollouts));
    }
    out.sort_by(|a, b| a.0.name().cmp(b.0.name()));
    Ok(out)
}

fn read_rollouts_file(rollouts_dir: &Path, name: &str) -> Result<VecDeque<Rollout>> {
    let path = rollouts_dir.join(format!("{name}.toml"));
    if !path.exists() {
        return Ok(VecDeque::new());
    }
    let body =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let parsed: RolloutsFile =
        toml::from_str(&body).with_context(|| format!("parse {}", path.display()))?;
    Ok(parsed.rollouts.into_iter().collect())
}
