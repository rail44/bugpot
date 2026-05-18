//! Host-side management of per-app persistent volume directories.
//!
//! Each volume in an `AppSpec` maps to `<state>/volumes/<app>/<name>/`.
//! Bugpot creates these on first start, optionally chowns them to a
//! caller-declared UID (so the container's non-root user can write),
//! and reclaims them when `cleanup_app_assets` runs on the
//! explicit-remove path.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Result, RuntimeError};

/// Materialise the host-side directories for an app's volumes and
/// (when a UID is declared) chown them so the container user can
/// read & write.
///
/// Returns the resolved host paths in the same order as `volumes` —
/// `build_spec` consumes them to emit bind mounts.
///
/// Idempotent: re-running for an existing app is a no-op for the
/// directories that already exist, but **re-asserts ownership**
/// every call. That's deliberate — if an operator updates `user`
/// in the TOML and redeploys, the next start picks up the new
/// ownership without any manual `chown` on the host.
pub(crate) fn ensure_volume_host_dirs(
    volumes_dir: &Path,
    app: &str,
    volumes: &[bugpot_config::VolumeSpec],
) -> Result<Vec<PathBuf>> {
    if volumes.is_empty() {
        return Ok(Vec::new());
    }
    let app_dir = volumes_dir.join(app);
    fs::create_dir_all(&app_dir).map_err(|e| RuntimeError::io(&app_dir, e))?;
    let mut out = Vec::with_capacity(volumes.len());
    for v in volumes {
        let host_path = app_dir.join(&v.name);
        fs::create_dir_all(&host_path).map_err(|e| RuntimeError::io(&host_path, e))?;
        if let Some(uid) = v.user {
            // Same UID for group; matches the typical container
            // image convention `appuser:appuser`. nix's wrapper
            // keeps us inside the workspace's `unsafe_code = deny`.
            nix::unistd::chown(
                &host_path,
                Some(nix::unistd::Uid::from_raw(uid)),
                Some(nix::unistd::Gid::from_raw(uid)),
            )
            .map_err(|e| RuntimeError::io(&host_path, std::io::Error::from(e)))?;
        }
        out.push(host_path);
    }
    Ok(out)
}

/// Remove all volume directories belonging to `app`. Called by
/// `cleanup_app_assets` on the explicit-remove path.
///
/// Best-effort: an IO failure is surfaced, but a missing dir is
/// fine (the app may never have started, or its TOML may never
/// have declared any volumes).
pub(crate) fn remove_volume_dirs(volumes_dir: &Path, app: &str) -> Result<()> {
    let app_dir = volumes_dir.join(app);
    if !app_dir.exists() {
        return Ok(());
    }
    fs::remove_dir_all(&app_dir).map_err(|e| RuntimeError::io(&app_dir, e))
}
