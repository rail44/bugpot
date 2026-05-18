//! Resolves the admin bearer token and the deploy-key HMAC secret
//! from env / file.
//!
//! Both share the same shape: a `_FILE` env var (preferred — strict
//! permission check, no leak through `/proc/<pid>/environ`) and an
//! env-var fallback that logs a warning. Either is required —
//! bugpot refuses to start otherwise, because the admin API has no
//! "trust the listener" path (one accidental `0.0.0.0` bind makes
//! that footgun-grade).

use anyhow::{Context, Result};
use bugpot_admin::DeployKeySecret;
use tracing::warn;

/// Read the admin token from env or file.
///
/// Precedence: `BUGPOT_ADMIN_TOKEN_FILE` first, then `BUGPOT_ADMIN_TOKEN`
/// as a fallback. The file path is preferred — its strict mode
/// requirement (`chmod 600`) keeps the secret out of `/proc/PID/environ`,
/// `ps auxe`, and shell history. The env-var path remains for dev
/// convenience but logs a warning.
pub(crate) fn read_admin_token() -> Result<String> {
    if let Ok(path) = std::env::var("BUGPOT_ADMIN_TOKEN_FILE") {
        return read_admin_token_from_file(&path);
    }
    if let Ok(raw) = std::env::var("BUGPOT_ADMIN_TOKEN") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            warn!(
                "admin token loaded from BUGPOT_ADMIN_TOKEN; the env-var \
                 path is visible in /proc/<pid>/environ. Prefer \
                 BUGPOT_ADMIN_TOKEN_FILE for production deployments.",
            );
            return Ok(trimmed.to_owned());
        }
    }
    anyhow::bail!(
        "admin token is required: set BUGPOT_ADMIN_TOKEN_FILE (preferred) or BUGPOT_ADMIN_TOKEN"
    );
}

/// Read the admin token from `path` after asserting it (and all of
/// its ancestor directories) is accessible only by the bugpot owner.
/// Delegates the permissions check to `bugpot_config::require_owner_only`
/// so both the admin token and `auth.toml` share one enforcement path.
fn read_admin_token_from_file(path: &str) -> Result<String> {
    bugpot_config::require_owner_only(std::path::Path::new(path))?;
    let body =
        std::fs::read_to_string(path).with_context(|| format!("read admin token from {path}"))?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        anyhow::bail!("admin token file {path} is empty");
    }
    Ok(trimmed.to_owned())
}

/// Read the HMAC secret used to derive per-app deploy tokens. Same
/// shape as the admin token: a file path (preferred) or an env var
/// fallback that logs a warning. The secret is purely a server-side
/// derivation key — leaking it lets an attacker mint a deploy token
/// for any app, so the same `chmod 600` + ancestor-permission rules
/// apply.
pub(crate) fn read_deploy_secret() -> Result<DeployKeySecret> {
    if let Ok(path) = std::env::var("BUGPOT_DEPLOY_SECRET_FILE") {
        return read_deploy_secret_from_file(&path);
    }
    if let Ok(raw) = std::env::var("BUGPOT_DEPLOY_SECRET") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            warn!(
                "deploy-key secret loaded from BUGPOT_DEPLOY_SECRET; the \
                 env-var path is visible in /proc/<pid>/environ. Prefer \
                 BUGPOT_DEPLOY_SECRET_FILE for production deployments.",
            );
            return Ok(DeployKeySecret::from_bytes(trimmed.as_bytes().to_vec()));
        }
    }
    anyhow::bail!(
        "deploy-key secret is required: set BUGPOT_DEPLOY_SECRET_FILE (preferred) or BUGPOT_DEPLOY_SECRET"
    );
}

fn read_deploy_secret_from_file(path: &str) -> Result<DeployKeySecret> {
    bugpot_config::require_owner_only(std::path::Path::new(path))?;
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read deploy-key secret from {path}"))?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        anyhow::bail!("deploy-key secret file {path} is empty");
    }
    Ok(DeployKeySecret::from_bytes(trimmed.as_bytes().to_vec()))
}
