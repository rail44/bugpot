//! Resolves the admin bearer token and the deploy-key HMAC secret
//! from env / file.
//!
//! Both share the same shape: a `_FILE` env var (preferred — strict
//! permission check, no leak through `/proc/<pid>/environ`) and an
//! env-var fallback that logs a warning. Either is required —
//! bugpot refuses to start otherwise, because the admin API has no
//! "trust the listener" path (one accidental `0.0.0.0` bind makes
//! that footgun-grade).

use std::path::Path;

use anyhow::{Context, Result};
use bugpot_admin::DeployKeySecret;
use tracing::warn;

/// Read the admin token from env or file. The file path
/// (`BUGPOT_ADMIN_TOKEN_FILE`) is preferred — its strict mode
/// requirement (`chmod 600`) keeps the secret out of
/// `/proc/PID/environ`, `ps auxe`, and shell history. The direct
/// env-var (`BUGPOT_ADMIN_TOKEN`) remains for dev convenience but
/// logs a warning.
pub(crate) fn read_admin_token() -> Result<String> {
    read_secret(
        "admin token",
        "BUGPOT_ADMIN_TOKEN_FILE",
        "BUGPOT_ADMIN_TOKEN",
    )
}

/// Read the HMAC secret used to derive per-app deploy tokens. Same
/// shape as the admin token; the secret is purely a server-side
/// derivation key, so the same `chmod 600` + ancestor-permission
/// rules apply.
pub(crate) fn read_deploy_secret() -> Result<DeployKeySecret> {
    let secret = read_secret(
        "deploy-key secret",
        "BUGPOT_DEPLOY_SECRET_FILE",
        "BUGPOT_DEPLOY_SECRET",
    )?;
    Ok(DeployKeySecret::from_bytes(secret.into_bytes()))
}

/// Shared resolver for the file-or-env credential pattern. `kind` is
/// the human-readable label used in log messages and error text.
fn read_secret(kind: &str, file_var: &str, direct_var: &str) -> Result<String> {
    if let Ok(path) = std::env::var(file_var) {
        return read_from_file(kind, &path);
    }
    if let Ok(raw) = std::env::var(direct_var)
        && let Some(trimmed) = non_empty(&raw)
    {
        warn!(
            "{kind} loaded from {direct_var}; the env-var path is visible \
             in /proc/<pid>/environ. Prefer {file_var} for production \
             deployments.",
        );
        return Ok(trimmed.to_owned());
    }
    anyhow::bail!("{kind} is required: set {file_var} (preferred) or {direct_var}")
}

fn read_from_file(kind: &str, path: &str) -> Result<String> {
    bugpot_config::require_owner_only(Path::new(path))?;
    let body = std::fs::read_to_string(path).with_context(|| format!("read {kind} from {path}"))?;
    let trimmed = non_empty(&body).ok_or_else(|| anyhow::anyhow!("{kind} file {path} is empty"))?;
    Ok(trimmed.to_owned())
}

fn non_empty(s: &str) -> Option<&str> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}
