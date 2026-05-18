//! Public error types for the controller's mutation API.
//!
//! Each operation (`deploy_app`, `update_app`, `set_rollout`,
//! `remove_app`) has its own narrow error enum so adapter crates
//! (admin HTTP, CLI, future webhook receiver) can map every variant
//! to the right transport-level response — typically an HTTP status
//! code. The enums share *shape* (`NotFound`, `Internal`) but stay
//! split rather than collapsing into one `ControllerError`: the
//! valid-variants-per-operation set is part of each entry point's
//! type signature, and combining them would lose that.

use thiserror::Error;

use bugpot_runtime::RuntimeError;

#[derive(Debug, Error)]
pub enum DeployError {
    #[error("spec.name is required for deploy")]
    MissingName,
    #[error("invalid spec: {0}")]
    InvalidSpec(#[from] bugpot_config::InvalidSpec),
    #[error("app '{0}' already exists")]
    AlreadyExists(String),
    #[error("subdomain '{0}' already in use")]
    SubdomainTaken(String),
    /// The registry rejected bugpot's credentials (or the image
    /// requires credentials and none were configured). Distinct from
    /// the general `ImagePull` so operators can grep audit logs for
    /// auth-side failures specifically — the message conveys
    /// "fix bugpot's auth.toml" rather than "retry later".
    #[error("registry authentication failed: {0:#}")]
    ImageAuth(#[source] anyhow::Error),
    #[error("image pull failed: {0:#}")]
    ImagePull(#[source] anyhow::Error),
    #[error("eager start failed: {0:#}")]
    StartFailed(#[source] anyhow::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum RemoveError {
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Errors specific to the rollout plane (image-tag updates that do not
/// touch app config). Adapter crates map these to HTTP status codes.
#[derive(Debug, Error)]
pub enum RolloutError {
    #[error("rollout tag must not be empty")]
    EmptyTag,
    #[error("registry authentication failed: {0:#}")]
    ImageAuth(#[source] anyhow::Error),
    #[error("image pull failed: {0:#}")]
    ImagePull(#[source] anyhow::Error),
    /// App is mid-transition (Starting / Stopping); the caller should
    /// retry once the state settles.
    #[error("app '{0}' is currently transitioning state; retry")]
    Conflict(String),
    /// Pull + persist succeeded but the cold start (or re-start)
    /// driven by the rollout failed. The rollout history still
    /// contains the new entry; operators can roll back to a previous
    /// tag.
    #[error("rollout started but app failed to come up: {0:#}")]
    StartFailed(#[source] anyhow::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Errors specific to the config plane's `PATCH /apps/<name>` path.
/// Adapter crates map these to HTTP status codes.
#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("invalid spec: {0}")]
    InvalidSpec(#[from] bugpot_config::InvalidSpec),
    /// The caller attempted to change `name` (identity). Rename =
    /// delete + recreate; PATCH does not perform it.
    #[error("name is immutable; delete + recreate to rename")]
    NameImmutable,
    /// Same constraint as `name`. Routing identity is fixed for the
    /// life of an app.
    #[error("subdomain is immutable; delete + recreate to change")]
    SubdomainImmutable,
    /// App is mid-transition (Starting / Stopping); the caller should
    /// retry once the state settles.
    #[error("app '{0}' is currently transitioning state; retry")]
    Conflict(String),
    /// PATCH succeeded at the config-store level but the post-update
    /// restart (stop + start) of a running container failed. The new
    /// config has already been persisted.
    #[error("config updated but app failed to restart: {0:#}")]
    RestartFailed(#[source] anyhow::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Classify a `pull_image` failure into the rollout-level error
/// variant. Auth-side failures (registry rejected bugpot's
/// credentials, or none were configured for a private image) become
/// [`RolloutError::ImageAuth`]; everything else (network, manifest
/// parsing, missing image) stays in the generic
/// [`RolloutError::ImagePull`].
pub(crate) fn classify_pull_error_for_rollout(
    err: RuntimeError,
    name: &str,
    image_ref: &str,
) -> RolloutError {
    let is_auth = err.is_registry_auth_error();
    let context = anyhow::Error::from(err).context(format!("pull {image_ref} for {name}"));
    if is_auth {
        RolloutError::ImageAuth(context)
    } else {
        RolloutError::ImagePull(context)
    }
}
