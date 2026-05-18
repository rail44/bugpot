//! HTTP error envelope for the admin API.
//!
//! [`AdminError`] is the single rejection type every handler returns;
//! its `IntoResponse` implementation renders the
//! `{"error": "<message>"}` JSON body and attaches the right status
//! code. `From` impls below translate every controller-side error
//! enum into the corresponding HTTP status, keeping the per-route
//! handler bodies free of `match` ladders.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tracing::warn;

use bugpot_core::{DeployError, RemoveError, RolloutError, UpdateError};

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
pub(crate) struct AdminError {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            warn!(status = %self.status, message = %self.message, "admin request failed");
        }
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

impl From<DeployError> for AdminError {
    fn from(err: DeployError) -> Self {
        let status = match &err {
            DeployError::InvalidSpec(_) => StatusCode::BAD_REQUEST,
            DeployError::AlreadyExists(_) | DeployError::SubdomainTaken(_) => StatusCode::CONFLICT,
            DeployError::ImageAuth(_) | DeployError::ImagePull(_) => StatusCode::BAD_GATEWAY,
            DeployError::StartFailed(_) | DeployError::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        Self {
            status,
            message: format!("{err:#}"),
        }
    }
}

impl From<RemoveError> for AdminError {
    fn from(err: RemoveError) -> Self {
        let status = match &err {
            RemoveError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: format!("{err:#}"),
        }
    }
}

impl From<UpdateError> for AdminError {
    fn from(err: UpdateError) -> Self {
        let status = match &err {
            UpdateError::InvalidSpec(_)
            | UpdateError::NameImmutable
            | UpdateError::SubdomainImmutable => StatusCode::BAD_REQUEST,
            UpdateError::Conflict(_) => StatusCode::CONFLICT,
            UpdateError::RestartFailed(_) | UpdateError::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        Self {
            status,
            message: format!("{err:#}"),
        }
    }
}

impl From<RolloutError> for AdminError {
    fn from(err: RolloutError) -> Self {
        let status = match &err {
            RolloutError::EmptyTag => StatusCode::BAD_REQUEST,
            RolloutError::Conflict(_) => StatusCode::CONFLICT,
            RolloutError::ImageAuth(_) | RolloutError::ImagePull(_) => StatusCode::BAD_GATEWAY,
            RolloutError::StartFailed(_) | RolloutError::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        Self {
            status,
            message: format!("{err:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn deploy_error_maps_to_status() {
        let cases: Vec<(DeployError, StatusCode)> = vec![
            (DeployError::AlreadyExists("x".into()), StatusCode::CONFLICT),
            (
                DeployError::SubdomainTaken("y".into()),
                StatusCode::CONFLICT,
            ),
            (
                DeployError::ImagePull(anyhow!("registry 503")),
                StatusCode::BAD_GATEWAY,
            ),
            (
                DeployError::ImageAuth(anyhow!("401 from ghcr")),
                StatusCode::BAD_GATEWAY,
            ),
            (
                DeployError::StartFailed(anyhow!("port bind")),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                DeployError::Internal(anyhow!("disk full")),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (err, expected) in cases {
            let admin: AdminError = err.into();
            assert_eq!(admin.status, expected);
        }
    }

    #[test]
    fn remove_error_maps_to_status() {
        let internal: AdminError = RemoveError::Internal(anyhow!("io")).into();
        assert_eq!(internal.status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
