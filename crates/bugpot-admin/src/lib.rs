//! HTTP admin adapter for bugpot.
//!
//! Translates HTTP requests to mutations on [`bugpot_controller::AppController`].
//! This crate is one of several possible deploy frontends (future: webhook
//! receiver, GitHub poller, CLI over Unix socket); each translates an
//! external trigger into the same controller method calls.
//!
//! # Routes
//!
//! - `POST   /apps`         JSON body → `AppSpec`, returns 200 + `AppView`
//! - `GET    /apps`         returns 200 + `[AppView]`
//! - `GET    /apps/{name}`  returns 200 + `AppView`, or 404
//! - `DELETE /apps/{name}`  returns 204, or 404
//!
//! # Auth
//!
//! Authorisation is *not* enforced in code. Deployment is expected to put
//! the listener on a trusted interface (loopback for self-hosted-runner
//! flows, or a Tailscale IP with ACL when CI calls in from outside).

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bugpot_config::AppSpec;
use bugpot_controller::{AppController, AppView, DeployError, RemoveError};
use serde::Serialize;
use tracing::{info, warn};

/// Bind the admin API at `addr` and serve until the future is dropped.
pub async fn serve(addr: SocketAddr, controller: Arc<AppController>) -> anyhow::Result<()> {
    let app = router(controller);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "bugpot-admin listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn router(controller: Arc<AppController>) -> Router {
    Router::new()
        .route("/apps", post(deploy).get(list))
        .route("/apps/{name}", get(get_one).delete(remove))
        .with_state(controller)
}

async fn deploy(
    State(controller): State<Arc<AppController>>,
    Json(spec): Json<AppSpec>,
) -> Result<(StatusCode, Json<AppView>), AdminError> {
    let view = controller.deploy_app(spec).await?;
    Ok((StatusCode::CREATED, Json(view)))
}

async fn remove(
    State(controller): State<Arc<AppController>>,
    Path(name): Path<String>,
) -> Result<StatusCode, AdminError> {
    controller.remove_app(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list(State(controller): State<Arc<AppController>>) -> Json<Vec<AppView>> {
    Json(controller.list_apps().await)
}

async fn get_one(
    State(controller): State<Arc<AppController>>,
    Path(name): Path<String>,
) -> Result<Json<AppView>, AdminError> {
    controller
        .get_app(&name)
        .await
        .map(Json)
        .ok_or_else(|| AdminError {
            status: StatusCode::NOT_FOUND,
            message: format!("app '{name}' not found"),
        })
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
struct AdminError {
    status: StatusCode,
    message: String,
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
            DeployError::MissingName => StatusCode::BAD_REQUEST,
            DeployError::AlreadyExists(_) | DeployError::SubdomainTaken(_) => StatusCode::CONFLICT,
            DeployError::ImagePull(_) => StatusCode::BAD_GATEWAY,
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
            RemoveError::NotFound(_) => StatusCode::NOT_FOUND,
            RemoveError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
            (DeployError::MissingName, StatusCode::BAD_REQUEST),
            (
                DeployError::AlreadyExists("x".into()),
                StatusCode::CONFLICT,
            ),
            (
                DeployError::SubdomainTaken("y".into()),
                StatusCode::CONFLICT,
            ),
            (
                DeployError::ImagePull(anyhow!("registry 503")),
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
        let nf: AdminError = RemoveError::NotFound("a".into()).into();
        assert_eq!(nf.status, StatusCode::NOT_FOUND);
        let internal: AdminError = RemoveError::Internal(anyhow!("io")).into();
        assert_eq!(internal.status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
