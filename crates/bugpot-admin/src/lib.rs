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
//! Optional bearer-token auth via [`AdminAuth`]. When configured, all
//! routes require `Authorization: Bearer <token>` and use constant-time
//! comparison to avoid character-by-character timing leaks. When the
//! token is absent (`AdminAuth::disabled`), auth is a no-op and trust is
//! delegated entirely to the listener binding (loopback for self-hosted-
//! runner flows, Tailscale IP + ACL for remote CI).

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bugpot_config::AppSpec;
use bugpot_controller::{AppController, AppView, DeployError, RemoveError};
use bugpot_egress::EgressOps;
use bugpot_runtime::RuntimeOps;
use serde::Serialize;
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Bearer-token verifier for the admin API.
///
/// When `expected_token` is `Some`, all requests must carry
/// `Authorization: Bearer <token>` whose body matches. When `None`,
/// auth is disabled — every request is allowed through (current dev
/// default).
#[derive(Debug)]
pub struct AdminAuth {
    /// Wrapped in `Zeroizing` so the secret is wiped on drop and never
    /// accidentally exposed via `Debug`.
    expected_token: Option<Zeroizing<Vec<u8>>>,
}

impl AdminAuth {
    /// Build with a token. Pass `None` (or use [`Self::disabled`]) to
    /// run without auth.
    #[must_use]
    pub fn from_token(token: Option<String>) -> Self {
        Self {
            expected_token: token.map(|s| Zeroizing::new(s.into_bytes())),
        }
    }

    /// Convenience: no auth required (passes everything through).
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            expected_token: None,
        }
    }

    /// `true` when a token is configured.
    #[must_use]
    pub const fn is_enforced(&self) -> bool {
        self.expected_token.is_some()
    }

    fn check(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        let Some(expected) = self.expected_token.as_ref() else {
            return Ok(());
        };
        let presented = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;
        // `ct_eq` returns Choice(0) for length mismatch without leaking
        // which byte differed; bool::from converts to a normal bool.
        if bool::from(presented.as_bytes().ct_eq(expected.as_slice())) {
            Ok(())
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

async fn require_token(
    State(auth): State<Arc<AdminAuth>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    auth.check(req.headers())?;
    Ok(next.run(req).await)
}

/// Bind the admin API at `addr` and serve until the future is dropped.
pub async fn serve<R, E>(
    addr: SocketAddr,
    controller: Arc<AppController<R, E>>,
    auth: Arc<AdminAuth>,
) -> anyhow::Result<()>
where
    R: RuntimeOps,
    E: EgressOps,
{
    let app = router(controller, auth);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "bugpot-admin listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn router<R, E>(controller: Arc<AppController<R, E>>, auth: Arc<AdminAuth>) -> Router
where
    R: RuntimeOps,
    E: EgressOps,
{
    Router::new()
        .route("/apps", post(deploy::<R, E>).get(list::<R, E>))
        .route(
            "/apps/{name}",
            get(get_one::<R, E>).delete(remove::<R, E>),
        )
        .with_state(controller)
        .layer(middleware::from_fn_with_state(auth, require_token))
}

async fn deploy<R, E>(
    State(controller): State<Arc<AppController<R, E>>>,
    Json(spec): Json<AppSpec>,
) -> Result<(StatusCode, Json<AppView>), AdminError>
where
    R: RuntimeOps,
    E: EgressOps,
{
    let view = controller.deploy_app(spec).await?;
    Ok((StatusCode::CREATED, Json(view)))
}

async fn remove<R, E>(
    State(controller): State<Arc<AppController<R, E>>>,
    Path(name): Path<String>,
) -> Result<StatusCode, AdminError>
where
    R: RuntimeOps,
    E: EgressOps,
{
    controller.remove_app(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list<R, E>(State(controller): State<Arc<AppController<R, E>>>) -> Json<Vec<AppView>>
where
    R: RuntimeOps,
    E: EgressOps,
{
    Json(controller.list_apps().await)
}

async fn get_one<R, E>(
    State(controller): State<Arc<AppController<R, E>>>,
    Path(name): Path<String>,
) -> Result<Json<AppView>, AdminError>
where
    R: RuntimeOps,
    E: EgressOps,
{
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
            DeployError::MissingName | DeployError::InvalidSpec(_) => StatusCode::BAD_REQUEST,
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
    use axum::http::HeaderValue;

    fn header(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    #[test]
    fn auth_disabled_passes_without_header() {
        let auth = AdminAuth::disabled();
        assert!(auth.check(&HeaderMap::new()).is_ok());
        assert!(auth.check(&header("Bearer anything")).is_ok());
        assert!(!auth.is_enforced());
    }

    #[test]
    fn auth_rejects_missing_header() {
        let auth = AdminAuth::from_token(Some("expected-token".into()));
        assert_eq!(
            auth.check(&HeaderMap::new()).unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        assert!(auth.is_enforced());
    }

    #[test]
    fn auth_rejects_wrong_scheme() {
        let auth = AdminAuth::from_token(Some("expected-token".into()));
        assert_eq!(
            auth.check(&header("Basic expected-token")).unwrap_err(),
            StatusCode::UNAUTHORIZED,
        );
        // Bare token without "Bearer " prefix is also rejected.
        assert_eq!(
            auth.check(&header("expected-token")).unwrap_err(),
            StatusCode::UNAUTHORIZED,
        );
    }

    #[test]
    fn auth_accepts_matching_bearer() {
        let auth = AdminAuth::from_token(Some("expected-token".into()));
        assert!(auth.check(&header("Bearer expected-token")).is_ok());
    }

    #[test]
    fn auth_rejects_wrong_token_same_length() {
        let auth = AdminAuth::from_token(Some("expected-token".into()));
        assert_eq!(
            auth.check(&header("Bearer ExPeCtEd-tOkEn")).unwrap_err(),
            StatusCode::UNAUTHORIZED,
        );
    }

    #[test]
    fn auth_rejects_wrong_token_length_mismatch() {
        let auth = AdminAuth::from_token(Some("expected-token".into()));
        assert_eq!(
            auth.check(&header("Bearer expected")).unwrap_err(),
            StatusCode::UNAUTHORIZED,
        );
        assert_eq!(
            auth.check(&header("Bearer expected-token-extra-suffix"))
                .unwrap_err(),
            StatusCode::UNAUTHORIZED,
        );
    }

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
