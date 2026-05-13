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
//! Bearer-token auth via [`AdminAuth`] is **mandatory**. All routes
//! require `Authorization: Bearer <token>` and the comparison uses
//! `subtle::ConstantTimeEq` to avoid character-by-character timing
//! leaks. `cmd/bugpot::main` refuses to start without a token —
//! there is no "trust delegated to the listener binding" path, even
//! when bound to loopback or a private network.
//!
//! # Defences
//!
//! - `RequestBodyLimitLayer` caps incoming bodies at `MAX_BODY_BYTES`
//!   (256 KB). `AppSpec` JSON is normally ~1 KB; the cap stops the
//!   `env` map from being weaponised into memory exhaustion.
//! - `tower::limit::RateLimitLayer` enforces a global limit of
//!   `RATE_LIMIT_REQUESTS` per `RATE_LIMIT_PERIOD`. Brute-forcing the
//!   bearer token over the network is infeasible at that rate.
//! - Order matters: rate limit + body limit are *outside* the auth
//!   layer (they protect the constant-time comparison itself); auth
//!   is *inside* (so unauthorised requests don't consume the
//!   rate-limit budget for legitimate clients).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    BoxError, Json, Router,
    error_handling::HandleErrorLayer,
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
use tower::ServiceBuilder;
use tower::limit::RateLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Maximum POST body size for `POST /apps`. `AppSpec` JSON is usually
/// well under 1 KB; the cap stops the `env` map from being weaponised
/// into a memory-exhaustion vector.
const MAX_BODY_BYTES: usize = 256 * 1024;
/// Global rate limit on admin API requests. Brute-forcing a bearer
/// token at this rate is infeasible.
const RATE_LIMIT_REQUESTS: u64 = 60;
const RATE_LIMIT_PERIOD: Duration = Duration::from_mins(1);

/// Bearer-token verifier for the admin API.
///
/// A token is **mandatory** — `cmd/bugpot::main` refuses to start
/// without one. The `Token` newtype here exists so the type system
/// records that fact (no `Option`, no "disabled" path).
///
/// The expected value is wrapped in `Zeroizing` so the secret is wiped
/// on drop and never accidentally exposed via `Debug`.
#[derive(Debug)]
pub struct AdminAuth {
    expected_token: Zeroizing<Vec<u8>>,
}

impl AdminAuth {
    /// Build with a token. The string must not be empty; callers
    /// should have validated that already.
    #[must_use]
    pub fn from_token(token: String) -> Self {
        Self {
            expected_token: Zeroizing::new(token.into_bytes()),
        }
    }

    fn check(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        let presented = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;
        // `ct_eq` returns Choice(0) for length mismatch without leaking
        // which byte differed; bool::from converts to a normal bool.
        if bool::from(presented.as_bytes().ct_eq(self.expected_token.as_slice())) {
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
    // `RateLimitLayer` makes the inner service non-Clone and produces
    // `BoxError`, so it has to sit inside a `buffer` (for Clone) and
    // a `HandleErrorLayer` (so the BoxError can be converted into a
    // 429/500 response that axum's Router accepts). Both layer compose
    // via `ServiceBuilder`.
    let throttle = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_rate_limit_error))
        .buffer(32)
        .layer(RateLimitLayer::new(RATE_LIMIT_REQUESTS, RATE_LIMIT_PERIOD));

    Router::new()
        .route("/apps", post(deploy::<R, E>).get(list::<R, E>))
        .route(
            "/apps/{name}",
            get(get_one::<R, E>).delete(remove::<R, E>),
        )
        .with_state(controller)
        // Auth runs first (innermost layer) so unauthorised requests
        // don't burn a rate-limit slot. Body limit + rate limit are
        // outermost — they protect the auth comparison itself.
        .layer(middleware::from_fn_with_state(auth, require_token))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(throttle)
}

/// Map `tower::limit::RateLimitLayer`'s `BoxError` into a 429. The
/// rate limiter's `poll_ready` returns `Pending` when the bucket is
/// dry; the `buffer` ahead of it returns `BoxError` when its queue is
/// full or the inner service yields.
async fn handle_rate_limit_error(err: BoxError) -> Response {
    AdminError {
        status: StatusCode::TOO_MANY_REQUESTS,
        message: format!("rate limit exceeded: {err}"),
    }
    .into_response()
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
    fn auth_rejects_missing_header() {
        let auth = AdminAuth::from_token("expected-token".into());
        assert_eq!(
            auth.check(&HeaderMap::new()).unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn auth_rejects_wrong_scheme() {
        let auth = AdminAuth::from_token("expected-token".into());
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
        let auth = AdminAuth::from_token("expected-token".into());
        assert!(auth.check(&header("Bearer expected-token")).is_ok());
    }

    #[test]
    fn auth_rejects_wrong_token_same_length() {
        let auth = AdminAuth::from_token("expected-token".into());
        assert_eq!(
            auth.check(&header("Bearer ExPeCtEd-tOkEn")).unwrap_err(),
            StatusCode::UNAUTHORIZED,
        );
    }

    #[test]
    fn auth_rejects_wrong_token_length_mismatch() {
        let auth = AdminAuth::from_token("expected-token".into());
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
