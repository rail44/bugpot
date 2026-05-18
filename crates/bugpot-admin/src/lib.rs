//! HTTP admin adapter for bugpot.
//!
//! Two auth scopes live side by side here:
//!
//! - **Admin token** (`BUGPOT_ADMIN_TOKEN[_FILE]`): full config-plane
//!   access — register / view / remove apps and mint per-app deploy
//!   keys.
//! - **Deploy token** (`bp1.<hex>`, derived from
//!   `BUGPOT_DEPLOY_SECRET[_FILE]`): scoped to one app's rollout
//!   plane — `POST/GET /apps/<name>/rollouts` only. See
//!   [`deploy_key`] for the HMAC derivation and verification rules.
//!
//! Translates HTTP requests to mutations on [`bugpot_controller::AppController`].
//! This crate is one of several possible deploy frontends (future: webhook
//! receiver, GitHub poller, CLI over Unix socket); each translates an
//! external trigger into the same controller method calls.
//!
//! # Routes
//!
//! Config plane (rare, admin-token scoped):
//!
//! - `POST   /apps`                  JSON body → `AppSpec`, returns 201 + `AppView`. Registers only — does not pull an image or start a container.
//! - `GET    /apps`                  returns 200 + `[AppView]`
//! - `GET    /apps/{name}`           returns 200 + `AppView`, or 404
//! - `PATCH  /apps/{name}`           replace-style update of every mutable field; `name` and `subdomain` are immutable. 200 + `AppView`, or 404 / 400 / 409 / 500. Same body shape as POST (JSON or TOML); if the body's TOML projection equals the current spec the call is a no-op.
//! - `DELETE /apps/{name}`           returns 204, or 404
//!
//! Rollout plane (frequent, deploy-token scoped):
//!
//! - `POST   /apps/{name}/rollouts`  JSON `{tag}`, returns 201 + `Rollout`. Pulls and (re)starts the container.
//! - `GET    /apps/{name}/rollouts`  returns 200 + `[Rollout]` (oldest first, current last)
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
    extract::{ConnectInfo, FromRequestParts, Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bugpot_config::{AppSpec, Rollout};
use bugpot_controller::{
    AppController, AppHandle, AppView, DeployError, RemoveError, RolloutError, UpdateError,
};
use bugpot_egress::Egress;
use bugpot_runtime::Runtime;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tower::ServiceBuilder;
use tower::limit::RateLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};
use zeroize::Zeroizing;

pub mod deploy_key;
pub use deploy_key::DeployKeySecret;

/// Emit a `status="ok"` audit-log entry for a completed admin action.
///
/// Fields after `$app` are forwarded as tracing key/values, so callers
/// add per-action context (`repo = %r`, `tag = %t`, etc.) without
/// repeating the common envelope (`target`, `action`, `peer`, `app`,
/// `status`).
macro_rules! audit_ok {
    ($action:expr, $peer:expr, $app:expr $(, $($extra:tt)*)?) => {
        ::tracing::info!(
            target: "bugpot::audit",
            action = $action,
            peer = %$peer.ip(),
            app = %$app,
            $($($extra)*,)?
            status = "ok",
        )
    };
}

/// Emit a `status="error"` audit-log entry for a failed admin action.
/// Same shape as [`audit_ok!`] plus a mandatory `$err` slot that
/// becomes `error = %err`.
macro_rules! audit_err {
    ($action:expr, $peer:expr, $app:expr, $err:expr $(, $($extra:tt)*)?) => {
        ::tracing::warn!(
            target: "bugpot::audit",
            action = $action,
            peer = %$peer.ip(),
            app = %$app,
            $($($extra)*,)?
            status = "error",
            error = %$err,
        )
    };
}

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

/// Combined state passed to every handler / middleware.
///
/// Bundling these together lets one merged router cover both auth
/// scopes (admin token + deploy token) without the State-type
/// juggling that arises from per-route `.with_state(...)`.
/// The fully-resolved controller type the admin layer talks to.
///
/// The Linux production stack only has one `Runtime` / `Egress` pair,
/// so spelling them out here avoids the `<R, E>` noise that used to
/// follow every handler signature — without resorting to a `dyn`
/// abstraction that no caller swaps. The `AppController`'s own
/// parameterisation stays in place for controller-side tests
/// (the mocks live in that crate); this crate just commits to the
/// one shape it actually deploys with.
type Controller = AppController<Runtime, Egress>;

#[derive(Clone, Debug)]
pub struct AdminState {
    pub controller: Arc<Controller>,
    pub admin_auth: Arc<AdminAuth>,
    pub deploy_secret: Arc<DeployKeySecret>,
}

async fn require_admin_token(
    State(state): State<AdminState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    state.admin_auth.check(req.headers())?;
    Ok(next.run(req).await)
}

/// Path-aware deploy-token check: extracts `{name}` from the
/// matched route, looks up the app's current `repo`, and verifies
/// the Bearer token against the per-app HMAC. A miss at any step
/// returns 401 with no detail, so the verdict reveals nothing
/// about app existence or token shape.
async fn require_deploy_token(
    State(state): State<AdminState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (mut parts, body) = req.into_parts();
    let Path(name) = Path::<String>::from_request_parts(&mut parts, &state)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let presented = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let handle = state
        .controller
        .find_handle(&name)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let repo = handle.repo().await;
    if !state.deploy_secret.verify(presented, handle.name(), &repo) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // Forward the handle so the downstream rollout handlers can use
    // it directly — `find_handle` is the only registry lookup on this
    // path, regardless of which handler runs next.
    let mut req = Request::from_parts(parts, body);
    req.extensions_mut().insert(handle);
    Ok(next.run(req).await)
}

/// Bind the admin API at `addr` and serve until the future is dropped.
pub async fn serve(
    addr: SocketAddr,
    controller: Arc<Controller>,
    admin_auth: Arc<AdminAuth>,
    deploy_secret: Arc<DeployKeySecret>,
) -> anyhow::Result<()> {
    let state = AdminState {
        controller,
        admin_auth,
        deploy_secret,
    };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "bugpot-admin listening");
    // `into_make_service_with_connect_info` exposes the peer's
    // `SocketAddr` to handlers via `axum::extract::ConnectInfo`. We
    // use that to attach the peer's IP to every mutating action's
    // audit-log entry.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn router(state: AdminState) -> Router {
    // `RateLimitLayer` makes the inner service non-Clone and produces
    // `BoxError`, so it has to sit inside a `buffer` (for Clone) and
    // a `HandleErrorLayer` (so the BoxError can be converted into a
    // 429/500 response that axum's Router accepts). Both layer compose
    // via `ServiceBuilder`.
    let throttle = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_rate_limit_error))
        .buffer(32)
        .layer(RateLimitLayer::new(RATE_LIMIT_REQUESTS, RATE_LIMIT_PERIOD));

    // Two route groups, each with its own auth middleware. Merging
    // them rather than layering one global middleware lets the
    // rollout routes skip the admin-token check entirely — they're
    // scoped to a per-app credential instead.
    let admin_routes = Router::new()
        .route("/apps", post(deploy).get(list))
        .route("/apps/{name}", get(get_one).patch(update).delete(remove))
        .route("/apps/{name}/deploy-keys", post(issue_deploy_key))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_token,
        ));

    let rollout_routes = Router::new()
        .route("/apps/{name}/rollouts", post(roll_out).get(list_rollouts))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_deploy_token,
        ));

    Router::new()
        .merge(admin_routes)
        .merge(rollout_routes)
        .with_state(state)
        // Body limit + rate limit are outermost — they protect both
        // auth comparisons themselves.
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

/// Axum extractor that consumes the request body as an `AppSpec`.
/// Composes naturally in handler signatures so `deploy` / `update`
/// drop the manual `HeaderMap + Bytes + parse_app_spec(...)` triple.
///
/// Must be the last extractor in a handler signature — it consumes
/// the request body.
struct ParsedAppSpec(AppSpec);

impl<S: Send + Sync> axum::extract::FromRequest<S> for ParsedAppSpec {
    type Rejection = AdminError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let headers = req.headers().clone();
        let bytes = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
            .await
            .map_err(|e| AdminError {
                status: StatusCode::BAD_REQUEST,
                message: format!("read body: {e}"),
            })?;
        parse_app_spec(&headers, &bytes).map(Self)
    }
}

/// Parse an `AppSpec` from a request body, dispatching on
/// `Content-Type`:
///
/// - `application/toml` (or `text/toml`) → decoded as TOML so the
///   ops repo's TOML files can be `POST`ed directly with
///   `curl --data-binary @alpha.toml`.
/// - Anything else (including no header) → decoded as JSON. The
///   default kept matching legacy admin clients without an
///   explicit `Content-Type`.
fn parse_app_spec(headers: &HeaderMap, body: &[u8]) -> Result<AppSpec, AdminError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // `application/toml` is the IANA-registered form (RFC 9707);
    // `text/toml` was used informally before that and is still
    // produced by some tools. Match both, parameter-tolerant.
    let media_type = ct.split(';').next().unwrap_or("").trim();
    if media_type.eq_ignore_ascii_case("application/toml")
        || media_type.eq_ignore_ascii_case("text/toml")
    {
        let s = std::str::from_utf8(body).map_err(|_| AdminError {
            status: StatusCode::BAD_REQUEST,
            message: "TOML body must be UTF-8".to_owned(),
        })?;
        toml::from_str::<AppSpec>(s).map_err(|e| AdminError {
            status: StatusCode::BAD_REQUEST,
            message: format!("invalid TOML body: {e}"),
        })
    } else {
        serde_json::from_slice::<AppSpec>(body).map_err(|e| AdminError {
            status: StatusCode::BAD_REQUEST,
            message: format!("invalid JSON body: {e}"),
        })
    }
}

async fn deploy(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AdminState>,
    ParsedAppSpec(spec): ParsedAppSpec,
) -> Result<(StatusCode, Json<AppView>), AdminError> {
    // Capture what we know up-front so the audit entry stays useful
    // even when validation rejects the spec before a name lands in
    // the controller's maps.
    let audit_name = spec.name.clone().unwrap_or_else(|| "<unnamed>".to_owned());
    let audit_repo = spec.repo.clone();
    // `audit_err!` uses `warn!`, not `error!`: admin errors are
    // routinely user-driven (collisions, bad image refs) and
    // shouldn't fire pager rules. The mapped HTTP status carries
    // severity.
    match state.controller.deploy_app(spec).await {
        Ok(view) => {
            audit_ok!("register", peer, audit_name, repo = %audit_repo);
            Ok((StatusCode::CREATED, Json(view)))
        }
        Err(e) => {
            audit_err!("register", peer, audit_name, e, repo = %audit_repo);
            Err(e.into())
        }
    }
}

async fn update(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AdminState>,
    Path(name): Path<String>,
    ParsedAppSpec(spec): ParsedAppSpec,
) -> Result<Json<AppView>, AdminError> {
    let audit_repo = spec.repo.clone();
    let handle = state
        .controller
        .find_handle(&name)
        .await
        .ok_or_else(|| app_not_found(&name))?;
    match state.controller.update_app(&handle, spec).await {
        Ok(view) => {
            audit_ok!("update", peer, name, repo = %audit_repo);
            Ok(Json(view))
        }
        Err(e) => {
            audit_err!("update", peer, name, e, repo = %audit_repo);
            Err(e.into())
        }
    }
}

#[derive(Debug, Deserialize)]
struct RolloutBody {
    tag: String,
}

async fn roll_out(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AdminState>,
    axum::extract::Extension(handle): axum::extract::Extension<Arc<AppHandle>>,
    Json(body): Json<RolloutBody>,
) -> Result<(StatusCode, Json<Rollout>), AdminError> {
    let name = handle.name().to_owned();
    let audit_tag = body.tag.clone();
    match state.controller.set_rollout(&handle, body.tag).await {
        Ok(rollout) => {
            audit_ok!("rollout", peer, name, tag = %audit_tag);
            Ok((StatusCode::CREATED, Json(rollout)))
        }
        Err(e) => {
            audit_err!("rollout", peer, name, e, tag = %audit_tag);
            Err(e.into())
        }
    }
}

async fn list_rollouts(
    State(state): State<AdminState>,
    axum::extract::Extension(handle): axum::extract::Extension<Arc<AppHandle>>,
) -> Json<Vec<Rollout>> {
    Json(state.controller.list_rollouts(&handle).await)
}

#[derive(Debug, Serialize)]
struct DeployKeyResponse {
    /// Wire-format deploy token (`bp1.<hex>`). Bearer this in
    /// `Authorization` against `/apps/<name>/rollouts`.
    token: String,
}

async fn issue_deploy_key(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AdminState>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<DeployKeyResponse>), AdminError> {
    let Some(handle) = state.controller.find_handle(&name).await else {
        audit_err!("issue_deploy_key", peer, name, "not found");
        return Err(app_not_found(&name));
    };
    let repo = handle.repo().await;
    let token = state.deploy_secret.derive(&name, &repo);
    audit_ok!("issue_deploy_key", peer, name);
    Ok((StatusCode::CREATED, Json(DeployKeyResponse { token })))
}

async fn remove(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AdminState>,
    Path(name): Path<String>,
) -> Result<StatusCode, AdminError> {
    let handle = state
        .controller
        .find_handle(&name)
        .await
        .ok_or_else(|| app_not_found(&name))?;
    match state.controller.remove_app(&handle).await {
        Ok(()) => {
            audit_ok!("remove", peer, name);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            audit_err!("remove", peer, name, e);
            Err(e.into())
        }
    }
}

async fn list(State(state): State<AdminState>) -> Json<Vec<AppView>> {
    Json(state.controller.list_apps().await)
}

async fn get_one(
    State(state): State<AdminState>,
    Path(name): Path<String>,
) -> Result<Json<AppView>, AdminError> {
    state
        .controller
        .get_app(&name)
        .await
        .map(Json)
        .ok_or_else(|| app_not_found(&name))
}

/// Canonical 404 for "no such app". Centralises the message string
/// so the four name-keyed admin paths (`update`, `remove`, `get_one`,
/// `issue_deploy_key`) all produce identical bodies.
fn app_not_found(name: &str) -> AdminError {
    AdminError {
        status: StatusCode::NOT_FOUND,
        message: format!("app '{name}' not found"),
    }
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

    fn ct(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    #[test]
    fn parse_app_spec_accepts_json_by_default() {
        let body = br#"{"repo":"ghcr.io/owner/x","port":8080,"name":"alpha"}"#;
        let spec = parse_app_spec(&HeaderMap::new(), body).expect("json default");
        assert_eq!(spec.repo, "ghcr.io/owner/x");
        assert_eq!(spec.name.as_deref(), Some("alpha"));
    }

    #[test]
    fn parse_app_spec_accepts_explicit_json() {
        let body = br#"{"repo":"ghcr.io/owner/x","port":8080,"name":"alpha"}"#;
        let spec = parse_app_spec(&ct("application/json"), body).expect("explicit json");
        assert_eq!(spec.repo, "ghcr.io/owner/x");
    }

    #[test]
    fn parse_app_spec_accepts_toml() {
        let body = br#"
            repo = "ghcr.io/owner/x"
            port = 8080
            name = "alpha"
        "#;
        let spec = parse_app_spec(&ct("application/toml"), body).expect("application/toml");
        assert_eq!(spec.repo, "ghcr.io/owner/x");
        assert_eq!(spec.name.as_deref(), Some("alpha"));
    }

    #[test]
    fn parse_app_spec_accepts_text_toml_alias() {
        let body = br#"
            repo = "ghcr.io/owner/x"
            port = 8080
            name = "alpha"
        "#;
        let spec = parse_app_spec(&ct("text/toml"), body).expect("text/toml");
        assert_eq!(spec.repo, "ghcr.io/owner/x");
    }

    #[test]
    fn parse_app_spec_strips_content_type_parameters() {
        let body = br#"
            repo = "ghcr.io/owner/x"
            port = 8080
            name = "alpha"
        "#;
        let spec = parse_app_spec(&ct("application/toml; charset=utf-8"), body)
            .expect("toml with charset param");
        assert_eq!(spec.repo, "ghcr.io/owner/x");
    }

    #[test]
    fn parse_app_spec_rejects_invalid_toml_with_400() {
        let body = b"this = is = not = valid toml";
        let err = parse_app_spec(&ct("application/toml"), body).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid TOML"), "got {}", err.message);
    }

    #[test]
    fn parse_app_spec_rejects_invalid_json_with_400() {
        let body = b"{this is not json}";
        let err = parse_app_spec(&HeaderMap::new(), body).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid JSON"), "got {}", err.message);
    }

    /// The defensive path: a `Content-Type: application/toml` header
    /// on a body that isn't valid UTF-8 must not panic the parser.
    #[test]
    fn parse_app_spec_rejects_non_utf8_toml_body() {
        // 0xFF is invalid as a leading UTF-8 byte.
        let body: &[u8] = &[0xff, 0xfe];
        let err = parse_app_spec(&ct("application/toml"), body).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("UTF-8"), "got {}", err.message);
    }
}
