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
//! Translates HTTP requests to mutations on [`bugpot_core::AppHost`].
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
//!
//! Note: `pub(crate)` is used for cross-module items inside this crate
//! (`handlers.rs`, `auth.rs`, `error.rs`); the
//! `clippy::redundant_pub_crate` warning conflicts with the
//! workspace's `unreachable_pub` rule, so the former is allowed
//! crate-wide (same convention as `bugpot-core` / `bugpot-runtime`).

#![allow(clippy::redundant_pub_crate)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::http::StatusCode;
use axum::middleware;
use axum::{
    BoxError, Router,
    error_handling::HandleErrorLayer,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bugpot_core::AppHost;
use bugpot_egress::Egress;
use bugpot_runtime::Runtime;
use tower::ServiceBuilder;
use tower::limit::RateLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

pub mod deploy_key;
pub use deploy_key::DeployKeySecret;

mod auth;
mod error;
mod handlers;

pub use auth::AdminAuth;

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
pub(crate) use audit_ok;

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
pub(crate) use audit_err;

/// Maximum POST body size for `POST /apps`. `AppSpec` JSON is usually
/// well under 1 KB; the cap stops the `env` map from being weaponised
/// into a memory-exhaustion vector.
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024;
/// Global rate limit on admin API requests. Brute-forcing a bearer
/// token at this rate is infeasible.
const RATE_LIMIT_REQUESTS: u64 = 60;
const RATE_LIMIT_PERIOD: Duration = Duration::from_mins(1);

/// The fully-resolved controller type the admin layer talks to.
///
/// The Linux production stack only has one `Runtime` / `Egress` pair,
/// so spelling them out here avoids the `<R, E>` noise that used to
/// follow every handler signature — without resorting to a `dyn`
/// abstraction that no caller swaps. The `AppHost`'s own
/// parameterisation stays in place for controller-side tests
/// (the mocks live in that crate); this crate just commits to the
/// one shape it actually deploys with.
type Controller = AppHost<Runtime, Egress>;

/// Combined state passed to every handler / middleware.
///
/// Bundling these together lets one merged router cover both auth
/// scopes (admin token + deploy token) without the State-type
/// juggling that arises from per-route `.with_state(...)`.
#[derive(Clone, Debug)]
pub struct AdminState {
    pub controller: Arc<Controller>,
    pub admin_auth: Arc<AdminAuth>,
    pub deploy_secret: Arc<DeployKeySecret>,
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
        .route("/apps", post(handlers::deploy).get(handlers::list))
        .route(
            "/apps/{name}",
            get(handlers::get_one)
                .patch(handlers::update)
                .delete(handlers::remove),
        )
        .route("/apps/{name}/deploy-keys", post(handlers::issue_deploy_key))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin_token,
        ));

    let rollout_routes = Router::new()
        .route(
            "/apps/{name}/rollouts",
            post(handlers::roll_out).get(handlers::list_rollouts),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_deploy_token,
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
    error::AdminError {
        status: StatusCode::TOO_MANY_REQUESTS,
        message: format!("rate limit exceeded: {err}"),
    }
    .into_response()
}
