//! Request handlers for the admin API + the shared body extractor
//! and DTOs.
//!
//! Each handler is a thin axum signature that:
//!   1. Extracts state / path / body.
//!   2. Calls one [`AppHost`] method.
//!   3. Emits an `audit_ok!` / `audit_err!` envelope.
//!   4. Maps the controller's result into JSON via `AdminError`'s
//!      `From` impls (in [`crate::error`]).
//!
//! Heavy lifting (state mutation, persistence) lives in
//! `bugpot-core`; this module is the translator.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::body;
use axum::extract::{ConnectInfo, FromRequest, Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};

use bugpot_config::{AppSpec, Rollout};
use bugpot_core::{AppHandle, AppView};

use crate::error::AdminError;
use crate::{AdminState, MAX_BODY_BYTES, audit_err, audit_ok};

/// Axum extractor that consumes the request body as an `AppSpec`.
/// Composes naturally in handler signatures so `deploy` / `update`
/// drop the manual `HeaderMap + Bytes + parse_app_spec(...)` triple.
///
/// Must be the last extractor in a handler signature — it consumes
/// the request body.
pub(crate) struct ParsedAppSpec(pub(crate) AppSpec);

impl<S: Send + Sync> FromRequest<S> for ParsedAppSpec {
    type Rejection = AdminError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let headers = req.headers().clone();
        let bytes = body::to_bytes(req.into_body(), MAX_BODY_BYTES)
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
pub(crate) fn parse_app_spec(headers: &HeaderMap, body: &[u8]) -> Result<AppSpec, AdminError> {
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

pub(crate) async fn deploy(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AdminState>,
    ParsedAppSpec(spec): ParsedAppSpec,
) -> Result<(StatusCode, Json<AppView>), AdminError> {
    let audit_name = spec.name.clone();
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

pub(crate) async fn update(
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
pub(crate) struct RolloutBody {
    tag: String,
}

pub(crate) async fn roll_out(
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

pub(crate) async fn list_rollouts(
    State(state): State<AdminState>,
    axum::extract::Extension(handle): axum::extract::Extension<Arc<AppHandle>>,
) -> Json<Vec<Rollout>> {
    Json(state.controller.list_rollouts(&handle).await)
}

#[derive(Debug, Serialize)]
pub(crate) struct DeployKeyResponse {
    /// Wire-format deploy token (`bp1.<hex>`). Bearer this in
    /// `Authorization` against `/apps/<name>/rollouts`.
    token: String,
}

pub(crate) async fn issue_deploy_key(
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

pub(crate) async fn remove(
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

pub(crate) async fn list(State(state): State<AdminState>) -> Json<Vec<AppView>> {
    Json(state.controller.list_apps().await)
}

pub(crate) async fn get_one(
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

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
        assert_eq!(spec.name, "alpha");
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
        assert_eq!(spec.name, "alpha");
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
