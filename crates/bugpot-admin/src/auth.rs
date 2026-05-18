//! Bearer-token auth for the admin API.
//!
//! Two scopes live here, sharing one `subtle::ConstantTimeEq`-based
//! comparison path:
//!
//! - **Admin token** ([`AdminAuth`]): full config-plane access. The
//!   single expected token is set at boot from
//!   `BUGPOT_ADMIN_TOKEN[_FILE]`.
//! - **Deploy token**: per-app HMAC checked by
//!   [`require_deploy_token`] against the spec's current `repo`. The
//!   verifier lives in [`crate::deploy_key`]; this module wires it
//!   into the request middleware.

use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::AdminState;

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

pub(crate) async fn require_admin_token(
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
pub(crate) async fn require_deploy_token(
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
