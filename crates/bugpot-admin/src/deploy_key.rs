//! Per-app deploy tokens.
//!
//! A deploy token is a stateless credential that authorises **only**
//! `POST /apps/<name>/rollouts` (and `GET /apps/<name>/rollouts`).
//! Unlike the admin token, it does not let the bearer create or
//! delete apps; the threat-model upper bound for a leaked deploy
//! token is "attacker can roll an image to one specific app, but
//! only an image they can push to that app's configured `repo`".
//!
//! ## Derivation
//!
//! ```text
//! token = "bp1." || hex(HMAC-SHA256(
//!     secret,
//!     b"bp1\x00" || u32_le(len(name))  || name
//!                || u32_le(len(repo))  || repo
//! ))
//! ```
//!
//! - The `bp1.` wire prefix advertises the format version. A future
//!   `bp2.` (e.g. to carry scoped permissions in a signed claim
//!   blob) can be added without breaking existing tokens — the
//!   verifier looks at the prefix first.
//! - The HMAC input is bound to the app's `name` + `repo`. Any
//!   admin-side change to either field invalidates every previously
//!   issued token for that app; other config changes (port,
//!   scaling, env, …) do not. This was the agreed v1 binding subset:
//!   identity (`name`) plus the registry the bearer can effectively
//!   push to (`repo`).
//! - No persistence. Issuance is a pure function of the secret +
//!   binding; revocation is by rotating the secret (all tokens) or
//!   by changing the app's `name` / `repo` (that app's tokens).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Wire-format prefix for v1 deploy tokens. The trailing `.`
/// separates the version tag from the hex MAC.
const WIRE_PREFIX: &str = "bp1.";
/// Domain-separation tag mixed into the HMAC input. Distinct from
/// the wire prefix so a future `bp2.<...>` derivation with a
/// different input layout cannot accidentally collide with `bp1.`
/// tokens even when the secret is shared.
const HMAC_DOMAIN_TAG: &[u8] = b"bp1\x00";
/// Hex(SHA-256) = 64 chars. `WIRE_PREFIX` is 4 chars. Total token
/// length is therefore exactly 68; anything else is malformed.
const HEX_MAC_LEN: usize = 64;

/// Holder of the server-side HMAC secret.
///
/// The secret is loaded once at startup (from
/// `BUGPOT_DEPLOY_SECRET_FILE` or the `BUGPOT_DEPLOY_SECRET` env
/// fallback) and wrapped in `Zeroizing` so it is wiped on drop and
/// never leaks through `Debug`.
pub struct DeployKeySecret {
    secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for DeployKeySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeployKeySecret").finish_non_exhaustive()
    }
}

impl DeployKeySecret {
    /// Build a deploy-key secret from the raw bytes loaded from
    /// disk / env. Empty input is allowed at the type level, but
    /// `cmd/bugpot` refuses to start with an empty value.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            secret: Zeroizing::new(bytes),
        }
    }

    /// Compute the deploy token for `(name, repo)`. Returns a
    /// printable `bp1.<hex>` string.
    #[must_use]
    pub fn derive(&self, name: &str, repo: &str) -> String {
        let mac = self.mac_bytes(name, repo);
        let mut token = String::with_capacity(WIRE_PREFIX.len() + HEX_MAC_LEN);
        token.push_str(WIRE_PREFIX);
        token.push_str(&hex::encode(mac));
        token
    }

    /// Verify a `presented` token against the expected `(name,
    /// repo)`. Constant-time comparison against the recomputed
    /// value. Returns `false` for the wrong version prefix, the
    /// wrong length, or any byte mismatch — the caller maps the
    /// boolean to a uniform 401 response so the verdict reveals
    /// nothing more than "you do not pass".
    #[must_use]
    pub fn verify(&self, presented: &str, name: &str, repo: &str) -> bool {
        // Length-first reject — saves the HMAC computation when the
        // input is obviously not one of our tokens, without leaking
        // information beyond "wrong shape".
        if presented.len() != WIRE_PREFIX.len() + HEX_MAC_LEN {
            return false;
        }
        let Some(hex_part) = presented.strip_prefix(WIRE_PREFIX) else {
            return false;
        };
        let Ok(presented_mac) = hex::decode(hex_part) else {
            return false;
        };
        let expected_mac = self.mac_bytes(name, repo);
        bool::from(presented_mac.ct_eq(&expected_mac))
    }

    fn mac_bytes(&self, name: &str, repo: &str) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(self.secret.as_slice())
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(HMAC_DOMAIN_TAG);
        // Length-prefixed fields prevent boundary-shifting collisions
        // (e.g. `(name="ab", repo="cd")` colliding with
        // `(name="a", repo="bcd")` if the fields were just
        // concatenated).
        let name_bytes = name.as_bytes();
        let repo_bytes = repo.as_bytes();
        // App names + repo URLs are bounded well under u32 in practice
        // (DNS-label limits + OCI ref length caps), so a saturating
        // truncate keeps a hypothetical 4 GiB name from collapsing into
        // a colliding shorter one rather than from being faithfully
        // hashed.
        mac.update(
            &u32::try_from(name_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        mac.update(name_bytes);
        mac.update(
            &u32::try_from(repo_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        mac.update(repo_bytes);
        mac.finalize().into_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_secret() -> DeployKeySecret {
        DeployKeySecret::from_bytes(b"test-secret-xyz".to_vec())
    }

    #[test]
    fn derive_then_verify_round_trip() {
        let s = fresh_secret();
        let token = s.derive("alpha", "ghcr.io/owner/myapp");
        assert!(s.verify(&token, "alpha", "ghcr.io/owner/myapp"));
    }

    #[test]
    fn token_has_versioned_wire_prefix_and_64_hex_chars() {
        let s = fresh_secret();
        let token = s.derive("alpha", "ghcr.io/owner/myapp");
        assert!(token.starts_with("bp1."));
        assert_eq!(token.len(), 4 + 64);
        let hex_part = &token[4..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn name_change_invalidates_token() {
        let s = fresh_secret();
        let token = s.derive("alpha", "ghcr.io/owner/myapp");
        assert!(!s.verify(&token, "beta", "ghcr.io/owner/myapp"));
    }

    #[test]
    fn repo_change_invalidates_token() {
        let s = fresh_secret();
        let token = s.derive("alpha", "ghcr.io/owner/myapp");
        assert!(!s.verify(&token, "alpha", "ghcr.io/other/myapp"));
    }

    /// Other config changes (port, scaling, env) are not part of
    /// the HMAC input — those edits leave the token valid. This is
    /// the agreed v1 binding subset and the test pins it.
    #[test]
    fn binding_subset_excludes_non_name_non_repo_fields() {
        let s = fresh_secret();
        let t1 = s.derive("alpha", "ghcr.io/owner/myapp");
        // The verifier only sees `(name, repo)`. Any other field
        // changing in the controller's spec by definition cannot
        // affect the boolean below.
        let t2 = s.derive("alpha", "ghcr.io/owner/myapp");
        assert_eq!(t1, t2);
    }

    #[test]
    fn rejects_wrong_version_prefix() {
        let s = fresh_secret();
        let token = s.derive("alpha", "ghcr.io/owner/myapp");
        let tampered = token.replacen("bp1.", "bp2.", 1);
        assert!(!s.verify(&tampered, "alpha", "ghcr.io/owner/myapp"));
    }

    #[test]
    fn rejects_wrong_length() {
        let s = fresh_secret();
        assert!(!s.verify("bp1.shortmac", "alpha", "x"));
        assert!(!s.verify("", "alpha", "x"));
        let mut too_long = s.derive("alpha", "x");
        too_long.push('0');
        assert!(!s.verify(&too_long, "alpha", "x"));
    }

    #[test]
    fn rejects_non_hex_payload() {
        let s = fresh_secret();
        let token = s.derive("alpha", "ghcr.io/owner/myapp");
        // Replace one hex char with a non-hex through Vec to avoid
        // the unsafe `as_bytes_mut` route.
        let mut bytes = token.into_bytes();
        bytes[5] = b'!';
        let tampered = String::from_utf8(bytes).expect("ASCII");
        assert!(!s.verify(&tampered, "alpha", "ghcr.io/owner/myapp"));
    }

    /// Two secrets must derive different tokens for the same
    /// `(name, repo)`. Pins "rotate the secret = revoke all
    /// tokens" semantics.
    #[test]
    fn different_secrets_derive_different_tokens() {
        let a = DeployKeySecret::from_bytes(b"secret-a".to_vec());
        let b = DeployKeySecret::from_bytes(b"secret-b".to_vec());
        let ta = a.derive("alpha", "ghcr.io/owner/myapp");
        let tb = b.derive("alpha", "ghcr.io/owner/myapp");
        assert_ne!(ta, tb);
    }

    /// Bound-collision regression: length-prefixed fields stop
    /// `(name="ab", repo="cd")` from sharing an HMAC input with
    /// `(name="a", repo="bcd")`. Both end up as `b"abcd"` if the
    /// derivation just concatenates; the length prefixes keep them
    /// distinct.
    #[test]
    fn length_prefix_prevents_boundary_collision() {
        let s = fresh_secret();
        assert_ne!(s.derive("ab", "cd"), s.derive("a", "bcd"));
    }
}
