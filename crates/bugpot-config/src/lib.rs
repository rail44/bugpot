use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppSpec {
    pub image: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,
    #[serde(default, skip_serializing_if = "Egress::is_empty")]
    pub egress: Egress,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Scaling::is_empty")]
    pub scaling: Scaling,
    #[serde(default, skip_serializing_if = "Readiness::is_empty")]
    pub readiness: Readiness,
    #[serde(default, skip_serializing_if = "Resources::is_empty")]
    pub resources: Resources,
    #[serde(default, skip_serializing_if = "Runtime::is_empty")]
    pub runtime: Runtime,
    #[serde(skip)]
    pub source_path: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Egress {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

impl Egress {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Scaling {
    /// Idle timeout for scale-to-zero. Accepted forms:
    ///   - `"0"`, `""`, missing: always-on (container never auto-stops).
    ///   - Any [`humantime`]-compatible duration: `"30s"`, `"5m"`,
    ///     `"1h"`, `"5m 30s"`, `"2d"`, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,
}

impl Scaling {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.idle_timeout.is_none()
    }

    /// Resolve `idle_timeout` to a `Duration`. `Ok(None)` means "always on";
    /// `Ok(Some(d))` means "stop after `d` of idleness".
    pub fn resolve_idle_timeout(&self) -> Result<Option<std::time::Duration>, String> {
        let raw = self.idle_timeout.as_deref().unwrap_or("5m").trim();
        if raw.is_empty() || raw == "0" {
            return Ok(None);
        }
        humantime::parse_duration(raw)
            .map(Some)
            .map_err(|e| format!("scaling.idle_timeout: {e}"))
    }
}

/// Per-app readiness probe tuning. Currently exposes the timeout for
/// the post-start TCP probe; the poll interval stays a workspace
/// constant.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Readiness {
    /// How long to wait for the container to bind on its declared port
    /// before declaring the start a failure. Accepts any
    /// [`humantime`]-compatible duration (`"30s"`, `"5m"`, `"1m 30s"`,
    /// etc.). Missing or empty → use the workspace default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

impl Readiness {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.timeout.is_none()
    }

    /// Resolve `timeout`, falling back to `default` when unset or empty.
    pub fn resolve_timeout(
        &self,
        default: std::time::Duration,
    ) -> Result<std::time::Duration, String> {
        let raw = self.timeout.as_deref().unwrap_or("").trim();
        if raw.is_empty() {
            return Ok(default);
        }
        humantime::parse_duration(raw).map_err(|e| format!("readiness.timeout: {e}"))
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Resources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
}

impl Resources {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.memory.is_none() && self.cpu.is_none()
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Runtime {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<String>,
}

impl Runtime {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.isolation.is_none()
    }
}

impl AppSpec {
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or_else(|| {
            self.source_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
        })
    }

    #[must_use]
    pub fn subdomain(&self) -> &str {
        self.subdomain.as_deref().unwrap_or_else(|| self.name())
    }

    /// Reject specs that would put user-controlled strings on paths or
    /// kernel-namespace names. `name` becomes `<apps_dir>/<name>.toml`
    /// (path traversal would land arbitrary writes as root) and
    /// `bugpot-<name>` (netns name), so both must be a strict DNS
    /// label.
    ///
    /// Called by [`load_apps`] when reading from disk and by the admin
    /// API's `deploy_app` path; either rejects before any side effect.
    pub fn validate(&self) -> Result<(), InvalidSpec> {
        // First: refuse a spec whose `name` resolves only via the
        // `"unknown"` fallback in [`Self::name`]. That sentinel can
        // collide with other unnamed specs in `AppController.apps` —
        // here we reject early instead of silently letting two apps
        // share a key.
        if self.name.is_none() && self.source_path.file_stem().is_none() {
            return Err(InvalidSpec {
                field: "name",
                value: String::new(),
                reason: "name is required when the spec has no inferrable source path",
            });
        }
        validate_dns_label("name", self.name())?;
        // `subdomain()` defaults to `name`, so this also catches the
        // common case. When explicitly set it gets the same check.
        validate_dns_label("subdomain", self.subdomain())?;
        Ok(())
    }
}

/// Reason an `AppSpec` field failed validation. Surface this to the
/// admin API as HTTP 400.
#[derive(Debug, thiserror::Error)]
#[error("invalid {field}: {reason} (value={value:?})")]
pub struct InvalidSpec {
    pub field: &'static str,
    pub value: String,
    pub reason: &'static str,
}

/// Strict DNS label: ASCII lowercase letters, digits, and hyphens. No
/// leading or trailing hyphen. Length 1..=63 (kept inline with RFC 1035
/// section 2.3.4).
///
/// Notably **rejects** `..`, `/`, whitespace, uppercase letters,
/// underscores, and dots — the path-traversal / netns-name-escape
/// vectors the admin API would otherwise expose.
fn validate_dns_label(field: &'static str, s: &str) -> Result<(), InvalidSpec> {
    fn invalid(field: &'static str, value: &str, reason: &'static str) -> InvalidSpec {
        InvalidSpec {
            field,
            value: value.to_owned(),
            reason,
        }
    }
    if s.is_empty() {
        return Err(invalid(field, s, "must not be empty"));
    }
    if s.len() > 63 {
        return Err(invalid(field, s, "must be at most 63 characters"));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(invalid(field, s, "must not start or end with '-'"));
    }
    for c in s.chars() {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
        if !ok {
            return Err(invalid(
                field,
                s,
                "must contain only lowercase ASCII letters, digits, and '-'",
            ));
        }
    }
    Ok(())
}

/// Per-registry pull credentials.
///
/// Loaded from a single TOML file (typically `/etc/bugpot/auth.toml`,
/// root:root 0600) and keyed by registry hostname (e.g. `"ghcr.io"`,
/// `"docker.io"`, `"registry.gitlab.com"`).
#[derive(Clone, Default, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub registries: HashMap<String, RegistryCredential>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose hostnames in case the set itself is sensitive; just
        // show the count.
        f.debug_struct("AuthConfig")
            .field("registries", &self.registries.len())
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RegistryCredential {
    Bearer { token: String },
    Basic { username: String, password: String },
}

impl std::fmt::Debug for RegistryCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer { .. } => f
                .debug_struct("Bearer")
                .field("token", &"<redacted>")
                .finish(),
            Self::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}

/// Load a registry-auth TOML. Returns an empty config when `path` does
/// not exist (so missing `auth.toml` is silently equivalent to "no auth
/// configured").
pub fn load_auth(path: impl AsRef<Path>) -> Result<AuthConfig> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(AuthConfig::default());
    }
    // Auth.toml holds registry passwords; mirror what
    // `BUGPOT_ADMIN_TOKEN_FILE` enforces. Any group / other access bit
    // set (mask `0o077`) makes us refuse to start, ssh-key style.
    require_owner_only(path)?;
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&body).with_context(|| format!("failed to parse {}", path.display()))
}

/// Reject files that any non-owner principal can read, write, or
/// execute. Used for credential files (auth.toml, admin-token files).
/// Returns the original error context when the file is unreadable.
#[cfg(unix)]
fn require_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("stat credentials file {}", path.display()))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "credentials file {} has permissive mode {mode:#o}; refusing to start (run `chmod 600 {0}` so only its owner can read it)",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

/// Extract the registry hostname from an image reference.
///
/// Follows the OCI / Docker rule: a reference with no `/` (e.g.
/// `alpine:latest`) implies `docker.io`. Otherwise, if the part before
/// the first `/` contains a `.` or a `:`, or equals `"localhost"`, treat
/// it as a hostname; else also default to `"docker.io"` (e.g.
/// `library/alpine:latest`).
#[must_use]
pub fn registry_host(image_ref: &str) -> &str {
    let Some(first_slash) = image_ref.find('/') else {
        return "docker.io";
    };
    let first = &image_ref[..first_slash];
    if first.contains('.') || first.contains(':') || first == "localhost" {
        first
    } else {
        "docker.io"
    }
}

pub fn load_apps(dir: impl AsRef<Path>) -> Result<Vec<AppSpec>> {
    let dir = dir.as_ref();
    anyhow::ensure!(
        dir.exists(),
        "apps directory not found: {}",
        dir.display()
    );

    let mut apps = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .max_depth(1)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file()
                && e.path().extension().and_then(|s| s.to_str()) == Some("toml")
        })
    {
        let path = entry.path();
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut spec: AppSpec = toml::from_str(&body)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        spec.source_path = path.to_path_buf();
        spec.validate()
            .with_context(|| format!("invalid spec in {}", path.display()))?;
        apps.push(spec);
    }
    apps.sort_by(|a, b| a.name().cmp(b.name()));
    Ok(apps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_dns_label_accepts_typical_names() {
        for s in ["alpha", "beta", "dev-alpha", "app-1", "x", &"a".repeat(63)] {
            assert!(validate_dns_label("name", s).is_ok(), "should accept: {s:?}");
        }
    }

    #[test]
    fn validate_dns_label_rejects_path_traversal_and_meta() {
        for s in [
            "",
            "../foo",
            "foo/bar",
            "foo bar",
            "foo.bar",
            "Foo",          // uppercase
            "foo_bar",      // underscore
            "-foo",         // leading hyphen
            "foo-",         // trailing hyphen
            &"a".repeat(64),
            "foo\0bar",
            "foo;bar",
            "foo$bar",
        ] {
            assert!(validate_dns_label("name", s).is_err(), "should reject: {s:?}");
        }
    }

    #[test]
    fn appspec_validate_catches_path_traversal_via_name() {
        let body = r#"
            image = "x:1"
            port = 8080
            name = "../../etc/cron.d/evil"
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        let err = spec.validate().expect_err("path traversal name must be rejected");
        assert_eq!(err.field, "name");
    }

    #[test]
    fn appspec_validate_rejects_unresolvable_name() {
        // No `name` field, no `source_path` → would fall back to the
        // `"unknown"` sentinel. Must be caught at validate-time so two
        // such specs can't collide in `AppController.apps`.
        let body = r#"
            image = "x:1"
            port = 8080
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        // `source_path` defaults to `PathBuf::new()`, which has no file_stem.
        let err = spec
            .validate()
            .expect_err("unresolvable name must be rejected");
        assert_eq!(err.field, "name");
    }

    #[test]
    fn appspec_validate_catches_bad_subdomain() {
        let body = r#"
            image = "x:1"
            port = 8080
            name = "ok"
            subdomain = "Bad-Subdomain"
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        let err = spec.validate().expect_err("uppercase subdomain must be rejected");
        assert_eq!(err.field, "subdomain");
    }

    #[test]
    fn parses_minimum_toml() {
        let body = r#"
            image = "ghcr.io/org/myapp:sha-abc"
            port = 3000
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        assert_eq!(spec.image, "ghcr.io/org/myapp:sha-abc");
        assert_eq!(spec.port, 3000);
        assert!(spec.egress.allow.is_empty());
    }

    #[test]
    fn parses_full_toml() {
        let body = r#"
            image = "ghcr.io/org/myapp:sha-abc"
            port = 3000
            name = "myapp"
            subdomain = "my-custom"

            [egress]
            allow = ["api.openai.com", "*.googleapis.com"]

            [env]
            LOG_LEVEL = "info"

            [scaling]
            idle_timeout = "5m"

            [resources]
            memory = "256MB"
            cpu = "0.5"

            [runtime]
            isolation = "crun"
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        assert_eq!(spec.name(), "myapp");
        assert_eq!(spec.subdomain(), "my-custom");
        assert_eq!(spec.egress.allow.len(), 2);
        assert_eq!(spec.env.get("LOG_LEVEL").map(String::as_str), Some("info"));
    }

    #[test]
    fn scaling_default_idle_timeout_is_five_minutes() {
        let s = Scaling::default();
        assert_eq!(
            s.resolve_idle_timeout().unwrap(),
            Some(std::time::Duration::from_mins(5))
        );
    }

    #[test]
    fn scaling_zero_is_always_on() {
        let s = Scaling {
            idle_timeout: Some("0".into()),
        };
        assert_eq!(s.resolve_idle_timeout().unwrap(), None);
    }

    #[test]
    fn scaling_units() {
        for (raw, want_secs) in [
            ("30s", 30),
            ("5m", 300),
            ("2h", 7200),
            ("1m 30s", 90), // humantime composite form
            ("2d", 2 * 86_400),
        ] {
            let s = Scaling {
                idle_timeout: Some(raw.into()),
            };
            assert_eq!(
                s.resolve_idle_timeout().unwrap(),
                Some(std::time::Duration::from_secs(want_secs)),
                "case {raw}"
            );
        }
    }

    #[test]
    fn scaling_empty_string_means_always_on() {
        let s = Scaling {
            idle_timeout: Some(String::new()),
        };
        assert!(s.resolve_idle_timeout().unwrap().is_none());
    }

    #[test]
    fn scaling_rejects_garbage() {
        // humantime requires a unit on every numeric — bare numbers and
        // unknown trailing letters both fail.
        for raw in ["abc", "5", "5xyz"] {
            let s = Scaling {
                idle_timeout: Some(raw.into()),
            };
            assert!(s.resolve_idle_timeout().is_err(), "should reject: {raw}");
        }
    }

    #[test]
    fn readiness_default_returns_supplied_fallback() {
        let r = Readiness::default();
        let got = r.resolve_timeout(std::time::Duration::from_secs(7)).unwrap();
        assert_eq!(got, std::time::Duration::from_secs(7));
    }

    #[test]
    fn readiness_explicit_value_overrides_default() {
        let r = Readiness {
            timeout: Some("30s".into()),
        };
        let got = r.resolve_timeout(std::time::Duration::from_secs(7)).unwrap();
        assert_eq!(got, std::time::Duration::from_secs(30));
    }

    #[test]
    fn readiness_empty_string_uses_default() {
        let r = Readiness {
            timeout: Some(String::new()),
        };
        let got = r.resolve_timeout(std::time::Duration::from_secs(7)).unwrap();
        assert_eq!(got, std::time::Duration::from_secs(7));
    }

    #[test]
    fn readiness_rejects_garbage() {
        let r = Readiness {
            timeout: Some("not-a-duration".into()),
        };
        assert!(r.resolve_timeout(std::time::Duration::from_secs(7)).is_err());
    }

    #[test]
    fn name_defaults_to_filename_stem() {
        let mut spec: AppSpec = toml::from_str(r#"image = "x"
port = 80
"#)
        .unwrap();
        spec.source_path = PathBuf::from("/tmp/apps/some-app.toml");
        assert_eq!(spec.name(), "some-app");
        assert_eq!(spec.subdomain(), "some-app");
    }

    /// Adapter crates persist specs back to disk via `toml::to_string`.
    /// Guarantee that the round-trip (Serialize → Deserialize) is stable
    /// so a deploy followed by a restart sees the same logical spec.
    #[test]
    fn serialize_deserialize_round_trip_minimum() {
        let original: AppSpec = toml::from_str(
            r#"
            image = "ghcr.io/org/app:sha-abc"
            port = 3000
            name = "myapp"
        "#,
        )
        .unwrap();
        let body = toml::to_string(&original).expect("serialize");
        let parsed: AppSpec = toml::from_str(&body).expect("deserialize");
        assert_eq!(parsed.image, original.image);
        assert_eq!(parsed.port, original.port);
        assert_eq!(parsed.name, original.name);
    }

    #[test]
    fn serialize_omits_default_sections() {
        let spec: AppSpec = toml::from_str(
            r#"
            image = "x"
            port = 80
            name = "x"
        "#,
        )
        .unwrap();
        let body = toml::to_string(&spec).unwrap();
        assert!(!body.contains("[egress]"), "got: {body}");
        assert!(!body.contains("[env]"), "got: {body}");
        assert!(!body.contains("[scaling]"), "got: {body}");
        assert!(!body.contains("[resources]"), "got: {body}");
        assert!(!body.contains("[runtime]"), "got: {body}");
    }

    #[test]
    fn registry_host_extracts_hostname() {
        assert_eq!(registry_host("ghcr.io/owner/repo:tag"), "ghcr.io");
        assert_eq!(
            registry_host("registry.gitlab.com/group/project:1.0"),
            "registry.gitlab.com"
        );
        assert_eq!(registry_host("localhost:5000/foo:bar"), "localhost:5000");
        // No hostname-looking first component → defaults to docker.io.
        assert_eq!(registry_host("library/alpine:latest"), "docker.io");
        assert_eq!(registry_host("alpine:latest"), "docker.io");
    }

    #[test]
    fn parses_auth_toml() {
        let body = r#"
            [registries."ghcr.io"]
            type = "bearer"
            token = "ghp_abc"

            [registries."docker.io"]
            type = "basic"
            username = "myuser"
            password = "mypass"
        "#;
        let cfg: AuthConfig = toml::from_str(body).unwrap();
        assert_eq!(cfg.registries.len(), 2);
        let RegistryCredential::Bearer { token } = cfg.registries.get("ghcr.io").unwrap() else {
            panic!("expected Bearer for ghcr.io");
        };
        assert_eq!(token, "ghp_abc");
        let RegistryCredential::Basic { username, password } =
            cfg.registries.get("docker.io").unwrap()
        else {
            panic!("expected Basic for docker.io");
        };
        assert_eq!(username, "myuser");
        assert_eq!(password, "mypass");
    }

    #[test]
    fn auth_debug_redacts_secrets() {
        let bearer = RegistryCredential::Bearer {
            token: "supersecret-xyz".to_string(),
        };
        let basic = RegistryCredential::Basic {
            username: "alice".to_string(),
            password: "p4ssw0rd!".to_string(),
        };
        let bearer_dbg = format!("{bearer:?}");
        let basic_dbg = format!("{basic:?}");
        assert!(!bearer_dbg.contains("supersecret-xyz"), "got: {bearer_dbg}");
        assert!(!basic_dbg.contains("p4ssw0rd!"), "got: {basic_dbg}");
        // Non-secret fields stay visible for debugging.
        assert!(basic_dbg.contains("alice"), "got: {basic_dbg}");
    }

    #[test]
    fn load_auth_missing_file_is_empty() {
        let cfg = load_auth("/nonexistent/path/auth.toml").unwrap();
        assert!(cfg.registries.is_empty());
    }

    #[test]
    fn serialize_preserves_egress_and_scaling() {
        let original: AppSpec = toml::from_str(
            r#"
            image = "x"
            port = 80
            name = "x"
            [egress]
            allow = ["api.openai.com"]
            [scaling]
            idle_timeout = "30s"
        "#,
        )
        .unwrap();
        let body = toml::to_string(&original).unwrap();
        let parsed: AppSpec = toml::from_str(&body).unwrap();
        assert_eq!(parsed.egress.allow, vec!["api.openai.com"]);
        assert_eq!(parsed.scaling.idle_timeout.as_deref(), Some("30s"));
    }
}
