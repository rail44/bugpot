use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// One image-rollout event for an app.
///
/// The pair `(repo from AppSpec, tag)` is what bugpot actually pulls
/// and runs; rollouts are appended to a bounded per-app history so a
/// rollback can re-deploy a previous tag without going back to the
/// registry's mutable view.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Rollout {
    /// Image tag (e.g. `v1.2.3`, a git SHA, or `latest`). Combined with
    /// the app's `repo` to form the full reference bugpot pulls.
    pub tag: String,
    /// RFC 3339 timestamp produced by bugpot at rollout creation time.
    /// Stored as a string (rather than a typed `DateTime`) so the TOML
    /// is round-trippable without pulling in a heavyweight time-format
    /// dependency on the config side.
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppSpec {
    /// OCI image repository without tag or digest, e.g.
    /// `ghcr.io/owner/myapp`. The specific image to run (which tag /
    /// digest) is selected by a separate Rollout — this field
    /// answers only the "where does bugpot pull from" question.
    /// Validation rejects `:` (tag separator) and `@` (digest
    /// separator) in this value.
    pub repo: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,
    #[serde(default, skip_serializing_if = "EgressSpec::is_empty")]
    pub egress: EgressSpec,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Scaling::is_empty")]
    pub scaling: Scaling,
    #[serde(default, skip_serializing_if = "Readiness::is_empty")]
    pub readiness: Readiness,
    #[serde(default, skip_serializing_if = "Resources::is_empty")]
    pub resources: Resources,
    /// Persistent volumes bind-mounted from
    /// `<state>/volumes/<app>/<name>/` into the container at the
    /// declared path. Survives `idle` freeze, memory-pressure
    /// eviction, and rollouts; cleared only on `DELETE /apps/<name>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<VolumeSpec>,
    #[serde(skip)]
    pub source_path: PathBuf,
}

/// One persistent bind mount into a container.
///
/// **Permissions trap.** Containers commonly run as a non-root user
/// (Linkding uid=33, Vaultwarden uid=1000, …). The host-side directory
/// inherits root ownership at creation, so the app gets EACCES on
/// first write. Set `user` to the container's expected UID and bugpot
/// chowns the directory at start time; leave it `None` only if the
/// image runs as root or pre-chowns the path itself.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VolumeSpec {
    /// Volume identifier, unique within an app. Maps to the host
    /// directory `<state>/volumes/<app>/<name>/`. Must be a strict
    /// DNS label (same alphabet as `name` / `subdomain`) so it can't
    /// path-escape its parent.
    pub name: String,
    /// Absolute mount point inside the container.
    pub path: PathBuf,
    /// Optional UID to `chown` the host directory to at start time
    /// (also used as the GID, mirroring how most container images
    /// stage `user:user 0755` dirs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<u32>,
}

/// `[egress]` section of an app TOML. The name distinguishes the
/// configuration shape from the engine struct in `bugpot-egress`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EgressSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

impl EgressSpec {
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

/// Per-app readiness probe tuning.
///
/// **`timeout`** caps how long the controller waits for the app to
/// signal ready after a cold start; falls back to the workspace
/// default when missing.
///
/// **`path`** opts the app into an HTTP-level probe instead of the
/// default TCP-bind check. When set, `bugpot-controller` issues
/// `GET <ip>:<port><path>` until it gets a 2xx response (or the
/// timeout fires). When unset, the controller only waits for the
/// container to accept TCP connections on `port`.
///
/// HTTP is opt-in rather than the default because the canonical
/// `/healthz` is a Kubernetes idiom, not a self-hosted-tool one:
/// Vaultwarden serves `/alive`, Linkding `/health`, Miniflux
/// `/healthcheck`, Grafana `/api/health`, etc. Forcing a fixed path
/// would break every pre-built image that picked a different name.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Readiness {
    /// How long to wait for the container to bind on its declared port
    /// before declaring the start a failure. Accepts any
    /// [`humantime`]-compatible duration (`"30s"`, `"5m"`, `"1m 30s"`,
    /// etc.). Missing or empty → use the workspace default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// Absolute HTTP path the controller should GET to declare the app
    /// ready. Must start with `/` and not contain `..`. When `None`
    /// (the default) the controller falls back to TCP-only probing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Readiness {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.timeout.is_none() && self.path.is_none()
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
    /// Hard memory ceiling applied when an app spec omits `[resources]
    /// memory`. Sized for the "many small apps on a cheap VM" scenario
    /// — without a default an unbounded app can OOM-kill the host.
    pub const DEFAULT_MEMORY: &'static str = "128MB";
    /// Default CPU share when `[resources] cpu` is omitted: half a core.
    /// Two apps can comfortably share one vCPU at this default.
    pub const DEFAULT_CPU: &'static str = "0.5";

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.memory.is_none() && self.cpu.is_none()
    }

    /// Memory limit string actually applied at start time.
    /// Falls back to [`Self::DEFAULT_MEMORY`] when not specified.
    #[must_use]
    pub fn effective_memory(&self) -> &str {
        self.memory.as_deref().unwrap_or(Self::DEFAULT_MEMORY)
    }

    /// CPU share string actually applied at start time. Falls back to
    /// [`Self::DEFAULT_CPU`] when not specified.
    #[must_use]
    pub fn effective_cpu(&self) -> &str {
        self.cpu.as_deref().unwrap_or(Self::DEFAULT_CPU)
    }
}

/// Immutable identity of a registered app.
///
/// The pair `(name, subdomain)` pins an app to a filesystem path, a
/// netns, a cgroup, and a routing key. Computed once from an
/// `AppSpec` (typically at deploy / load time) and never mutated.
///
/// Consumers that hold an `AppIdentity` can safely treat the values
/// as the *authoritative* identifiers, regardless of whether a
/// later spec update tries to change them: PUT-style adapters
/// compare against this identity and reject mismatched updates.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppIdentity {
    pub name: String,
    pub subdomain: String,
}

impl AppIdentity {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn subdomain(&self) -> &str {
        &self.subdomain
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

    /// Resolve the spec's mutable `name` / `subdomain` fields into an
    /// owned, immutable [`AppIdentity`]. Returns the resolved identity
    /// only after `validate()` would succeed, so callers can rely on
    /// the strings being valid DNS labels.
    pub fn identity(&self) -> Result<AppIdentity, InvalidSpec> {
        self.validate()?;
        Ok(AppIdentity {
            name: self.name().to_owned(),
            subdomain: self.subdomain().to_owned(),
        })
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
        validate_repo(&self.repo)?;
        validate_volumes(&self.volumes)?;
        validate_readiness_path(self.readiness.path.as_deref())?;
        Ok(())
    }
}

/// `readiness.path` (when set) must be an absolute HTTP path with no
/// traversal segments. Query strings or fragments are rejected: the
/// probe path should be canonical and stable, not carry per-request
/// state.
fn validate_readiness_path(path: Option<&str>) -> Result<(), InvalidSpec> {
    let Some(raw) = path else {
        return Ok(());
    };
    let invalid = |reason: &'static str| InvalidSpec {
        field: "readiness.path",
        value: raw.to_owned(),
        reason,
    };
    if !raw.starts_with('/') {
        return Err(invalid("must start with '/'"));
    }
    if raw.split('/').any(|seg| seg == "..") {
        return Err(invalid("must not contain '..' segments"));
    }
    if raw.contains('?') || raw.contains('#') {
        return Err(invalid("must not contain query string or fragment"));
    }
    Ok(())
}

/// Reserved mount points: bugpot or libcontainer already binds something
/// here, so user volumes that target the same path would shadow or
/// conflict. Compared as path strings (trailing slashes normalised away).
const RESERVED_MOUNT_PATHS: &[&str] = &[
    "/",
    "/proc",
    "/sys",
    "/dev",
    "/dev/pts",
    "/dev/shm",
    "/dev/mqueue",
    "/etc/resolv.conf",
];

fn validate_volumes(volumes: &[VolumeSpec]) -> Result<(), InvalidSpec> {
    let mut seen_names: HashSet<&str> = HashSet::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    for v in volumes {
        validate_dns_label("volumes.name", &v.name)?;
        let path = &v.path;
        if !path.is_absolute() {
            return Err(InvalidSpec {
                field: "volumes.path",
                value: path.display().to_string(),
                reason: "must be an absolute container-internal path",
            });
        }
        let normalised: PathBuf = path
            .components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .collect();
        let s = normalised.to_string_lossy();
        if s.contains("..") {
            return Err(InvalidSpec {
                field: "volumes.path",
                value: path.display().to_string(),
                reason: "must not contain '..' segments",
            });
        }
        if RESERVED_MOUNT_PATHS.iter().any(|r| *r == s) {
            return Err(InvalidSpec {
                field: "volumes.path",
                value: path.display().to_string(),
                reason: "collides with a path bugpot or libcontainer already mounts",
            });
        }
        if !seen_names.insert(v.name.as_str()) {
            return Err(InvalidSpec {
                field: "volumes.name",
                value: v.name.clone(),
                reason: "duplicate volume name within app",
            });
        }
        if !seen_paths.insert(normalised) {
            return Err(InvalidSpec {
                field: "volumes.path",
                value: path.display().to_string(),
                reason: "duplicate mount point within app",
            });
        }
    }
    Ok(())
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
/// Reject image references that include a tag (`repo:tag`) or digest
/// (`repo@sha256:...`). The spec carries only the repository part;
/// the specific tag / digest to run is the Rollout's job.
fn validate_repo(s: &str) -> Result<(), InvalidSpec> {
    fn invalid(value: &str, reason: &'static str) -> InvalidSpec {
        InvalidSpec {
            field: "repo",
            value: value.to_owned(),
            reason,
        }
    }
    if s.is_empty() {
        return Err(invalid(s, "must not be empty"));
    }
    if s.contains('@') {
        return Err(invalid(
            s,
            "must not include a digest (`@sha256:…`); pin via a rollout instead",
        ));
    }
    // A `:` in the last path component (or in a tail with no `/`) is the
    // tag separator. A `:` in the host component (e.g. `localhost:5000`)
    // is the port — allow that.
    let last = s.rsplit('/').next().unwrap_or(s);
    if last.contains(':') {
        return Err(invalid(
            s,
            "must not include a tag (`:tag`); pin via a rollout instead",
        ));
    }
    Ok(())
}

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

/// Reject credentials files that are accessible to anyone other than
/// the bugpot owner.
///
/// Delegates to `fs-mistrust`, which checks both the file's own mode
/// and **every ancestor directory** on the path — so a `0600` file
/// inside a world-writable directory (where an attacker could `unlink`
/// + replace it between bugpot runs) is rejected.
///
/// Used for `auth.toml`, the admin-token file, and any other file
/// whose disclosure equals a compliance / security incident.
pub fn require_owner_only(path: &Path) -> Result<()> {
    fs_mistrust::Mistrust::new()
        .verifier()
        .require_file()
        .check(path)
        .with_context(|| {
            format!(
                "credentials file {} (or one of its ancestor directories) is accessible to a non-owner; refusing to start",
                path.display()
            )
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_dns_label_accepts_typical_names() {
        for s in ["alpha", "beta", "dev-alpha", "app-1", "x", &"a".repeat(63)] {
            assert!(
                validate_dns_label("name", s).is_ok(),
                "should accept: {s:?}"
            );
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
            "Foo",     // uppercase
            "foo_bar", // underscore
            "-foo",    // leading hyphen
            "foo-",    // trailing hyphen
            &"a".repeat(64),
            "foo\0bar",
            "foo;bar",
            "foo$bar",
        ] {
            assert!(
                validate_dns_label("name", s).is_err(),
                "should reject: {s:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn require_owner_only_accepts_tight_path() {
        use std::os::unix::fs::PermissionsExt;
        // Use a `tempfile::Builder` so the temp dir lives in `/tmp`
        // (whose ancestor chain is acceptable to fs-mistrust). Tighten
        // the dir + file to owner-only and confirm we pass.
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        require_owner_only(&path).expect("tight permissions must pass");
    }

    #[cfg(unix)]
    #[test]
    fn require_owner_only_rejects_world_writable_parent() {
        use std::os::unix::fs::PermissionsExt;
        // Regression guard for fs-mistrust's *ancestor* walk: even a
        // 0600 file is unsafe inside a world-writable directory, since
        // an attacker can `unlink` + replace it between bugpot runs.
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = require_owner_only(&path).expect_err("permissive parent must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("non-owner") || msg.contains("ancestor"),
            "error should mention non-owner / ancestor access: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn require_owner_only_rejects_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        // Note: `fs-mistrust` deliberately allows group-readable files
        // when the file's group has no other members beyond the owner
        // (typical "user:user" primary-group layout on Linux). That's
        // a stricter notion than the old `mode & 0o077 != 0` check —
        // it considers actual access, not just bits — and we accept
        // the nuance. World-readable, however, is unambiguously bad
        // and must always be rejected.
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o604)).unwrap();
        assert!(
            require_owner_only(&path).is_err(),
            "world-readable file must be rejected"
        );
    }

    #[test]
    fn appspec_validate_catches_path_traversal_via_name() {
        let body = r#"
            repo = "x"
            port = 8080
            name = "../../etc/cron.d/evil"
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        let err = spec
            .validate()
            .expect_err("path traversal name must be rejected");
        assert_eq!(err.field, "name");
    }

    #[test]
    fn appspec_validate_rejects_unresolvable_name() {
        // No `name` field, no `source_path` → would fall back to the
        // `"unknown"` sentinel. Must be caught at validate-time so two
        // such specs can't collide in `AppController.apps`.
        let body = r#"
            repo = "x"
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
            repo = "x"
            port = 8080
            name = "ok"
            subdomain = "Bad-Subdomain"
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        let err = spec
            .validate()
            .expect_err("uppercase subdomain must be rejected");
        assert_eq!(err.field, "subdomain");
    }

    #[test]
    fn appspec_validate_rejects_repo_with_tag() {
        let body = r#"
            repo = "ghcr.io/owner/repo:v1"
            port = 8080
            name = "ok"
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        let err = spec.validate().expect_err("tag in repo must be rejected");
        assert_eq!(err.field, "repo");
    }

    #[test]
    fn appspec_validate_rejects_repo_with_digest() {
        let body = r#"
            repo = "ghcr.io/owner/repo@sha256:abc"
            port = 8080
            name = "ok"
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        let err = spec
            .validate()
            .expect_err("digest in repo must be rejected");
        assert_eq!(err.field, "repo");
    }

    #[test]
    fn appspec_validate_accepts_registry_port() {
        let body = r#"
            repo = "localhost:5000/foo"
            port = 8080
            name = "ok"
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        spec.validate()
            .expect("registry port (host-component colon) must be allowed");
    }

    #[test]
    fn parses_minimum_toml() {
        let body = r#"
            repo = "ghcr.io/org/myapp"
            port = 3000
        "#;
        let spec: AppSpec = toml::from_str(body).unwrap();
        assert_eq!(spec.repo, "ghcr.io/org/myapp");
        assert_eq!(spec.port, 3000);
        assert!(spec.egress.allow.is_empty());
    }

    #[test]
    fn parses_full_toml() {
        let body = r#"
            repo = "ghcr.io/org/myapp"
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
        let got = r
            .resolve_timeout(std::time::Duration::from_secs(7))
            .unwrap();
        assert_eq!(got, std::time::Duration::from_secs(7));
    }

    #[test]
    fn readiness_explicit_value_overrides_default() {
        let r = Readiness {
            timeout: Some("30s".into()),
            path: None,
        };
        let got = r
            .resolve_timeout(std::time::Duration::from_secs(7))
            .unwrap();
        assert_eq!(got, std::time::Duration::from_secs(30));
    }

    #[test]
    fn readiness_empty_string_uses_default() {
        let r = Readiness {
            timeout: Some(String::new()),
            path: None,
        };
        let got = r
            .resolve_timeout(std::time::Duration::from_secs(7))
            .unwrap();
        assert_eq!(got, std::time::Duration::from_secs(7));
    }

    #[test]
    fn readiness_rejects_garbage() {
        let r = Readiness {
            timeout: Some("not-a-duration".into()),
            path: None,
        };
        assert!(
            r.resolve_timeout(std::time::Duration::from_secs(7))
                .is_err()
        );
    }

    #[test]
    fn name_defaults_to_filename_stem() {
        let mut spec: AppSpec = toml::from_str(
            r#"repo = "x"
port = 80
"#,
        )
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
            repo = "ghcr.io/org/app"
            port = 3000
            name = "myapp"
        "#,
        )
        .unwrap();
        let body = toml::to_string(&original).expect("serialize");
        let parsed: AppSpec = toml::from_str(&body).expect("deserialize");
        assert_eq!(parsed.repo, original.repo);
        assert_eq!(parsed.port, original.port);
        assert_eq!(parsed.name, original.name);
    }

    #[test]
    fn serialize_omits_default_sections() {
        let spec: AppSpec = toml::from_str(
            r#"
            repo = "x"
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
            repo = "x"
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

    #[test]
    fn volumes_parse_and_validate() {
        let spec: AppSpec = toml::from_str(
            r#"
            repo = "ghcr.io/org/app"
            port = 80
            name = "alpha"

            [[volumes]]
            name = "data"
            path = "/data"
            user = 33

            [[volumes]]
            name = "cache"
            path = "/var/cache/app"
            "#,
        )
        .expect("parse");
        spec.validate().expect("validate");
        assert_eq!(spec.volumes.len(), 2);
        assert_eq!(spec.volumes[0].name, "data");
        assert_eq!(spec.volumes[0].user, Some(33));
        assert!(spec.volumes[1].user.is_none());
    }

    #[test]
    fn volumes_reject_relative_paths() {
        let mut spec: AppSpec = toml::from_str(
            r#"
            repo = "x"
            port = 80
            name = "alpha"
            "#,
        )
        .unwrap();
        spec.volumes = vec![VolumeSpec {
            name: "data".into(),
            path: PathBuf::from("data"),
            user: None,
        }];
        let err = spec.validate().expect_err("relative path must fail");
        assert_eq!(err.field, "volumes.path");
    }

    #[test]
    fn volumes_reject_reserved_mount_paths() {
        let mut spec: AppSpec = toml::from_str(
            r#"
            repo = "x"
            port = 80
            name = "alpha"
            "#,
        )
        .unwrap();
        // /proc is a default OCI mount; user-mounting over it is a
        // footgun (libcontainer's mount would shadow it).
        spec.volumes = vec![VolumeSpec {
            name: "p".into(),
            path: PathBuf::from("/proc"),
            user: None,
        }];
        let err = spec.validate().expect_err("reserved path must fail");
        assert_eq!(err.field, "volumes.path");
    }

    #[test]
    fn volumes_reject_duplicate_names() {
        let mut spec: AppSpec = toml::from_str(
            r#"
            repo = "x"
            port = 80
            name = "alpha"
            "#,
        )
        .unwrap();
        spec.volumes = vec![
            VolumeSpec {
                name: "data".into(),
                path: PathBuf::from("/a"),
                user: None,
            },
            VolumeSpec {
                name: "data".into(),
                path: PathBuf::from("/b"),
                user: None,
            },
        ];
        let err = spec.validate().expect_err("dup name must fail");
        assert_eq!(err.field, "volumes.name");
    }

    #[test]
    fn volumes_reject_duplicate_paths() {
        let mut spec: AppSpec = toml::from_str(
            r#"
            repo = "x"
            port = 80
            name = "alpha"
            "#,
        )
        .unwrap();
        spec.volumes = vec![
            VolumeSpec {
                name: "a".into(),
                path: PathBuf::from("/data"),
                user: None,
            },
            VolumeSpec {
                name: "b".into(),
                path: PathBuf::from("/data"),
                user: None,
            },
        ];
        let err = spec.validate().expect_err("dup path must fail");
        assert_eq!(err.field, "volumes.path");
    }

    #[test]
    fn readiness_path_parses() {
        let spec: AppSpec = toml::from_str(
            r#"
            repo = "x"
            port = 80
            name = "alpha"

            [readiness]
            path = "/health"
            timeout = "30s"
            "#,
        )
        .expect("parse");
        spec.validate().expect("validate");
        assert_eq!(spec.readiness.path.as_deref(), Some("/health"));
    }

    #[test]
    fn readiness_path_rejects_relative() {
        let mut spec: AppSpec = toml::from_str(
            r#"
            repo = "x"
            port = 80
            name = "alpha"
            "#,
        )
        .unwrap();
        spec.readiness.path = Some("health".into());
        let err = spec.validate().expect_err("relative must fail");
        assert_eq!(err.field, "readiness.path");
    }

    #[test]
    fn readiness_path_rejects_traversal() {
        let mut spec: AppSpec = toml::from_str(
            r#"
            repo = "x"
            port = 80
            name = "alpha"
            "#,
        )
        .unwrap();
        spec.readiness.path = Some("/foo/../etc/passwd".into());
        let err = spec.validate().expect_err("traversal must fail");
        assert_eq!(err.field, "readiness.path");
    }

    #[test]
    fn readiness_path_rejects_query_string() {
        let mut spec: AppSpec = toml::from_str(
            r#"
            repo = "x"
            port = 80
            name = "alpha"
            "#,
        )
        .unwrap();
        spec.readiness.path = Some("/health?token=x".into());
        let err = spec.validate().expect_err("query string must fail");
        assert_eq!(err.field, "readiness.path");
    }

    /// Every TOML shipped under `examples/self-hosted/` must parse and
    /// validate cleanly. The directory is hand-edited and copied into
    /// operator ops repos, so a silently-broken template would only
    /// surface as a confusing admin-API 400 in production. Catch it
    /// at the workspace level instead.
    #[test]
    fn self_hosted_examples_parse_and_validate() {
        // Crate path: `crates/bugpot-config/`, two levels up to repo
        // root, then into examples/self-hosted/.
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("examples")
            .join("self-hosted");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("read examples/self-hosted dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let mut spec: AppSpec =
                toml::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
            spec.source_path = path.clone();
            spec.validate()
                .unwrap_or_else(|e| panic!("validate {}: {e}", path.display()));
            checked += 1;
        }
        assert!(
            checked > 0,
            "expected at least one example TOML under {}",
            dir.display(),
        );
    }
}
