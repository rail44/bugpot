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
    ///   - `"30s"`, `"5m"`, `"1h"`: stop after this much idle time.
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
    pub fn resolve_idle_timeout(&self) -> Result<Option<std::time::Duration>, &'static str> {
        let raw = self.idle_timeout.as_deref().unwrap_or("5m").trim();
        if raw.is_empty() || raw == "0" {
            return Ok(None);
        }
        let (num_part, unit) = raw.split_at(raw.len().saturating_sub(1));
        let n: u64 = num_part.parse().map_err(|_| "scaling.idle_timeout: leading number must parse")?;
        let secs = match unit {
            "s" => n,
            "m" => n.saturating_mul(60),
            "h" => n.saturating_mul(3600),
            _ => return Err("scaling.idle_timeout: trailing unit must be one of s/m/h"),
        };
        Ok(Some(std::time::Duration::from_secs(secs)))
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
        apps.push(spec);
    }
    apps.sort_by(|a, b| a.name().cmp(b.name()));
    Ok(apps)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            Some(std::time::Duration::from_secs(300))
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
        for (raw, want_secs) in [("30s", 30), ("5m", 300), ("2h", 7200)] {
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
    fn scaling_rejects_garbage() {
        for raw in ["abc", "5", "5y", ""] {
            let s = Scaling {
                idle_timeout: Some(raw.into()),
            };
            if raw.is_empty() {
                assert!(s.resolve_idle_timeout().unwrap().is_none());
            } else {
                assert!(s.resolve_idle_timeout().is_err(), "should reject: {raw}");
            }
        }
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
