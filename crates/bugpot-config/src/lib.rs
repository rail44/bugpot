use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct AppSpec {
    pub image: String,
    pub port: u16,
    pub name: Option<String>,
    pub subdomain: Option<String>,
    #[serde(default)]
    pub egress: Egress,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub scaling: Scaling,
    #[serde(default)]
    pub resources: Resources,
    #[serde(default)]
    pub runtime: Runtime,
    #[serde(skip)]
    pub source_path: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Egress {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Scaling {
    /// Idle timeout for scale-to-zero. Accepted forms:
    ///   - `"0"`, `""`, missing: always-on (container never auto-stops).
    ///   - `"30s"`, `"5m"`, `"1h"`: stop after this much idle time.
    pub idle_timeout: Option<String>,
}

impl Scaling {
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

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Resources {
    pub memory: Option<String>,
    pub cpu: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Runtime {
    pub isolation: Option<String>,
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
}
