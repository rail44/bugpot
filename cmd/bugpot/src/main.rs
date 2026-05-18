//! `bugpot` — admin CLI for the `bugpotd` daemon.
//!
//! Talks to a running `bugpotd` instance's admin API (the binding of
//! `BUGPOT_ADMIN_LISTEN`). Auth via bearer token sourced from env:
//! `BUGPOT_ADMIN_TOKEN` (literal) or `BUGPOT_ADMIN_TOKEN_FILE`
//! (path; trimmed contents). Exactly one of the two must be set.
//!
//! Endpoint is `BUGPOT_ADMIN_URL`, default `http://127.0.0.1:8081`.
//!
//! Output is tabular / human-readable by default; pass `--json` to
//! forward the raw API response to stdout instead.
//!
//! Intentionally pure-Rust: this crate compiles on macOS so an
//! operator can run `bugpot` against a remote `bugpotd` from their
//! laptop without the Linux-only daemon-side deps.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

const DEFAULT_ADMIN_URL: &str = "http://127.0.0.1:8081";

// ---- CLI surface ----------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "bugpot",
    version,
    about = "bugpot admin client",
    long_about = "CLI front-end for bugpotd's admin API.\n\
                  Set BUGPOT_ADMIN_URL + BUGPOT_ADMIN_TOKEN[_FILE]."
)]
struct Cli {
    /// Output as JSON (raw API response) instead of human-readable.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

/// Top-level groups are plural nouns (`apps`, `rollouts`); the verb
/// always comes second. Avoids the older `bugpot rollout` /
/// `bugpot deploy-key` shape where some actions sat at the root and
/// others under a noun.
#[derive(Subcommand, Debug)]
enum Cmd {
    /// App config plane.
    #[command(subcommand)]
    Apps(AppsCmd),

    /// Rollouts plane (history + push).
    #[command(subcommand)]
    Rollouts(RolloutsCmd),
}

#[derive(Subcommand, Debug)]
enum AppsCmd {
    /// List all registered apps.
    List,
    /// Inspect a single app.
    Get {
        /// App name.
        name: String,
    },
    /// Register a new app from a TOML spec file.
    Create {
        /// Path to the app's `<name>.toml`. Required field `name`
        /// must match the intended app name (the admin API has no
        /// filename context).
        #[arg(short = 'f', long)]
        file: PathBuf,
    },
    /// Replace mutable fields of an app from a TOML spec file
    /// (server-side semantics: PATCH).
    Update {
        /// App name to update.
        name: String,
        /// Path to the updated `<name>.toml`. Same shape as `create`;
        /// `name` and `subdomain` are immutable and must match the
        /// existing app or the server returns 400.
        #[arg(short = 'f', long)]
        file: PathBuf,
    },
    /// Stop and remove an app.
    Delete {
        /// App name.
        name: String,
    },
    /// Issue a deploy key for an app (one-time output — the token is
    /// not retrievable afterwards).
    DeployKey {
        /// App name.
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum RolloutsCmd {
    /// List rollout history for an app (oldest first).
    List {
        /// App name.
        app: String,
    },
    /// Push a new rollout (pull + restart). Uses the per-app deploy
    /// token from `$BUGPOT_DEPLOY_TOKEN` or `$BUGPOT_DEPLOY_TOKEN_FILE`.
    Push {
        /// App name.
        app: String,
        /// Image tag (e.g. `v1.2.3` or a git SHA).
        tag: String,
    },
}

// ---- Wire types (mirror of bugpot-admin / bugpot-controller) --------------
//
// These are the *client* view. We don't share the server crate's structs
// because pulling in `bugpot-controller` would drag the Linux-only
// libcontainer dependency tree into the CLI.

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AppView {
    name: String,
    subdomain: String,
    repo: String,
    port: u16,
    /// `stopped` | `starting` | `running` | `stopping` — kept as a
    /// String for forward-compat with future server-side additions.
    state: String,
    #[serde(default)]
    current_rollout: Option<Rollout>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Rollout {
    tag: String,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct DeployKeyResponse {
    token: String,
}

// ---- Config ---------------------------------------------------------------

/// Resolved API client config — base URL plus the bearer token for
/// whichever auth scope the command needs (`admin` or `deploy`).
///
/// One struct instead of two-distinguished-by-name: there is no
/// compile-time invariant the previous split could express (any
/// `AdminConfig` was structurally interchangeable with a
/// `DeployConfig`), and both paths read the same `BUGPOT_ADMIN_URL`.
/// The auth-scope distinction lives in the env-var name passed to
/// `read_token`; the resulting `ApiConfig` is just data.
struct ApiConfig {
    base_url: String,
    token: String,
}

impl ApiConfig {
    fn from_env(token_kind: &str) -> Result<Self> {
        let base_url =
            std::env::var("BUGPOT_ADMIN_URL").unwrap_or_else(|_| DEFAULT_ADMIN_URL.to_string());
        let token = read_token(token_kind)?;
        Ok(Self { base_url, token })
    }
}

/// Read a bearer token from `BUGPOT_<KIND>_TOKEN` (literal) or
/// `BUGPOT_<KIND>_TOKEN_FILE` (trimmed file contents). The file path
/// is preferred for production; the literal exists for convenience.
fn read_token(kind: &str) -> Result<String> {
    let kind_upper = kind.to_ascii_uppercase();
    let direct_var = format!("BUGPOT_{kind_upper}_TOKEN");
    let file_var = format!("BUGPOT_{kind_upper}_TOKEN_FILE");
    let direct = std::env::var(&direct_var).ok();
    let file_path = std::env::var(&file_var).ok();
    resolve_token(
        direct.as_deref(),
        file_path.as_deref(),
        &direct_var,
        &file_var,
    )
}

/// Pure resolution logic, split out from `read_token` so unit tests
/// can exercise it without mutating the process environment.
fn resolve_token(
    direct: Option<&str>,
    file_path: Option<&str>,
    direct_var: &str,
    file_var: &str,
) -> Result<String> {
    if let Some(v) = direct {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            bail!("${direct_var} is set but empty");
        }
        return Ok(trimmed.to_owned());
    }
    if let Some(p) = file_path {
        let s = std::fs::read_to_string(p).with_context(|| format!("read {p}"))?;
        let trimmed = s.trim();
        if trimmed.is_empty() {
            bail!("${file_var} points at an empty file");
        }
        return Ok(trimmed.to_owned());
    }
    bail!("Neither ${direct_var} nor ${file_var} is set")
}

// ---- Entry point ----------------------------------------------------------

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new();

    match cli.cmd {
        Cmd::Apps(op) => run_apps(&client, op, cli.json).await,
        Cmd::Rollouts(op) => run_rollouts(&client, op, cli.json).await,
    }
}

// ---- Apps subcommands -----------------------------------------------------

async fn run_apps(client: &Client, op: AppsCmd, json: bool) -> Result<()> {
    let cfg = ApiConfig::from_env("admin")?;
    match op {
        AppsCmd::List => {
            let v: Vec<AppView> = http_get_json(client, &cfg.base_url, "/apps", &cfg.token).await?;
            if json {
                print_json(&v)?;
            } else {
                print_apps_table(&v);
            }
        }
        AppsCmd::Get { name } => {
            let v: AppView =
                http_get_json(client, &cfg.base_url, &format!("/apps/{name}"), &cfg.token).await?;
            if json {
                print_json(&v)?;
            } else {
                print_app_human(&v);
            }
        }
        AppsCmd::Create { file } => {
            let body = std::fs::read_to_string(&file)
                .with_context(|| format!("read {}", file.display()))?;
            let v: AppView = http_post_toml(client, &cfg.base_url, "/apps", &cfg.token, &body)
                .await
                .context("POST /apps")?;
            if json {
                print_json(&v)?;
            } else {
                eprintln!("created");
                print_app_human(&v);
            }
        }
        AppsCmd::Update { name, file } => {
            let body = std::fs::read_to_string(&file)
                .with_context(|| format!("read {}", file.display()))?;
            let v: AppView = http_patch_toml(
                client,
                &cfg.base_url,
                &format!("/apps/{name}"),
                &cfg.token,
                &body,
            )
            .await
            .context("PATCH /apps")?;
            if json {
                print_json(&v)?;
            } else {
                eprintln!("updated");
                print_app_human(&v);
            }
        }
        AppsCmd::Delete { name } => {
            http_delete(client, &cfg.base_url, &format!("/apps/{name}"), &cfg.token).await?;
            if !json {
                eprintln!("deleted {name}");
            }
        }
        AppsCmd::DeployKey { name } => {
            let v: DeployKeyResponse = http_post_json(
                client,
                &cfg.base_url,
                &format!("/apps/{name}/deploy-keys"),
                &cfg.token,
                &serde_json::json!({}),
            )
            .await?;
            if json {
                // The wire format is `{"token": "bp1..."}` — pass through.
                println!("{}", serde_json::json!({ "token": v.token }));
            } else {
                // Token is unrecoverable after this print — flag it loudly.
                eprintln!(
                    "deploy key for {name} (record this NOW — server does not retain the plaintext):"
                );
                println!("{}", v.token);
            }
        }
    }
    Ok(())
}

// ---- Rollouts subcommands -------------------------------------------------

async fn run_rollouts(client: &Client, op: RolloutsCmd, json: bool) -> Result<()> {
    let cfg = ApiConfig::from_env("deploy")?;
    match op {
        RolloutsCmd::List { app } => {
            let v: Vec<Rollout> = http_get_json(
                client,
                &cfg.base_url,
                &format!("/apps/{app}/rollouts"),
                &cfg.token,
            )
            .await?;
            if json {
                print_json(&v)?;
            } else {
                print_rollouts_table(&v);
            }
        }
        RolloutsCmd::Push { app, tag } => {
            let body = serde_json::json!({ "tag": tag });
            let v: Rollout = http_post_json(
                client,
                &cfg.base_url,
                &format!("/apps/{app}/rollouts"),
                &cfg.token,
                &body,
            )
            .await?;
            if json {
                print_json(&v)?;
            } else {
                eprintln!("rolled out {app} → {}", v.tag);
                eprintln!("  created_at: {}", v.created_at);
            }
        }
    }
    Ok(())
}

// ---- HTTP helpers ---------------------------------------------------------

async fn http_get_json<T>(client: &Client, base: &str, path: &str, token: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let url = format!("{base}{path}");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    check_status(&url, resp.status(), resp).await
}

async fn http_post_json<T>(
    client: &Client,
    base: &str,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let url = format!("{base}{path}");
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    check_status(&url, resp.status(), resp).await
}

async fn http_post_toml<T>(
    client: &Client,
    base: &str,
    path: &str,
    token: &str,
    body: &str,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let url = format!("{base}{path}");
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .header("content-type", "application/toml")
        .body(body.to_owned())
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    check_status(&url, resp.status(), resp).await
}

async fn http_patch_toml<T>(
    client: &Client,
    base: &str,
    path: &str,
    token: &str,
    body: &str,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let url = format!("{base}{path}");
    let resp = client
        .patch(&url)
        .bearer_auth(token)
        .header("content-type", "application/toml")
        .body(body.to_owned())
        .send()
        .await
        .with_context(|| format!("PATCH {url}"))?;
    check_status(&url, resp.status(), resp).await
}

async fn http_delete(client: &Client, base: &str, path: &str, token: &str) -> Result<()> {
    let url = format!("{base}{path}");
    let resp = client
        .delete(&url)
        .bearer_auth(token)
        .send()
        .await
        .with_context(|| format!("DELETE {url}"))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp.text().await.unwrap_or_default();
    Err(anyhow!("{url} → {status}: {}", body.trim()))
}

async fn check_status<T>(url: &str, status: StatusCode, resp: reqwest::Response) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("{url} → {status}: {}", body.trim()));
    }
    resp.json::<T>()
        .await
        .with_context(|| format!("parse response from {url}"))
}

// ---- Output formatting ----------------------------------------------------

fn print_json<T: Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn print_apps_table(apps: &[AppView]) {
    if apps.is_empty() {
        eprintln!("(no apps registered)");
        return;
    }
    println!(
        "NAME                 SUBDOMAIN            STATE      REPO                                     ROLLOUT"
    );
    for a in apps {
        let rollout = a.current_rollout.as_ref().map_or("-", |r| r.tag.as_str());
        println!(
            "{:<20} {:<20} {:<10} {:<40} {rollout}",
            a.name, a.subdomain, a.state, a.repo,
        );
    }
}

fn print_app_human(a: &AppView) {
    println!("name      : {}", a.name);
    println!("subdomain : {}", a.subdomain);
    println!("repo      : {}", a.repo);
    println!("port      : {}", a.port);
    println!("state     : {}", a.state);
    if let Some(r) = &a.current_rollout {
        println!("rollout   : {} (at {})", r.tag, r.created_at);
    } else {
        println!("rollout   : (none — app registered but never deployed)");
    }
}

fn print_rollouts_table(rollouts: &[Rollout]) {
    if rollouts.is_empty() {
        eprintln!("(no rollouts)");
        return;
    }
    println!("CREATED_AT               TAG");
    for r in rollouts {
        println!("{:<24} {}", r.created_at, r.tag);
    }
}

// ---- Unit tests -----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_literal_takes_precedence_and_trims() {
        let got = resolve_token(Some("  secret  "), None, "DIRECT", "FILE").unwrap();
        assert_eq!(got, "secret");
    }

    #[test]
    fn token_literal_rejects_empty() {
        let err = resolve_token(Some("   "), None, "DIRECT", "FILE")
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty"), "{err}");
        assert!(err.contains("DIRECT"), "{err}");
    }

    #[test]
    fn token_missing_both_errors_clearly() {
        let err = resolve_token(None, None, "DIRECT", "FILE")
            .unwrap_err()
            .to_string();
        assert!(err.contains("DIRECT"), "{err}");
        assert!(err.contains("FILE"), "{err}");
    }

    #[test]
    fn token_file_path_is_read() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("bugpot-cli-token-test-{}.tok", std::process::id()));
        std::fs::write(&p, "  filetoken  \n").unwrap();
        let got = resolve_token(None, p.to_str(), "DIRECT", "FILE").unwrap();
        let _ = std::fs::remove_file(&p);
        assert_eq!(got, "filetoken");
    }

    #[test]
    fn appview_round_trips_through_json() {
        let v = AppView {
            name: "alpha".into(),
            subdomain: "alpha".into(),
            repo: "ghcr.io/x/y".into(),
            port: 8080,
            state: "running".into(),
            current_rollout: Some(Rollout {
                tag: "v1".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
            }),
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: AppView = serde_json::from_str(&s).unwrap();
        assert_eq!(back.name, "alpha");
        assert_eq!(back.current_rollout.as_ref().unwrap().tag, "v1");
    }
}
