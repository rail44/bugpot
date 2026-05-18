//! Microbenchmarks for `AppSpec` TOML parse + `validate`.
//!
//! Both are called per `POST /apps` (and on every bugpot start for
//! every persisted spec on disk). Pure Rust, no I/O after the body
//! is read — a regression here directly translates to admin-API
//! latency on cold paths and rehydrate-from-disk startup time. Three
//! shapes are exercised so a future change that disproportionately
//! slows a particular subsection (volume validation, readiness path
//! parsing, env-map walking) shows up against its peers.

use bugpot_config::AppSpec;
use divan::Bencher;

fn main() {
    divan::main();
}

/// Smallest spec the admin API accepts.
const MINIMAL_TOML: &str = r#"
name = "alpha"
repo = "ghcr.io/owner/alpha"
port = 8080
"#;

/// Typical small-app spec with env vars + an HTTP readiness probe.
/// Matches the "self-hosted tool" shape (Vaultwarden / Linkding /
/// Miniflux) bugpot is sized for.
const TYPICAL_TOML: &str = r#"
name = "linkding"
repo = "sissbruecker/linkding"
port = 9090

[scaling]
idle_timeout = "5m"

[readiness]
path = "/health"
timeout = "30s"

[env]
LD_SUPERUSER_NAME = "admin"
LD_DISABLE_BACKGROUND_TASKS = "False"
LD_DB_ENGINE = "sqlite"
LD_DB_DATABASE = "/data/db.sqlite3"

[egress]
allow = ["*.duckduckgo.com", "github.com"]
"#;

/// Spec exercising every section bugpot understands. Real apps don't
/// look like this — it's a stress test for the validate path's
/// per-section work.
const MAXIMAL_TOML: &str = r#"
name = "maximal"
subdomain = "max"
repo = "ghcr.io/example/maximal"
port = 8080

[scaling]
idle_timeout = "1h"

[readiness]
path = "/api/health"
timeout = "60s"

[env]
A = "1"
B = "2"
C = "3"
D = "4"
E = "5"
F = "6"
G = "7"
H = "8"

[egress]
allow = [
    "github.com",
    "*.github.com",
    "objects.githubusercontent.com",
    "registry-1.docker.io",
    "*.cloudflare.com",
]

[[volumes]]
name = "data"
path = "/data"
user = 1000

[[volumes]]
name = "cache"
path = "/var/cache"
user = 1000
"#;

fn bench_parse(bencher: Bencher, src: &'static str) {
    bencher.bench(|| toml::from_str::<AppSpec>(divan::black_box(src)).expect("bench input parses"));
}

fn bench_validate(bencher: Bencher, src: &'static str) {
    let spec: AppSpec = toml::from_str(src).expect("bench input parses");
    bencher.bench(|| {
        divan::black_box(&spec)
            .validate()
            .expect("bench input validates");
    });
}

#[divan::bench]
fn parse_minimal(bencher: Bencher) {
    bench_parse(bencher, MINIMAL_TOML);
}

#[divan::bench]
fn parse_typical(bencher: Bencher) {
    bench_parse(bencher, TYPICAL_TOML);
}

#[divan::bench]
fn parse_maximal(bencher: Bencher) {
    bench_parse(bencher, MAXIMAL_TOML);
}

#[divan::bench]
fn validate_minimal(bencher: Bencher) {
    bench_validate(bencher, MINIMAL_TOML);
}

#[divan::bench]
fn validate_typical(bencher: Bencher) {
    bench_validate(bencher, TYPICAL_TOML);
}

#[divan::bench]
fn validate_maximal(bencher: Bencher) {
    bench_validate(bencher, MAXIMAL_TOML);
}
