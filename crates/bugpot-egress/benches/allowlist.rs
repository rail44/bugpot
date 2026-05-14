//! Microbenchmarks for [`bugpot_egress::Allowlist::matches_domain`].
//!
//! `matches_domain` is on the DNS resolver's hot path — every container
//! DNS query routes through it. The bench measures three plausible
//! deployment shapes:
//!
//! - a tiny allowlist (one bare domain) representing a single-purpose app
//! - a medium list (8 mixed bare + wildcard rules) representing a typical app
//! - a large list (64 rules) representing a "kitchen-sink" or
//!   policy-driven deployment
//!
//! For each shape we measure two query distributions: queries that hit
//! the rule set, and queries that miss it. Miss path matters because
//! attacker / buggy-container queries exercise it disproportionately.
//!
//! Allocation counts are auto-reported by divan; watch them across
//! changes to spot regressions hidden by wall-clock noise.

use bugpot_egress::allowlist::Allowlist;
use divan::Bencher;

fn main() {
    divan::main();
}

fn tiny() -> Allowlist {
    Allowlist::parse(["example.com"]).unwrap()
}

fn medium() -> Allowlist {
    Allowlist::parse([
        "github.com",
        "*.github.com",
        "ghcr.io",
        "*.ghcr.io",
        "registry-1.docker.io",
        "*.docker.io",
        "pypi.org",
        "files.pythonhosted.org",
    ])
    .unwrap()
}

fn large() -> Allowlist {
    let mut rules: Vec<String> = (0..32).map(|i| format!("api{i}.example.com")).collect();
    rules.extend((0..32).map(|i| format!("*.svc-{i}.example.com")));
    Allowlist::parse(rules).unwrap()
}

#[divan::bench]
fn tiny_hit(bencher: Bencher) {
    let allow = tiny();
    bencher.bench(|| divan::black_box(&allow).matches_domain(divan::black_box("example.com")));
}

#[divan::bench]
fn tiny_miss(bencher: Bencher) {
    let allow = tiny();
    bencher.bench(|| {
        divan::black_box(&allow).matches_domain(divan::black_box("notmatched.example.org"))
    });
}

#[divan::bench]
fn medium_hit(bencher: Bencher) {
    let allow = medium();
    bencher.bench(|| divan::black_box(&allow).matches_domain(divan::black_box("ghcr.io")));
}

#[divan::bench]
fn medium_wildcard_hit(bencher: Bencher) {
    let allow = medium();
    bencher.bench(|| divan::black_box(&allow).matches_domain(divan::black_box("api.github.com")));
}

#[divan::bench]
fn medium_miss(bencher: Bencher) {
    let allow = medium();
    bencher.bench(|| divan::black_box(&allow).matches_domain(divan::black_box("evil.example.org")));
}

#[divan::bench]
fn large_hit(bencher: Bencher) {
    let allow = large();
    bencher
        .bench(|| divan::black_box(&allow).matches_domain(divan::black_box("api17.example.com")));
}

#[divan::bench]
fn large_miss(bencher: Bencher) {
    let allow = large();
    bencher.bench(|| {
        divan::black_box(&allow).matches_domain(divan::black_box("notlisted.example.org"))
    });
}
