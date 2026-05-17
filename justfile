set shell := ["bash", "-cu"]

# Mac-side task runner. Most recipes shell into the bugpot Lima VM via
# `limactl shell bugpot`, which preserves the host cwd inside the VM (the
# repo is bind-mounted at the same absolute path).

# Show available recipes.
default:
    @just --list

# --- VM lifecycle ---

# Start the bugpot Lima VM (no-op if already running).
vm-start:
    limactl start bugpot

# Stop the Lima VM.
vm-stop:
    limactl stop bugpot

# Open an interactive shell in the VM.
shell:
    limactl shell bugpot

# --- Build / test (inside the VM) ---

# Build the bugpotd daemon binary.
build:
    limactl shell bugpot -- bash -lc 'cargo build -p bugpotd'

# cargo check across the workspace.
check:
    limactl shell bugpot -- bash -lc 'cargo check --workspace --all-targets'

# Run all unit tests (excludes #[ignore]).
test:
    limactl shell bugpot -- bash -lc 'cargo test --workspace'

# Run clippy at the workspace lint level.
clippy:
    limactl shell bugpot -- bash -lc 'cargo clippy --workspace --all-targets'

# Single-crate variants. Faster than the workspace recipes when
# iterating on one crate: cargo doesn't reanalyse the whole graph.
# Example: `just check-crate bugpot-router`.
check-crate crate:
    limactl shell bugpot -- bash -lc 'cargo check -p {{crate}} --all-targets'

clippy-crate crate:
    limactl shell bugpot -- bash -lc 'cargo clippy -p {{crate}} --all-targets'

test-crate crate:
    limactl shell bugpot -- bash -lc 'cargo test -p {{crate}}'

# --- Mac-native (no Lima round-trip) ---

# Format the whole workspace. `rustfmt` is pure-Rust so it runs
# natively on macOS — no Linux deps, no Lima overhead.
fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# cargo check / clippy for the three crates that compile on macOS
# (no `libcontainer` / `nix::sched` / `procfs` dependencies). Lets
# the editor / a quick sanity loop skip the Lima round-trip on these.
# The other five crates (controller, runtime, egress, admin, cmd)
# must still go through `just check` / `just clippy`.
HOST_CRATES := "-p bugpot-config -p bugpot-router -p bugpot-metrics"

check-host:
    cargo check {{HOST_CRATES}} --all-targets

clippy-host:
    cargo clippy {{HOST_CRATES}} --all-targets

# --- tokio-console workflow ---

# Build bugpotd with the tokio-console feature. Sets `RUSTFLAGS` so
# `console-subscriber` and the unstable-only `bugpot_tokio_*`
# metric fields compile in. Use with `just run-console` (foreground)
# or `just shell` + manual `./target/debug/bugpotd`.
build-console:
    limactl shell bugpot -- bash -lc 'RUSTFLAGS="--cfg tokio_unstable" cargo build -p bugpotd --features tokio-console'

# Foreground run with tokio-console enabled. Attach from another
# shell inside the VM: `tokio-console http://127.0.0.1:6669`.
run-console:
    limactl shell bugpot -- bash -lc 'RUSTFLAGS="--cfg tokio_unstable" sudo -E env "PATH=$PATH" cargo run -p bugpotd --features tokio-console'

# --- Microbenchmarks (divan) ---

# Run every divan microbench in the workspace. Each bench prints its
# own table (wall-clock + allocation count); the run is read-only
# and safe to repeat. Pass extra args after `--` to scope the run,
# e.g. `just bench -- medium_hit`.
bench *args:
    limactl shell bugpot -- bash -lc 'cargo bench --workspace {{args}}'

# --- Smoke tests (need root inside the VM) ---

# Infrastructure-only: bridge / nft / DNS / router, no apps.
smoke-infra:
    limactl shell bugpot -- sudo bash scripts/smoke-infra.sh

# Single-app: pull image, start container, HTTP round-trip.
smoke-app:
    limactl shell bugpot -- sudo bash scripts/smoke-app.sh

# Multi-app: Host-header dispatch between two apps.
smoke-multi:
    limactl shell bugpot -- sudo bash scripts/smoke-multi.sh

# Freezer scale-to-zero end-to-end (~2 min wall-clock; sweep tick is
# 30 s). Verifies idle → frozen → resume + reattach across restart.
smoke-freeze:
    limactl shell bugpot -- sudo bash scripts/smoke-freeze.sh

# Persistent volume end-to-end (~1 min wall-clock; one freeze cycle).
# Verifies host dir creation, mount visibility in container,
# sentinel persistence across freeze→resume, DELETE cleanup.
smoke-volume:
    limactl shell bugpot -- sudo bash scripts/smoke-volume.sh

# HTTP readiness end-to-end (<30s; no freeze cycle). Two apps in
# parallel: one with a passing 2xx path, one with a non-2xx path
# that must fail the cold start.
smoke-readiness:
    limactl shell bugpot -- sudo bash scripts/smoke-readiness.sh

# Long-running interactive demo (foreground; Ctrl+C to stop).
run:
    limactl shell bugpot -- sudo bash scripts/run-local.sh

# --- Background dev server (alpha + beta, eager-started) ---

# Start bugpot in the background; blocks until "bugpot up".
start:
    limactl shell bugpot -- sudo bash scripts/dev-server.sh start

# Stop the background bugpot and tear down bridge / nft.
stop:
    limactl shell bugpot -- sudo bash scripts/dev-server.sh stop

# Tail the dev-server log. Pass `-f` to follow, `-n N` for line count.
logs *args="-n 50":
    limactl shell bugpot -- sudo bash scripts/dev-server.sh logs {{args}}

# --- Mac-side helpers ---

# curl an app via *.localhost. e.g. `just hit beta /healthz`.
hit host="alpha" path="/":
    curl -sS -i --max-time 30 "http://{{host}}.localhost:8080{{path}}"

# Scrape the dev-server's Prometheus endpoint (always bound at
# 127.0.0.1:9090 by `scripts/dev-server.sh`; loopback-only).
metrics:
    @limactl shell bugpot -- curl -sS http://127.0.0.1:9090/metrics

# Filter the metrics scrape to lines starting with `prefix`.
# Example: `just metrics-grep bugpot_cold_start` for cold-start
# histograms only.
metrics-grep prefix:
    @limactl shell bugpot -- curl -sS http://127.0.0.1:9090/metrics | grep -E '^{{prefix}}'
