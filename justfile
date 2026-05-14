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

# Authenticate the dev VM into your tailnet (interactive on first run).
tailscale-up *args="--advertise-tags=tag:bugpot --hostname=bugpot-dev":
    limactl shell bugpot -- sudo tailscale up {{args}}

# Tailscale status as seen by the dev VM.
tailscale-status:
    limactl shell bugpot -- tailscale status

# --- Build / test (inside the VM) ---

# Build the bugpot binary.
build:
    limactl shell bugpot -- bash -lc 'cargo build -p bugpot'

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
