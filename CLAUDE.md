# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Bugpot is an internal Heroku-like PaaS for running experimental apps as OCI containers behind a Host-header–routed reverse proxy with per-app network isolation, DNS-driven egress allowlists, and scale-to-zero. Rust workspace targeting Linux only (uses libcontainer/youki, nftables, netns).

## Development environment (macOS host)

bugpot only runs on Linux. The repo ships a Lima template at `lima/bugpot.yaml`
that provisions an Ubuntu 24.04 VM with the Rust toolchain, `nftables`, and
`iproute2` ready to go. The repo is bind-mounted writable at the same
absolute path inside the VM, so edits on macOS show up immediately.

First-time setup:

```sh
brew install lima just
limactl create --name=bugpot ./lima/bugpot.yaml
limactl start bugpot
```

Daily use is via `just` from the macOS host — each recipe delegates into the
VM as needed. Run `just` (or `just --list`) for the full menu. Selected
recipes:

```sh
just build            # cargo build -p bugpot (in VM)
just test             # cargo test --workspace (in VM)
just clippy
just smoke-infra      # scripts/smoke-infra.sh under sudo
just smoke-app        # scripts/smoke-app.sh
just shell            # interactive shell in the VM, cwd preserved

just start            # background dev server: alpha + beta, eager-started
just hit alpha        # curl http://alpha.localhost:8080/ from macOS
just hit beta /foo
just logs -f
just stop
```

The Lima VM forwards guest `127.0.0.1:8080` to host `127.0.0.1:8080`. App
subdomains resolve via the `*.localhost` wildcard, so `just hit alpha` and
browsing `http://alpha.localhost:8080/` both work with no `/etc/hosts`
changes.

### Background dev server

`just start` runs `scripts/dev-server.sh start` inside the VM, which
launches bugpot as a transient systemd unit `bugpot-dev.service` with two
eager-started demo apps. Critical design points:

- The unit name is the **only** handle for stop/status/logs. The script
  never uses `pkill -f bugpot` or similar broad matching — that would
  clobber any other bugpot instance the user runs in parallel.
- App names are `dev-alpha` / `dev-beta` (subdomain stays short: `alpha` /
  `beta`). Resulting netns are `bugpot-dev-*`, unambiguously owned by the
  dev-server and safe to clean up on its own teardown.
- Shared infra (`bugpot0` bridge, `nft inet bugpot` table) is left
  **alone** on stop. bugpot's own setup is idempotent; another instance
  may still need them.
- `KillSignal=SIGINT` is set on the unit so `systemctl stop` triggers
  bugpot's main-loop teardown (which releases endpoints and removes
  netns). `SIGTERM` would skip teardown and leak netns.
- State dir is persistent at `/var/lib/bugpot-dev` so restarts reuse the
  image cache.

Logs go through journalctl; `just logs` is equivalent to
`journalctl -u bugpot-dev.service`.

### Smoke scripts

For one-shot verification rather than iterative work, the smoke scripts
under `scripts/` are still the canonical end-to-end tests:

- `scripts/run-local.sh` — long-running demo with two apps under scale-to-zero (foreground)
- `scripts/smoke-infra.sh` — bring-up only (no apps, validates bridge/nft/DNS)
- `scripts/smoke-app.sh` — single-app end-to-end (pull → start → HTTP → shutdown)
- `scripts/smoke-multi.sh` — Host-header dispatch between two apps

These scripts DO tear down `bugpot0` + the `nft` table on exit because
they're explicit single-shot tests. The dev-server intentionally does not.

Env vars (read by bugpot directly):

- `BUGPOT_APPS_DIR` (default `./apps`)
- `BUGPOT_STATE_DIR` (default `/var/lib/bugpot`)
- `BUGPOT_LISTEN` — public HTTP router (default `127.0.0.1:8080`)
- `BUGPOT_ADMIN_LISTEN` — admin HTTP API (default `127.0.0.1:8081`)
- `BUGPOT_ADMIN_TOKEN` — bearer token for admin API; if set, all admin routes require `Authorization: Bearer <token>` (constant-time compare). Unset = no auth (trust delegated to listener binding).
- `BUGPOT_ADMIN_TOKEN_FILE` — path to a file whose trimmed contents are the token. Used when `BUGPOT_ADMIN_TOKEN` is not set. Typical layout: `/etc/bugpot/admin-token` with `root:root 0600` permissions.
- `BUGPOT_AUTH_FILE` — registry-auth TOML (default `/etc/bugpot/auth.toml`, missing file = anonymous)
- `RUST_LOG`

### Admin HTTP API

`bugpot-admin` exposes a minimal CRUD surface for runtime app management.
Listener is whatever `BUGPOT_ADMIN_LISTEN` points at.

Auth is optional bearer-token (`BUGPOT_ADMIN_TOKEN` / `BUGPOT_ADMIN_TOKEN_FILE`).
Verification uses `subtle::ConstantTimeEq` so wrong tokens do not leak
through timing. When no token is configured, auth is a no-op and trust
is delegated to the listener binding (loopback for self-hosted runner
flows, Tailscale IP + ACL for remote CI).

| Method | Path           | Body / Response                                    |
|--------|----------------|----------------------------------------------------|
| POST   | `/apps`        | JSON `AppSpec` in, `201` + `AppView`. Pulls image immediately; persists `apps/<name>.toml` only on success. |
| GET    | `/apps`        | `200` + `[AppView]`                                |
| GET    | `/apps/{name}` | `200` + `AppView`, `404` if absent                 |
| DELETE | `/apps/{name}` | `204` on stop+remove, `404` if absent              |

Error → status mapping:

- `400` missing `name`
- `404` not found
- `409` name or subdomain already in use
- `502` image pull failed (registry unreachable / auth wrong)
- `500` other internal errors

Adapter crates (webhook receiver, GitHub poller, CLI) can be added later
as siblings of `bugpot-admin`; the public mutation API on
`AppController` (`deploy_app` / `remove_app` / `list_apps` / `get_app`)
is the shared boundary.

## Architecture

Four library crates assembled by a single binary:

```
cmd/bugpot (main + controller)
   │
   ├─► bugpot-config  : parses apps/*.toml → AppSpec
   ├─► bugpot-egress  : bridge + netns + nft + DNS allowlist
   ├─► bugpot-runtime : OCI pull + libcontainer lifecycle
   └─► bugpot-router  : axum reverse proxy, resolves by Host subdomain
```

`experiments/youki-sandbox` is a standalone playground for oci-client/libcontainer experiments; it isn't part of the runtime path.

### Request flow

1. Router receives HTTP, extracts first DNS label of `Host` (see `subdomain_of` in `bugpot-router`).
2. Calls `UpstreamResolver::resolve` — the controller's impl, which **may take seconds** (cold start).
3. Controller's `AppHandle` state machine (`Stopped → Starting → Running → Stopping`) gates work: concurrent starts on the same app coalesce on a per-handle `Notify`.
4. On cold start: `Egress::allocate_endpoint` (netns + veth + IP + DNS registry) → `Runtime::pull_image` → `Runtime::start_app` (passes the netns path to libcontainer) → TCP readiness probe on the app's declared port.
5. Router proxies via `hyper_util` legacy client; HTTP/1.1 Upgrade (e.g. WebSocket) is spliced bidirectionally.

### Egress model (critical)

The nftables forward chain is **default-drop**. Packets only escape via a `(src_ip, dst_ip)` allow-set populated by the bugpot DNS resolver bound on the bridge IP. When a container resolves a domain on its app's allowlist, every answer is inserted into the set with a 60s TTL — that is the only path out. Direct-IP egress, DoH, DoT, and queries to external resolvers are all blocked. Allowlist semantics (in `bugpot-egress/src/allowlist.rs`): bare `example.com` matches `example.com` and subdomains; `*.example.com` matches subdomains only.

### Scale-to-zero

`scaling.idle_timeout` in app TOML: `"0"` / `""` / missing → always-on (eagerly started at bring-up); `"30s"` / `"5m"` / `"2h"` → reclaimed by `idle_stopper_loop` once `last_access` is older than the timeout. Default 5m. The state-transition logic is in `cmd/bugpot/src/controller.rs`.

### State directory

`/var/lib/bugpot/{images,bundles,containers}`. Images are content-addressed by digest; bundles are per-app (`rootfs` is a symlink into the image cache — read-only, no overlayfs yet). `Runtime::start_app` removes stale `containers/<name>` from a prior crash before letting libcontainer recreate it. Note that libcontainer's `with_root_path` takes the **parent** of the per-container state dir, not the dir itself.

## Conventions

- Workspace edition 2024, MSRV 1.85. Lints: `unsafe_code = "deny"` workspace-wide; clippy `all`/`pedantic`/`nursery`/`cargo` enabled.
- App TOML is the only config surface. `name` defaults to the file stem; `subdomain` defaults to `name`.
- Tests that need root, network, or a real kernel namespace setup are marked `#[ignore]` with a reason string — never silently skipped.
- `bugpot-egress` keeps host-touching code (`nft`, `ip`) and pure logic (allowlist, allocator, nft text rendering) in separate modules so the latter can be unit-tested without root.
