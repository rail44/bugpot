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
- `BUGPOT_ADMIN_TOKEN` — bearer token for admin API; if set, all admin routes require `Authorization: Bearer <token>` (constant-time compare via `subtle::ConstantTimeEq`, token held in `Zeroizing`). Unset = no auth (trust delegated to listener binding).
- `BUGPOT_ADMIN_TOKEN_FILE` — path to a file whose trimmed contents are the token. Used when `BUGPOT_ADMIN_TOKEN` is not set. Typical layout: `/etc/bugpot/admin-token` with `root:root 0600` permissions.
- `BUGPOT_AUTH_FILE` — registry-auth TOML (default `/etc/bugpot/auth.toml`, missing file = anonymous)
- `BUGPOT_METRICS_LISTEN` — opt-in Prometheus listener (e.g. `127.0.0.1:9090`). Unset = `/metrics` + `/healthz` disabled.
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

## Exposing apps on a tailnet (Tailscale Services)

For dogfooding on a real tailnet, bugpot integrates with **Tailscale
Services** (the 2026 feature that gives each registered service its own
`<service>.<tailnet>.ts.net` URL with automatic TLS). bugpot itself
contains no Tailscale code — exposure is configured externally via the
`tailscale serve` CLI on the bugpot host. Phase 1 is fully manual;
automating registration from `deploy_app` is a deferred follow-up.

### One-time host setup

```sh
# Join the tailnet (operator-supplied auth).
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --advertise-tags=tag:bugpot
```

Then enable HTTPS in the Tailscale admin console (DNS → HTTPS
Certificates → Enable). This authorises `*.ts.net` cert provisioning
for every device in the tailnet.

### Expose the admin API as a Service

For CI to call `POST /apps` over the tailnet, the admin port also gets
its own Service. (Service host devices cannot access their own
Services — this also keeps operator-local access and CI access on
different paths.)

```sh
sudo tailscale serve --service=svc:bugpot-admin --bg http://localhost:8081
```

Admin is then reachable from any other tailnet device at
`https://bugpot-admin.<tailnet>.ts.net/apps` with TLS provisioned by
Tailscale automatically.

### Per-app Service registration

For each app subdomain you want reachable from the tailnet, register a
Service whose name **matches** the app's subdomain (the part bugpot's
`subdomain_of` extracts from the `Host` header):

```sh
# Example: app TOML has subdomain = "alpha" (default = name).
sudo tailscale serve --service=svc:alpha --bg http://localhost:8080
sudo tailscale serve --service=svc:beta  --bg http://localhost:8080
```

Both Services proxy to bugpot's router on `127.0.0.1:8080`. The Host
header that arrives at bugpot is `<service>.<tailnet>.ts.net`, so
`subdomain_of` extracts `<service>` and routes to the matching app.
**Names must align**: `tailscale serve --service=svc:alpha …` ↔ app
spec `name = "alpha"` (or `subdomain = "alpha"`).

### CI deploy flow

`examples/github-actions-deploy.yml` is a copy-pasteable workflow for an
**application repo** that builds, pushes to GHCR, joins the tailnet via
`tailscale/github-action@v4`, and `POST`s the new spec to bugpot's admin
Service. Required secrets in the application repo:

- `TS_OAUTH_CLIENT_ID` / `TS_OAUTH_SECRET` — Tailscale OAuth client with
  `devices:core:write` and `tag:bugpot-ci`
- `BUGPOT_ADMIN_TOKEN` — bearer token from the bugpot host's
  `/etc/bugpot/admin-token`
- (`GHCR_PAT`) — only needed if the org disables packages:write on
  `GITHUB_TOKEN`

### Verifying end-to-end

Checklist for confirming a fresh tailnet deploy resolves all the way
through to a container:

1. `tailscale status` on the bugpot host: device shows as online, tags
   include `tag:bugpot`.
2. `sudo tailscale serve status` lists `svc:bugpot-admin` (and any
   per-app Services).
3. From a *second* tailnet device:
   `curl -fsS -H "Authorization: Bearer $TOKEN" https://bugpot-admin.<tailnet>.ts.net/apps`
   returns `200` + the current app list.
4. Trigger the deploy workflow (push to main, or
   `gh workflow run deploy.yml`); job log shows `DELETE` (`404` first
   time) and `POST` (`201` with `AppView`).
5. `curl -fsS https://<APP_NAME>.<tailnet>.ts.net/` from the second
   device returns the app's HTTP response. First request triggers TLS
   provisioning and can take ~30 s.
6. `journalctl` on the bugpot host shows
   `bugpot_router: matched route host=<APP_NAME>.<tailnet>.ts.net`.

### Phase 2 (deferred): automated Service registration

Eventually `AppController::deploy_app` could shell out to
`tailscale serve --service=svc:<name> --bg …` after a successful
deploy, and the inverse on `remove_app`. Gated behind an env
(e.g. `BUGPOT_TAILSCALE_SERVICES=on`) so non-Tailscale topologies stay
unchanged. Not in this iteration — the manual path is enough for
dogfooding and exposes operational gotchas (e.g. Service host
self-access restriction) before they get hidden behind automation.

## Architecture

Library crates assembled by a single binary:

```
cmd/bugpot (main: wires everything; no business logic)
   │
   ├─► bugpot-config     : parses apps/*.toml → AppSpec
   ├─► bugpot-egress     : bridge + netns + nft + DNS allowlist
   ├─► bugpot-runtime    : OCI pull + libcontainer lifecycle
   ├─► bugpot-router     : axum reverse proxy, resolves by Host subdomain
   ├─► bugpot-controller : AppHandle state machine + cold-start orchestration + idle reaper
   ├─► bugpot-admin      : admin HTTP API (CRUD over AppController), bearer auth
   └─► bugpot-metrics    : Prometheus recorder + /metrics + /healthz listener
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

`scaling.idle_timeout` in app TOML: `"0"` / `""` / missing → always-on (eagerly started at bring-up); `"30s"` / `"5m"` / `"2h"` → reclaimed by `idle_stopper_loop` once `last_access` is older than the timeout. Default 5m. The state-transition logic lives in `crates/bugpot-controller`.

### State directory

`/var/lib/bugpot/{images,bundles,containers}`. Images are content-addressed by digest; bundles are per-app (`rootfs` is a symlink into the image cache — read-only, no overlayfs yet). `Runtime::start_app` removes stale `containers/<name>` from a prior crash before letting libcontainer recreate it. Note that libcontainer's `with_root_path` takes the **parent** of the per-container state dir, not the dir itself.

### Multi-arch image handling

bugpot delegates image-index resolution to oci-client's default `current_platform_resolver`, which matches the first index entry whose `(os, architecture)` equals `(Os::default(), Arch::default())`. Both defaults are derived from `std::env::consts::{OS, ARCH}` (Rust compile target), with the arch string translated to its Go/OCI name (`x86_64 → amd64`, `aarch64 → arm64`, etc.).

- Verified empirically on aarch64: `docker.io/library/alpine:latest` resolves to `architecture=arm64, variant=v8, os=linux`.
- **No variant matching** — oci-client documents this explicitly. For `arm/v6` vs `arm/v7` indexes the first match wins; on `aarch64` it's almost always `v8` (or no variant), so this rarely bites.
- **No cross-architecture pulls** — if the index has no entry for the host arch the pull fails. That's deliberate: bugpot is the host that runs the container.
- A bugpot binary built for `x86_64` running under Rosetta on an `arm64` host will pull `amd64` images. The compile target wins, which matches the actual execution environment.

### Observability

- `bugpot-metrics::install_recorder` is called unconditionally at startup so `metrics` macros always emit; the HTTP listener (`/metrics`, `/healthz`) only binds when `BUGPOT_METRICS_LISTEN` is set. No auth — bind to a trusted interface.
- Cold-start instrumentation: `bugpot_cold_start_seconds{phase=endpoint|pull|start|readiness}` (controller, success-only), `bugpot_image_pull_seconds{step=…}` (runtime), `bugpot_container_start_seconds{step=…}` (runtime).
- Container stdout/stderr is captured by `bugpot-runtime` and re-emitted through `tracing` under target `bugpot::app` with fields `app` and `stream` — filter with `RUST_LOG=bugpot::app=info`.

## Conventions

- Workspace edition 2024, MSRV 1.85. Lints: `unsafe_code = "deny"` workspace-wide; clippy `all`/`pedantic`/`nursery`/`cargo` enabled.
- App TOML is the only config surface. `name` defaults to the file stem; `subdomain` defaults to `name`.
- Tests that need root, network, or a real kernel namespace setup are marked `#[ignore]` with a reason string — never silently skipped.
- `bugpot-egress` keeps host-touching code (`nft`, `ip`) and pure logic (allowlist, allocator, nft text rendering) in separate modules so the latter can be unit-tested without root.
