# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Bugpot is an internal Heroku-like PaaS for running experimental apps and self-hosted tools as OCI containers behind a Host-header–routed reverse proxy with per-app network isolation, DNS-driven egress allowlists, and **freezer-based scale-to-zero** (idle apps are cgroup-paused, not stopped — next request resumes in sub-ms; a memory-pressure handler evicts oldest-frozen to free RAM under load). Rust workspace targeting Linux only (uses libcontainer/youki, nftables, netns, cgroup v2 freezer).

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
just build            # cargo build -p bugpotd (in VM)
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

### Mac-native fast paths

Most cargo commands have to run inside Lima because `bugpot-runtime`,
`bugpot-egress`, `bugpot-core`, `bugpot-admin`, and `cmd/bugpotd`
all transitively depend on Linux-only crates (`libcontainer`,
`procfs`, `nix::sched`, `inotify`). Four crates are pure Rust and
compile on macOS directly:

- `bugpot-config`, `bugpot-router`, `bugpot-metrics`, `cmd/bugpot` (CLI)

For those crates and for `cargo fmt`, the justfile exposes
`-host` / `fmt` recipes that skip the Lima round-trip entirely:

```sh
just fmt              # rustfmt across the workspace, native
just fmt-check        # CI-style check, native
just check-host       # cargo check for the three host-compatible crates
just clippy-host      # likewise for clippy
```

For the Linux-only crates, prefer the single-crate `just check-crate
<name>` / `just clippy-crate <name>` / `just test-crate <name>` over
the workspace-wide `just check` etc. when iterating on one crate —
cargo skips the full-graph reanalysis and the Lima round-trip cost
is amortised across one compilation pass instead of eight.

Editor-side type checking is its own concern. `rustup target add
aarch64-unknown-linux-gnu` gives the rust-analyzer / IDE side the
Rust stdlib for the Linux target; configure your editor's
rust-analyzer with `cargo.target = "aarch64-unknown-linux-gnu"` so
diagnostics match what Lima sees. (Build scripts for libseccomp /
libcontainer C bindings still fail without a Linux cross-linker, but
rust-analyzer is tolerant of those failures and still surfaces
source-level type errors for the pure-Rust parts of every crate.)

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

The dev-server **always** publishes Prometheus metrics on
`127.0.0.1:9090` (loopback inside the VM, never forwarded out). Use
`just metrics` for a full scrape or `just metrics-grep <prefix>` to
filter, e.g. `just metrics-grep bugpot_cold_start` for the cold-start
phase histograms. The endpoint is unauthenticated by design and
relies on the loopback bind plus the dev-VM trust boundary.

### Smoke scripts

For one-shot verification rather than iterative work, the smoke scripts
under `scripts/` are still the canonical end-to-end tests:

- `scripts/run-local.sh` — long-running demo with two apps under scale-to-zero (foreground)
- `scripts/smoke-infra.sh` — bring-up only (no apps, validates bridge/nft/DNS)
- `scripts/smoke-app.sh` — single-app end-to-end (pull → start → HTTP → shutdown)
- `scripts/smoke-multi.sh` — Host-header dispatch between two apps
- `scripts/smoke-freeze.sh` — freezer-based scale-to-zero: idle → `frozen` (not `stopped`), resume in sub-ms
- `scripts/smoke-readiness.sh` — `[readiness] path` HTTP probe: cold-start blocks until 2xx
- `scripts/smoke-volume.sh` — `[[volumes]]` bind-mounts survive freeze / rollout / eviction

These scripts DO tear down `bugpot0` + the `nft` table on exit because
they're explicit single-shot tests. The dev-server intentionally does not.

Env vars (read by bugpot directly):

- `BUGPOT_STATE_DIR` (default `/var/lib/bugpot`). All daemon-managed state — image cache, container bundles, persisted `AppSpec`s (`<state>/apps/<name>.toml`), rollout history (`<state>/rollouts/<name>.toml`), per-app volumes — lives here. Specs are *only* set via the admin API; bugpotd does not read TOMLs from any operator-controlled directory.
- `BUGPOT_LISTEN` — public HTTP router (default `127.0.0.1:8080`)
- `BUGPOT_ADMIN_LISTEN` — admin HTTP API (default `127.0.0.1:8081`)
- `BUGPOT_ADMIN_TOKEN_FILE` — **required** unless `BUGPOT_ADMIN_TOKEN` is set. Path to a file whose trimmed contents are the bearer token. The file must be `0600` (any group/other permission bit set causes bugpot to refuse to start, ssh-key style). Typical layout when bugpot runs as the unprivileged `bugpot` user (the shipped systemd unit's setup): `/etc/bugpot/admin-token` with `bugpot:bugpot 0600`.
- `BUGPOT_ADMIN_TOKEN` — fallback bearer token for development. **Logs a warning** when used because env vars are visible in `/proc/<pid>/environ` and shell history; prefer `BUGPOT_ADMIN_TOKEN_FILE` in production. bugpot refuses to start unless one of these two is set.
- `BUGPOT_AUTH_FILE` — registry-auth TOML (default `/etc/bugpot/auth.toml`, missing file = anonymous)
- `BUGPOT_METRICS_LISTEN` — opt-in Prometheus listener (e.g. `127.0.0.1:9090`). Unset = `/metrics` + `/healthz` disabled.
- `BUGPOT_FREEZE_ENABLED` — `true` (default) or `false`. When on, `idle_timeout` freezes the container (cgroup v2 freezer) instead of stopping it, keeping RAM resident so the next request resumes in sub-ms. The memory-pressure handler evicts oldest-frozen apps to `Stopped` under low memory; see the two knobs below. Off restores pre-freeze behavior (idle = stop).
- `BUGPOT_FREEZE_MEM_LO` / `BUGPOT_FREEZE_MEM_HI` — bytes of `MemAvailable` that trigger / release the eviction handler (hysteresis pair, defaults 150 MiB / 250 MiB sized for e2-micro). Bump for larger VMs. `LO < HI` is enforced; the daemon refuses to start otherwise.
- `RUST_LOG`

### Admin HTTP API

`bugpot-admin` exposes a minimal CRUD surface for runtime app management.
Listener is whatever `BUGPOT_ADMIN_LISTEN` points at.

The pure-Rust **`bugpot` CLI** (`cmd/bugpot`) wraps the endpoints below
for daily use under a `<noun> <verb>` grammar:
`bugpot apps {list,get,create,update,delete,deploy-key}` and
`bugpot rollouts {list,push}`. Reads `BUGPOT_ADMIN_URL` /
`BUGPOT_ADMIN_TOKEN[_FILE]` (plus `BUGPOT_DEPLOY_TOKEN[_FILE]` for the
rollouts plane) from env; default `BUGPOT_ADMIN_URL` is
`http://127.0.0.1:8081`. Pass `--json` on any command to forward the
raw API response verbatim — useful for piping into `jq` from a
self-hosted CI runner.

The CLI is intentionally pure-Rust and dep-free of `bugpot-runtime` /
`bugpot-core` / `bugpot-admin` so it compiles on macOS too;
operators can run it from their laptop against a remote `bugpotd`.

Bearer-token auth is **mandatory** (`BUGPOT_ADMIN_TOKEN_FILE` preferred,
`BUGPOT_ADMIN_TOKEN` env var as fallback). bugpot refuses to start
without one — there is no "trust delegated to the listener binding"
path, since `BUGPOT_ADMIN_LISTEN=0.0.0.0:8081` is one typo away from
a fully public admin API. Verification uses `subtle::ConstantTimeEq`
so wrong tokens do not leak through timing.

The router also enforces a 256 KB request body cap and a 60-req/min
global rate limit (returns `429 Too Many Requests` when exceeded), so
brute-forcing the token over the network is infeasible even if a
weak token is configured.

Config plane (admin token):

| Method | Path                          | Body / Response                                    |
|--------|-------------------------------|----------------------------------------------------|
| POST   | `/apps`                       | `AppSpec` in (JSON by default; `Content-Type: application/toml` accepts the on-disk TOML form), `201` + `AppView`. Registers only — does NOT pull an image or start a container. |
| GET    | `/apps`                       | `200` + `[AppView]`                                |
| GET    | `/apps/{name}`                | `200` + `AppView`, `404` if absent                 |
| PATCH  | `/apps/{name}`                | Replace-style update of mutable fields. Body shape = `POST /apps` (JSON or TOML). `200` + `AppView`. `name` and `subdomain` are immutable (reject with 400). Container is restarted iff the spec actually changes (TOML projection equality short-circuit). |
| DELETE | `/apps/{name}`                | `204` on stop+remove, `404` if absent              |
| POST   | `/apps/{name}/deploy-keys`    | `201` + `{token: "bp1.<hex>"}`. The token authorises this app's rollout endpoints only. |

Rollout plane (per-app deploy token):

| Method | Path                          | Body / Response                                    |
|--------|-------------------------------|----------------------------------------------------|
| POST   | `/apps/{name}/rollouts`       | JSON `{tag}`. Pulls and (re)starts the container. `201` + `Rollout`. |
| GET    | `/apps/{name}/rollouts`       | `200` + `[Rollout]` (oldest first, current last).  |

Error → status mapping (POST/PATCH/DELETE `/apps`):

- `400` missing `name`, invalid spec, malformed JSON / TOML body
- `404` not found
- `409` name or subdomain already in use
- `500` internal errors

Rollout endpoint (`/apps/{name}/rollouts`):

- `400` empty tag
- `404` app not registered
- `409` app is mid-transition (Starting/Stopping); retry
- `502` registry auth / pull failure
- `500` post-pull start failure or internal error

Adapter crates (webhook receiver, GitHub poller, CLI) can be added later
as siblings of `bugpot-admin`; the public mutation API on
`AppHost` (`deploy_app` / `remove_app` / `list_apps` / `get_app`)
is the shared boundary.

## Exposing apps externally

bugpot's responsibility ends at binding the public router on
`BUGPOT_LISTEN` and the admin API on `BUGPOT_ADMIN_LISTEN`. Making
either reachable from outside the host (TLS termination, public DNS,
tailnet, reverse proxy, etc.) is the operator's concern; bugpot
itself ships no integration with any specific reachability layer.

Common patterns operators use:

- Tailscale Services / `tailscale serve` mapping a tailnet URL to
  `localhost:8080` / `localhost:8081`.
- A TLS-terminating reverse proxy (Caddy, nginx) in front of the
  router and admin listeners.
- Self-hosted GitHub Actions runner on the bugpot host so CI reaches
  admin via `localhost` without crossing the public internet.

Whichever path an operator picks, set `RouterConfig::trusted_proxies`
to the IP range of the front layer so `X-Forwarded-For` rewriting
works correctly.

## Architecture

Library crates assembled by two binaries (`bugpotd` daemon and
`bugpot` CLI):

```
cmd/bugpotd (main: wires everything; no business logic)
   │
   ├─► bugpot-config     : parses apps/*.toml → AppSpec
   ├─► bugpot-egress     : bridge + netns + nft + DNS allowlist
   ├─► bugpot-runtime    : OCI pull + libcontainer lifecycle
   ├─► bugpot-router     : axum reverse proxy, resolves by Host subdomain
   ├─► bugpot-core       : AppHandle state machine + cold-start orchestration + idle reaper
   ├─► bugpot-admin      : admin HTTP API (CRUD over AppHost), bearer auth
   └─► bugpot-metrics    : Prometheus recorder + /metrics + /healthz listener

cmd/bugpot (CLI; pure-Rust, also builds on macOS — talks to bugpotd's admin API)

scripts/analysis (`bugpot-analyzer`; dev-only static-analysis CLI for
                  `just hotspots` / `just modules` / `just depgraph`.
                  Workspace member, not in the runtime path.)
```

`experiments/youki-sandbox` is a standalone playground for oci-client/libcontainer experiments; it isn't part of the runtime path.

### Request flow

1. Router receives HTTP, extracts first DNS label of `Host` (see `subdomain_of` in `bugpot-router`).
2. Calls `UpstreamResolver::resolve` — the controller's impl, which **may take seconds** (cold start).
3. Controller's `AppHandle` state machine (`Stopped → Starting → Running ↔ Frozen → Stopping → Stopped`) gates work: concurrent starts on the same app coalesce on a per-handle `Notify`. `Frozen` is the idle-timeout target (see Scale-to-zero below); the `Running ↔ Frozen` edge is bidirectional (freeze on idle, resume on request).
4. On cold start: `Egress::allocate_endpoint` (netns + veth + IP + DNS registry) → `Runtime::pull_image` → `Runtime::start_app` (passes the netns path to libcontainer) → readiness probe on the app's declared port (TCP-bind by default; HTTP GET when `[readiness] path` is set — see below).
5. Router proxies via `hyper_util` legacy client; HTTP/1.1 Upgrade (e.g. WebSocket) is spliced bidirectionally.

### Router defences

Sized against a public-internet client. Whatever reachability layer the operator picks in front of bugpot is a deployment convenience, never a trust boundary. The router applies (constants in `crates/bugpot-router/src/lib.rs`):

Values sized for the "many small apps on a cheap VM (e2-micro / e2-small)" scenario — small enough that `MAX_BODY_BYTES * MAX_CONCURRENT_REQUESTS` (current floor 256 MiB of inbound bookkeeping) fits on a 1 GiB host with room to spare.

- Request-side: `MAX_BODY_BYTES` (4 MiB inbound cap), `HEADER_READ_TIMEOUT` (10 s slowloris guard), `REQUEST_TIMEOUT` (30 s time-to-headers cap), `MAX_CONCURRENT_REQUESTS` (64 in-flight via `tower::ConcurrencyLimitLayer`).
- Response-side: every response body is wrapped in `GuardedBody`, which enforces `RESPONSE_FRAME_TIMEOUT` (1 min per-frame idle — closes slow-reading clients) and `MAX_RESPONSE_BODY_BYTES` (64 MiB total — stops runaway upstream payloads from monopolising a connection or host bandwidth; larger responses should stream out-of-band via presigned URLs or similar).
- Upgrades (WebSocket): `MAX_CONCURRENT_UPGRADES` (32 simultaneous spliced sockets, enforced via `Arc<Semaphore>`; saturation returns `503`) and `UPGRADE_IDLE_TIMEOUT` (5 min of silence in **both** directions tears the splice down via `splice_with_idle`).
- HTTP/2: `H2_MAX_CONCURRENT_STREAMS = 16` so a single h2 client cannot exhaust `MAX_CONCURRENT_REQUESTS` with one connection.
- Hop-by-hop headers (RFC 7230 §6.1 + Connection-listed extras) are stripped both ways. The Upgrade path is exempt for the request because `Connection: Upgrade` must reach the upstream; the response is no-op here because hyper has already consumed it for the upgrade.
- `X-Forwarded-For` is rewritten per `RouterConfig::trusted_proxies`: untrusted peers see their chain discarded; the empty default list preserves the historical "trust everyone" behaviour, but real deployments should populate it.

### Egress model (critical)

The nftables forward chain is **default-drop**. Packets only escape via a `(src_ip, dst_ip)` allow-set populated by the bugpot DNS resolver bound on the bridge IP. When a container resolves a domain on its app's allowlist, every answer is inserted into the set with a 60s TTL — that is the only path out. Direct-IP egress, DoH, DoT, and queries to external resolvers are all blocked. Allowlist semantics (in `bugpot-egress/src/allowlist.rs`): bare `example.com` matches `example.com` and subdomains; `*.example.com` matches subdomains only.

### Container hardening

Every container runs with the **moby (Docker) default seccomp profile** vendored verbatim at `crates/bugpot-runtime/src/seccomp_default.json` and translated to an OCI `LinuxSeccomp` in `seccomp::runc_default`. The profile is the de-facto industry standard (~33 rules, ~440 syscall names; default action `SCMP_ACT_ERRNO`) and is attached to every spec by `build_spec`. Two intentional deviations from runc:

- The profile's `archMap`, `includes`, `excludes`, and `comment` extensions are **ignored**. Cap-conditional rules collapse to unconditional allow because the kernel's capability check fires after seccomp anyway — a container without `CAP_SYS_PTRACE` cannot call `ptrace` regardless of the seccomp verdict, so the two layers stay independent.
- Architectures are hard-coded to `x86_64 + aarch64` (bugpot's supported hosts).

Build dependency: libseccomp dev headers (`apt install libseccomp-dev`; pre-installed by `lima/bugpot.yaml`). Runtime needs only `libseccomp2`.

A user namespace was investigated and **deferred**: libcontainer creates the user namespace before processing any other namespace, so subsequent `setns` of an externally-prepared netns (created in bugpot's initial user_ns by `bugpot-egress`) fails with `EPERM` from the nested user_ns. Re-enabling it requires reworking egress to create the netns inside the container's user_ns.

### Scale-to-zero

`scaling.idle_timeout` in app TOML: `"0"` / `""` / missing → always-on (eagerly started at bring-up, never frozen); `"30s"` / `"5m"` / `"2h"` → freezer kicks in once `last_access` is older than the timeout. Default 5m. The state-transition logic lives in `crates/bugpot-core`.

**Freeze vs stop.** The default scale-to-zero path is **freeze, not stop** (cgroup v2 freezer). Frozen apps keep their full RSS resident but consume zero CPU; the next request resumes in sub-ms (no image pull, no libcontainer fork, no TCP readiness probe). The trade-off — RAM stays allocated — is bounded by a memory-pressure handler that polls `MemAvailable` and evicts oldest-frozen apps to `Stopped` when memory drops below `BUGPOT_FREEZE_MEM_LO`. This shifts the bottleneck from "cold-start CPU spike on every long-idle hit" to "RAM in steady state", which is what's wanted for the "many small self-hosted apps on a cheap VM" use case (Vaultwarden / Grafana / Linkding-class). Set `BUGPOT_FREEZE_ENABLED=false` to restore the pre-freeze idle = stop behavior. The router's `forward_upgrade` increments `AppHandle::active_upgrades` for the lifetime of every WebSocket / SSE splice, and the idle reaper refuses to freeze while that counter is non-zero — so long-lived upgraded connections survive idle gaps without being silently stranded.

### Readiness probe

`bugpot-core` waits for the app to signal ready after starting the container; the cold-start path doesn't return success (and the router doesn't forward the first request) until the probe passes. Two modes, selected per-app in TOML:

```toml
[readiness]
timeout = "30s"      # optional; how long to wait before giving up (workspace default if missing)
path = "/health"     # optional; opt into HTTP probing
```

- **TCP-bind (default, `path` unset):** the probe is a `TcpStream::connect` against `(container_ip, port)`. Sufficient for plain-TCP apps and for HTTP apps whose handlers come up the moment they bind.
- **HTTP (`path` set):** the controller sends `GET <path>` and waits for a 2xx status. This catches the common Rails / Django startup pattern where the listener binds early but the app responds 500 until its DB pool is connected, which the TCP-only probe lets slip through.

`path` is opt-in rather than a fixed default like `/healthz` because the self-hosted-tool ecosystem hasn't standardised: Vaultwarden serves `/alive`, Linkding `/health`, Miniflux `/healthcheck`, Grafana `/api/health`, Mastodon `/health`, Nextcloud `/status.php`. Forcing a single name would break most pre-built images. Operators pick the right path per app.

The HTTP probe is implemented inline (raw `TcpStream` + a 200-byte read of the response head) rather than via a hyper or reqwest client to keep `bugpot-core`'s dep graph stable — a single `GET` with `Connection: close` is the smallest possible HTTP/1.1 exchange and the parser only needs the status code.

### Persistent volumes

Stateful self-hosted apps (Vaultwarden's sqlite DB, Linkding's bookmarks DB, etc.) survive freeze (the container's fs is untouched while paused) but **would lose data on a stop** — including memory-pressure eviction, manual restart, or any bugpot-side teardown. The `[[volumes]]` section of an app TOML declares one or more bind mounts from `<state>/volumes/<app>/<name>/` into the container:

```toml
[[volumes]]
name = "data"       # → /var/lib/bugpot/volumes/<app>/data/
path = "/data"      # mount point inside container
user = 33           # optional: chown the host dir to this UID at start
```

**Permissions trap.** Containers typically run as a non-root user (Linkding uid=33, Vaultwarden uid=1000, …). The host-side directory inherits root ownership at creation; without setting `user` the app will get `EACCES` on first write. bugpot chowns to `user:user` on every start (idempotent for unchanged values; correctly re-chowns if the operator updates the TOML).

**Lifecycle.** Volumes are created lazily on first start (`volumes::ensure_volume_host_dirs`, a `bugpot-runtime` free fn called from `Runtime::start_app`), preserved across freeze / rollouts / memory-pressure eviction, and removed only when the app itself is removed (`DELETE /apps/<name>` flows through `cleanup_orphan_container`, which now also drops the volume dir). Removing the `[[volumes]]` entry from a TOML without deleting the app leaves the host directory on disk — operators can re-add the same `name` and the data is still there.

**Reserved paths.** Volumes cannot target `/`, `/proc`, `/sys`, `/dev`, `/dev/pts`, `/dev/shm`, `/dev/mqueue`, or `/etc/resolv.conf` — these are owned by the OCI default mounts or bugpot's DNS bind. `validate_volumes` rejects collisions at deploy time so a bad TOML never reaches `start_app`.

### State directory

`/var/lib/bugpot/{images,bundles,containers,logs,volumes}`. Images are content-addressed by digest; bundles are per-app (`rootfs` is a symlink into the image cache — read-only, no overlayfs yet); volumes are `volumes/<app>/<name>/` and survive across freeze / rollout / eviction. `Runtime::start_app` removes stale `containers/<name>` from a prior crash before letting libcontainer recreate it. Note that libcontainer's `with_root_path` takes the **parent** of the per-container state dir, not the dir itself.

**Image cache GC (#19):** `Runtime::gc_unused_images` runs once at startup before any pull. It treats the union of every `bundles/<app>/rootfs` symlink's target as the live set of image digests, and removes any `images/<digest>/` not in that set, plus any dir missing `.done` (orphaned `.tmp.*` leftovers from a crashed pull). Tradeoff: an app that's been **registered but never started** has no bundle, so its already-pulled image may get reclaimed and re-pulled on first start. The `live_image_digests` + `gc_unused_images` split keeps the call-site interface stable for the future overlayfs / layer-keyed storage migration — only the internal expansion to live layers changes there.

`logs/<app>/{stdout,stderr}.log` hold each container's fd 1 / fd 2 output. Container fds are opened by bugpot in `O_APPEND` mode and handed to libcontainer, so they survive bugpot crashes and restarts — `reattach_running` doesn't need to re-establish them. The files are NOT cleaned up when an app is removed (operators may want them for post-mortem); orphan-cleanup at startup explicitly skips them.

### Multi-arch image handling

bugpot delegates image-index resolution to oci-client's default `current_platform_resolver`, which matches the first index entry whose `(os, architecture)` equals `(Os::default(), Arch::default())`. Both defaults are derived from `std::env::consts::{OS, ARCH}` (Rust compile target), with the arch string translated to its Go/OCI name (`x86_64 → amd64`, `aarch64 → arm64`, etc.).

- Verified empirically on aarch64: `docker.io/library/alpine:latest` resolves to `architecture=arm64, variant=v8, os=linux`.
- **No variant matching** — oci-client documents this explicitly. For `arm/v6` vs `arm/v7` indexes the first match wins; on `aarch64` it's almost always `v8` (or no variant), so this rarely bites.
- **No cross-architecture pulls** — if the index has no entry for the host arch the pull fails. That's deliberate: bugpot is the host that runs the container.
- A bugpot binary built for `x86_64` running under Rosetta on an `arm64` host will pull `amd64` images. The compile target wins, which matches the actual execution environment.

### Observability

- `bugpot-metrics::install_recorder` is called unconditionally at startup so `metrics` macros always emit; the HTTP listener (`/metrics`, `/healthz`) only binds when `BUGPOT_METRICS_LISTEN` is set. No auth — bind to a trusted interface.
- Cold-start instrumentation: `bugpot_cold_start_seconds{phase=endpoint|pull|start|readiness}` (controller, success-only), `bugpot_image_pull_seconds{step=…}` (runtime), `bugpot_container_start_seconds{step=…}` (runtime).
- Freeze / resume instrumentation: `bugpot_freeze_seconds` (idle reaper, success-only), `bugpot_resume_seconds` (sub-ms cgroup unfreeze path through `ensure_running`), `bugpot_evictions_total` (counter — number of frozen apps the memory-pressure handler has dropped to `Stopped`).
- Container stdout/stderr lands in `<state>/logs/<app>/{stdout,stderr}.log` (container fd 1 / 2 opened `O_APPEND`). A per-stream task tails each file via inotify (`IN_MODIFY`) and re-emits each new line through `tracing` under target `bugpot::app` with fields `app` and `stream` — filter with `RUST_LOG=bugpot::app=info`.
- The tail opens at offset 0, not EOF: on bugpot restart, anything still in the file (incl. bytes the app wrote during the interregnum) replays through tracing once. The replay window is bounded by the truncation cap below, so a restart costs at most one cap-worth of duplicate emissions.
- **Log volume bound (#21):** when any of those files grows past `MAX_LOG_BYTES` (1 MiB), the tail truncates it in place via `ftruncate(0)`. The container's existing fd keeps working — its `O_APPEND` semantics make the next write seek to the new end (= 0). Bytes written between the size check and the truncate may be lost on disk; everything before that point was already emitted through tracing, so the loss is only visible to operators reading the file directly. No generations / no rotation files; if richer retention is needed, run an external collector (vector / otel-collector / fluent-bit) against the same files.

### Performance profiling (development)

The Lima VM provisioning sets `kernel.perf_event_paranoid = -1` and `kernel.kptr_restrict = 0` and installs `bpftrace`, `samply`, and `tokio-console`. These are dev-only choices — do **not** carry them into any production image.

**CPU profile a release build (samply):**

```sh
just shell                                          # inside the VM
cargo build --release -p bugpotd
samply record -- ./target/release/bugpotd          # ^C to stop and upload to Firefox Profiler
```

Samply pops a browser tab on the macOS host (via port forward) with a call tree / stack chart / CPU history. Symbolisation is automatic from DWARF.

**Kernel-side trace (bpftrace) — last-resort when user-space profilers say "blocked here, no idea why":**

```sh
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s -> %s\n", comm, str(args.filename)); }'
sudo bpftrace -e 'kprobe:do_unlinkat /comm == "bugpotd"/ { @ = count(); }'
```

Useful for nftables / netns / libcontainer `clone` cost questions that the in-process profilers can't see.

**Live task / runtime debugger (tokio-console):**

Bugpot has an opt-in `tokio-console` cargo feature on `cmd/bugpotd`. The feature gates `console-subscriber` and also unblocks the `tokio_unstable`-only portion of the `bugpot_tokio_*` Prometheus metric set in `bugpot-metrics`. The `tokio_unstable` cfg has to be set at build time — both `just build-console` and `just run-console` set `RUSTFLAGS="--cfg tokio_unstable"` for you:

```sh
just run-console                                    # foreground bugpotd with the console layer enabled
just shell                                          # in a separate terminal, inside the VM
tokio-console http://127.0.0.1:6669                 # attach to the running bugpotd
```

The console UI lists every tokio task with its busy / idle ratio and the longest `.await` poll. Useful when cold-start latency is dominated by a single stall and you don't know which one. The default build does **not** include the console layer or its overhead — only the on-demand `--features tokio-console` build does.

## Conventions

- Workspace edition 2024, MSRV 1.95. Lints: `unsafe_code = "deny"` workspace-wide; clippy `all`/`pedantic`/`nursery`/`cargo` enabled.
- App TOML is the only config surface. `name` defaults to the file stem; `subdomain` defaults to `name`.
- Tests that need root, network, or a real kernel namespace setup are marked `#[ignore]` with a reason string — never silently skipped.
- `bugpot-egress` keeps host-touching code (`nft`, `ip`) and pure logic (allowlist, allocator, nft text rendering) in separate modules so the latter can be unit-tested without root.
