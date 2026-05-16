# bugpot

A single-binary container PaaS for experimental apps.

> **Pre-1.0** — API and config may change without notice.

- **Host-header routing** — Multiple apps share one HTTP port; requests are dispatched by the Host header's subdomain.
- **Per-app egress allowlist** — Each app can only reach the domains you declare, enforced via DNS.
- **Scale-to-zero** — Idle apps stop automatically and cold-start on the next request.

## Requirements

**Runtime**
- Linux (uses netns, nftables, libcontainer)
- Root / `CAP_NET_ADMIN`
- `nftables`, `iproute2`, `libseccomp2`

**Build**
- Rust 1.95+
- `libseccomp-dev`

## Deploying

See [`docs/deploy.md`](docs/deploy.md) for the end-to-end flow
(set up bugpot host → ops repo with app configs → app repo with
Dockerfile → automated rollouts via GitHub Actions).

## Architecture

`cmd/bugpotd` is a thin wiring layer over seven library crates:

- **`bugpot-config`** — parses `apps/*.toml` into `AppSpec`
- **`bugpot-egress`** — bridge + netns + nftables + DNS allowlist
- **`bugpot-runtime`** — OCI image pull + libcontainer lifecycle
- **`bugpot-router`** — axum reverse proxy; routes by Host subdomain
- **`bugpot-controller`** — per-app state machine, cold-start, idle reaper
- **`bugpot-admin`** — admin HTTP API (CRUD over the controller)
- **`bugpot-metrics`** — Prometheus recorder + `/metrics`, `/healthz`

`cmd/bugpot` is the operator CLI (`bugpot apps …`, `bugpot rollouts …`) —
pure-Rust so it also builds on macOS for laptop-side use.

## License

MIT — see [LICENSE](LICENSE).
