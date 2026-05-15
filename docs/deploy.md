# Deploy guide

End-to-end walk-through for getting bugpot running and an app
deployed onto it via GitHub Actions.

## The model in one paragraph

bugpot manages a fleet of apps on one Linux host. **Config**
(name, subdomain, port, scaling, egress allowlist, …) lives in a
separate **ops repo**; **image rollouts** (which container tag to
run) live with each **app repo**'s normal CI. Two reusable
GitHub Actions workflows shipped with bugpot wire the two repos
to bugpot's admin API.

```
ops repo                 bugpot host                app repo
─────────                 ───────────                ────────
apps/alpha.toml ─PR─►  POST /apps              ◄─push─ Dockerfile + src
                       POST /apps/alpha/                  │
                            deploy-keys                   ▼
                              │                  docker build + ghcr push
                              ▼                       │
                  deploy token (per app)              ▼
                              │              POST /apps/alpha/rollouts
                              └─secret──────►  (with deploy token)
                                                      │
                                                      ▼
                                              bugpot pulls + (re)starts
```

The split keeps things separate that should be separate:

- **Admin token** (full config plane): held only by the ops repo.
- **Deploy token** (one app, image rollouts only): held by that
  app's repo. Leaks are bounded to one app and to images the
  attacker can push to its `repo`.

## Step 1 — bugpot on a Linux host

Out of scope for this guide; CLAUDE.md has the full operations
detail. The short version:

```sh
# build & install (or run from target/release/bugpot)
cargo build --release -p bugpot

# minimum env to start
export BUGPOT_APPS_DIR=/var/lib/bugpot/apps
export BUGPOT_STATE_DIR=/var/lib/bugpot
export BUGPOT_LISTEN=127.0.0.1:8080
export BUGPOT_ADMIN_LISTEN=127.0.0.1:8081
# one of these is required (file is preferred for production)
export BUGPOT_ADMIN_TOKEN_FILE=/etc/bugpot/admin-token
# same shape; rotates all deploy tokens when rotated
export BUGPOT_DEPLOY_SECRET_FILE=/etc/bugpot/deploy-secret

sudo -E ./target/release/bugpot
```

Both token files must be `chmod 600` and owned by the bugpot
user; bugpot refuses to start otherwise.

## Step 2 — reachability (operator's concern)

bugpot binds the **router** on `BUGPOT_LISTEN` (public HTTP for
app traffic, default `127.0.0.1:8080`) and the **admin API** on
`BUGPOT_ADMIN_LISTEN` (default `127.0.0.1:8081`). How either
reaches the outside world is **not bugpot's job**; pick the
pattern that fits your network.

Common patterns:

- **TLS reverse proxy** (Caddy, nginx, Traefik) in front of both
  listeners. Caddy is the lowest-friction choice if you have a
  public DNS name; it does automatic Let's Encrypt.
- **Tailscale** — `tailscale serve` mapping a tailnet URL to
  `localhost:8080` (router) and a separate Service to
  `localhost:8081` (admin). Operator-side only; bugpot ships no
  Tailscale integration.
- **Self-hosted GitHub Actions runner** on the bugpot host. CI
  reaches admin via `localhost:8081` without ever crossing the
  public internet. Useful if you want bugpot's admin API to
  stay fully private.

Whichever you pick, set the runner side appropriately:

- `BUGPOT_ADMIN_URL` (variable in both the ops and app repos) =
  the URL your runner can reach.
- If the runner is on a public network and bugpot is behind a
  TLS proxy, set `RouterConfig::trusted_proxies` (env
  `BUGPOT_TRUSTED_PROXIES`) to the proxy's IP range so
  `X-Forwarded-For` is honoured correctly.

## Step 3 — ops repo

Copy `examples/ops-repo-template/` into a new repository (private
recommended). It contains:

```
.
├── .github/workflows/apply.yml   # CI
└── apps/
    └── alpha.toml                # example app config
```

In the new ops repo, **Settings → Secrets and variables → Actions**:

- **Variable** `BUGPOT_ADMIN_URL` — your bugpot host's admin URL.
- **Secret** `BUGPOT_ADMIN_TOKEN` — the bearer token from
  `BUGPOT_ADMIN_TOKEN_FILE`.

Author one TOML per app under `apps/`. Each file requires
`name = "<file-stem>"` (the admin API has no filename context).
See [`examples/ops-repo-template/apps/alpha.toml`](../examples/ops-repo-template/apps/alpha.toml)
for the full annotated shape.

Open a PR, review, merge. The merge triggers the apply workflow:

1. POSTs every new TOML to `/apps`.
2. Mints a per-app **deploy token** for each new registration
   and prints it in the workflow's job summary table.
3. DELETEs apps whose TOML has been removed.

In-place edits to an existing TOML — env, scaling, egress, port,
repo, etc. — are picked up by the next apply-workflow run: it
PATCHes every common app with the current TOML body. bugpot
replaces the spec and restarts the container only if anything
actually changed (TOML projection equality short-circuit;
unchanged apps don't flap). `name` and `subdomain` remain
immutable — those rename via delete + re-add.

## Step 4 — app repo

Copy `examples/app-repo-template/` into the application's
repository. It contains:

```
.
├── .github/workflows/deploy.yml   # CI
├── Dockerfile
└── README.md
```

In the app repo, **Settings → Secrets and variables → Actions**:

- **Variable** `BUGPOT_ADMIN_URL` — same as the ops repo.
- **Secret** `BUGPOT_DEPLOY_TOKEN` — paste the `bp1.<hex>` token
  from the ops repo's apply workflow summary.

Edit `.github/workflows/deploy.yml` and replace the placeholder
`app_name` with this app's name (= the TOML's filename stem in
the ops repo).

The ops repo TOML's `repo = "..."` must equal
`ghcr.io/<owner>/<repo>` (lowercased) for this app — that's where
the rollout workflow pushes images.

On every push to `main`:

1. Builds the image from your Dockerfile.
2. Pushes to `ghcr.io/<owner>/<repo>:<commit-sha>`.
3. POSTs `/apps/<name>/rollouts {tag}` using the deploy token.
   bugpot pulls and (re)starts the container.

## Rollback

In the app repo, **Actions → Deploy to bugpot → Run workflow**,
and enter a previous commit SHA as the `tag` input. bugpot pulls
that older tag and rolls back. The rollout history kept on
bugpot is the four most recent tags (configurable in a future
release).

## What happens when…

| Event | Effect |
| --- | --- |
| Ops repo: TOML added | Registered + deploy token surfaced. |
| Ops repo: TOML removed | App stopped + unregistered on bugpot. |
| Ops repo: TOML edited | PATCH propagates the change; container restarts iff anything actually differs. `name` / `subdomain` edits are rejected. |
| App repo: push to main | New image tag pulled + container restarted. |
| Admin token leaks | Rotate `BUGPOT_ADMIN_TOKEN[_FILE]` + update the ops repo's secret. |
| One deploy token leaks | Rotate `BUGPOT_DEPLOY_SECRET[_FILE]` (revokes **every** deploy token), or change the offending app's `name` / `repo` in the ops repo TOML (revokes that one). |

## Security notes

- bugpot's defences (router rate limiting, body cap, slowloris
  guard, HTTP/2 stream cap, etc.) are sized against a
  public-internet client; treat any reachability layer as a
  deployment convenience, never a trust boundary.
- Per-container egress is **default-deny** via nftables. Each
  app's `egress.allow` list is the complete set of domains the
  container can reach; direct-IP egress, DoH, and DoT are
  blocked.
- Containers run with the moby (Docker) default seccomp profile,
  a non-root user where the image specifies one, and a
  capability set narrower than runc's default.
