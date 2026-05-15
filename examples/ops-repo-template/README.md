# bugpot ops repo template

Skeleton for an "ops repo" that bugpot's `apply-config` workflow uses
as the source of truth for app configurations.

## Layout

```
.
├── .github/workflows/apply.yml   # CI: applies config on push to main
└── apps/
    └── <app-name>.toml           # one file per registered app
```

Inside each TOML, set `name = "<app-name>"` to match the filename
stem. The admin API doesn't have filename context on a POST body,
so the identity has to be in the body.

## Setup

1. Copy this directory into a new repo (private is recommended).
2. In **Settings → Secrets and variables → Actions**:
   - **Variable** `BUGPOT_ADMIN_URL` — the URL of your bugpot host's
     admin API (e.g. `http://bugpot.internal:8081`). Must be
     reachable from the runner the workflow uses.
   - **Secret** `BUGPOT_ADMIN_TOKEN` — the bearer token your bugpot
     host loaded from `BUGPOT_ADMIN_TOKEN[_FILE]`.
3. Add one TOML per app under `apps/`. Open a PR. Review. Merge.
4. The post-merge run of `apply.yml` registers each new app and
   surfaces a per-app **deploy token** in its job summary. Copy
   each one into the matching app repo as the secret
   `BUGPOT_DEPLOY_TOKEN`; that's what the app's rollout workflow
   uses to push new images.

## Removing an app

Delete the TOML, open a PR, merge. The next workflow run calls
`DELETE /apps/<name>` on bugpot.

## Editing an existing app

In-place edits to a TOML (env, scaling, egress, port, repo, etc.)
are picked up by the next apply-workflow run: it `PATCH`es every
common app with the current TOML body. bugpot replaces the spec
and restarts the container if anything actually changed (TOML
projection equality short-circuit; unchanged apps don't flap).

`name` and `subdomain` are **immutable**. Bugpot rejects PATCH
attempts to change either with a 400. The fix path for a rename
is delete-then-re-add.
