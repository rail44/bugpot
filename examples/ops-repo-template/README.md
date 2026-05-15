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

`PATCH /apps/<name>` is not yet implemented in bugpot. Until it is,
the apply workflow does not propagate in-place TOML edits; the
fix path is delete-then-re-add (two PRs, or one PR that removes
and recreates).
