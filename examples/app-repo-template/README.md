# bugpot app repo template

Skeleton for an application repo whose container image is built
and rolled out to bugpot on every push to `main`.

## Layout

```
.
├── .github/workflows/deploy.yml   # CI: build + push + roll out
└── Dockerfile                     # your app
```

## One-time setup

Your **ops repo** (separate from this app repo) must already have
registered this app via its `apps/<name>.toml`. The post-merge run
of the ops repo's `apply` workflow surfaces a per-app deploy token
in its job summary; that token is the bridge between the two repos.

In this app repo, **Settings → Secrets and variables → Actions**:

- **Variable** `BUGPOT_ADMIN_URL` — the URL of your bugpot host's
  admin API (e.g. `http://bugpot.internal:8081`).
- **Secret** `BUGPOT_DEPLOY_TOKEN` — paste the `bp1.<hex>` token
  from the ops repo's `apply` workflow output.

Open `.github/workflows/deploy.yml` and replace `my-app` with the
app's name (= the filename stem of its TOML in the ops repo).

## On every push

The reusable workflow:

1. Builds the image from your `Dockerfile`.
2. Pushes it to `ghcr.io/<owner>/<repo>:<commit-sha>`.
3. Calls `POST /apps/<name>/rollouts` with the new tag using the
   deploy token. bugpot pulls the image and (re)starts the
   container.

The `repo` field in the ops repo's TOML for this app must equal
`ghcr.io/<owner>/<repo>` (lowercased) — that's where this workflow
pushes.

## Rollback

Trigger the workflow manually (Actions → Deploy to bugpot → Run
workflow) and enter a previous commit SHA as the `tag` input.
bugpot pulls that older tag and rolls back. The rollout history
(`GET /apps/<name>/rollouts`) is bounded at the four most recent
tags.
