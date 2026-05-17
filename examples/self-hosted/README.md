# Self-hosted app templates

Ready-to-adapt `apps/*.toml` for three representative self-hosted
tools that exercise different corners of bugpot.

| TOML | What it demonstrates |
|---|---|
| [`vaultwarden.toml`](./vaultwarden.toml) | Stateful (sqlite) + non-root UID + HTTP readiness on `/alive` |
| [`linkding.toml`](./linkding.toml) | Stateful + UID=33 (www-data) + an explicit "egress doesn't cover everything" call-out |
| [`gotify.toml`](./gotify.toml) | WebSocket-keepalive workload, always-on scaling (so push doesn't blink) |

These files aren't run by bugpot directly — they're meant to be
**copied into your ops repo's `apps/` directory** (the one the
[`docs/deploy.md`](../../docs/deploy.md) workflow points at). Then
adjust:

1. Replace the `# REPLACE_ME` placeholders (admin tokens, passwords)
   with values from your CI's secret store.
2. Verify the `[[volumes]] user =` matches the UID your chosen image
   runs as — these defaults track the upstream Dockerfiles at the
   time of writing, but every fork tends to ship a different one.
3. Tighten `[scaling] idle_timeout` and `[resources]` to taste.

After deploy, the matching `bugpot apps get <name>` will surface
`state` (Running / Frozen / Stopped); freeze and resume are
visible in the `bugpot_resume_seconds` and `bugpot_freeze_seconds`
metrics if `BUGPOT_METRICS_LISTEN` is configured.

## Why not just docker-compose?

Two reasons. First, bugpot's per-app netns + DNS-driven egress
allowlist limits the blast radius if a single self-hosted tool
turns out to have a CVE — a compromised Vaultwarden cannot reach
out to `evil.example` without you having written that allow rule.
Second, the freezer makes scale-to-zero invisible: you can sit a
dozen such apps on a 2 GiB VM and pay RAM cost only for whatever's
warm at the moment.
