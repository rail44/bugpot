# Code-base complexity analysis

Snapshot of a 4-axis read of the workspace at 2026-05-18 (HEAD `13277e3`
plus the `analysis-tooling` branch's scripts). Re-run any of the
commands below to get fresh data.

## Axes & how to re-run

1. **Hotspots — churn × production LOC** — `just hotspots`
2. **Static function structure** — read top hotspot files; the size of
   the largest function in each file is the single most useful signal.
   No tool needed beyond `grep -nE '^\s*(pub.*?)?(async )?fn '`.
3. **Crate / module structure** — `just depgraph` (workspace-level
   dependency edges) and `just modules <pkg>` (single-crate internal
   tree).
4. **Responsibility audit** — "1-sentence summary test": for each module
   / each crate, can you state what it does in one sentence? Modules
   that resist this are the candidates.

## Axis 1 — top 20 hotspots

Production LOC excludes the inline `mod tests` block. `churn` is the
commit count with `git log --follow`, so renames carry history forward.

| churn | prod LOC | test LOC | score | file |
|------:|---------:|---------:|------:|------|
|    21 |      510 |      121 | 10710 | crates/bugpot-router/src/lib.rs |
|    25 |      395 |       52 |  9875 | cmd/bugpot/src/main.rs |
|    24 |      329 |       92 |  7896 | crates/bugpot-runtime/src/runtime.rs |
|    18 |      424 |      169 |  7632 | crates/bugpot-admin/src/lib.rs |
|    21 |      363 |      590 |  7623 | crates/bugpot-config/src/lib.rs |
|    17 |      380 |      202 |  6460 | crates/bugpot-runtime/src/image.rs |
|    17 |      345 |       46 |  5865 | crates/bugpot-egress/src/lib.rs |
|    52 |       88 |      773 |  4576 | crates/bugpot-core/src/lib.rs |

**Outliers that look like hotspots but aren't refactor targets**:

- `bugpot-core/src/lib.rs` — churn 52 is the highest in the workspace,
  but prod LOC is only 88. The history is from when this file was the
  full `AppHost` impl; after the `ops/*` split it's a façade. The churn
  signal is a fossil of the previous shape, not current debt.
- `cmd/bugpotd/src/main.rs` — churn 27 / prod 42. Wiring binary;
  reshapes any time the workspace gains a new component.

## Axis 2 — function structure of the top 5

Largest production function per top hotspot, with a control-flow density
read (count of `if / match / else / for / while / loop / return / ? / =>`
keywords). Identifies "deep / linear" vs "deep / branchy" vs "wide" — the
right refactor differs.

| file | biggest fn | pattern |
|------|-----------:|---------|
| runtime/runtime.rs | `start_app` 172 lines, 6 branches | deep / linear — extract phases (prepare_bundle / build_spec / launch / setup_logs) |
| runtime/image.rs | `pull` 101 + `do_full_pull` 84, 12 branches | deep / branchy — leader/follower inflight coordination, candidate for a state-machine type |
| router/lib.rs | `forward` 87 + `forward_upgrade` 90 + `splice_with_idle` 71 | linear / 3-handler — async HTTP forwarding is inherently long; chase cross-handler duplication between `forward` and `forward_upgrade` |
| cmd/bugpot/main.rs | `run_apps` 84 (large match) | wide + 1 hill — split per subcommand |
| admin/lib.rs | `router` 45, handlers 20–30 | wide — no single monster; refactor by file split (handlers.rs / auth.rs / error.rs) |

## Axis 3 — crate & module structure

Workspace edges (`just depgraph`):

```
bugpotd → admin, config, core, egress, metrics, router, runtime
admin   → config, core, egress, runtime
core    → config, egress, router, runtime
egress  → config
router  → config
runtime → config
```

No cycles. `bugpot-config` is the universal leaf (fan-in 6). Two
edges look architecturally suspect:

1. **`bugpot-admin → bugpot-runtime, bugpot-egress`** — admin should
   only need core (the façade). It currently imports `Runtime` and
   `Egress` as concrete types so it can name `AppHost<Runtime, Egress>`
   in signatures. Fix: a concrete-type alias (`type BugpotAppHost = …`)
   placed in a small shared crate or in `bugpotd`.
2. **`bugpot-core → bugpot-router`** — `ops/resolver.rs` implements
   `UpstreamResolver`, a trait defined in router. The dependency
   direction is correct per the ports/adapters pattern (consumer defines
   the port, provider implements it), but core ends up compiling
   against all of router's proxy/body code just for a trait. Fix: split
   the trait + `Upstream` + `ResolveError` into a tiny port crate
   (e.g. `bugpot-router-port`).

`bugpot-core` internal structure (`just modules bugpot-core`) is
healthy: `handle` (= `AppHandle`) is the universal substrate used by 8
sibling modules, and the `ops/*` siblings don't cross-import — the
recent `AppHost` split is working.

## Axis 4 — responsibility audit

Every workspace crate and every `bugpot-core` module passes the
1-sentence summary test except one:

- **`bugpot-core/src/view.rs`** — name implies "projection from
  `AppHandle` to operator-facing `AppView`", and most of the file is
  that, but `emit_resource_metrics(handle, usage)` lives here too. That
  one's a side-effect emitter for `bugpot_app_memory_bytes` /
  `bugpot_app_cpu_microseconds_total`. Two unrelated responsibilities
  share a file. Fix: move `emit_resource_metrics` to `ops/loops.rs`
  (its only caller) or to a dedicated `metrics_emit.rs`.

## Refactor candidates, ranked

Effort estimates assume the current shape of the codebase; the priority
column folds axis 1's churn × LOC ranking into the impact axis.

| | candidate | sources | size | priority |
|---|---|---|---|---|
| A | admin: type erasure + file split | axis 2 wide + axis 3 leak | M | 1 |
| F | move `emit_resource_metrics` out of `view.rs` | axis 4 | S | 1 (bundle with A) |
| B | `runtime::start_app` phase extraction | axis 1 + axis 2 (172 lines / linear) | M | 2 |
| C | extract `bugpot-router-port` trait crate | axis 3 | M | 3 |
| D | `router::forward` / `forward_upgrade` dedup | axis 1 + axis 2 (87 + 90 lines) | M | 4 |
| E | `image::pull` state-machine type | axis 2 (101 + 84, branchy) | L | 5 |

## Why these axes (and not more tools)

- A 4-axis read this small fits inside one session and produces a
  rank-ordered list of *concrete* candidates rather than a generic
  pile of metrics.
- Each axis uses one binary at most (tokei / cargo-modules /
  cargo-depgraph) plus stdlib glue. No SaaS, no dashboard, no
  language-foreign tools.
- Re-running takes seconds and reflects whatever the current `git log`
  + crate graph look like. If `view.rs` gets split, axis 4 stops
  flagging it the next time; if `start_app` is decomposed, axis 1
  drops it down the ranking.
