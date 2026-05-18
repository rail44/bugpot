# Code-base complexity analysis

Snapshot of a 4-axis read of the workspace at 2026-05-18 (HEAD `13277e3`
plus the `analysis-tooling` branch's tooling). Re-run any of the
commands below to get fresh data.

## Axes & how to re-run

1. **Hotspots — churn × production LOC** — `just hotspots`. Add `--fns`
   for per-file "largest production fns" detail (size + cyclomatic).
2. **Static function structure** — `just hotspots-fns` lists each top
   file's biggest fns with brace-matched body size and McCabe
   cyclomatic. No regex approximation; `syn` parses the AST.
3. **Crate / module structure** — `just depgraph` (workspace
   dependency edges) and `just modules <pkg>` (single-crate internal
   tree).
4. **Responsibility audit** — "1-sentence summary test": for each module
   / crate, state what it does in one sentence. Modules that resist
   this are the candidates.

## Axis 1 — top 20 hotspots

`prod` = AST-tagged production lines (every `#[cfg(test)]` item is
subtracted, including stand-alone test fns inside non-test impls).
`cyc` = max McCabe cyclomatic among production fns in the file.
`churn` = `git log --follow` commit count.

| churn | prod | test |  cyc | score | file |
|------:|-----:|-----:|-----:|------:|------|
|    21 |  510 |  121 |   13 | 10710 | crates/bugpot-router/src/lib.rs |
|    25 |  395 |   52 |   25 |  9875 | cmd/bugpot/src/main.rs |
|    24 |  329 |   92 |   19 |  7896 | crates/bugpot-runtime/src/runtime.rs |
|    18 |  424 |  169 |    5 |  7632 | crates/bugpot-admin/src/lib.rs |
|    21 |  363 |  590 |    9 |  7623 | crates/bugpot-config/src/lib.rs |
|    17 |  380 |  202 |   15 |  6460 | crates/bugpot-runtime/src/image.rs |
|    17 |  345 |   46 |    5 |  5865 | crates/bugpot-egress/src/lib.rs |
|    52 |   74 |  787 |    5 |  3848 | crates/bugpot-core/src/lib.rs |
|     7 |  302 |  219 |   12 |  2114 | crates/bugpot-runtime/src/spec.rs |
|     7 |  191 |  107 |    6 |  1337 | crates/bugpot-egress/src/netns.rs |

**Outliers that look like hotspots but aren't refactor targets**:

- `bugpot-core/src/lib.rs` — churn 52 is the highest in the workspace,
  but prod is only 74. The history is from when this file was the full
  `AppHost` impl; after the `ops/*` split it's a façade. The churn
  signal is a fossil of the previous shape, not current debt.
- `cmd/bugpotd/src/main.rs` (not in top 10) — churn 27 / prod 42.
  Wiring binary, reshapes any time the workspace gains a new component.

## Axis 2 — function structure of the top 5

Largest production fn per top hotspot file. Body lines come from
brace-matched AST spans (start of `fn` keyword through the closing
brace). `cyc` is the McCabe cyclomatic count for the body.

| file | biggest fn | pattern |
|------|-----------:|---------|
| runtime/runtime.rs | `start_app` 163 lines, cyc 19 | deep — extract phases (prepare_bundle / build_spec / launch / setup_logs) |
| cmd/bugpot/main.rs | `run_apps` 81 lines, **cyc 25** | extreme branching for a CLI dispatcher; split per subcommand fn |
| router/lib.rs | `forward_upgrade` 81 / `forward` 79 / `splice_with_idle` 68 | 3-way async HTTP handlers; chase cross-handler duplication |
| image.rs | `pull` (cyc-heavy) + `do_full_pull` ~80 lines | leader/follower inflight coordination; state-machine candidate |
| admin/lib.rs | `router` 40 lines, cyc 1 | no monster; refactor by file split (handlers.rs / auth.rs / error.rs) |

`run_apps` cyc 25 is the standout. McCabe's original guidance flags
anything above 10 as "complex"; 25 means the `match AppsCmd { … }`
inside has many arms each with non-trivial bodies. Splitting per
subcommand drops it to ~1 + the call.

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
   direction is correct per the ports/adapters pattern (consumer
   defines the port, provider implements it), but core ends up
   compiling against all of router's proxy/body code just for a trait.
   Fix: split the trait + `Upstream` + `ResolveError` into a tiny port
   crate (e.g. `bugpot-router-port`).

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
folds axis 1's churn × LOC ranking into the impact axis.

| | candidate | sources | size | priority |
|---|---|---|---|---|
| A | admin: type erasure + file split | axis 2 wide + axis 3 leak | M | 1 |
| F | move `emit_resource_metrics` out of `view.rs` | axis 4 | S | 1 (bundle with A) |
| B | `runtime::start_app` phase extraction | axis 1 + axis 2 (163 lines / cyc 19) | M | 2 |
| G | `cmd/bugpot::run_apps` per-subcommand split | axis 2 (cyc **25**) | S–M | 2 |
| C | extract `bugpot-router-port` trait crate | axis 3 | M | 3 |
| D | `router::forward` / `forward_upgrade` dedup | axis 1 + axis 2 (79 + 81) | M | 4 |
| E | `image::pull` state-machine type | axis 2 (cyc 15 in `image.rs`) | L | 5 |

`G` is new since the Python-glued snapshot couldn't compute cyclomatic
— it's worth a quick PR because the value is so high (cyc 25).

## Tooling notes

- The analyzer is a tiny workspace crate at `scripts/analysis/`
  (`bugpot-analyzer`, binary `hotspot`). Parses each file with `syn`,
  walks `Item::Fn` / `ImplItem::Fn` / `TraitItem::Fn`, accumulates
  cyclomatic via the `syn::visit::Visit` trait over branching expr
  kinds.
- Test-line detection: walks AST attributes for `#[cfg(test)]` on mods,
  fns, and impl/trait items. Recurses into nested mods. Doesn't expand
  `#[cfg(any(test, ...))]` — none in the current workspace, the
  recursion can be added when needed.
- Comment / blank handling: per-line trim, skip `// …` and empty lines.
  Block comments aren't special-cased because the workspace uses `//`
  doc-comments throughout.
- Renames: `git log --follow` per file, so the AppController → AppHost
  rename carries history forward.
