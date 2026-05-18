# Code-base complexity analysis

Snapshot of a 4-axis read of the workspace at 2026-05-18, refreshed
after candidates A + F from the previous version's backlog were
addressed. Re-run any of the commands below to get fresh data.

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

## Axis 1 — top 10 hotspots

`prod` = AST-tagged production lines (every `#[cfg(test)]` item is
subtracted, including stand-alone test fns inside non-test impls).
`cyc` = max McCabe cyclomatic among production fns in the file.
`churn` = `git log --follow` commit count.

| churn | prod | test |  cyc | score | file |
|------:|-----:|-----:|-----:|------:|------|
|    21 |  510 |  121 |   13 | 10710 | crates/bugpot-router/src/lib.rs |
|    25 |  395 |   52 |   25 |  9875 | cmd/bugpot/src/main.rs |
|    24 |  329 |   92 |   19 |  7896 | crates/bugpot-runtime/src/runtime.rs |
|    21 |  363 |  590 |    9 |  7623 | crates/bugpot-config/src/lib.rs |
|    17 |  380 |  202 |   15 |  6460 | crates/bugpot-runtime/src/image.rs |
|    17 |  345 |   46 |    5 |  5865 | crates/bugpot-egress/src/lib.rs |
|    52 |   75 |  787 |    5 |  3900 | crates/bugpot-core/src/lib.rs |
|    18 |  120 |    0 |    3 |  2160 | crates/bugpot-admin/src/lib.rs |
|     7 |  302 |  219 |   12 |  2114 | crates/bugpot-runtime/src/spec.rs |
|     7 |  191 |  107 |    6 |  1337 | crates/bugpot-egress/src/netns.rs |

`bugpot-admin/src/lib.rs` dropped from prod 424 (#4 hotspot) to prod
120 (#8) after the file split — `auth.rs`, `error.rs`, `handlers.rs`
now share the surface area. The file-level churn count stays at 18
since the history followed `lib.rs`, but the per-file production load
is now distributed.

**Outliers that look like hotspots but aren't refactor targets**:

- `bugpot-core/src/lib.rs` — churn 52 / prod 75. Pure façade after
  the `ops/*` split; churn is a fossil of the previous shape, not
  current debt.

## Axis 2 — function structure of the top hotspots

| file | biggest fn | pattern |
|------|-----------:|---------|
| runtime/runtime.rs | `start_app` 163 lines, cyc 19 | deep — extract phases (prepare_bundle / build_spec / launch / setup_logs) |
| cmd/bugpot/main.rs | `run_apps` 81 lines, **cyc 25** | extreme branching for a CLI dispatcher; split per subcommand fn |
| router/lib.rs | `forward_upgrade` 81 / `forward` 79 / `splice_with_idle` 68 | 3-way async HTTP handlers; chase cross-handler duplication |
| image.rs | `pull` (cyc-heavy) + `do_full_pull` ~80 lines | leader/follower inflight coordination; state-machine candidate |

`run_apps` cyc 25 is the standout. McCabe's original guidance flags
anything above 10 as "complex"; 25 means the `match AppsCmd { … }`
inside has many arms each with non-trivial bodies. Splitting per
subcommand drops it to ~1 + the call.

## Axis 3 — crate & module structure

Workspace edges (`just depgraph`):

```
bugpotd → admin, config, core, egress, metrics, router, runtime
admin   → config, core
core    → config, egress, router, runtime
egress  → config
router  → config
runtime → config
```

No cycles. `bugpot-config` is the universal leaf (fan-in 6). After
the `BugpotAppHost` re-export, **admin's fan-out shrunk from 4 to 2**
— it no longer imports `bugpot-runtime` or `bugpot-egress` at the
source level. The concrete-type design (deliberate per the
`admin/src/lib.rs` doc) is preserved; the canonical spelling
`AppHost<Runtime, Egress>` now lives once, in `bugpot-core` as the
public `BugpotAppHost` type alias.

The remaining cross-layer edge worth re-examining:

- **`bugpot-core → bugpot-router`** — `ops/resolver.rs` implements
  `UpstreamResolver`, a trait defined in router. The dependency
  direction is correct per the ports/adapters pattern (consumer
  defines the port, provider implements it), but core ends up
  compiling against all of router's proxy/body code just for a trait.
  Fix: split the trait + `Upstream` + `ResolveError` into a tiny port
  crate (e.g. `bugpot-router-port`).

`bugpot-core` internal structure (`just modules bugpot-core`) is
healthy: `handle` (= `AppHandle`) is the universal substrate used by
8 sibling modules, and the `ops/*` siblings don't cross-import.

## Axis 4 — responsibility audit

Every workspace crate and every `bugpot-core` module passes the
1-sentence summary test. (The previous snapshot flagged `view.rs`
mixing projection with metrics emission — that has been resolved by
moving `emit_resource_metrics` next to its only caller in
`ops/loops.rs`.)

## Refactor candidates, ranked

Effort estimates assume the current shape of the codebase; the priority
folds axis 1's churn × LOC ranking into the impact axis.

| | candidate | sources | status |
|---|---|---|---|
| ~~A~~ | admin: file split + type erasure via `BugpotAppHost` re-export | axis 2 wide + axis 3 graph cleanup | **done** |
| ~~F~~ | move `emit_resource_metrics` out of `view.rs` | axis 4 | **done** |
| B | `runtime::start_app` phase extraction | axis 1 + axis 2 (163 lines / cyc 19) | next |
| G | `cmd/bugpot::run_apps` per-subcommand split | axis 2 (cyc **25**) | next |
| C | extract `bugpot-router-port` trait crate | axis 3 | follow-up |
| D | `router::forward` / `forward_upgrade` dedup | axis 1 + axis 2 (79 + 81) | follow-up |
| E | `image::pull` state-machine type | axis 2 (cyc 15 in `image.rs`) | later (high risk) |

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
