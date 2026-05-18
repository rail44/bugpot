# Code-base complexity analysis

Snapshot of a 4-axis read of the workspace at 2026-05-18, refreshed
after the full A/B/D/F/G/E refactor pass (PR #130–#136 plus the
#135 retraction of A1). All identified candidates are resolved.
Re-run any of the commands below to get fresh data.

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
5. **AST similarity (post-refactor dedup pass)** — `just similar`
   (default 0.85 threshold) / `just similar-strict` (0.92 + body
   prints). Catches Type-2 / Type-3 clones whose AST shapes match
   after identifier normalisation. Run after a refactor that
   splits functions to catch helpers whose pieces ended up similar
   enough to share. PR #138 / #139 used this to surface the
   `http_*` and `persist_*` / `parse_env_*` clusters; the residual
   high-similarity pairs left after those are intentional
   (symmetric trait methods, state-machine queries, mock helpers).
   See `cargo install similarity-rs`.

## Axis 1 — top 10 hotspots

`prod` = AST-tagged production lines (every `#[cfg(test)]` item is
subtracted, including stand-alone test fns inside non-test impls).
`cyc` = max McCabe cyclomatic among production fns in the file.
`churn` = `git log --follow` commit count.

| churn | prod | test |  cyc | score | file |
|------:|-----:|-----:|-----:|------:|------|
|    22 |  505 |  121 |   13 | 11110 | crates/bugpot-router/src/lib.rs |
|    26 |  424 |   52 |    7 | 11024 | cmd/bugpot/src/main.rs |
|    25 |  364 |   92 |    9 |  9100 | crates/bugpot-runtime/src/runtime.rs |
|    21 |  363 |  590 |    9 |  7623 | crates/bugpot-config/src/lib.rs |
|    18 |  395 |  202 |   15 |  7110 | crates/bugpot-runtime/src/image.rs |
|    17 |  345 |   46 |    5 |  5865 | crates/bugpot-egress/src/lib.rs |
|    54 |   74 |  787 |    5 |  3996 | crates/bugpot-core/src/lib.rs |
|    20 |  122 |    0 |    3 |  2440 | crates/bugpot-admin/src/lib.rs |
|     7 |  302 |  219 |   12 |  2114 | crates/bugpot-runtime/src/spec.rs |
|     7 |  191 |  107 |    6 |  1337 | crates/bugpot-egress/src/netns.rs |

`bugpot-admin/src/lib.rs` dropped from prod 424 (#4 hotspot) to prod
122 (#8) after the file split — `auth.rs`, `error.rs`, `handlers.rs`
now share the surface area. The file-level churn count stays close
to the original since the history followed `lib.rs`, but the per-file
production load is now distributed.

The remaining cyc-15 in `image.rs` is `extract_to_image_dir` (tar
unpack with branches for media type / file kind / compression).
That's essential complexity in tar parsing, not orchestration debt.

**Outliers that look like hotspots but aren't refactor targets**:

- `bugpot-core/src/lib.rs` — churn 52 / prod 75. Pure façade after
  the `ops/*` split; churn is a fossil of the previous shape, not
  current debt.

## Axis 2 — function structure of the top hotspots

Current state (production fns, post-refactor):

| file | biggest production fn | cyc |
|------|----------------------:|----:|
| runtime/runtime.rs | `start_app` 50 lines | 9 |
| cmd/bugpot/main.rs | `cmd_apps_deploy_key` 26 lines | 3 |
| router/lib.rs | `forward_upgrade` 67 lines / `splice_with_idle` 68 lines | 13 |
| image.rs | `do_full_pull` 61 / `coordinated_pull` 54 / `pull` 19 | 7 |

`splice_with_idle`'s cyc 13 in `router/lib.rs` is the highest
remaining among orchestration fns. The cyc-15 `extract_to_image_dir`
in `image.rs` is tar-unpack essential complexity, not orchestration
debt. Neither warrants further refactor at this scale.

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

No cycles. `bugpot-config` is the universal leaf (fan-in 6).

**On `bugpot-admin → bugpot-runtime, bugpot-egress`** — admin imports
the concrete `Runtime` and `Egress` types so it can name
`AppHost<Runtime, Egress>` (aliased locally as `Controller`). An
earlier draft of this report listed the edge as a "leak" and the
follow-up PR introduced a `BugpotAppHost` re-export in `bugpot-core`
to drop those two deps from admin's `Cargo.toml`. That was an
over-correction: the concrete spelling is a deliberate design choice
(admin's L172–180 doc justifies it — `<R, E>` generic propagation
through every handler signature was rejected for noise, and `dyn` for
runtime-polymorphism we don't need was rejected as wrong-shaped
abstraction). The re-export moved the canonical alias into a crate
that didn't need it (`bugpot-core` doesn't reference its own
`BugpotAppHost`), inverting responsibility. Reverted in a follow-up.

**On `bugpot-core → bugpot-router`** — `ops/resolver.rs` implements
`UpstreamResolver`, a trait defined in router. An earlier draft of
this report listed this as the next graph-cleanup candidate. On
re-examination it isn't: this *is* the correct dependency direction
under the ports & adapters pattern — the consumer (router) defines
the port (the trait), and the provider (core's `AppHost`) depends on
the port-defining crate to implement it. The compile-time cost of
core picking up router's axum/hyper/tower in its transitive deps is
real but marginal at our scale (one production adapter + one test
fixture). Extracting the trait into its own port crate is the right
move when there are many external implementers or a no_std consumer
(cf. `tracing-core` / `axum-core` / `futures-core`); we have neither.
Left as-is.

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
| ~~A2~~ | admin: file split into auth.rs / error.rs / handlers.rs | axis 2 wide | **done** (PR #130) |
| ~~A1~~ | admin: `BugpotAppHost` re-export from `bugpot-core` | (axis 3 misreading) | **reverted** (PR #135) — concrete-type design was deliberate per L172–180 doc; re-export moved the alias to a crate that didn't need it |
| ~~F~~ | move `emit_resource_metrics` out of `view.rs` | axis 4 | **done** (PR #130) |
| ~~B~~ | `runtime::start_app` phase extraction | axis 1 + axis 2 (163 lines / cyc 19) | **done** (PR #131) — 163 lines / cyc 19 → 50 / 9 |
| ~~G~~ | `cmd/bugpot::run_apps` per-subcommand split | axis 2 (cyc **25**) | **done** (PR #132) — cyc 25 → 7 |
| ~~D~~ | `router::forward` / `forward_upgrade` dedup | axis 1 + axis 2 (79 + 81) | **done** (PR #133) — extracted `send_upstream` |
| ~~C~~ | extract `bugpot-router-port` trait crate | axis 3 | **dropped** — direction was already correct per port/adapter; extraction not justified at our adapter count |
| ~~E~~ | `image::pull` phase extraction (scaled down from "state machine type") | axis 2 | **done** (PR #136) — pull 101/12 → 19/5; tar-unpack cyc-15 is essential complexity, out of scope |

All candidates resolved. The remaining file-level cyc maxes
(`router::splice_with_idle` at 13, `image::extract_to_image_dir` at
15) are essential complexity in async I/O splicing and tar parsing
respectively; neither is orchestration debt.

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
