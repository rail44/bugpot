//! Hotspot analyzer for the bugpot workspace.
//!
//! Ranks workspace `.rs` files by `churn × production LOC`, using `syn`
//! to parse each file so `#[cfg(test)]` boundaries (on mods, fns, and
//! impl items) are detected at the AST level rather than via regex.
//! Also computes per-function body span (from the AST brace token) and
//! cyclomatic complexity (`McCabe` count over the body's branching AST
//! nodes), so the "biggest fns" listing reflects true bodies instead of
//! line-delta approximations.
//!
//! Usage:
//!   cargo run -q --release -p bugpot-analyzer
//!   cargo run -q --release -p bugpot-analyzer -- --all
//!   cargo run -q --release -p bugpot-analyzer -- --fns
//!   cargo run -q --release -p bugpot-analyzer -- --csv > h.csv

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Block, ExprBinary, ExprForLoop, ExprIf, ExprLoop, ExprMatch, ExprTry,
    ExprWhile, ImplItem, ImplItemFn, Item, ItemFn, ItemImpl, ItemTrait, TraitItem, TraitItemFn,
};

/// Workspace roots to score. `experiments/` is excluded — scratch
/// playground per CLAUDE.md, not in the runtime path.
const ROOTS: &[&str] = &["crates", "cmd"];

#[derive(Debug, Clone)]
struct FnMetric {
    name: String,
    /// Lines from the `fn` keyword through the closing brace, inclusive.
    body_lines: u32,
    cyclomatic: u32,
    is_test: bool,
}

#[derive(Debug)]
struct FileAnalysis {
    path: PathBuf,
    prod_lines: u32,
    test_lines: u32,
    fns: Vec<FnMetric>,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let show_all = args.iter().any(|a| a == "--all");
    let csv = args.iter().any(|a| a == "--csv");
    let show_fns = args.iter().any(|a| a == "--fns");

    let mut analyses: Vec<FileAnalysis> = Vec::new();
    for path in list_rs_files()? {
        match analyse_file(&path) {
            Ok(a) => analyses.push(a),
            Err(e) => eprintln!("skip {}: {e:#}", path.display()),
        }
    }

    let mut rows: Vec<(FileAnalysis, u32, u32)> = analyses
        .into_iter()
        .map(|a| {
            let c = churn(&a.path).unwrap_or(0);
            let score = c.saturating_mul(a.prod_lines);
            (a, c, score)
        })
        .filter(|(_, _, s)| *s > 0)
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.2));

    let limit = if show_all {
        rows.len()
    } else {
        20.min(rows.len())
    };
    if csv {
        println!("file,churn,prod_lines,test_lines,max_cyc,score");
        for (a, c, s) in &rows[..limit] {
            let max_cyc = max_prod_cyc(&a.fns);
            println!(
                "{},{},{},{},{},{}",
                a.path.display(),
                c,
                a.prod_lines,
                a.test_lines,
                max_cyc,
                s,
            );
        }
        return Ok(());
    }

    println!(
        "{:>6} {:>5} {:>5} {:>4} {:>7}  file",
        "churn", "prod", "test", "cyc", "score",
    );
    println!(
        "{:>6} {:>5} {:>5} {:>4} {:>7}  ----",
        "-----", "----", "----", "---", "-----",
    );
    for (a, c, s) in &rows[..limit] {
        let max_cyc = max_prod_cyc(&a.fns);
        println!(
            "{:>6} {:>5} {:>5} {:>4} {:>7}  {}",
            c,
            a.prod_lines,
            a.test_lines,
            max_cyc,
            s,
            a.path.display(),
        );
    }
    if !show_all {
        println!("\n(showing top {limit} of {} files)", rows.len());
    }

    if show_fns {
        println!("\n=== top 5 hotspot files: largest production fns ===");
        for (a, _, _) in rows.iter().take(5) {
            println!("\n# {}", a.path.display());
            let mut sorted: Vec<&FnMetric> = a.fns.iter().filter(|f| !f.is_test).collect();
            sorted.sort_by_key(|f| std::cmp::Reverse(f.body_lines));
            for f in sorted.iter().take(6) {
                println!(
                    "  {:>4} lines  cyc={:>3}  {}",
                    f.body_lines, f.cyclomatic, f.name,
                );
            }
        }
    }
    Ok(())
}

fn max_prod_cyc(fns: &[FnMetric]) -> u32 {
    fns.iter()
        .filter(|f| !f.is_test)
        .map(|f| f.cyclomatic)
        .max()
        .unwrap_or(0)
}

fn list_rs_files() -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .args(["ls-files", "*.rs"])
        .output()
        .context("git ls-files")?;
    if !output.status.success() {
        anyhow::bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let s = String::from_utf8(output.stdout).context("git ls-files utf8")?;
    let mut out = Vec::new();
    for line in s.lines() {
        let p = PathBuf::from(line);
        if let Some(Component::Normal(first)) = p.components().next()
            && first.to_str().is_some_and(|c| ROOTS.contains(&c))
        {
            out.push(p);
        }
    }
    Ok(out)
}

fn churn(path: &Path) -> Result<u32> {
    let output = Command::new("git")
        .args(["log", "--follow", "--pretty=format:%H", "--"])
        .arg(path)
        .output()
        .context("git log")?;
    let s = String::from_utf8(output.stdout).context("git log utf8")?;
    Ok(u32::try_from(s.lines().filter(|l| !l.is_empty()).count()).unwrap_or(u32::MAX))
}

fn is_test_file(path: &Path) -> bool {
    if path
        .components()
        .any(|c| matches!(c, Component::Normal(s) if s == "tests"))
    {
        return true;
    }
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.ends_with("_test.rs"))
}

fn analyse_file(path: &Path) -> Result<FileAnalysis> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let total_lines = u32::try_from(text.lines().count()).unwrap_or(u32::MAX);

    // Whole-file test crates (tests/*.rs, *_test.rs) — no production
    // content, no need to parse.
    if is_test_file(path) {
        let coded = count_code_lines(&text);
        return Ok(FileAnalysis {
            path: path.to_path_buf(),
            prod_lines: 0,
            test_lines: coded,
            fns: Vec::new(),
        });
    }

    let file = syn::parse_file(&text).with_context(|| format!("parse {}", path.display()))?;

    let mut walker = Walker::default();
    walker.walk_items(&file.items, false);

    let test_line_set = expand_ranges(&walker.test_ranges, total_lines);
    let (prod_lines, test_lines) = count_split(&text, &test_line_set);

    Ok(FileAnalysis {
        path: path.to_path_buf(),
        prod_lines,
        test_lines,
        fns: walker.fns,
    })
}

#[derive(Default)]
struct Walker {
    /// `(start_line, end_line)` for every item whose attributes carry
    /// `#[cfg(test)]` directly. Nested items inherit the outer flag, so
    /// we only record the outermost span and let the line-set expansion
    /// cover children.
    test_ranges: Vec<(u32, u32)>,
    fns: Vec<FnMetric>,
}

impl Walker {
    fn walk_items(&mut self, items: &[Item], in_test: bool) {
        for item in items {
            let attrs_test = item_has_cfg_test(item);
            let now_test = in_test || attrs_test;
            if attrs_test && !in_test {
                let s = item.span();
                self.test_ranges
                    .push((line(s.start().line), line(s.end().line)));
            }
            match item {
                Item::Fn(f) => self.push_fn(f, now_test),
                Item::Impl(i) => self.walk_impl(i, now_test),
                Item::Mod(m) => {
                    if let Some((_, items)) = &m.content {
                        self.walk_items(items, now_test);
                    }
                }
                Item::Trait(t) => self.walk_trait(t, now_test),
                _ => {}
            }
        }
    }

    fn walk_impl(&mut self, i: &ItemImpl, in_test: bool) {
        for ii in &i.items {
            if let ImplItem::Fn(m) = ii {
                let attrs_test = has_cfg_test(&m.attrs);
                let now_test = in_test || attrs_test;
                if attrs_test && !in_test {
                    let s = m.span();
                    self.test_ranges
                        .push((line(s.start().line), line(s.end().line)));
                }
                self.push_impl_fn(m, now_test);
            }
        }
    }

    fn walk_trait(&mut self, t: &ItemTrait, in_test: bool) {
        for ti in &t.items {
            if let TraitItem::Fn(m) = ti
                && m.default.is_some()
            {
                let attrs_test = has_cfg_test(&m.attrs);
                let now_test = in_test || attrs_test;
                if attrs_test && !in_test {
                    let s = m.span();
                    self.test_ranges
                        .push((line(s.start().line), line(s.end().line)));
                }
                self.push_trait_fn(m, now_test);
            }
        }
    }

    fn push_fn(&mut self, f: &ItemFn, is_test: bool) {
        let start = line(f.sig.fn_token.span().start().line);
        let end = line(f.block.brace_token.span.close().end().line);
        let body_lines = end.saturating_sub(start).saturating_add(1);
        let cyclomatic = compute_cyclomatic(&f.block);
        self.fns.push(FnMetric {
            name: f.sig.ident.to_string(),
            body_lines,
            cyclomatic,
            is_test,
        });
    }

    fn push_impl_fn(&mut self, m: &ImplItemFn, is_test: bool) {
        let start = line(m.sig.fn_token.span().start().line);
        let end = line(m.block.brace_token.span.close().end().line);
        let body_lines = end.saturating_sub(start).saturating_add(1);
        let cyclomatic = compute_cyclomatic(&m.block);
        self.fns.push(FnMetric {
            name: m.sig.ident.to_string(),
            body_lines,
            cyclomatic,
            is_test,
        });
    }

    fn push_trait_fn(&mut self, m: &TraitItemFn, is_test: bool) {
        let Some(block) = &m.default else { return };
        let start = line(m.sig.fn_token.span().start().line);
        let end = line(block.brace_token.span.close().end().line);
        let body_lines = end.saturating_sub(start).saturating_add(1);
        let cyclomatic = compute_cyclomatic(block);
        self.fns.push(FnMetric {
            name: m.sig.ident.to_string(),
            body_lines,
            cyclomatic,
            is_test,
        });
    }
}

#[allow(clippy::cast_possible_truncation)]
const fn line(n: usize) -> u32 {
    n as u32
}

fn item_has_cfg_test(item: &Item) -> bool {
    let attrs: &[Attribute] = match item {
        Item::Fn(f) => &f.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Mod(m) => &m.attrs,
        Item::Trait(t) => &t.attrs,
        Item::Const(c) => &c.attrs,
        Item::Static(s) => &s.attrs,
        Item::Struct(s) => &s.attrs,
        Item::Enum(e) => &e.attrs,
        Item::Use(u) => &u.attrs,
        _ => return false,
    };
    has_cfg_test(attrs)
}

/// Recognises `#[cfg(test)]`. Doesn't try to expand
/// `#[cfg(any(test, ...))]` — those would be a false negative, but they
/// don't appear in this workspace today and adding the recursion would
/// double the size of this function for no current benefit.
fn has_cfg_test(attrs: &[Attribute]) -> bool {
    for a in attrs {
        if !a.path().is_ident("cfg") {
            continue;
        }
        let mut found = false;
        let _ = a.parse_nested_meta(|m| {
            if m.path.is_ident("test") {
                found = true;
            }
            Ok(())
        });
        if found {
            return true;
        }
    }
    false
}

fn expand_ranges(ranges: &[(u32, u32)], total: u32) -> HashSet<u32> {
    let mut s = HashSet::new();
    for &(start, end) in ranges {
        for l in start..=end.min(total) {
            s.insert(l);
        }
    }
    s
}

/// Walk raw text once, classifying each line. Block comments aren't
/// special-cased — the workspace uses `//` doc-comments throughout, so
/// the simpler classifier is accurate in practice.
fn count_split(text: &str, test_lines: &HashSet<u32>) -> (u32, u32) {
    let mut prod_count = 0u32;
    let mut test_count = 0u32;
    for (idx, line_str) in text.lines().enumerate() {
        let trimmed = line_str.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if test_lines.contains(&lineno) {
            test_count += 1;
        } else {
            prod_count += 1;
        }
    }
    (prod_count, test_count)
}

fn count_code_lines(text: &str) -> u32 {
    let mut n = 0u32;
    for line_str in text.lines() {
        let trimmed = line_str.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        n += 1;
    }
    n
}

fn compute_cyclomatic(block: &Block) -> u32 {
    let mut c = Cyc { count: 1 };
    c.visit_block(block);
    c.count
}

/// `McCabe` cyclomatic complexity: start at 1, +1 per branching node.
/// `if` and `else if` each count once (the AST nests them, so visiting
/// `ExprIf` covers both). `match` counts the number of arms beyond the
/// first. `?`, `&&`, `||` each count once.
struct Cyc {
    count: u32,
}

impl<'ast> Visit<'ast> for Cyc {
    fn visit_expr_if(&mut self, e: &'ast ExprIf) {
        self.count += 1;
        visit::visit_expr_if(self, e);
    }
    fn visit_expr_match(&mut self, m: &'ast ExprMatch) {
        self.count = self
            .count
            .saturating_add(u32::try_from(m.arms.len().saturating_sub(1)).unwrap_or(0));
        visit::visit_expr_match(self, m);
    }
    fn visit_expr_while(&mut self, e: &'ast ExprWhile) {
        self.count += 1;
        visit::visit_expr_while(self, e);
    }
    fn visit_expr_for_loop(&mut self, e: &'ast ExprForLoop) {
        self.count += 1;
        visit::visit_expr_for_loop(self, e);
    }
    fn visit_expr_loop(&mut self, e: &'ast ExprLoop) {
        self.count += 1;
        visit::visit_expr_loop(self, e);
    }
    fn visit_expr_try(&mut self, e: &'ast ExprTry) {
        self.count += 1;
        visit::visit_expr_try(self, e);
    }
    fn visit_expr_binary(&mut self, b: &'ast ExprBinary) {
        if matches!(b.op, BinOp::And(_) | BinOp::Or(_)) {
            self.count += 1;
        }
        visit::visit_expr_binary(self, b);
    }
}
