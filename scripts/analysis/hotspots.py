#!/usr/bin/env python3
"""Hotspot analysis: churn × LOC ranking.

For each workspace .rs file, multiplies its commit count (with rename
following) by its production LOC. Highlights files that are both large
*and* frequently touched — i.e. where the next refactor pays back most.

Production LOC = non-blank, non-comment lines that appear *before* the
file's inline `#[cfg(test)] mod tests { ... }` block (if any).
Whole-file test crates (`*/tests/*.rs`, `*_test.rs`) are excluded by
default; pass --include-tests to score them as their own column.

Churn uses `git log --follow` so a rename (e.g. bugpot-controller →
bugpot-core) carries its history forward.

Python 3 stdlib only.

Usage:
  scripts/analysis/hotspots.py              # top 20 production hotspots
  scripts/analysis/hotspots.py --all
  scripts/analysis/hotspots.py --include-tests
  scripts/analysis/hotspots.py --csv > h.csv
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

# Workspace roots that count. experiments/ is excluded — scratch
# playground, not in the runtime path (per CLAUDE.md).
ROOTS = ("crates", "cmd")

# `mod tests { ... }` preceded by `#[cfg(test)]`. Matches the
# conventional Rust placement at the bottom of a file.
TEST_MOD_RE = re.compile(r"^#\[cfg\(test\)\]\s*\nmod\s+tests\b", re.MULTILINE)


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def list_rs_files() -> list[Path]:
    raw = run(["git", "ls-files", "*.rs"]).splitlines()
    return [Path(p) for p in raw if p and Path(p).parts[0] in ROOTS]


def churn(path: Path) -> int:
    out = run(["git", "log", "--follow", "--pretty=format:%H", "--", str(path)])
    return sum(1 for line in out.splitlines() if line)


def count_code_lines(text: str) -> int:
    """Count non-blank, non-comment lines. Recognises //, ///, //!, and
    /* */ block comments. Inline trailing comments still count the
    line (we only filter pure-comment / pure-blank lines)."""
    count = 0
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if in_block:
            if "*/" in line:
                in_block = False
                # If anything follows `*/` on the same line, count it.
                tail = line.split("*/", 1)[1].strip()
                if tail and not tail.startswith("//"):
                    count += 1
            continue
        if line.startswith("/*"):
            if "*/" not in line:
                in_block = True
            continue
        if line.startswith("//"):
            continue
        count += 1
    return count


def split_prod_test(text: str) -> tuple[str, str]:
    m = TEST_MOD_RE.search(text)
    if not m:
        return text, ""
    return text[: m.start()], text[m.start():]


def is_test_file(path: Path) -> bool:
    parts = path.parts
    return "tests" in parts or path.name.endswith("_test.rs")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--all", action="store_true", help="print full ranking, not just top 20")
    ap.add_argument(
        "--include-tests",
        action="store_true",
        help="rank test files / test mods too (off by default)",
    )
    ap.add_argument("--csv", action="store_true", help="emit CSV instead of a human table")
    args = ap.parse_args()

    rows = []
    for p in list_rs_files():
        text = p.read_text()
        if is_test_file(p):
            prod_loc, test_loc = 0, count_code_lines(text)
        else:
            prod_text, test_text = split_prod_test(text)
            prod_loc = count_code_lines(prod_text)
            test_loc = count_code_lines(test_text)
        c = churn(p)
        score_loc = (prod_loc + test_loc) if args.include_tests else prod_loc
        rows.append((str(p), c, prod_loc, test_loc, c * score_loc))

    rows = [r for r in rows if r[4] > 0]
    rows.sort(key=lambda r: r[4], reverse=True)

    limit = len(rows) if args.all else 20
    if args.csv:
        print("file,churn,prod_loc,test_loc,score")
        for path, c, p_loc, t_loc, s in rows[:limit]:
            print(f"{path},{c},{p_loc},{t_loc},{s}")
    else:
        print(f"{'churn':>6} {'prod':>5} {'test':>5} {'score':>7}  file")
        print(f"{'-----':>6} {'----':>5} {'----':>5} {'-----':>7}  ----")
        for path, c, p_loc, t_loc, s in rows[:limit]:
            print(f"{c:>6} {p_loc:>5} {t_loc:>5} {s:>7}  {path}")
        if not args.all:
            print(f"\n(showing top {limit} of {len(rows)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
