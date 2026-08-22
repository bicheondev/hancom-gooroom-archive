#!/usr/bin/env python3
"""Discover a bounded set of public integration-applet source snapshots.

The output is deliberately only a candidate matrix. A candidate is never treated
as recovered vendor source until the independent package/function/resource
comparison workflow proves it.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REQUIRED_COMMITS = (
    "0f7897ad068da63c6529c5725afdf569152ca4c7",
    "bcca083b854e4a6c99e0bb69db4d4868e1210cdd",
    "168ff81421ea1f5bae9e715c5ccdd559e015d44c",
)

SOURCE_PATHS = (
    "src/gooroom-integration-applet.c",
    "src/popup-window.c",
    "modules/user/user-module.c",
    "modules/nimf/nimf-module.c",
)

SIGNALS: tuple[tuple[str, int], ...] = (
    ("notify::gtk-icon-theme-name", 40),
    ("gtk_widget_get_settings", 20),
    ("gtk_widget_override_background_color", 20),
    ("gtk-icon-theme-name", 16),
    ("style1.css", 8),
    ("style2.css", 8),
    ("style4", 6),
    ("style5", 6),
    ("icon-theme", 4),
    ("/tmp/.cleanmode", 3),
)

HISTORY_REGEXES = (
    r"notify::gtk-icon-theme-name|gtk_widget_get_settings|gtk_widget_override_background_color",
    r"style[1245](?:\\.css)?|gtk-icon-theme-name|icon-theme",
    r"/tmp/\\.cleanmode|cleanmode",
)


@dataclass(frozen=True)
class Candidate:
    commit: str
    tree: str
    timestamp: int
    subject: str
    score: int
    signals: tuple[str, ...]
    reasons: tuple[str, ...]


def run(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and process.returncode:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({process.returncode})\n"
            f"{process.stdout}\n{process.stderr}"
        )
    return process


def parent(repo: Path, commit: str) -> str | None:
    process = run(repo, "rev-parse", f"{commit}^", check=False)
    return process.stdout.strip() if process.returncode == 0 else None


def add_with_parent(repo: Path, output: set[str], commit: str) -> None:
    process = run(repo, "rev-parse", "--verify", f"{commit}^{{commit}}", check=False)
    if process.returncode:
        return
    resolved = process.stdout.strip()
    output.add(resolved)
    previous = parent(repo, resolved)
    if previous:
        output.add(previous)


def show_text(repo: Path, commit: str, path: str) -> str:
    process = run(repo, "show", f"{commit}:{path}", check=False)
    return process.stdout if process.returncode == 0 else ""


def history_hits(repo: Path, regex: str) -> Iterable[str]:
    process = run(
        repo,
        "log",
        "--all",
        "--format=%H",
        f"-G{regex}",
        "--",
        *SOURCE_PATHS,
        check=False,
    )
    if process.returncode not in (0, 1):
        raise RuntimeError(process.stderr)
    for line in process.stdout.splitlines():
        value = line.strip()
        if value:
            yield value


def candidate(repo: Path, commit: str, reasons: set[str]) -> Candidate:
    tree = run(repo, "rev-parse", f"{commit}^{{tree}}").stdout.strip()
    timestamp = int(run(repo, "show", "-s", "--format=%ct", commit).stdout.strip())
    subject = run(repo, "show", "-s", "--format=%s", commit).stdout.strip()
    source = "\n".join(show_text(repo, commit, path) for path in SOURCE_PATHS)
    found: list[str] = []
    score = 0
    for signal, weight in SIGNALS:
        if signal in source:
            found.append(signal)
            score += weight

    # Prefer snapshots around the Gooroom 3.x period without excluding later
    # upstreamed changes that may carry the Hancom delta.
    if 1_609_459_200 <= timestamp <= 1_735_689_600:  # 2021-01-01..2024-12-31
        score += 5
    if commit in REQUIRED_COMMITS:
        score += 100
    if "branch-tip" in reasons:
        score += 2

    return Candidate(
        commit=commit,
        tree=tree,
        timestamp=timestamp,
        subject=subject,
        score=score,
        signals=tuple(found),
        reasons=tuple(sorted(reasons)),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=14)
    args = parser.parse_args()

    repo = args.repository.resolve()
    if not (repo / "HEAD").exists() and not (repo / ".git").exists():
        raise RuntimeError(f"not a Git repository: {repo}")
    if args.limit < len(REQUIRED_COMMITS) or args.limit > 24:
        raise RuntimeError("limit must be between required baseline count and 24")

    reasons: dict[str, set[str]] = {}

    def remember(commit: str, reason: str, with_parent: bool = False) -> None:
        values: set[str] = set()
        if with_parent:
            add_with_parent(repo, values, commit)
        else:
            process = run(repo, "rev-parse", "--verify", f"{commit}^{{commit}}", check=False)
            if process.returncode == 0:
                values.add(process.stdout.strip())
        for value in values:
            reasons.setdefault(value, set()).add(reason)

    for commit in REQUIRED_COMMITS:
        remember(commit, "required-baseline")

    refs = run(
        repo,
        "for-each-ref",
        "--format=%(objectname)",
        "refs/heads",
        "refs/remotes",
        "refs/tags",
    ).stdout.splitlines()
    for value in refs:
        value = value.strip()
        if value:
            remember(value, "branch-tip")

    for regex in HISTORY_REGEXES:
        for value in history_hits(repo, regex):
            remember(value, f"history-regex:{regex}", with_parent=True)

    rows = [candidate(repo, commit, why) for commit, why in reasons.items()]

    # Git trees, not commit labels, define source snapshots. Keep the strongest
    # representative for each unique tree.
    by_tree: dict[str, Candidate] = {}
    for row in rows:
        current = by_tree.get(row.tree)
        key = (row.score, row.timestamp, row.commit)
        if current is None or key > (current.score, current.timestamp, current.commit):
            by_tree[row.tree] = row

    required_resolved = {
        run(repo, "rev-parse", "--verify", f"{commit}^{{commit}}").stdout.strip()
        for commit in REQUIRED_COMMITS
    }
    required_rows = [row for row in by_tree.values() if row.commit in required_resolved]
    optional_rows = [row for row in by_tree.values() if row.commit not in required_resolved]
    optional_rows.sort(key=lambda row: (-row.score, -row.timestamp, row.commit))

    selected = required_rows + optional_rows[: max(0, args.limit - len(required_rows))]
    selected.sort(key=lambda row: (-row.score, -row.timestamp, row.commit))

    if not selected:
        raise RuntimeError("history discovery produced no candidates")

    matrix = []
    report_rows = []
    for index, row in enumerate(selected, start=1):
        label = f"c{index:02d}-{row.commit[:10]}-s{row.score}"
        matrix.append(
            {
                "label": label,
                "commit": row.commit,
                "tree": row.tree,
                "discovery_score": row.score,
            }
        )
        report_rows.append(
            {
                **matrix[-1],
                "timestamp": row.timestamp,
                "subject": row.subject,
                "signals": list(row.signals),
                "reasons": list(row.reasons),
            }
        )

    document = {
        "schema": 1,
        "repository": "gooroom/gooroom-integration-applet",
        "selection_policy": (
            "required-releases-plus-branch-tips-and-history-regex-commits-with-parents;"
            "unique-tree;bounded-score-order"
        ),
        "limit": args.limit,
        "candidate_count": len(matrix),
        "matrix": {"include": matrix},
        "candidates": report_rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document["matrix"], separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
