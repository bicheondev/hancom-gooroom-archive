#!/usr/bin/env python3
"""Discover a bounded set of public integration-applet source snapshots.

This tool only emits candidates. No snapshot is promoted unless an independent
package, resource, function, and allocated-section comparison proves it.
"""
from __future__ import annotations

import argparse
import json
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

# Git -G uses POSIX extended regular expressions. Keep these free of PCRE-only
# constructs such as non-capturing groups.
HISTORY_REGEXES = (
    r"notify::gtk-icon-theme-name|gtk_widget_get_settings|gtk_widget_override_background_color",
    r"style[1245](\\.css)?|gtk-icon-theme-name|icon-theme",
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


def resolve_commit(repo: Path, value: str) -> str | None:
    process = run(repo, "rev-parse", "--verify", f"{value}^{{commit}}", check=False)
    return process.stdout.strip() if process.returncode == 0 else None


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
        raise RuntimeError(
            f"history search failed for {regex!r}\n{process.stdout}\n{process.stderr}"
        )
    for line in process.stdout.splitlines():
        value = line.strip()
        if value:
            yield value


def describe(repo: Path, commit: str, reasons: set[str]) -> Candidate:
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

    if 1_609_459_200 <= timestamp <= 1_735_689_600:
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
        raise RuntimeError("limit must be between the required baseline count and 24")

    reasons: dict[str, set[str]] = {}

    def remember(value: str, reason: str, include_parent: bool = False) -> None:
        commit = resolve_commit(repo, value)
        if not commit:
            return
        reasons.setdefault(commit, set()).add(reason)
        if include_parent:
            previous = parent(repo, commit)
            if previous:
                reasons.setdefault(previous, set()).add(reason + ":parent")

    for commit in REQUIRED_COMMITS:
        remember(commit, "required-baseline")

    for value in run(
        repo,
        "for-each-ref",
        "--format=%(objectname)",
        "refs/heads",
        "refs/remotes",
        "refs/tags",
    ).stdout.splitlines():
        if value.strip():
            remember(value.strip(), "branch-tip")

    for regex in HISTORY_REGEXES:
        for value in history_hits(repo, regex):
            remember(value, f"history-regex:{regex}", include_parent=True)

    rows = [describe(repo, commit, why) for commit, why in reasons.items()]

    # A Git tree is the source snapshot. Keep one strongest representative per
    # tree so tags and branch aliases cannot waste the bounded matrix.
    by_tree: dict[str, Candidate] = {}
    for row in rows:
        previous = by_tree.get(row.tree)
        rank = (row.score, row.timestamp, row.commit)
        if previous is None or rank > (previous.score, previous.timestamp, previous.commit):
            by_tree[row.tree] = row

    required_resolved = {
        commit
        for value in REQUIRED_COMMITS
        if (commit := resolve_commit(repo, value)) is not None
    }
    required_rows = [row for row in by_tree.values() if row.commit in required_resolved]
    optional_rows = [row for row in by_tree.values() if row.commit not in required_resolved]
    optional_rows.sort(key=lambda row: (-row.score, -row.timestamp, row.commit))

    selected = required_rows + optional_rows[: max(0, args.limit - len(required_rows))]
    selected.sort(key=lambda row: (-row.score, -row.timestamp, row.commit))
    if len(selected) < 3:
        raise RuntimeError(f"history discovery produced only {len(selected)} candidates")

    matrix: list[dict[str, object]] = []
    reports: list[dict[str, object]] = []
    for index, row in enumerate(selected, start=1):
        label = f"c{index:02d}-{row.commit[:10]}-s{row.score}"
        compact = {
            "label": label,
            "commit": row.commit,
            "tree": row.tree,
            "discovery_score": row.score,
        }
        matrix.append(compact)
        reports.append(
            {
                **compact,
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
            "required-releases-plus-ref-tips-and-posix-history-regex-commits-with-parents;"
            "unique-tree;bounded-score-order"
        ),
        "limit": args.limit,
        "candidate_count": len(matrix),
        "matrix": {"include": matrix},
        "candidates": reports,
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
