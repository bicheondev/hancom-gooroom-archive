#!/usr/bin/env python3
"""Merge newly resolved exact Git rows into the effective source lock.

Only exact Git selections whose changelog-declared source/version matches the
AMD64 reference row are eligible.  Existing resolved rows are immutable unless
the candidate has the same Git tree.  A different tree for the same exact
source version is treated as a hard conflict, never as an automatic upgrade.
APT source payloads are deliberately left for the separate APT-source builder.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


def rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    value = document.get("sources")
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise SystemExit("source lock has no sources list")
    return value


def key(row: dict[str, Any]) -> tuple[str, str]:
    return str(row.get("source", "")), str(row.get("source_version", ""))


def validate_git_selection(row: dict[str, Any]) -> dict[str, Any] | None:
    if row.get("status") != "resolved":
        return None
    selected = row.get("selected")
    if not isinstance(selected, dict):
        return None
    if selected.get("type", "git") != "git":
        return None
    required = ("repository_full_name", "commit_sha", "tree_sha")
    if any(not selected.get(field) for field in required):
        raise SystemExit(f"{key(row)}: resolved Git selection lacks immutable identity")
    declared_source = selected.get("declared_source")
    declared_version = selected.get("declared_version")
    if declared_source != row.get("source") or declared_version != row.get("source_version"):
        raise SystemExit(
            f"{key(row)}: selected changelog identity does not match the target row"
        )
    return selected


def recompute_summary(document: dict[str, Any]) -> dict[str, Any]:
    source_rows = rows(document)
    resolved = [row for row in source_rows if row.get("status") == "resolved" and row.get("selected")]
    unresolved = [row for row in source_rows if row not in resolved]
    rebuild = [row for row in source_rows if "rebuild" in str(row.get("role", "")).lower()]
    rebuild_unresolved = [row for row in rebuild if row not in resolved]
    summary = dict(document.get("summary") or {})
    summary.update(
        source_count=len(source_rows),
        resolved_count=len(resolved),
        unresolved_count=len(unresolved),
        rebuild_source_count=len(rebuild),
        rebuild_unresolved_count=len(rebuild_unresolved),
        resolved_sources=sorted({row["source"] for row in resolved}),
        unresolved_sources=sorted({row["source"] for row in unresolved}),
        rebuild_unresolved_sources=sorted(
            {row["source"] for row in rebuild_unresolved}
        ),
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--effective", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    effective = json.loads(args.effective.read_text(encoding="utf-8"))
    candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
    output = copy.deepcopy(effective)
    target_rows = rows(output)
    target_by_key = {key(row): row for row in target_rows}
    if len(target_by_key) != len(target_rows):
        raise SystemExit("effective source lock contains duplicate source/version rows")

    merged: list[dict[str, Any]] = []
    same_tree: list[dict[str, Any]] = []
    skipped_non_git: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []

    for candidate_row in rows(candidate):
        selected = validate_git_selection(candidate_row)
        if selected is None:
            if candidate_row.get("status") == "resolved" and candidate_row.get("selected"):
                skipped_non_git.append(
                    {
                        "source": candidate_row.get("source"),
                        "source_version": candidate_row.get("source_version"),
                        "selected_type": candidate_row.get("selected", {}).get("type"),
                    }
                )
            continue
        row_key = key(candidate_row)
        target = target_by_key.get(row_key)
        if target is None:
            raise SystemExit(f"candidate row is absent from the effective lock: {row_key}")
        existing = target.get("selected") if target.get("status") == "resolved" else None
        if isinstance(existing, dict):
            existing_tree = existing.get("tree_sha")
            candidate_tree = selected.get("tree_sha")
            if existing_tree != candidate_tree:
                conflicts.append(
                    {
                        "source": row_key[0],
                        "source_version": row_key[1],
                        "existing": existing,
                        "candidate": selected,
                    }
                )
                continue
            alternatives = list(target.get("equivalent_exact_git_selections") or [])
            identity = (selected["repository_full_name"], selected["commit_sha"])
            existing_identities = {
                (item.get("repository_full_name"), item.get("commit_sha"))
                for item in alternatives
                if isinstance(item, dict)
            }
            existing_identities.add(
                (existing.get("repository_full_name"), existing.get("commit_sha"))
            )
            if identity not in existing_identities:
                alternatives.append(selected)
                target["equivalent_exact_git_selections"] = alternatives
            same_tree.append(
                {
                    "source": row_key[0],
                    "source_version": row_key[1],
                    "tree_sha": candidate_tree,
                }
            )
            continue

        preserved = {
            field: target.get(field)
            for field in (
                "source",
                "source_version",
                "binary_packages",
                "binary_architectures",
                "role",
            )
        }
        target.update(
            status="resolved",
            reason=candidate_row.get("reason"),
            selected=selected,
            exact_matches=candidate_row.get("exact_matches", []),
            resolution_policy=candidate_row.get("resolution_policy"),
        )
        target.update(preserved)
        merged.append(
            {
                "source": row_key[0],
                "source_version": row_key[1],
                "repository_full_name": selected["repository_full_name"],
                "commit_sha": selected["commit_sha"],
                "tree_sha": selected["tree_sha"],
            }
        )

    report = {
        "status": "conflict" if conflicts else "merged",
        "effective_input": str(args.effective),
        "candidate_input": str(args.candidate),
        "merged_count": len(merged),
        "same_tree_count": len(same_tree),
        "skipped_non_git_count": len(skipped_non_git),
        "conflict_count": len(conflicts),
        "merged": merged,
        "same_tree": same_tree,
        "skipped_non_git": skipped_non_git,
        "conflicts": conflicts,
    }
    output["summary"] = recompute_summary(output)
    output["effective_git_merge"] = report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 3 if conflicts else 0


if __name__ == "__main__":
    raise SystemExit(main())
