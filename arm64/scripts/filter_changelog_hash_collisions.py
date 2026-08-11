#!/usr/bin/env python3
"""Remove unrelated global short-SHA collisions from changelog archaeology.

An eight-character Git prefix is not globally unique.  The primary auditor
retains GitHub's global commit-search output for evidence, but only objects in
an identified candidate repository, one of its public forks, or an object with
an independently exact Debian changelog head may affect source status.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-results", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--raw-output", type=Path, required=True)
    args = parser.parse_args()

    rows = json.loads(args.target_results.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise SystemExit("target results are not an array")
    args.raw_output.write_text(args.target_results.read_text(encoding="utf-8"), encoding="utf-8")

    total_collisions = 0
    for row in rows:
        if not isinstance(row, dict):
            raise SystemExit("malformed target result")
        relevant_repositories = {
            str(value)
            for key in ("candidate_repositories", "fork_repositories")
            for value in row.get(key, [])
            if isinstance(value, str)
        }
        original = [value for value in row.get("resolutions", []) if isinstance(value, dict)]
        related: list[dict[str, Any]] = []
        collisions: list[dict[str, Any]] = []
        for resolution in original:
            repository = str(resolution.get("repository", ""))
            if repository in relevant_repositories or resolution.get("exact_changelog_head") is True:
                related.append(resolution)
            else:
                collisions.append(resolution)

        final_change_id = str(row.get("final_change_id", ""))
        final_resolutions = [
            value for value in related if value.get("change_id") == final_change_id
        ]
        exact_final = [
            value for value in final_resolutions if value.get("exact_changelog_head") is True
        ]
        if exact_final:
            status = "exact-source-candidate-found"
        elif related:
            status = "candidate-network-change-object-found-without-exact-changelog-head"
        else:
            status = "unresolved"

        total_collisions += len(collisions)
        row.update(
            {
                "status": status,
                "resolution_count": len(related),
                "resolved_change_ids": sorted(
                    {str(value.get("change_id")) for value in related if value.get("change_id")}
                ),
                "final_change_resolution_count": len(final_resolutions),
                "exact_final_candidate_count": len(exact_final),
                "resolutions": related,
                "source_lock_candidate": exact_final[0] if len(exact_final) == 1 else None,
                "unrelated_global_hash_collision_count": len(collisions),
                "unrelated_global_hash_collisions": collisions,
                "promotion_allowed": False,
            }
        )

    exact = [row for row in rows if row.get("status") == "exact-source-candidate-found"]
    object_only = [
        row
        for row in rows
        if row.get("status")
        == "candidate-network-change-object-found-without-exact-changelog-head"
    ]
    unresolved = [row for row in rows if row.get("status") == "unresolved"]
    change_ids = {
        str(value)
        for row in rows
        for value in row.get("change_ids", [])
        if isinstance(value, str)
    }
    summary = {
        "schema": 2,
        "policy": (
            "candidate-repository-or-public-fork-short-object-resolution-plus-"
            "exact-debian-changelog-head-required"
        ),
        "target_count": len(rows),
        "change_id_count": len(change_ids),
        "exact_source_candidate_count": len(exact),
        "change_object_only_target_count": len(object_only),
        "unresolved_target_count": len(unresolved),
        "unrelated_global_hash_collision_count": total_collisions,
        "exact_source_candidates": [
            {
                "source": row.get("source"),
                "source_version": row.get("source_version"),
                "candidate": row.get("source_lock_candidate"),
            }
            for row in exact
        ],
        "change_object_only_sources": [row.get("source") for row in object_only],
        "unresolved_sources": [row.get("source") for row in unresolved],
        "promotion_allowed": False,
    }
    write_json(args.target_results, rows)
    write_json(args.summary, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
