#!/usr/bin/env python3
"""Select the next never-successful exact Git-or-DSC ARM64 rebuild wave."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from source_authority_v3 import (
    all_reserved_names,
    exact_build_candidates,
    latest_results,
    load_json,
    matrix_document,
)


def result_authority_identity(row: dict[str, Any]) -> tuple[str, str] | None:
    source_type = row.get("source_type")
    build_lock = row.get("build_lock") if isinstance(row.get("build_lock"), dict) else {}
    source_evidence = (
        row.get("source_lock_evidence")
        if isinstance(row.get("source_lock_evidence"), dict)
        else {}
    )
    source_type = source_type or build_lock.get("source_type") or source_evidence.get(
        "source_type"
    )
    if source_type in (None, "", "git"):
        tree = row.get("tree_sha") or build_lock.get("tree_sha") or source_evidence.get(
            "tree_sha"
        )
        return ("git", tree) if tree else None
    if source_type == "dsc":
        dsc = build_lock.get("dsc") if isinstance(build_lock.get("dsc"), dict) else {}
        if not dsc:
            dsc = (
                source_evidence.get("dsc")
                if isinstance(source_evidence.get("dsc"), dict)
                else {}
            )
        sha256 = dsc.get("sha256")
        return ("dsc", sha256) if sha256 else None
    return None


def candidate_identity(row: dict[str, Any]) -> tuple[str, str]:
    return (
        row["source_type"],
        row["tree_sha"] if row["source_type"] == "git" else row["dsc_sha256"],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=6)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lock = load_json(args.lock)
    reference = load_json(args.reference)
    plan = load_json(args.plan)
    candidates = exact_build_candidates(lock, reference)
    latest = latest_results(args.results)
    reserved = all_reserved_names(plan)

    eligible = []
    skipped = []
    for key, candidate in sorted(candidates.items()):
        source, version = key
        if source in reserved:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "reserved-for-baseline-or-curated-batch",
                }
            )
            continue
        previous = latest.get(key)
        if previous:
            result, _ = previous
            if (
                result.get("passed") is True
                and result_authority_identity(result) == candidate_identity(candidate)
            ):
                skipped.append(
                    {
                        "source": source,
                        "source_version": version,
                        "reason": "exact-authority-already-passed",
                    }
                )
                continue
            if result_authority_identity(result) == candidate_identity(candidate):
                skipped.append(
                    {
                        "source": source,
                        "source_version": version,
                        "reason": "same-exact-authority-already-attempted",
                        "passed": bool(result.get("passed")),
                    }
                )
                continue
        eligible.append(candidate)

    eligible.sort(
        key=lambda row: (
            len(row["required_native_packages"]),
            row["source_type"],
            row["source"],
            row["source_version"],
        )
    )
    limit = max(0, args.limit)
    selected = eligible[:limit]
    deferred = eligible[limit:]
    summary = {
        "schema": 3,
        "policy": "one-attempt-per-exact-authority-with-separate-retry-controller",
        "limit": limit,
        "exact_build_candidate_count": len(candidates),
        "reserved_source_count": len(reserved),
        "eligible_count": len(eligible),
        "selected_count": len(selected),
        "remaining_unattempted_count": len(deferred),
        "skipped_count": len(skipped),
        "source_type_counts": {
            source_type: sum(row["source_type"] == source_type for row in selected)
            for source_type in sorted({row["source_type"] for row in selected})
        },
    }
    output = {
        "summary": summary,
        "selected": selected,
        "deferred": [
            {
                "source": row["source"],
                "source_version": row["source_version"],
                "source_type": row["source_type"],
            }
            for row in deferred
        ],
        "skipped": skipped,
        "matrix": matrix_document(selected),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
