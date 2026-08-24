#!/usr/bin/env python3
"""Select dependency failures across exact Git or signed DSC authorities."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from source_authority_v3 import exact_build_candidates, load_json, matrix_document


def classification_identity(row: dict[str, Any]) -> tuple[str, str] | None:
    source_type = row.get("source_type")
    if source_type == "dsc":
        value = row.get("dsc_sha256")
        return ("dsc", value) if value else None
    value = row.get("tree_sha")
    return ("git", value) if value else None


def candidate_identity(row: dict[str, Any]) -> tuple[str, str]:
    return (
        row["source_type"],
        row["tree_sha"] if row["source_type"] == "git" else row["dsc_sha256"],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--classifications", type=Path, required=True)
    parser.add_argument("--dependency-repository", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=4)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lock = load_json(args.lock)
    reference = load_json(args.reference)
    classifications_document = load_json(args.classifications)
    dependency_document = load_json(args.dependency_repository)
    candidates = exact_build_candidates(lock, reference)

    dependency_summary = dependency_document.get("summary", {})
    current_packages_sha256 = dependency_summary.get("packages_sha256")
    current_release_lock_sha256 = dependency_summary.get("release_lock_sha256")
    dependency_ready = dependency_summary.get("ready") is True

    eligible = []
    skipped = []
    for classification in classifications_document.get("sources", []):
        source = classification.get("source")
        version = classification.get("source_version")
        if not source or not version:
            continue
        key = (source, version)
        candidate = candidates.get(key)
        if classification.get("passed") is True:
            skipped.append(
                {"source": source, "source_version": version, "reason": "already-passed"}
            )
            continue
        if classification.get("category") != "dependency-resolution":
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "not-a-dependency-resolution-failure",
                    "category": classification.get("category"),
                }
            )
            continue
        if candidate is None:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "no-single-exact-build-authority",
                }
            )
            continue
        if not dependency_ready or not current_packages_sha256:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "current-dependency-repository-not-ready",
                }
            )
            continue
        previous_hash = classification.get("dependency_repository_packages_sha256")
        if previous_hash == current_packages_sha256:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "same-dependency-repository-already-attempted",
                    "packages_sha256": current_packages_sha256,
                }
            )
            continue
        previous_identity = classification_identity(classification)
        if previous_identity and previous_identity != candidate_identity(candidate):
            retry_reason = "exact-source-authority-changed"
        else:
            retry_reason = "dependency-repository-changed"
        eligible.append(
            {
                **candidate,
                "retry_reason": retry_reason,
                "previous_dependency_repository_packages_sha256": previous_hash,
                "dependency_repository_packages_sha256": current_packages_sha256,
                "dependency_release_lock_sha256": current_release_lock_sha256,
                "previous_actions_run_id": classification.get("actions_run_id"),
                "classification_evidence": classification.get(
                    "classification_evidence", []
                ),
            }
        )

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
    for row in deferred:
        skipped.append(
            {
                "source": row["source"],
                "source_version": row["source_version"],
                "reason": "deferred-to-next-dependency-retry-wave",
            }
        )

    summary = {
        "schema": 3,
        "policy": "dependency-retry-on-new-repository-hash-or-new-exact-authority",
        "dependency_repository_ready": dependency_ready,
        "dependency_repository_packages_sha256": current_packages_sha256,
        "dependency_release_lock_sha256": current_release_lock_sha256,
        "limit": limit,
        "eligible_count": len(eligible),
        "selected_count": len(selected),
        "remaining_eligible_count": len(deferred),
        "skipped_count": len(skipped),
        "source_type_counts": {
            source_type: sum(row["source_type"] == source_type for row in selected)
            for source_type in sorted({row["source_type"] for row in selected})
        },
    }
    output = {
        "summary": summary,
        "selected": selected,
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
