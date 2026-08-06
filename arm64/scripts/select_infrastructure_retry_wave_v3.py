#!/usr/bin/env python3
"""Retry exact ARM64 sources whose latest attempt failed in build infrastructure.

A source is eligible only when its exact Git tree or signed DSC identity still
matches the current authority and its latest failure is clearly infrastructural
(exit 69/126/127 or a bounded diagnostic marker). A retry using the same current
builder SHA-256 is never repeated.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from source_authority_v3 import exact_build_candidates, latest_results, load_json, matrix_document


INFRASTRUCTURE_EXIT_CODES = {"69", "126", "127"}
INFRASTRUCTURE_MARKERS = (
    "base builder is missing:",
    "exact package builder is missing:",
    "required command is missing:",
    "no such file or directory",
    "command not found",
)


def result_authority_identity(row: dict[str, Any]) -> tuple[str, str] | None:
    source_type = row.get("source_type")
    build_lock = row.get("build_lock") if isinstance(row.get("build_lock"), dict) else {}
    source_evidence = row.get("source_lock_evidence") if isinstance(row.get("source_lock_evidence"), dict) else {}
    source_type = source_type or build_lock.get("source_type") or source_evidence.get("source_type")
    if source_type in (None, "", "git"):
        tree = row.get("tree_sha") or build_lock.get("tree_sha") or source_evidence.get("tree_sha")
        return ("git", tree) if tree else None
    if source_type == "dsc":
        dsc = build_lock.get("dsc") if isinstance(build_lock.get("dsc"), dict) else {}
        if not dsc:
            dsc = source_evidence.get("dsc") if isinstance(source_evidence.get("dsc"), dict) else {}
        value = row.get("dsc_sha256") or dsc.get("sha256")
        return ("dsc", value) if value else None
    return None


def candidate_identity(row: dict[str, Any]) -> tuple[str, str]:
    return (
        row["source_type"],
        row["tree_sha"] if row["source_type"] == "git" else row["dsc_sha256"],
    )


def diagnostic_text(row: dict[str, Any]) -> str:
    parts: list[str] = []
    for diagnostic in row.get("diagnostics", []):
        if isinstance(diagnostic, dict):
            parts.append(str(diagnostic.get("tail", "")))
    for key in ("error", "failure_reason", "verification_errors"):
        value = row.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
        elif value:
            parts.append(str(value))
    return "\n".join(parts).lower()


def infrastructure_failure(row: dict[str, Any]) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    exit_code = str(row.get("build_exit_code", ""))
    if exit_code in INFRASTRUCTURE_EXIT_CODES:
        evidence.append(f"build-exit-code:{exit_code}")
    text = diagnostic_text(row)
    for marker in INFRASTRUCTURE_MARKERS:
        if marker in text:
            evidence.append(f"diagnostic:{marker}")
    no_binary = not row.get("deb_artifacts")
    verification_skipped = row.get("verify_outcome") in (None, "", "skipped")
    return bool(evidence) and no_binary and verification_skipped, sorted(set(evidence))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--builder-sha256", required=True)
    parser.add_argument("--limit", type=int, default=6)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if len(args.builder_sha256) != 64:
        raise SystemExit("builder SHA-256 must be 64 hexadecimal characters")
    int(args.builder_sha256, 16)

    lock = load_json(args.lock)
    reference = load_json(args.reference)
    candidates = exact_build_candidates(lock, reference)
    latest = latest_results(args.results)
    eligible: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for key, previous_entry in sorted(latest.items()):
        source, version = key
        result, result_path = previous_entry
        candidate = candidates.get(key)
        if result.get("passed") is True:
            skipped.append({"source": source, "source_version": version, "reason": "already-passed"})
            continue
        if candidate is None:
            skipped.append({"source": source, "source_version": version, "reason": "no-single-exact-build-authority"})
            continue
        previous_identity = result_authority_identity(result)
        current_identity = candidate_identity(candidate)
        if previous_identity and previous_identity != current_identity:
            retry_reason = "exact-source-authority-changed-after-infrastructure-failure"
        else:
            retry_reason = "builder-infrastructure-changed"
        is_infrastructure, evidence = infrastructure_failure(result)
        if not is_infrastructure:
            skipped.append({
                "source": source,
                "source_version": version,
                "reason": "latest-failure-is-not-infrastructure",
                "build_exit_code": result.get("build_exit_code"),
            })
            continue
        previous_builder_sha256 = result.get("builder_sha256")
        if previous_builder_sha256 == args.builder_sha256 and previous_identity == current_identity:
            skipped.append({
                "source": source,
                "source_version": version,
                "reason": "same-builder-and-authority-already-retried",
                "builder_sha256": args.builder_sha256,
            })
            continue
        eligible.append({
            **candidate,
            "retry_reason": retry_reason,
            "infrastructure_evidence": evidence,
            "previous_actions_run_id": result.get("actions_run_id"),
            "previous_builder_sha256": previous_builder_sha256 or "",
            "builder_sha256": args.builder_sha256,
            "previous_result_path": str(result_path),
        })

    eligible.sort(key=lambda row: (
        len(row["required_native_packages"]),
        row["source_type"],
        row["source"],
        row["source_version"],
    ))
    limit = max(0, args.limit)
    selected = eligible[:limit]
    deferred = eligible[limit:]
    for row in deferred:
        skipped.append({
            "source": row["source"],
            "source_version": row["source_version"],
            "reason": "deferred-to-next-infrastructure-retry-wave",
        })

    summary = {
        "schema": 3,
        "policy": "retry-infrastructure-failures-on-new-builder-identity-once",
        "builder_sha256": args.builder_sha256,
        "limit": limit,
        "eligible_count": len(eligible),
        "selected_count": len(selected),
        "remaining_eligible_count": len(deferred),
        "skipped_count": len(skipped),
    }
    output = {
        "summary": summary,
        "selected": selected,
        "deferred": [
            {"source": row["source"], "source_version": row["source_version"]}
            for row in deferred
        ],
        "skipped": skipped,
        "matrix": matrix_document(selected),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
