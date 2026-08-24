#!/usr/bin/env python3
"""Retry exact ARM64 sources whose latest attempt failed in build infrastructure.

A source is eligible only when its exact Git tree or signed DSC identity still
matches the current authority and its latest failure is clearly infrastructural.
A retry using the same current builder SHA-256 is never repeated. Sources with
a proven missing-source blocker are excluded even when an older attempt was
misclassified as infrastructure.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from source_authority_v3 import (
    exact_build_candidates,
    latest_results,
    load_json,
    matrix_document,
)


INFRASTRUCTURE_EXIT_CODES = {"69", "126", "127"}
INFRASTRUCTURE_MARKERS = (
    "base builder is missing:",
    "exact package builder is missing:",
    "required command is missing:",
    "no such file or directory",
    "command not found",
)
CONTAINER_REGISTRY_TRANSIENT_MARKERS = (
    "registry-1.docker.io",
    "500 internal server error",
    "unexpected http status: 500",
    "error response from daemon",
    "failed to resolve reference",
    "failed to do request",
)


def result_authority_identity(row: dict[str, Any]) -> tuple[str, str] | None:
    source_type = row.get("source_type")
    build_lock = (
        row.get("build_lock") if isinstance(row.get("build_lock"), dict) else {}
    )
    source_evidence = (
        row.get("source_lock_evidence")
        if isinstance(row.get("source_lock_evidence"), dict)
        else {}
    )
    source_type = (
        source_type
        or build_lock.get("source_type")
        or source_evidence.get("source_type")
    )
    if source_type in (None, "", "git"):
        tree = (
            row.get("tree_sha")
            or build_lock.get("tree_sha")
            or source_evidence.get("tree_sha")
        )
        return ("git", tree) if tree else None
    if source_type == "dsc":
        dsc = (
            build_lock.get("dsc")
            if isinstance(build_lock.get("dsc"), dict)
            else {}
        )
        if not dsc:
            dsc = (
                source_evidence.get("dsc")
                if isinstance(source_evidence.get("dsc"), dict)
                else {}
            )
        value = row.get("dsc_sha256") or dsc.get("sha256")
        return ("dsc", value) if value else None
    return None


def candidate_identity(row: dict[str, Any]) -> tuple[str, str]:
    return (
        row["source_type"],
        row["tree_sha"]
        if row["source_type"] == "git"
        else row["dsc_sha256"],
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
    text = diagnostic_text(row)

    if exit_code in INFRASTRUCTURE_EXIT_CODES:
        evidence.append(f"build-exit-code:{exit_code}")
    for marker in INFRASTRUCTURE_MARKERS:
        if marker in text:
            evidence.append(f"diagnostic:{marker}")

    transient_markers = sorted(
        {
            marker
            for marker in CONTAINER_REGISTRY_TRANSIENT_MARKERS
            if marker in text
        }
    )
    # Docker exits 125 when the client cannot create the build container. Treat
    # that code as infrastructure only when the bounded diagnostic proves an
    # external registry/daemon transport failure; an arbitrary exit 125 is not
    # enough to qualify for a retry.
    if exit_code == "125" and transient_markers:
        evidence.append("build-exit-code:125-container-start-failure")
        evidence.extend(
            f"diagnostic:{marker}" for marker in transient_markers
        )

    no_binary = not row.get("deb_artifacts")
    verification_skipped = row.get("verify_outcome") in (None, "", "skipped")
    return (
        bool(evidence) and no_binary and verification_skipped,
        sorted(set(evidence)),
    )


def load_source_recovery_blockers(
    path: Path | None,
) -> dict[tuple[str, str], dict[str, Any]]:
    if path is None:
        return {}
    if not path.exists():
        raise SystemExit(f"source-recovery blocker file not found: {path}")
    document = load_json(path)
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for row in document.get("sources", []):
        source = row.get("source")
        version = row.get("source_version")
        if not source or not version:
            raise SystemExit(
                f"malformed source-recovery blocker without identity: {row!r}"
            )
        key = (str(source), str(version))
        if key in rows and rows[key] != row:
            raise SystemExit(f"conflicting source-recovery blockers for {key}")
        rows[key] = row
    declared_count = document.get("blocker_count")
    if declared_count is not None and int(declared_count) != len(rows):
        raise SystemExit(
            "source-recovery blocker_count does not match the number of rows"
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--source-recovery-blockers", type=Path)
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
    source_recovery = load_source_recovery_blockers(
        args.source_recovery_blockers
    )
    eligible: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    excluded_source_recovery: list[dict[str, Any]] = []

    for key, previous_entry in sorted(latest.items()):
        source, version = key
        result, result_path = previous_entry
        blocker = source_recovery.get(key)
        if blocker is not None:
            record = {
                "source": source,
                "source_version": version,
                "reason": "source-recovery-required",
                "blocker_status": blocker.get("status"),
                "blocker_reason": blocker.get("reason"),
                "automatic_substitution_allowed": (
                    blocker.get("acceptance_gate", {}).get(
                        "automatic_substitution_allowed"
                    )
                ),
            }
            excluded_source_recovery.append(record)
            skipped.append(record)
            continue

        candidate = candidates.get(key)
        if result.get("passed") is True:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "already-passed",
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
        previous_identity = result_authority_identity(result)
        current_identity = candidate_identity(candidate)
        if previous_identity and previous_identity != current_identity:
            retry_reason = (
                "exact-source-authority-changed-after-infrastructure-failure"
            )
        else:
            retry_reason = "builder-infrastructure-changed"
        is_infrastructure, evidence = infrastructure_failure(result)
        if not is_infrastructure:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "latest-failure-is-not-infrastructure",
                    "build_exit_code": result.get("build_exit_code"),
                }
            )
            continue
        previous_builder_sha256 = result.get("builder_sha256")
        if (
            previous_builder_sha256 == args.builder_sha256
            and previous_identity == current_identity
        ):
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "same-builder-and-authority-already-retried",
                    "builder_sha256": args.builder_sha256,
                }
            )
            continue
        eligible.append(
            {
                **candidate,
                "retry_reason": retry_reason,
                "infrastructure_evidence": evidence,
                "previous_actions_run_id": result.get("actions_run_id"),
                "previous_builder_sha256": previous_builder_sha256 or "",
                "builder_sha256": args.builder_sha256,
                "previous_result_path": str(result_path),
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
                "reason": "deferred-to-next-infrastructure-retry-wave",
            }
        )

    summary = {
        "schema": 5,
        "policy": (
            "retry-proven-infrastructure-failures-on-new-builder-identity-once-"
            "including-bounded-container-registry-transients-and-excluding-"
            "proven-source-recovery-blockers"
        ),
        "builder_sha256": args.builder_sha256,
        "limit": limit,
        "configured_source_recovery_blocker_count": len(source_recovery),
        "excluded_source_recovery_count": len(excluded_source_recovery),
        "eligible_count": len(eligible),
        "selected_count": len(selected),
        "remaining_eligible_count": len(deferred),
        "skipped_count": len(skipped),
    }
    output = {
        "summary": summary,
        "selected": selected,
        "deferred": [
            {
                "source": row["source"],
                "source_version": row["source_version"],
            }
            for row in deferred
        ],
        "source_recovery_exclusions": excluded_source_recovery,
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
