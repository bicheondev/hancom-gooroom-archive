#!/usr/bin/env python3
"""Select dependency-resolution failures for one hash-gated retry wave."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")


def exact_git_identity(rows: list[dict[str, Any]], source: str, version: str) -> tuple[str, str, str] | None:
    identities = {
        (
            row["selected"]["repository_full_name"],
            row["selected"]["commit_sha"],
            row["selected"]["tree_sha"],
        )
        for row in rows
        if row.get("status") == "resolved"
        and isinstance(row.get("selected"), dict)
        and row["selected"].get("type") in (None, "git")
        and row["selected"].get("repository_full_name")
        and row["selected"].get("commit_sha")
        and row["selected"].get("tree_sha")
        and row["selected"].get("declared_source", source) == source
        and row["selected"].get("declared_version", version) == version
    }
    return next(iter(identities)) if len(identities) == 1 else None


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
    dependency_summary = dependency_document.get("summary", {})
    current_packages_sha256 = dependency_summary.get("packages_sha256")
    current_release_lock_sha256 = dependency_summary.get("release_lock_sha256")
    dependency_ready = dependency_summary.get("ready") is True

    lock_rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in lock.get("sources", []):
        lock_rows.setdefault((row["source"], row["source_version"]), []).append(row)

    packages_by_source: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for package in reference.get("packages", []):
        packages_by_source.setdefault(
            (package["source"], package["source_version"]), []
        ).append(package)

    candidates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for classification in classifications_document.get("sources", []):
        source = classification.get("source")
        version = classification.get("source_version")
        key = (source, version)
        if not source or not version:
            continue
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
        previous_packages_sha256 = classification.get(
            "dependency_repository_packages_sha256"
        )
        if not dependency_ready or not current_packages_sha256:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "current-dependency-repository-not-ready",
                }
            )
            continue
        if previous_packages_sha256 == current_packages_sha256:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "same-dependency-repository-already-attempted",
                    "packages_sha256": current_packages_sha256,
                }
            )
            continue

        identity = exact_git_identity(lock_rows.get(key, []), source, version)
        if identity is None:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "no-single-exact-git-lock",
                }
            )
            continue
        repository, commit_sha, tree_sha = identity
        source_packages = packages_by_source.get(key, [])
        native_packages = sorted(
            {
                package["package"]
                for package in source_packages
                if package.get("architecture") == "amd64"
            }
        )
        reused_all = sorted(
            {
                package["package"]
                for package in source_packages
                if package.get("architecture") == "all"
            }
        )
        if not native_packages:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "no-native-binary-package",
                }
            )
            continue

        candidates.append(
            {
                "source": source,
                "source_version": version,
                "repository_full_name": repository,
                "commit_sha": commit_sha,
                "tree_sha": tree_sha,
                "required_native_packages": native_packages,
                "required_native_packages_space": " ".join(native_packages),
                "reused_all_packages": reused_all,
                "artifact_name": (
                    f"arm64-rebuild-{safe_component(source)}-"
                    f"{safe_component(version)}"
                ),
                "retry_reason": "dependency-repository-changed",
                "previous_dependency_repository_packages_sha256": previous_packages_sha256,
                "dependency_repository_packages_sha256": current_packages_sha256,
                "dependency_release_lock_sha256": current_release_lock_sha256,
                "previous_actions_run_id": classification.get("actions_run_id"),
                "classification_evidence": classification.get(
                    "classification_evidence", []
                ),
            }
        )

    candidates.sort(
        key=lambda row: (
            len(row["required_native_packages"]),
            row["source"],
            row["source_version"],
        )
    )
    selected = candidates[: max(0, args.limit)]
    deferred = candidates[max(0, args.limit) :]
    for row in deferred:
        skipped.append(
            {
                "source": row["source"],
                "source_version": row["source_version"],
                "reason": "deferred-to-next-dependency-retry-wave",
            }
        )

    summary = {
        "schema": 1,
        "policy": "dependency-failure-retry-only-on-new-packages-index-hash",
        "dependency_repository_ready": dependency_ready,
        "dependency_repository_packages_sha256": current_packages_sha256,
        "dependency_release_lock_sha256": current_release_lock_sha256,
        "limit": args.limit,
        "eligible_count": len(candidates),
        "selected_count": len(selected),
        "remaining_eligible_count": len(deferred),
        "skipped_count": len(skipped),
    }
    output = {
        "summary": summary,
        "selected": selected,
        "skipped": skipped,
        "matrix": {"include": selected},
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
