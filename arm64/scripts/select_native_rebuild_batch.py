#!/usr/bin/env python3
"""Select a staged native ARM64 rebuild matrix from exact source locks.

The selector never guesses a version or repository. A source enters the matrix
only when the lock proves an exact Git commit/tree whose declared Source and
Version match the immutable AMD64 reference. Architecture: all packages are not
native rebuild requirements; their exact original .deb is reused separately.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def safe_artifact_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def index_reference(reference: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for package in reference.get("packages", []):
        key = (package["source"], package["source_version"])
        rows.setdefault(key, []).append(package)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--batch", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lock = load_json(args.lock)
    reference = load_json(args.reference)
    plan = load_json(args.plan)

    batches = plan.get("batches", {})
    if args.batch not in batches:
        raise SystemExit(
            f"unknown batch {args.batch!r}; available: {', '.join(sorted(batches))}"
        )

    lock_rows = {
        (row["source"], row["source_version"]): row
        for row in lock.get("sources", [])
    }
    lock_by_source: dict[str, list[dict[str, Any]]] = {}
    for row in lock.get("sources", []):
        lock_by_source.setdefault(row["source"], []).append(row)
    reference_rows = index_reference(reference)
    known_success = set(plan.get("known_success", {}))

    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for source in batches[args.batch]:
        if source in known_success:
            skipped.append({"source": source, "reason": "already-recorded-success"})
            continue

        candidates = lock_by_source.get(source, [])
        resolved = [
            row
            for row in candidates
            if row.get("status") == "resolved"
            and isinstance(row.get("selected"), dict)
            and (row["selected"].get("type") in (None, "git"))
            and row["selected"].get("repository_full_name")
            and row["selected"].get("commit_sha")
            and row["selected"].get("tree_sha")
            and row["selected"].get("declared_source") == row["source"]
            and row["selected"].get("declared_version") == row["source_version"]
        ]
        if not resolved:
            skipped.append(
                {
                    "source": source,
                    "reason": "no-exact-resolved-git-lock",
                    "candidate_statuses": sorted(
                        {row.get("status", "missing") for row in candidates}
                    ),
                }
            )
            continue

        distinct = {
            (
                row["source_version"],
                row["selected"]["repository_full_name"],
                row["selected"]["commit_sha"],
                row["selected"]["tree_sha"],
            )
            for row in resolved
        }
        if len(distinct) != 1:
            skipped.append(
                {
                    "source": source,
                    "reason": "ambiguous-exact-git-lock",
                    "identities": [list(identity) for identity in sorted(distinct)],
                }
            )
            continue

        row = sorted(
            resolved,
            key=lambda item: (
                item["selected"].get("ref_kind", ""),
                item["selected"].get("ref_name", ""),
                item["selected"]["commit_sha"],
            ),
        )[0]
        key = (row["source"], row["source_version"])
        installed = reference_rows.get(key, [])
        required_native = sorted(
            {
                package["package"]
                for package in installed
                if package.get("architecture") == "amd64"
            }
        )
        reused_all = sorted(
            {
                package["package"]
                for package in installed
                if package.get("architecture") == "all"
            }
        )
        if not required_native:
            skipped.append(
                {
                    "source": source,
                    "source_version": row["source_version"],
                    "reason": "architecture-all-only-no-native-rebuild",
                    "reused_all_packages": reused_all,
                }
            )
            continue

        expected_versions = {
            package["package"]: package["version"]
            for package in installed
            if package["package"] in required_native
        }
        selected.append(
            {
                "source": source,
                "source_version": row["source_version"],
                "repository_full_name": row["selected"]["repository_full_name"],
                "commit_sha": row["selected"]["commit_sha"],
                "tree_sha": row["selected"]["tree_sha"],
                "required_native_packages": required_native,
                "required_native_packages_space": " ".join(required_native),
                "expected_binary_versions": expected_versions,
                "reused_all_packages": reused_all,
                "artifact_name": (
                    "arm64-rebuild-"
                    + safe_artifact_component(source)
                    + "-"
                    + safe_artifact_component(row["source_version"])
                ),
            }
        )

    result = {
        "schema": 1,
        "batch": args.batch,
        "policy": "exact-git-source-native-amd64-binaries-only",
        "selected_count": len(selected),
        "skipped_count": len(skipped),
        "selected": selected,
        "skipped": skipped,
        "matrix": {"include": selected},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
