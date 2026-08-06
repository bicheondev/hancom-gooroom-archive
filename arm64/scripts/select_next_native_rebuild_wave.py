#!/usr/bin/env python3
"""Select the next unattempted exact-source native ARM64 rebuild wave."""

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


def latest_results(root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    if not root.exists():
        return result
    for path in root.rglob("result.json"):
        try:
            row = load_json(path)
        except Exception:
            continue
        key = (row.get("source"), row.get("source_version"))
        if not all(key):
            continue
        try:
            run_id = int(str(row.get("actions_run_id", "0")))
        except ValueError:
            run_id = 0
        previous = result.get(key)
        try:
            previous_id = int(str(previous.get("actions_run_id", "0"))) if previous else -1
        except ValueError:
            previous_id = -1
        if previous is None or run_id >= previous_id:
            row["evidence_path"] = str(path)
            result[key] = row
    return result


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
    attempts = latest_results(args.results)

    known_success = set(plan.get("known_success", {}))
    reserved = {
        source
        for batch in plan.get("batches", {}).values()
        for source in batch
    }

    packages_by_source: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for package in reference.get("packages", []):
        key = (package["source"], package["source_version"])
        packages_by_source.setdefault(key, []).append(package)

    custom_keys = {
        (source["source"], source["source_version"])
        for source in reference.get("sources", [])
        if source.get("custom_candidate")
    }

    lock_rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in lock.get("sources", []):
        key = (row["source"], row["source_version"])
        lock_rows.setdefault(key, []).append(row)

    selected_candidates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for key in sorted(custom_keys):
        source, source_version = key
        packages = packages_by_source.get(key, [])
        native = sorted(
            {package["package"] for package in packages if package["architecture"] == "amd64"}
        )
        reused_all = sorted(
            {package["package"] for package in packages if package["architecture"] == "all"}
        )
        if not native:
            skipped.append({
                "source": source,
                "source_version": source_version,
                "reason": "architecture-all-only",
            })
            continue
        if source in known_success:
            skipped.append({
                "source": source,
                "source_version": source_version,
                "reason": "known-success-or-compile-record",
            })
            continue
        if source in reserved:
            skipped.append({
                "source": source,
                "source_version": source_version,
                "reason": "reserved-for-curated-batch",
            })
            continue
        if key in attempts:
            skipped.append({
                "source": source,
                "source_version": source_version,
                "reason": "already-attempted",
                "passed": bool(attempts[key].get("passed")),
                "actions_run_id": attempts[key].get("actions_run_id"),
            })
            continue

        candidates = [
            row
            for row in lock_rows.get(key, [])
            if row.get("status") == "resolved"
            and isinstance(row.get("selected"), dict)
            and row["selected"].get("repository_full_name")
            and row["selected"].get("commit_sha")
            and row["selected"].get("tree_sha")
            and row["selected"].get("declared_source", source) == source
            and row["selected"].get("declared_version", source_version)
            == source_version
            and row["selected"].get("type") in (None, "git")
        ]
        identities = {
            (
                row["selected"]["repository_full_name"],
                row["selected"]["commit_sha"],
                row["selected"]["tree_sha"],
            )
            for row in candidates
        }
        if len(identities) != 1:
            skipped.append({
                "source": source,
                "source_version": source_version,
                "reason": (
                    "no-exact-resolved-git-lock"
                    if not identities
                    else "ambiguous-exact-git-lock"
                ),
                "identity_count": len(identities),
            })
            continue
        repository, commit_sha, tree_sha = next(iter(identities))
        selected_candidates.append({
            "source": source,
            "source_version": source_version,
            "repository_full_name": repository,
            "commit_sha": commit_sha,
            "tree_sha": tree_sha,
            "required_native_packages": native,
            "required_native_packages_space": " ".join(native),
            "reused_all_packages": reused_all,
            "artifact_name": (
                f"arm64-rebuild-{safe_component(source)}-"
                f"{safe_component(source_version)}"
            ),
            "priority": [len(native), source],
        })

    selected_candidates.sort(key=lambda row: (row["priority"][0], row["priority"][1]))
    selected = selected_candidates[: max(0, args.limit)]
    deferred = selected_candidates[max(0, args.limit) :]
    for row in deferred:
        skipped.append({
            "source": row["source"],
            "source_version": row["source_version"],
            "reason": "deferred-to-next-wave",
        })

    for row in selected:
        row.pop("priority", None)
    summary = {
        "schema": 1,
        "policy": "attempt-each-unreserved-exact-source-once",
        "limit": args.limit,
        "selected_count": len(selected),
        "remaining_unattempted_count": len(deferred),
        "skipped_count": len(skipped),
        "attempted_result_count": len(attempts),
    }
    output = {
        "summary": summary,
        "selected": selected,
        "skipped": skipped,
        "matrix": {"include": selected},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
