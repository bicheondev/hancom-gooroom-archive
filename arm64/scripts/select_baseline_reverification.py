#!/usr/bin/env python3
"""Select legacy known-success sources for evidence-complete rebuilding."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")


def result_keys(root: Path) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    if not root.exists():
        return keys
    for path in root.rglob("result.json"):
        try:
            row = load(path)
        except Exception:
            continue
        if row.get("passed") is True and row.get("source") and row.get("source_version"):
            keys.add((row["source"], row["source_version"]))
    return keys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lock = load(args.lock)
    reference = load(args.reference)
    plan = load(args.plan)
    passed = result_keys(args.results)
    targets = set(plan.get("known_success", {}))

    packages: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in reference.get("packages", []):
        packages.setdefault((row["source"], row["source_version"]), []).append(row)
    custom_versions: dict[str, list[str]] = {}
    for row in reference.get("sources", []):
        if row.get("custom_candidate") and row["source"] in targets:
            custom_versions.setdefault(row["source"], []).append(row["source_version"])

    lock_rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in lock.get("sources", []):
        lock_rows.setdefault((row["source"], row["source_version"]), []).append(row)

    selected = []
    skipped = []
    for source in sorted(targets):
        versions = sorted(set(custom_versions.get(source, [])))
        if len(versions) != 1:
            skipped.append({
                "source": source,
                "reason": "missing-or-ambiguous-reference-source-version",
                "versions": versions,
            })
            continue
        version = versions[0]
        key = (source, version)
        if key in passed:
            skipped.append({"source": source, "source_version": version, "reason": "already-passed-new-verifier"})
            continue
        exact = [
            row
            for row in lock_rows.get(key, [])
            if row.get("status") == "resolved"
            and isinstance(row.get("selected"), dict)
            and row["selected"].get("repository_full_name")
            and row["selected"].get("commit_sha")
            and row["selected"].get("tree_sha")
            and row["selected"].get("declared_source", source) == source
            and row["selected"].get("declared_version", version) == version
            and row["selected"].get("type") in (None, "git")
        ]
        identities = {
            (
                row["selected"]["repository_full_name"],
                row["selected"]["commit_sha"],
                row["selected"]["tree_sha"],
            )
            for row in exact
        }
        if len(identities) != 1:
            skipped.append({
                "source": source,
                "source_version": version,
                "reason": "no-single-exact-git-lock",
                "identity_count": len(identities),
            })
            continue
        repository, commit_sha, tree_sha = next(iter(identities))
        source_packages = packages.get(key, [])
        native = sorted({row["package"] for row in source_packages if row["architecture"] == "amd64"})
        reused_all = sorted({row["package"] for row in source_packages if row["architecture"] == "all"})
        if not native:
            skipped.append({"source": source, "source_version": version, "reason": "no-native-binary"})
            continue
        selected.append({
            "source": source,
            "source_version": version,
            "repository_full_name": repository,
            "commit_sha": commit_sha,
            "tree_sha": tree_sha,
            "required_native_packages": native,
            "required_native_packages_space": " ".join(native),
            "reused_all_packages": reused_all,
            "artifact_name": f"arm64-rebuild-{safe(source)}-{safe(version)}",
        })

    result = {
        "schema": 1,
        "policy": "rebuild-prior-successes-under-current-verifier",
        "selected_count": len(selected),
        "skipped_count": len(skipped),
        "selected": selected,
        "skipped": skipped,
        "matrix": {"include": selected},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
