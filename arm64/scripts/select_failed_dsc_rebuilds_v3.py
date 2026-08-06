#!/usr/bin/env python3
"""Select exact signed DSC sources not yet backed by a verified ARM64 result."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")


def verified_sources(index: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (row.get("source"), row.get("source_version"))
        for row in index.get("sources", [])
        if row.get("status") == "verified"
        and isinstance(row.get("selected"), dict)
        and row["selected"].get("passed") is True
    }


def latest_attempts(root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    if not root.exists():
        return rows
    for path in root.rglob("result.json"):
        try:
            row = load(path)
        except Exception:
            continue
        source = row.get("source")
        version = row.get("source_version")
        if not source or not version:
            continue
        key = (source, version)
        try:
            run_id = int(str(row.get("actions_run_id", "0")))
        except ValueError:
            run_id = 0
        current = rows.get(key)
        try:
            current_run = int(str(current.get("actions_run_id", "0"))) if current else -1
        except ValueError:
            current_run = -1
        if current is None or run_id >= current_run:
            row["evidence_path"] = str(path)
            rows[key] = row
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--effective-lock", type=Path, required=True)
    parser.add_argument("--result-index", type=Path, required=True)
    parser.add_argument("--attempt-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    effective = load(args.effective_lock)
    index = load(args.result_index) if args.result_index.exists() else {"sources": []}
    passed = verified_sources(index)
    attempts = latest_attempts(args.attempt_root)
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for row in effective.get("sources", []):
        source = row.get("source")
        version = row.get("source_version")
        selection = row.get("selected") or {}
        key = (source, version)
        if row.get("role") != "rebuild-arm64":
            continue
        if row.get("status") != "resolved" or selection.get("type") != "dsc":
            continue
        if key in passed:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "already-verified-native-arm64",
                }
            )
            continue
        components = selection.get("components") or []
        if selection.get("signature_valid") is not True or not components:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "invalid-exact-dsc-authority",
                }
            )
            continue
        if not all(component.get("verified") is True for component in components):
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "unverified-source-component",
                }
            )
            continue
        native = row.get("native_binary_packages") or []
        if not native:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "no-native-binary-package",
                }
            )
            continue
        previous = attempts.get(key)
        selected.append(
            {
                "source": source,
                "source_version": version,
                "required_native_packages": native,
                "required_native_packages_space": " ".join(native),
                "artifact_name": f"arm64-dsc-rebuild-v3-{safe(source)}-{safe(version)}",
                "dsc_sha256": selection.get("dsc_sha256"),
                "repository": selection.get("repository"),
                "previous_attempt": {
                    "actions_run_id": previous.get("actions_run_id"),
                    "build_exit_code": previous.get("build_exit_code"),
                    "passed": previous.get("passed"),
                    "evidence_path": previous.get("evidence_path"),
                }
                if previous
                else None,
            }
        )

    selected.sort(key=lambda item: (len(item["required_native_packages"]), item["source"]))
    result = {
        "schema": 1,
        "policy": "retry-only-unverified-exact-signed-dsc-sources",
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
