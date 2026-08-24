#!/usr/bin/env python3
"""Run base failure classification and add exact source-authority identities."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import classify_native_rebuild_failures as base


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def latest_results(root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], tuple[dict[str, Any], int]] = {}
    if not root.exists():
        return {}
    for path in root.rglob("result.json"):
        try:
            row = load_json(path)
        except Exception:
            continue
        source = row.get("source")
        version = row.get("source_version")
        if not source or not version:
            continue
        try:
            run_id = int(str(row.get("actions_run_id", "0")))
        except ValueError:
            run_id = 0
        key = (source, version)
        previous = rows.get(key)
        if previous is None or run_id >= previous[1]:
            rows[key] = (row, run_id)
    return {key: row for key, (row, _) in rows.items()}


def authority_identity(result: dict[str, Any]) -> dict[str, Any]:
    build_lock = result.get("build_lock") if isinstance(result.get("build_lock"), dict) else {}
    evidence = (
        result.get("source_lock_evidence")
        if isinstance(result.get("source_lock_evidence"), dict)
        else {}
    )
    source_type = (
        result.get("source_type")
        or build_lock.get("source_type")
        or evidence.get("source_type")
        or "git"
    )
    if source_type == "dsc":
        dsc = build_lock.get("dsc") if isinstance(build_lock.get("dsc"), dict) else {}
        if not dsc:
            dsc = evidence.get("dsc") if isinstance(evidence.get("dsc"), dict) else {}
        return {
            "source_type": "dsc",
            "tree_sha": None,
            "dsc_sha256": result.get("dsc_sha256") or dsc.get("sha256"),
        }
    return {
        "source_type": "git",
        "tree_sha": result.get("tree_sha")
        or build_lock.get("tree_sha")
        or evidence.get("tree_sha"),
        "dsc_sha256": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args, _ = parser.parse_known_args()

    rc = base.main()
    classifications_path = args.output_dir / "classifications.json"
    if not classifications_path.exists():
        return rc or 2
    document = load_json(classifications_path)
    results = latest_results(args.results)
    for row in document.get("sources", []):
        result = results.get((row.get("source"), row.get("source_version")), {})
        row.update(authority_identity(result))

    summary = document.get("summary", {})
    summary.update(
        {
            "schema": 3,
            "policy": "diagnostic-failure-classification-with-exact-source-authority",
            "source_type_counts": {
                source_type: sum(
                    row.get("source_type") == source_type
                    for row in document.get("sources", [])
                )
                for source_type in sorted(
                    {
                        row.get("source_type")
                        for row in document.get("sources", [])
                        if row.get("source_type")
                    }
                )
            },
        }
    )
    document["summary"] = summary
    classifications_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
