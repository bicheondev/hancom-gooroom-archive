#!/usr/bin/env python3
"""Enrich rebuild failure classification with exact source-authority identity."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import classify_native_rebuild_failures as base


def authority_identity(result: dict[str, Any]) -> dict[str, Any]:
    build_lock = result.get("build_lock") if isinstance(result.get("build_lock"), dict) else {}
    evidence = (
        result.get("source_lock_evidence")
        if isinstance(result.get("source_lock_evidence"), dict)
        else {}
    )
    source_type = result.get("source_type") or build_lock.get("source_type") or evidence.get(
        "source_type"
    )
    if source_type in (None, "", "git"):
        return {
            "source_type": "git",
            "tree_sha": result.get("tree_sha")
            or build_lock.get("tree_sha")
            or evidence.get("tree_sha"),
            "dsc_sha256": None,
        }
    if source_type == "dsc":
        dsc = build_lock.get("dsc") if isinstance(build_lock.get("dsc"), dict) else {}
        if not dsc:
            dsc = evidence.get("dsc") if isinstance(evidence.get("dsc"), dict) else {}
        return {
            "source_type": "dsc",
            "tree_sha": None,
            "dsc_sha256": dsc.get("sha256"),
        }
    return {"source_type": source_type, "tree_sha": None, "dsc_sha256": None}


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args, _ = parser.parse_known_args()

    rc = base.main()
    classifications_path = args.output_dir / "classifications.json"
    summary_path = args.output_dir / "summary.json"
    if not classifications_path.exists():
        return rc or 2

    document = json.loads(classifications_path.read_text(encoding="utf-8"))
    latest = base.latest_results(args.results)
    latest_by_key = {
        key: row for key, (row, _) in latest.items()
    }
    for row in document.get("sources", []):
        key = (row.get("source"), row.get("source_version"))
        result = latest_by_key.get(key, {})
        row.update(authority_identity(result))

    summary = document.get("summary", {})
    summary.update(
        {
            "schema": 2,
            "policy": "diagnostic-failure-classification-with-source-authority-identity",
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
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
