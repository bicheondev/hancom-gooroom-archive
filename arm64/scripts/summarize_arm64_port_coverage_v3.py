#!/usr/bin/env python3
"""Coverage v3: extend v2 with reconstructed source-archive identities."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ARCHIVE_SELECTED_TYPE = "reconstructed-source-archive"
ARCHIVE_RESULT_TYPE = "verified-reconstructed-source-archive"


def load_v2():
    path = Path(__file__).with_name("summarize_arm64_port_coverage_v2.py")
    spec = importlib.util.spec_from_file_location("arm64_coverage_v2", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"unable to load coverage v2 implementation: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def nested(document: dict[str, Any]) -> dict[str, Any]:
    value = document.get("summary")
    return value if isinstance(value, dict) else document


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    known, _ = parser.parse_known_args()

    module = load_v2()
    original_normalize = module.normalize_source_type
    original_authority = module.authority_identity
    original_result = module.result_identity

    def normalize_source_type(value: Any) -> str:
        source_type = str(value or "git")
        if source_type in {ARCHIVE_SELECTED_TYPE, ARCHIVE_RESULT_TYPE}:
            return ARCHIVE_SELECTED_TYPE
        return original_normalize(source_type)

    def authority_identity(source_row: dict[str, Any]):
        selected = source_row.get("selected")
        if isinstance(selected, dict) and normalize_source_type(selected.get("type")) == ARCHIVE_SELECTED_TYPE:
            value = selected.get("source_tree_manifest_sha256") or selected.get("source_archive_sha256")
            return (ARCHIVE_SELECTED_TYPE, value) if value else None
        return original_authority(source_row)

    def result_identity(result: dict[str, Any]):
        build_lock = result.get("build_lock") if isinstance(result.get("build_lock"), dict) else {}
        evidence = result.get("source_lock_evidence") if isinstance(result.get("source_lock_evidence"), dict) else {}
        source_type = normalize_source_type(
            result.get("source_type")
            or build_lock.get("source_type")
            or evidence.get("source_type")
            or "git"
        )
        if source_type == ARCHIVE_SELECTED_TYPE:
            selected = evidence.get("selected") if isinstance(evidence.get("selected"), dict) else {}
            value = (
                result.get("source_authority_sha256")
                or build_lock.get("source_authority_sha256")
                or selected.get("source_tree_manifest_sha256")
                or selected.get("source_archive_sha256")
            )
            return (ARCHIVE_SELECTED_TYPE, value) if value else None
        return original_result(result)

    module.normalize_source_type = normalize_source_type
    module.authority_identity = authority_identity
    module.result_identity = result_identity
    rc = int(module.main())

    source_lock = json.loads(known.source_lock.read_text(encoding="utf-8"))
    source_rows = source_lock.get("sources", [])
    archive_count = sum(
        isinstance(row, dict)
        and isinstance(row.get("selected"), dict)
        and row["selected"].get("type") == ARCHIVE_SELECTED_TYPE
        for row in source_rows
    )

    coverage_path = known.output_dir / "coverage.json"
    summary_path = known.output_dir / "summary.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    summary = nested(coverage)
    summary.update(
        {
            "schema": max(int(summary.get("schema", 1)), 3),
            "policy": "current-exact-authority-including-reconstructed-source-archive-and-phase-gate-coverage",
            "reconstructed_source_archive_source_count": archive_count,
        }
    )
    coverage["summary"] = summary
    coverage_path.write_text(json.dumps(coverage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "coverage_v3": True,
        "reconstructed_source_archive_source_count": archive_count,
        "source_blocker_count": summary.get("source_blocker_count"),
        "native_rebuild_passed_count": summary.get("native_rebuild_passed_count"),
    }, ensure_ascii=False, indent=2))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
