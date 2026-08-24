#!/usr/bin/env python3
"""Overlay independently verified reconstructed source locks onto an effective source lock."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-lock", type=Path, required=True)
    parser.add_argument("--reconstructed-locks", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    base = load(args.base_lock)
    reconstructed = load(args.reconstructed_locks)
    rows = base.get("sources")
    overlays = reconstructed.get("sources")
    if not isinstance(rows, list) or not isinstance(overlays, list):
        raise SystemExit("both lock documents must contain a sources array")

    positions: dict[tuple[str, str], int] = {}
    for index, row in enumerate(rows):
        key = (str(row.get("source", "")), str(row.get("source_version", "")))
        if not all(key):
            raise SystemExit(f"malformed base source row at index {index}")
        if key in positions:
            raise SystemExit(f"duplicate base source row: {key}")
        positions[key] = index

    applied: list[dict[str, str]] = []
    for overlay in overlays:
        source = str(overlay.get("source", ""))
        version = str(overlay.get("source_version", ""))
        key = (source, version)
        if not source or not version or key not in positions:
            raise SystemExit(f"reconstructed source is absent from base authority: {key}")
        if overlay.get("status") != "resolved" or not overlay.get("selected"):
            raise SystemExit(f"reconstructed source is not resolved: {key}")
        if not overlay.get("verification", {}).get("passed"):
            raise SystemExit(f"reconstructed source verification did not pass: {key}")
        selected = overlay["selected"]
        if selected.get("declared_source") != source or selected.get("declared_version") != version:
            raise SystemExit(f"reconstructed selected identity mismatch: {key}")
        tree = str(selected.get("tree_sha", ""))
        commit = str(selected.get("commit_sha", ""))
        repository = str(selected.get("repository_full_name", ""))
        if len(tree) != 40 or len(commit) != 40 or "/" not in repository:
            raise SystemExit(f"invalid reconstructed source identity: {key}")

        original = rows[positions[key]]
        merged = deepcopy(original)
        merged.update(
            {
                "status": "resolved",
                "provenance": overlay.get("provenance", "verified-reconstructed-source"),
                "selected": deepcopy(selected),
                "reconstruction_evidence": deepcopy(overlay.get("verification")),
            }
        )
        rows[positions[key]] = merged
        applied.append({"source": source, "source_version": version})

    result = deepcopy(base)
    result["sources"] = rows
    summary = deepcopy(result.get("summary", {}))
    summary["reconstructed_overlay_count"] = len(applied)
    summary["reconstructed_overlay_authority"] = str(args.reconstructed_locks)
    summary["effective_source_authority"] = str(args.base_lock)
    summary["reconstructed_overlays"] = applied
    result["summary"] = summary
    result["reconstructed_source_overlay"] = {
        "schema": 1,
        "authority": str(args.reconstructed_locks),
        "applied": applied,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["reconstructed_source_overlay"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
