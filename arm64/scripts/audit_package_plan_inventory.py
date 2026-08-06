#!/usr/bin/env python3
"""Discover and summarize package-plan documents used by final ISO assembly."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PACKAGE_KEYS = ("package", "binary_package", "name")
VERSION_KEYS = ("version", "binary_version", "reference_version")
ARCH_KEYS = ("architecture", "arch", "target_architecture")
STATUS_KEYS = ("status", "mapping_status", "resolution", "action", "strategy")
LIST_KEYS = ("packages", "mappings", "entries", "rows", "results", "plan")


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def first(row: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    return None


def candidate_lists(value: Any, prefix: str = "$") -> list[tuple[str, list[Any]]]:
    found: list[tuple[str, list[Any]]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}"
            if key in LIST_KEYS and isinstance(item, list):
                found.append((child, item))
            if isinstance(item, (dict, list)):
                found.extend(candidate_lists(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value[:2000]):
            if isinstance(item, (dict, list)):
                found.extend(candidate_lists(item, f"{prefix}[{index}]"))
    return found


def summarize_rows(rows: list[Any]) -> dict[str, Any] | None:
    dictionaries = [row for row in rows if isinstance(row, dict)]
    if not dictionaries:
        return None
    package_rows = [row for row in dictionaries if first(row, PACKAGE_KEYS)]
    if not package_rows:
        return None
    status_counts: Counter[str] = Counter()
    architecture_counts: Counter[str] = Counter()
    version_count = 0
    url_count = 0
    sha256_count = 0
    examples = []
    for row in package_rows:
        status = first(row, STATUS_KEYS)
        architecture = first(row, ARCH_KEYS)
        version = first(row, VERSION_KEYS)
        if status is not None:
            status_counts[str(status)] += 1
        if architecture is not None:
            architecture_counts[str(architecture)] += 1
        if version is not None:
            version_count += 1
        if any("url" in key.lower() and value for key, value in row.items()):
            url_count += 1
        if any("sha256" in key.lower() and value for key, value in row.items()):
            sha256_count += 1
        if len(examples) < 5:
            examples.append(
                {
                    "package": first(row, PACKAGE_KEYS),
                    "version": version,
                    "architecture": architecture,
                    "status": status,
                    "keys": sorted(row.keys()),
                }
            )
    score = 0
    score += min(len(package_rows), 1279)
    score += version_count
    score += sum(status_counts.values()) * 2
    score += url_count * 2
    score += sha256_count * 3
    if len(package_rows) == 1279:
        score += 5000
    return {
        "row_count": len(rows),
        "dictionary_count": len(dictionaries),
        "package_row_count": len(package_rows),
        "version_row_count": version_count,
        "status_counts": dict(sorted(status_counts.items())),
        "architecture_counts": dict(sorted(architecture_counts.items())),
        "url_row_count": url_count,
        "sha256_row_count": sha256_count,
        "score": score,
        "examples": examples,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--locks-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    candidates = []
    parse_failures = []
    for path in sorted(args.locks_root.rglob("*.json")):
        if path.stat().st_size > 128 * 1024 * 1024:
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except Exception as error:
            parse_failures.append({"path": str(path), "error": repr(error)})
            continue
        lists = []
        if isinstance(document, list):
            lists.append(("$", document))
        lists.extend(candidate_lists(document))
        seen_paths = set()
        for json_path, rows in lists:
            if json_path in seen_paths:
                continue
            seen_paths.add(json_path)
            summary = summarize_rows(rows)
            if summary is None:
                continue
            candidates.append(
                {
                    "file": str(path),
                    "json_path": json_path,
                    **summary,
                }
            )
    candidates.sort(
        key=lambda item: (
            -item["score"],
            -item["package_row_count"],
            item["file"],
            item["json_path"],
        )
    )
    result = {
        "schema": "hancom-gooroom-arm64-package-plan-inventory-v1",
        "generated_at": now(),
        "status": "discovered" if candidates else "missing",
        "locks_root": str(args.locks_root),
        "candidate_count": len(candidates),
        "best_candidate": candidates[0] if candidates else None,
        "candidates": candidates,
        "parse_failures": parse_failures,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if candidates else 13


if __name__ == "__main__":
    raise SystemExit(main())
