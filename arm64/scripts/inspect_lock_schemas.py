#!/usr/bin/env python3
"""Produce a compact schema inventory for generated ARM64 lock JSON files."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def walk_keys(value: Any, prefix: str, depth: int, counter: Counter[str]) -> None:
    if depth < 0:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            counter[path] += 1
            walk_keys(child, path, depth - 1, counter)
    elif isinstance(value, list):
        for child in value[:20]:
            walk_keys(child, f"{prefix}[]", depth - 1, counter)


def describe(path: Path, root: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    counter: Counter[str] = Counter()
    walk_keys(data, "", 4, counter)
    record: dict[str, Any] = {
        "path": str(path.relative_to(root)),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "top_type": type(data).__name__,
        "key_frequency": dict(counter.most_common(100)),
    }
    if isinstance(data, dict):
        record["top_keys"] = sorted(data)
        fields: dict[str, Any] = {}
        for key, value in data.items():
            item: dict[str, Any] = {"type": type(value).__name__}
            if isinstance(value, list):
                item["length"] = len(value)
                if value:
                    item["first_item_type"] = type(value[0]).__name__
                    if isinstance(value[0], dict):
                        item["first_item_keys"] = sorted(value[0])
            elif isinstance(value, dict):
                item["keys"] = sorted(value)
            fields[key] = item
        record["fields"] = fields
    elif isinstance(data, list):
        record["length"] = len(data)
        if data:
            record["first_item_type"] = type(data[0]).__name__
            if isinstance(data[0], dict):
                record["first_item_keys"] = sorted(data[0])
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    records = []
    errors = []
    for path in sorted(args.root.rglob("*.json")):
        try:
            records.append(describe(path, args.root))
        except Exception as error:
            errors.append({"path": str(path), "error": repr(error)})
    result = {
        "schema": 1,
        "root": str(args.root),
        "json_file_count": len(records),
        "error_count": len(errors),
        "files": records,
        "errors": errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
