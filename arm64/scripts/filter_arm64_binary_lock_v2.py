#!/usr/bin/env python3
"""Create a native ARM64 build view from the exact source lock.

A Debian ``dpkg-buildpackage -B`` build intentionally emits only
architecture-dependent binaries.  Architecture-independent companions are
reused from the immutable AMD64 ISO when their package records are explicitly
``Architecture: all``.  This helper will not trust the source-lock arrays by
themselves: every omitted package must also be present as ``all`` in the
reference ISO inventory.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


def list_rows(document: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    for key in ("sources", "packages", "entries"):
        value = document.get(key)
        if isinstance(value, list) and all(isinstance(row, dict) for row in value):
            return key, value
    raise SystemExit("lock does not contain a supported source-row list")


def reference_packages(document: dict[str, Any]) -> list[dict[str, Any]]:
    value = document.get("packages")
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise SystemExit("reference inventory does not contain a packages list")
    return value


def source_name(row: dict[str, Any]) -> str | None:
    for key in ("source", "source_package", "source_name"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", type=Path)
    parser.add_argument("reference", type=Path)
    parser.add_argument("source")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    original = json.loads(args.lock.read_text(encoding="utf-8"))
    document = copy.deepcopy(original)
    _, rows = list_rows(document)
    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    inventory = reference_packages(reference)

    matches = [row for row in rows if row.get("source") == args.source]
    if len(matches) != 1:
        raise SystemExit(
            f"{args.source}: expected exactly one exact source-lock row, found {len(matches)}"
        )
    row = matches[0]
    packages = row.get("binary_packages")
    architectures = row.get("binary_architectures")
    if not isinstance(packages, list) or not isinstance(architectures, list):
        raise SystemExit(f"{args.source}: binary package metadata is absent")
    if len(packages) != len(architectures):
        raise SystemExit(f"{args.source}: binary package/architecture arrays differ")

    omitted: list[dict[str, Any]] = []
    kept_packages: list[str] = []
    kept_architectures: list[str] = []
    for package, architecture in zip(packages, architectures):
        if architecture != "all":
            kept_packages.append(package)
            kept_architectures.append(architecture)
            continue

        candidates = [
            item
            for item in inventory
            if item.get("package") == package and item.get("architecture") == "all"
        ]
        if not candidates:
            raise SystemExit(
                f"{args.source}: refusing to omit {package}; the reference ISO does not record it as Architecture: all"
            )
        source_consistent = [
            item
            for item in candidates
            if source_name(item) in (None, args.source)
        ]
        if not source_consistent:
            raise SystemExit(
                f"{args.source}: refusing to omit {package}; reference source ownership conflicts"
            )
        omitted.append(
            {
                "package": package,
                "architecture": "all",
                "reference_records": source_consistent,
            }
        )

    if not kept_packages:
        raise SystemExit(
            f"{args.source}: no architecture-dependent binary remains for a native ARM64 -B build"
        )

    row["binary_packages"] = kept_packages
    row["binary_architectures"] = kept_architectures
    row["native_arm64_build_filter"] = {
        "policy": "dpkg-buildpackage--build=any",
        "reference_iso_sha256": reference.get("reference_iso", {}).get("sha256"),
        "omitted_architecture_all": omitted,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "source": args.source,
                "kept": kept_packages,
                "omitted_architecture_all": [item["package"] for item in omitted],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
