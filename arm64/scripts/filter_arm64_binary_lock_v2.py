#!/usr/bin/env python3
"""Create a native ARM64 build view from the exact source lock.

A Debian ``dpkg-buildpackage -B`` build intentionally emits only
architecture-dependent binaries. Architecture-independent companions are
reused from the immutable AMD64 ISO when their package records are explicitly
``Architecture: all``.

The source lock records ``binary_packages`` as package names and may record
``binary_architectures`` as the distinct architecture set for the source,
rather than as a positional array parallel to the package names. Therefore
this helper derives each package's architecture from the immutable reference
inventory and uses the source-lock architecture list only as a consistency
summary. It will not infer, omit, or replace a package without an exact
reference record.
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


def exact_reference_records(
    inventory: list[dict[str, Any]],
    *,
    package: str,
    source: str,
    source_version: str | None,
) -> list[dict[str, Any]]:
    records = [item for item in inventory if item.get("package") == package]
    records = [item for item in records if source_name(item) == source]
    if source_version:
        records = [
            item
            for item in records
            if item.get("source_version") == source_version
        ]
    return records


def package_architecture(
    inventory: list[dict[str, Any]],
    *,
    package: str,
    source: str,
    source_version: str | None,
) -> tuple[str, list[dict[str, Any]]]:
    records = exact_reference_records(
        inventory,
        package=package,
        source=source,
        source_version=source_version,
    )
    if not records:
        version_text = f" {source_version}" if source_version else ""
        raise SystemExit(
            f"{source}: no immutable reference record for {package} from {source}{version_text}"
        )

    architectures = {
        item.get("architecture")
        for item in records
        if isinstance(item.get("architecture"), str)
        and item.get("architecture")
    }
    if len(architectures) != 1:
        raise SystemExit(
            f"{source}: {package} has ambiguous reference architectures: "
            f"{sorted(str(value) for value in architectures)}"
        )
    return next(iter(architectures)), records


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
    declared_architectures = row.get("binary_architectures")
    if not isinstance(packages, list) or not all(
        isinstance(package, str) and package for package in packages
    ):
        raise SystemExit(f"{args.source}: binary package metadata is absent")
    if not isinstance(declared_architectures, list) or not all(
        isinstance(architecture, str) and architecture
        for architecture in declared_architectures
    ):
        raise SystemExit(f"{args.source}: binary architecture metadata is absent")

    source_version = row.get("source_version")
    if source_version is not None and not isinstance(source_version, str):
        raise SystemExit(f"{args.source}: source version metadata is invalid")

    package_records: list[tuple[str, str, list[dict[str, Any]]]] = []
    for package in packages:
        architecture, records = package_architecture(
            inventory,
            package=package,
            source=args.source,
            source_version=source_version,
        )
        package_records.append((package, architecture, records))

    inferred_architecture_set = sorted(
        {architecture for _, architecture, _ in package_records}
    )
    declared_architecture_set = sorted(set(declared_architectures))
    if inferred_architecture_set != declared_architecture_set:
        raise SystemExit(
            f"{args.source}: source-lock architecture summary differs from immutable reference; "
            f"declared={declared_architecture_set}, inferred={inferred_architecture_set}"
        )

    omitted: list[dict[str, Any]] = []
    kept_packages: list[str] = []
    kept_architectures: list[str] = []
    for package, architecture, records in package_records:
        if architecture != "all":
            kept_packages.append(package)
            kept_architectures.append(architecture)
            continue

        omitted.append(
            {
                "package": package,
                "architecture": "all",
                "reference_records": records,
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
        "architecture_resolution": "exact-immutable-reference-per-package",
        "declared_source_architectures": declared_architecture_set,
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
                "kept_architectures": kept_architectures,
                "omitted_architecture_all": [item["package"] for item in omitted],
                "architecture_resolution": "exact-immutable-reference-per-package",
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
