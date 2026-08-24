#!/usr/bin/env python3
"""Create the native-ARM64 ``dpkg-buildpackage -B`` verification view.

The effective source lock stores ``binary_architectures`` as a source-level
set, not as an array parallel to ``binary_packages``.  Resolve every package's
reference architecture from the immutable AMD64 ISO package lock, then omit
only packages whose exact reference row is ``Architecture: all``.

All source/version/repository/commit/tree fields remain unchanged.  Missing,
duplicate, or contradictory reference rows fail closed.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

DEFAULT_REFERENCE = (
    Path(__file__).resolve().parents[1]
    / "locks"
    / "reference"
    / "amd64-reference.json"
)


def rows_container(document: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    for key in ("sources", "packages", "entries"):
        value = document.get(key)
        if isinstance(value, list) and all(isinstance(row, dict) for row in value):
            return key, value
    raise SystemExit("lock does not contain a supported source-row list")


def require_string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise SystemExit(f"{label}: expected a list of non-empty strings")
    if not allow_empty and not value:
        raise SystemExit(f"{label}: list is empty")
    return list(value)


def unique_in_order(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def resolve_reference_architectures(
    reference: dict[str, Any],
    source: str,
    source_version: str,
    packages: list[str],
) -> list[dict[str, str]]:
    rows = reference.get("packages")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise SystemExit("AMD64 reference lock does not contain a valid packages list")

    resolved: list[dict[str, str]] = []
    for package in packages:
        matches = [
            row
            for row in rows
            if row.get("source") == source
            and row.get("source_version") == source_version
            and row.get("package") == package
        ]
        if len(matches) != 1:
            raise SystemExit(
                f"{source}: expected exactly one AMD64 reference row for "
                f"{package} at source version {source_version}, found {len(matches)}"
            )
        architecture = matches[0].get("architecture")
        if not isinstance(architecture, str) or not architecture:
            raise SystemExit(
                f"{source}: reference architecture is absent for {package}"
            )
        resolved.append({"package": package, "architecture": architecture})
    return resolved


def filter_document(
    document: dict[str, Any],
    source: str,
    reference: dict[str, Any],
    reference_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    filtered = copy.deepcopy(document)
    _, rows = rows_container(filtered)
    matched = 0
    summary: dict[str, Any] | None = None

    for row in rows:
        if row.get("source") != source:
            continue
        matched += 1

        source_version = row.get("source_version")
        if not isinstance(source_version, str) or not source_version:
            raise SystemExit(f"{source}: source_version is absent")

        packages = require_string_list(
            row.get("binary_packages"), f"{source}: binary_packages"
        )
        if len(packages) != len(set(packages)):
            raise SystemExit(f"{source}: binary_packages contains duplicates")

        input_architectures = require_string_list(
            row.get("binary_architectures"),
            f"{source}: binary_architectures",
        )
        if len(input_architectures) != len(set(input_architectures)):
            raise SystemExit(
                f"{source}: binary_architectures must be a source-level set"
            )

        resolved = resolve_reference_architectures(
            reference, source, source_version, packages
        )
        reference_architectures = unique_in_order(
            item["architecture"] for item in resolved
        )
        if set(input_architectures) != set(reference_architectures):
            raise SystemExit(
                f"{source}: source-lock architecture summary "
                f"{input_architectures!r} contradicts AMD64 reference rows "
                f"{reference_architectures!r}"
            )

        kept = [item for item in resolved if item["architecture"] != "all"]
        omitted = [item for item in resolved if item["architecture"] == "all"]
        if not kept:
            raise SystemExit(
                f"{source}: no architecture-dependent binary remains for an ARM64 -B build"
            )

        kept_architecture_set = {item["architecture"] for item in kept}
        filtered_architectures = [
            architecture
            for architecture in input_architectures
            if architecture in kept_architecture_set
        ]
        if set(filtered_architectures) != kept_architecture_set:
            raise SystemExit(
                f"{source}: could not preserve the architecture-dependent summary"
            )

        row["binary_packages"] = [item["package"] for item in kept]
        row["binary_architectures"] = filtered_architectures
        row["native_arm64_build_filter"] = {
            "policy": "dpkg-buildpackage--build=any",
            "architecture_resolution": "amd64-reference-lock",
            "reference_lock_sha256": reference_sha256,
            "input_binary_architectures": input_architectures,
            "kept_architecture_dependent": kept,
            "omitted_architecture_all": omitted,
        }
        summary = {
            "source": source,
            "source_version": source_version,
            "kept_architecture_dependent": kept,
            "omitted_architecture_all": omitted,
            "reference_lock_sha256": reference_sha256,
        }

    if matched != 1:
        raise SystemExit(f"{source}: expected exactly one source row, found {matched}")
    if summary is None:
        raise SystemExit(f"{source}: filter summary was not created")
    return filtered, summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", type=Path)
    parser.add_argument("source")
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--reference",
        type=Path,
        default=Path(
            os.environ.get("HANCOM_GOOROOM_REFERENCE_JSON", str(DEFAULT_REFERENCE))
        ),
        help="immutable AMD64 ISO package lock",
    )
    args = parser.parse_args()

    lock_bytes = args.lock.read_bytes()
    reference_bytes = args.reference.read_bytes()
    document = json.loads(lock_bytes.decode("utf-8"))
    reference = json.loads(reference_bytes.decode("utf-8"))
    reference_sha256 = hashlib.sha256(reference_bytes).hexdigest()

    filtered, summary = filter_document(
        document,
        args.source,
        reference,
        reference_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(filtered, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
