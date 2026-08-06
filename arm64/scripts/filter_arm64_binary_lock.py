#!/usr/bin/env python3
"""Filter Architecture: all binaries from a native ARM64 -B build expectation.

The reference lock records every binary emitted by a Debian source package,
including Architecture: all compatibility/transitional packages. A native
``dpkg-buildpackage -B`` invocation intentionally emits only architecture-
dependent binaries. This helper creates a temporary verification view that
keeps the exact source/version/commit lock unchanged while omitting only the
parallel binary entries whose reference architecture is ``all``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def rows_container(document: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    for key in ("sources", "packages", "entries"):
        value = document.get(key)
        if isinstance(value, list) and all(isinstance(row, dict) for row in value):
            return key, value
    raise SystemExit("lock does not contain a supported source-row list")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", type=Path)
    parser.add_argument("source")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    document = json.loads(args.lock.read_text(encoding="utf-8"))
    _, rows = rows_container(document)
    matched = 0
    omitted: list[dict[str, str]] = []

    for row in rows:
        if row.get("source") != args.source:
            continue
        matched += 1
        packages = row.get("binary_packages")
        architectures = row.get("binary_architectures")
        if not isinstance(packages, list) or not isinstance(architectures, list):
            raise SystemExit(f"{args.source}: binary package metadata is absent")
        if len(packages) != len(architectures):
            raise SystemExit(f"{args.source}: binary package/architecture arrays differ")

        keep = [index for index, arch in enumerate(architectures) if arch != "all"]
        for index, arch in enumerate(architectures):
            if arch == "all":
                omitted.append({"package": str(packages[index]), "architecture": "all"})
        if not keep:
            raise SystemExit(
                f"{args.source}: no architecture-dependent binary remains for an ARM64 -B build"
            )
        row["binary_packages"] = [packages[index] for index in keep]
        row["binary_architectures"] = [architectures[index] for index in keep]
        row["native_arm64_build_filter"] = {
            "policy": "dpkg-buildpackage--build=any",
            "omitted_architecture_all": omitted,
        }

    if matched != 1:
        raise SystemExit(f"{args.source}: expected exactly one source row, found {matched}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"source": args.source, "omitted": omitted}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
