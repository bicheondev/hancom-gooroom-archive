#!/usr/bin/env python3
"""Turn an offline dpkg status database into reproducible package/source locks."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable

SOURCE_RE = re.compile(r"^\s*([^\s(]+)(?:\s*\(([^)]+)\))?\s*$")
CUSTOM_RE = re.compile(r"(?:^|[-_.])(hancom|gooroom|hancomgrm|grm)(?:$|[-_.])", re.I)


def parse_control_paragraphs(text: str) -> list[dict[str, str]]:
    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key: str | None = None

    for raw_line in text.splitlines():
        if not raw_line.strip():
            if current:
                paragraphs.append(current)
                current = {}
                last_key = None
            continue

        if raw_line[:1].isspace():
            if last_key is not None:
                current[last_key] += "\n" + raw_line[1:]
            continue

        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        last_key = key
        current[key] = value.lstrip()

    if current:
        paragraphs.append(current)
    return paragraphs


def source_identity(package: dict[str, str]) -> tuple[str, str]:
    binary_name = package["Package"]
    binary_version = package["Version"]
    source = package.get("Source", "")
    if not source:
        return binary_name, binary_version

    match = SOURCE_RE.match(source)
    if not match:
        raise ValueError(f"Unsupported Source field for {binary_name!r}: {source!r}")
    return match.group(1), match.group(2) or binary_version


def write_tsv(path: Path, rows: Iterable[dict[str, object]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("status", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    packages = []
    for para in parse_control_paragraphs(args.status.read_text(encoding="utf-8", errors="replace")):
        if para.get("Status") != "install ok installed":
            continue
        for required in ("Package", "Version", "Architecture"):
            if required not in para:
                raise ValueError(f"Installed package paragraph lacks {required}: {para!r}")

        source_name, source_version = source_identity(para)
        custom_hint = bool(CUSTOM_RE.search(para["Package"]) or CUSTOM_RE.search(source_name))
        packages.append(
            {
                "package": para["Package"],
                "version": para["Version"],
                "architecture": para["Architecture"],
                "source": source_name,
                "source_version": source_version,
                "multi_arch": para.get("Multi-Arch", ""),
                "essential": para.get("Essential", "no"),
                "priority": para.get("Priority", ""),
                "custom_hint": "yes" if custom_hint else "no",
            }
        )

    packages.sort(key=lambda item: (str(item["package"]), str(item["architecture"])))
    sources: dict[tuple[str, str], dict[str, object]] = {}
    versions_by_source: dict[str, set[str]] = defaultdict(set)
    for package in packages:
        key = (str(package["source"]), str(package["source_version"]))
        versions_by_source[key[0]].add(key[1])
        record = sources.setdefault(
            key,
            {
                "source": key[0],
                "source_version": key[1],
                "binary_packages": [],
                "binary_architectures": [],
                "custom_hint": "no",
            },
        )
        record["binary_packages"].append(package["package"])
        record["binary_architectures"].append(package["architecture"])
        if package["custom_hint"] == "yes":
            record["custom_hint"] = "yes"

    source_rows = []
    for record in sources.values():
        source_rows.append(
            {
                **record,
                "binary_packages": ",".join(sorted(set(record["binary_packages"]))),
                "binary_architectures": ",".join(sorted(set(record["binary_architectures"]))),
            }
        )
    source_rows.sort(key=lambda item: (str(item["source"]), str(item["source_version"])))

    args.output.mkdir(parents=True, exist_ok=True)
    package_fields = [
        "package",
        "version",
        "architecture",
        "source",
        "source_version",
        "multi_arch",
        "essential",
        "priority",
        "custom_hint",
    ]
    source_fields = [
        "source",
        "source_version",
        "binary_packages",
        "binary_architectures",
        "custom_hint",
    ]
    write_tsv(args.output / "packages.amd64.tsv", packages, package_fields)
    write_tsv(args.output / "sources.amd64.tsv", source_rows, source_fields)
    write_tsv(
        args.output / "custom-packages.amd64.tsv",
        (row for row in packages if row["custom_hint"] == "yes"),
        package_fields,
    )
    write_tsv(
        args.output / "custom-sources.amd64.tsv",
        (row for row in source_rows if row["custom_hint"] == "yes"),
        source_fields,
    )

    conflicting_sources = {
        source: sorted(versions)
        for source, versions in sorted(versions_by_source.items())
        if len(versions) > 1
    }
    summary = {
        "installed_binary_package_count": len(packages),
        "installed_source_version_count": len(source_rows),
        "architecture_counts": {
            arch: sum(1 for package in packages if package["architecture"] == arch)
            for arch in sorted({str(package["architecture"]) for package in packages})
        },
        "custom_binary_package_count": sum(1 for package in packages if package["custom_hint"] == "yes"),
        "custom_source_version_count": sum(1 for source in source_rows if source["custom_hint"] == "yes"),
        "sources_with_multiple_installed_versions": conflicting_sources,
    }
    (args.output / "package-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
