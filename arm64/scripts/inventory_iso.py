#!/usr/bin/env python3
"""Create a deterministic package inventory from an extracted dpkg status file.

The output is intentionally architecture-neutral and becomes the only accepted
version authority for the ARM64 port. Source repositories may be used only when
one of their commits declares the exact source version recorded here.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


def parse_deb822(text: str) -> Iterable[dict[str, str]]:
    stanza: dict[str, str] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip():
            if stanza:
                yield stanza
                stanza = {}
                current = None
            continue
        if raw_line[0].isspace():
            if current is not None:
                stanza[current] += "\n" + raw_line[1:]
            continue
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        current = key.strip()
        stanza[current] = value.lstrip()
    if stanza:
        yield stanza


def parse_source(value: str | None, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, version
    match = re.fullmatch(r"\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*", value)
    if not match:
        return value.strip(), version
    return match.group(1), (match.group(2) or version)


def is_custom_candidate(package: str, source: str) -> bool:
    haystack = f"{package} {source}".lower()
    markers = (
        "gooroom",
        "hancom",
        "hancomgrm",
        "nimf",
        "live-installer",
        "dockbarx",
    )
    return any(marker in haystack for marker in markers)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--iso-sha256", required=True)
    parser.add_argument("--iso-size", required=True, type=int)
    parser.add_argument("--iso-name", required=True)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []

    for stanza in parse_deb822(args.status.read_text(encoding="utf-8", errors="replace")):
        if stanza.get("Status") != "install ok installed":
            continue
        package = stanza.get("Package", "")
        version = stanza.get("Version", "")
        architecture = stanza.get("Architecture", "")
        if not package or not version or not architecture:
            continue
        source, source_version = parse_source(stanza.get("Source"), package, version)
        record: dict[str, Any] = {
            "package": package,
            "version": version,
            "architecture": architecture,
            "source": source,
            "source_version": source_version,
            "multi_arch": stanza.get("Multi-Arch", ""),
            "essential": stanza.get("Essential", "no"),
            "priority": stanza.get("Priority", ""),
            "section": stanza.get("Section", ""),
            "depends": stanza.get("Depends", ""),
            "pre_depends": stanza.get("Pre-Depends", ""),
            "provides": stanza.get("Provides", ""),
            "custom_candidate": is_custom_candidate(package, source),
        }
        records.append(record)

    records.sort(key=lambda item: item["package"])
    arch_counts = Counter(item["architecture"] for item in records)
    source_groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for item in records:
        source_groups[(item["source"], item["source_version"])].append(item["package"])

    sources = [
        {
            "source": source,
            "source_version": source_version,
            "binary_packages": sorted(binary_packages),
            "custom_candidate": is_custom_candidate(" ".join(binary_packages), source),
        }
        for (source, source_version), binary_packages in sorted(source_groups.items())
    ]

    manifest = {
        "schema": 1,
        "policy": "fail-closed-exact-version",
        "reference_iso": {
            "name": args.iso_name,
            "size": args.iso_size,
            "sha256": args.iso_sha256,
        },
        "package_count": len(records),
        "source_count": len(sources),
        "architecture_counts": dict(sorted(arch_counts.items())),
        "packages": records,
        "sources": sources,
    }

    (args.output_dir / "amd64-reference.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    package_fields = [
        "package",
        "version",
        "architecture",
        "source",
        "source_version",
        "multi_arch",
        "essential",
        "priority",
        "section",
        "custom_candidate",
    ]
    with (args.output_dir / "amd64-packages.tsv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=package_fields, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)

    source_fields = ["source", "source_version", "binary_packages", "custom_candidate"]
    with (args.output_dir / "amd64-sources.tsv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=source_fields, delimiter="\t")
        writer.writeheader()
        for source in sources:
            row = dict(source)
            row["binary_packages"] = ",".join(source["binary_packages"])
            writer.writerow(row)

    custom = [item for item in sources if item["custom_candidate"]]
    (args.output_dir / "custom-source-candidates.json").write_text(
        json.dumps(custom, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    summary = {
        "package_count": len(records),
        "source_count": len(sources),
        "architecture_counts": dict(sorted(arch_counts.items())),
        "custom_source_candidate_count": len(custom),
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
