#!/usr/bin/env python3
"""Lock exact source package records from the original Gooroom/Hancom APT repos.

This is a provenance fallback for source versions that are installed in the
AMD64 image but are not recoverable as an exact `debian/changelog` commit in the
three public GitHub organizations. Nothing is accepted by name alone: Package
and Version must both match the ISO-derived reference exactly, and conflicting
checksums fail closed.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


def parse_deb822(text: str) -> Iterable[dict[str, str]]:
    stanza: dict[str, str] = {}
    key: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if stanza:
                yield stanza
                stanza = {}
                key = None
            continue
        if line[0].isspace():
            if key is not None:
                stanza[key] += "\n" + line[1:]
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stanza[key] = value.lstrip()
    if stanza:
        yield stanza


def parse_checksums(value: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not value:
        return rows
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        digest, size, name = parts
        rows.append({"sha256": digest, "size": int(size), "name": name})
    return rows


def target_sources(reference_path: Path) -> list[dict[str, Any]]:
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    packages: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for package in reference["packages"]:
        packages[(package["source"], package["source_version"])].append(package)

    targets: list[dict[str, Any]] = []
    for source in reference["sources"]:
        if not source.get("custom_candidate"):
            continue
        members = packages[(source["source"], source["source_version"])]
        architectures = sorted({member["architecture"] for member in members})
        targets.append(
            {
                "source": source["source"],
                "source_version": source["source_version"],
                "role": "reuse-all" if architectures == ["all"] else "rebuild-arm64",
                "binary_packages": sorted(member["package"] for member in members),
                "binary_architectures": architectures,
            }
        )
    return sorted(targets, key=lambda target: target["source"])


def canonical_candidate(
    repository: str,
    suite: str,
    base_url: str,
    stanza: dict[str, str],
) -> dict[str, Any] | None:
    package = stanza.get("Package", "")
    version = stanza.get("Version", "")
    directory = stanza.get("Directory", "").strip("/")
    files = parse_checksums(stanza.get("Checksums-Sha256"))
    if not package or not version or not directory or not files:
        return None
    return {
        "repository": repository,
        "suite": suite,
        "base_url": base_url.rstrip("/"),
        "source": package,
        "source_version": version,
        "directory": directory,
        "files": files,
        "dsc_files": [file for file in files if file["name"].endswith(".dsc")],
        "source_urls": [
            f"{base_url.rstrip('/')}/{directory}/{file['name']}" for file in files
        ],
        "record_fields": {
            key: stanza.get(key, "")
            for key in (
                "Binary",
                "Architecture",
                "Maintainer",
                "Uploaders",
                "Standards-Version",
                "Build-Depends",
                "Build-Depends-Indep",
                "Homepage",
                "Vcs-Browser",
                "Vcs-Git",
                "Package-List",
            )
            if stanza.get(key)
        },
    }


def preferred_repository(version: str) -> tuple[str, ...]:
    if "+han" in version.lower():
        return ("hancom", "gooroom")
    return ("gooroom", "hancom")


def candidate_identity(candidate: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(
        sorted((file["name"], file["size"], file["sha256"]) for file in candidate["files"])
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--index", action="append", type=Path, required=True)
    parser.add_argument("--index-metadata", action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    if len(args.index) != len(args.index_metadata):
        parser.error("--index and --index-metadata counts must match")

    records: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    index_evidence: list[dict[str, Any]] = []
    for path, metadata_text in zip(args.index, args.index_metadata):
        metadata = json.loads(metadata_text)
        count = 0
        for stanza in parse_deb822(path.read_text(encoding="utf-8", errors="replace")):
            candidate = canonical_candidate(
                metadata["repository"],
                metadata["suite"],
                metadata["base_url"],
                stanza,
            )
            if candidate is None:
                continue
            records[(candidate["source"], candidate["source_version"])].append(candidate)
            count += 1
        index_evidence.append({**metadata, "path": str(path), "record_count": count})

    rows: list[dict[str, Any]] = []
    for target in target_sources(args.reference):
        candidates = records.get((target["source"], target["source_version"]), [])
        row: dict[str, Any] = {
            **target,
            "status": "missing-exact-source",
            "selected": None,
            "exact_candidates": candidates,
        }
        if not candidates:
            rows.append(row)
            continue

        rank = {
            repository: index
            for index, repository in enumerate(preferred_repository(target["source_version"]))
        }
        best_rank = min(rank.get(candidate["repository"], 99) for candidate in candidates)
        authoritative = [
            candidate
            for candidate in candidates
            if rank.get(candidate["repository"], 99) == best_rank
        ]
        identities = {candidate_identity(candidate) for candidate in authoritative}
        if len(identities) != 1:
            row["status"] = "ambiguous-exact-source"
            rows.append(row)
            continue
        authoritative.sort(
            key=lambda candidate: (
                candidate["repository"],
                candidate["suite"],
                candidate["directory"],
            )
        )
        row["selected"] = authoritative[0]
        row["status"] = "resolved"
        rows.append(row)

    unresolved = [row for row in rows if row["status"] != "resolved"]
    rebuild_unresolved = [
        row
        for row in unresolved
        if row["role"] == "rebuild-arm64"
        and row["source"] != "linux-signed-amd64"
    ]
    summary = {
        "schema": 1,
        "policy": "exact-apt-source-version-and-sha256",
        "index_evidence": index_evidence,
        "source_target_count": len(rows),
        "resolved_count": sum(row["status"] == "resolved" for row in rows),
        "unresolved_count": len(unresolved),
        "rebuild_unresolved_count": len(rebuild_unresolved),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "vendor-source-lock.json").write_text(
        json.dumps({"summary": summary, "sources": rows}, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "vendor-source-lock-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output_dir / "vendor-source-unresolved.json").write_text(
        json.dumps(unresolved, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output_dir / "vendor-source-rebuild-blockers.json").write_text(
        json.dumps(rebuild_unresolved, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    fields = [
        "source",
        "source_version",
        "role",
        "status",
        "repository",
        "suite",
        "directory",
        "dsc",
    ]
    with (args.output_dir / "vendor-source-lock.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in rows:
            selected = row.get("selected") or {}
            dsc_files = selected.get("dsc_files") or []
            writer.writerow(
                {
                    "source": row["source"],
                    "source_version": row["source_version"],
                    "role": row["role"],
                    "status": row["status"],
                    "repository": selected.get("repository", ""),
                    "suite": selected.get("suite", ""),
                    "directory": selected.get("directory", ""),
                    "dsc": dsc_files[0]["name"] if dsc_files else "",
                }
            )

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 2 if rebuild_unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main())
