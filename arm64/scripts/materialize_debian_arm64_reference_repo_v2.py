#!/usr/bin/env python3
"""Materialize exact Debian ARM64/all packages from the normalized package map."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any


SOURCE_RE = re.compile(r"^\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*$")
BINNMU_RE = re.compile(r"\+b\d+$")


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        **kwargs,
    )


def deb_field(path: Path, field: str) -> str:
    process = run(["dpkg-deb", "-f", str(path), field])
    return process.stdout.strip() if process.returncode == 0 else ""


def parse_source(value: str, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, BINNMU_RE.sub("", version)
    match = SOURCE_RE.fullmatch(value)
    if not match:
        return value, BINNMU_RE.sub("", version)
    return match.group(1), match.group(2) or BINNMU_RE.sub("", version)


def candidate_dicts(value: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(value, dict):
        rows.append(value)
        for child in value.values():
            rows.extend(candidate_dicts(child))
    elif isinstance(value, list):
        for child in value:
            rows.extend(candidate_dicts(child))
    return rows


def first(containers: list[dict[str, Any]], names: tuple[str, ...]) -> Any:
    for container in containers:
        for name in names:
            value = container.get(name)
            if value not in (None, ""):
                return value
    return None


def replacement_target(row: dict[str, Any]) -> dict[str, Any] | None:
    containers = []
    for value in (row.get("selected"), row.get("replacement")):
        containers.extend(candidate_dicts(value))
    package = first(
        containers,
        ("package", "target_package", "replacement_package", "arm64_package", "name"),
    )
    version = first(
        containers,
        ("version", "target_version", "replacement_version", "arm64_version"),
    )
    architecture = first(
        containers,
        ("architecture", "target_architecture", "arm64_architecture"),
    )
    if not package or not version:
        return None
    if architecture in (None, ""):
        architecture = "arm64"
    return {
        "package": str(package),
        "version": str(version),
        "architecture": str(architecture),
    }


def acquisition_targets(
    normalized: dict[str, Any], reference: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    reference_rows = {
        (row["package"], row["version"], row["architecture"]): row
        for row in reference.get("packages", [])
    }
    targets: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []

    for row in normalized.get("packages", []):
        reference_row = reference_rows.get(
            (
                row["package"],
                row["reference_version"],
                row["reference_architecture"],
            )
        )
        if reference_row is None:
            blockers.append({**row, "reason": "reference-row-not-found"})
            continue
        status = row["status"]
        if status in {"rebuild-arm64", "exclude"}:
            skipped.append({**row, "reason": status})
            continue
        if status == "reuse-all" and reference_row.get("custom_candidate"):
            skipped.append({**row, "reason": "custom-architecture-all-from-vendor-lock"})
            continue

        target: dict[str, Any] | None = None
        if status in {"exact-arm64", "reuse-all"}:
            selected = row.get("selected") or {}
            target = {
                "package": selected.get("package") or row["package"],
                "version": selected.get("version") or row["reference_version"],
                "architecture": selected.get("architecture")
                or ("all" if status == "reuse-all" else "arm64"),
            }
        elif status == "arch-replace":
            target = replacement_target(row)
            if target is None:
                blockers.append({**row, "reason": "architecture-replacement-not-described"})
                continue
        else:
            blockers.append({**row, "reason": f"unsupported-status:{status}"})
            continue

        target = {key: str(value) for key, value in target.items()}
        if target["architecture"] not in {"arm64", "all"}:
            blockers.append(
                {**row, "reason": f"invalid-target-architecture:{target['architecture']}"}
            )
            continue
        targets.append(
            {
                "reference_package": row["package"],
                "reference_version": row["reference_version"],
                "reference_architecture": row["reference_architecture"],
                "source": row["source"],
                "source_version": row["source_version"],
                "mapping_status": status,
                "target_package": target["package"],
                "target_version": target["version"],
                "target_architecture": target["architecture"],
            }
        )

    identities: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for target in targets:
        identities[
            (
                target["target_package"],
                target["target_version"],
                target["target_architecture"],
            )
        ].append(target)
    conflicting = [
        {"identity": list(identity), "routes": routes}
        for identity, routes in identities.items()
        if len(
            {
                (
                    route["source"],
                    route["source_version"],
                    route["mapping_status"],
                )
                for route in routes
            }
        )
        > 1
        and len({(route["source"], route["source_version"]) for route in routes}) > 1
    ]
    blockers.extend(
        {"reason": "conflicting-target-identity", **conflict} for conflict in conflicting
    )
    unique = []
    seen = set()
    for target in targets:
        identity = (
            target["target_package"],
            target["target_version"],
            target["target_architecture"],
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(target)
    return unique, skipped, blockers


def download_specs(
    apt_config: Path,
    targets: list[dict[str, Any]],
    repository: Path,
    chunk_size: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    downloaded: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    def execute(chunk: list[dict[str, Any]]) -> bool:
        specs = [
            f"{target['target_package']}:arm64={target['target_version']}"
            for target in chunk
        ]
        for attempt in range(1, 5):
            process = run(
                ["apt-get", "-c", str(apt_config), "download", *specs],
                cwd=repository,
            )
            if process.returncode == 0:
                downloaded.append(
                    {
                        "specs": specs,
                        "attempts": attempt,
                        "stdout": process.stdout[-4000:],
                        "stderr": process.stderr[-4000:],
                    }
                )
                return True
            if attempt < 4:
                time.sleep(2**attempt)
        failures.append(
            {
                "specs": specs,
                "stdout": process.stdout[-16000:],
                "stderr": process.stderr[-16000:],
                "returncode": process.returncode,
            }
        )
        return False

    for offset in range(0, len(targets), chunk_size):
        chunk = targets[offset : offset + chunk_size]
        if execute(chunk):
            continue
        failures.pop()  # replace broad failure with exact individual failures
        for target in chunk:
            if not execute([target]):
                failures[-1]["target"] = target
    return downloaded, failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normalized-map", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--apt-config", type=Path, required=True)
    parser.add_argument("--repository-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--chunk-size", type=int, default=40)
    args = parser.parse_args()

    normalized = load(args.normalized_map)
    reference = load(args.reference)
    targets, skipped, blockers = acquisition_targets(normalized, reference)
    args.repository_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    download_records, download_failures = download_specs(
        args.apt_config, targets, args.repository_dir, max(1, args.chunk_size)
    )
    blockers.extend(
        {"reason": "apt-download-failed", **failure} for failure in download_failures
    )

    expected_by_identity = {
        (
            target["target_package"],
            target["target_version"],
            target["target_architecture"],
        ): target
        for target in targets
    }
    observed: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    unrecognized: list[dict[str, Any]] = []
    for deb in sorted(args.repository_dir.glob("*.deb")):
        package = deb_field(deb, "Package")
        version = deb_field(deb, "Version")
        architecture = deb_field(deb, "Architecture")
        source, source_version = parse_source(
            deb_field(deb, "Source"), package, version
        )
        record = {
            "filename": deb.name,
            "size": deb.stat().st_size,
            "sha256": sha256(deb),
            "package": package,
            "version": version,
            "architecture": architecture,
            "source": source,
            "source_version": source_version,
        }
        identity = (package, version, architecture)
        if identity not in expected_by_identity:
            unrecognized.append(record)
            continue
        expected = expected_by_identity[identity]
        if expected["mapping_status"] != "arch-replace":
            if source != expected["source"]:
                blockers.append(
                    {
                        "reason": "source-name-mismatch",
                        "expected": expected,
                        "actual": record,
                    }
                )
                continue
            if source_version != expected["source_version"]:
                blockers.append(
                    {
                        "reason": "source-version-mismatch",
                        "expected": expected,
                        "actual": record,
                    }
                )
                continue
        observed[identity].append(record)

    verified = []
    for identity, target in expected_by_identity.items():
        rows = observed.get(identity, [])
        if len(rows) != 1:
            blockers.append(
                {
                    "reason": "missing-or-ambiguous-downloaded-deb",
                    "target": target,
                    "observed_count": len(rows),
                }
            )
        else:
            verified.append({**target, **rows[0]})
    if unrecognized:
        blockers.append(
            {
                "reason": "unrecognized-downloaded-debs",
                "packages": unrecognized,
            }
        )

    if not blockers:
        scan = run(
            ["dpkg-scanpackages", "--multiversion", "."], cwd=args.repository_dir
        )
        if scan.returncode:
            blockers.append(
                {"reason": "dpkg-scanpackages-failed", "stderr": scan.stderr}
            )
        else:
            (args.repository_dir / "Packages").write_text(scan.stdout, encoding="utf-8")
            release = run(
                ["apt-ftparchive", "release", "."], cwd=args.repository_dir
            )
            if release.returncode:
                blockers.append(
                    {"reason": "apt-ftparchive-failed", "stderr": release.stderr}
                )
            else:
                (args.repository_dir / "Release").write_text(
                    release.stdout, encoding="utf-8"
                )

    repository_files = [
        {
            "filename": path.name,
            "size": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in sorted(args.repository_dir.glob("*"))
        if path.is_file()
    ]
    summary = {
        "schema": 2,
        "policy": "normalized-map-exact-debian-arm64-and-all-packages",
        "normalized_map_complete": normalized.get("summary", {}).get("complete"),
        "target_count": len(targets),
        "verified_deb_count": len(verified),
        "skipped_count": len(skipped),
        "blocker_count": len(blockers),
        "repository_file_count": len(repository_files),
        "repository_ready": (
            normalized.get("summary", {}).get("complete") is True
            and bool(targets)
            and not blockers
        ),
    }
    manifest = {
        "summary": summary,
        "targets": targets,
        "verified_packages": verified,
        "skipped": skipped,
        "blockers": blockers,
        "download_records": download_records,
        "repository_files": repository_files,
    }
    (args.output_dir / "debian-arm64-reference-repository.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "blockers.json").write_text(
        json.dumps(blockers, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    with (args.output_dir / "verified-packages.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        fields = [
            "package",
            "version",
            "architecture",
            "source",
            "source_version",
            "filename",
            "size",
            "sha256",
            "mapping_status",
            "reference_package",
            "reference_version",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in verified:
            writer.writerow({field: row.get(field, "") for field in fields})
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["repository_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
