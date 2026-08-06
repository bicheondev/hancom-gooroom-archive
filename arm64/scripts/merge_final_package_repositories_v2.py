#!/usr/bin/env python3
"""Merge exact Debian and custom package repositories for final ARM64 rootfs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
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


def field(path: Path, name: str) -> str:
    process = run(["dpkg-deb", "-f", str(path), name])
    if process.returncode:
        raise RuntimeError(f"dpkg-deb {name} failed for {path.name}")
    return process.stdout.strip()


def parse_source(value: str, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, BINNMU_RE.sub("", version)
    match = SOURCE_RE.fullmatch(value)
    if not match:
        return value, BINNMU_RE.sub("", version)
    return match.group(1), match.group(2) or BINNMU_RE.sub("", version)


def nested_dicts(value: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(value, dict):
        rows.append(value)
        for child in value.values():
            rows.extend(nested_dicts(child))
    elif isinstance(value, list):
        for child in value:
            rows.extend(nested_dicts(child))
    return rows


def first(containers: list[dict[str, Any]], fields: tuple[str, ...]) -> Any:
    for container in containers:
        for field_name in fields:
            value = container.get(field_name)
            if value not in (None, ""):
                return value
    return None


def replacement_target(row: dict[str, Any]) -> dict[str, str] | None:
    containers = []
    containers.extend(nested_dicts(row.get("selected")))
    containers.extend(nested_dicts(row.get("replacement")))
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
    return {
        "package": str(package),
        "version": str(version),
        "architecture": str(architecture or "arm64"),
    }


def expected_routes(
    normalized: dict[str, Any], reference: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    reference_rows = {
        (row["package"], row["version"], row["architecture"]): row
        for row in reference.get("packages", [])
    }
    expected: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []

    for row in normalized.get("packages", []):
        ref = reference_rows.get(
            (
                row["package"],
                row["reference_version"],
                row["reference_architecture"],
            )
        )
        if ref is None:
            blockers.append({**row, "reason": "reference-row-not-found"})
            continue
        status = row["status"]
        if status == "exclude":
            excluded.append(
                {
                    "reference_package": row["package"],
                    "reference_version": row["reference_version"],
                    "reference_architecture": row["reference_architecture"],
                    "source": row["source"],
                    "source_version": row["source_version"],
                    "reason": "architecture-exclusion",
                }
            )
            continue

        require_source_identity = True
        target: dict[str, str] | None = None
        if status == "exact-arm64":
            selected = row.get("selected") or {}
            target = {
                "package": str(selected.get("package") or row["package"]),
                "version": str(selected.get("version") or row["reference_version"]),
                "architecture": str(selected.get("architecture") or "arm64"),
            }
        elif status == "reuse-all":
            target = {
                "package": row["package"],
                "version": row["reference_version"],
                "architecture": "all",
            }
        elif status == "rebuild-arm64":
            target = {
                "package": row["package"],
                "version": row["reference_version"],
                "architecture": "arm64",
            }
        elif status == "arch-replace":
            target = replacement_target(row)
            require_source_identity = False
        else:
            blockers.append({**row, "reason": f"unsupported-mapping-status:{status}"})
            continue

        if target is None:
            blockers.append({**row, "reason": "target-package-not-described"})
            continue
        if target["architecture"] not in {"arm64", "all"}:
            blockers.append(
                {**row, "reason": f"invalid-target-architecture:{target['architecture']}"}
            )
            continue
        expected.append(
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
                "require_source_identity": require_source_identity,
                "custom_candidate": bool(ref.get("custom_candidate")),
            }
        )
    return expected, excluded, blockers


def scan_repository(root: Path, origin: str) -> list[dict[str, Any]]:
    records = []
    for path in sorted(root.glob("*.deb")):
        package = field(path, "Package")
        version = field(path, "Version")
        architecture = field(path, "Architecture")
        source, source_version = parse_source(
            field(path, "Source"), package, version
        )
        records.append(
            {
                "origin": origin,
                "path": str(path),
                "filename": path.name,
                "size": path.stat().st_size,
                "sha256": sha256(path),
                "package": package,
                "version": version,
                "architecture": architecture,
                "source": source,
                "source_version": source_version,
            }
        )
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normalized-map", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--debian-repository", type=Path, required=True)
    parser.add_argument("--custom-repository", type=Path, required=True)
    parser.add_argument("--output-repository", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    normalized = load(args.normalized_map)
    reference = load(args.reference)
    expected, excluded, blockers = expected_routes(normalized, reference)
    candidates = scan_repository(args.debian_repository, "debian-reference")
    candidates.extend(scan_repository(args.custom_repository, "custom-exact"))

    by_identity: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        by_identity[
            (
                candidate["package"],
                candidate["version"],
                candidate["architecture"],
            )
        ].append(candidate)

    selected: list[dict[str, Any]] = []
    for route in expected:
        identity = (
            route["target_package"],
            route["target_version"],
            route["target_architecture"],
        )
        matches = by_identity.get(identity, [])
        unique_payloads = {
            (match["sha256"], match["size"]) for match in matches
        }
        if not matches:
            blockers.append({**route, "reason": "target-deb-not-found"})
            continue
        if len(unique_payloads) != 1:
            blockers.append(
                {**route, "reason": "conflicting-target-deb-payloads", "matches": matches}
            )
            continue
        match = sorted(matches, key=lambda item: (item["origin"], item["filename"]))[0]
        if route["require_source_identity"]:
            if match["source"] != route["source"]:
                blockers.append(
                    {
                        **route,
                        "reason": "target-source-name-mismatch",
                        "actual": match,
                    }
                )
                continue
            if match["source_version"] != route["source_version"]:
                blockers.append(
                    {
                        **route,
                        "reason": "target-source-version-mismatch",
                        "actual": match,
                    }
                )
                continue
        selected.append({**route, "deb": match})

    # One final target may satisfy multiple reference packages (for example a
    # metapackage replacement). Copy each unique payload exactly once.
    args.output_repository.mkdir(parents=True, exist_ok=True)
    copied: dict[tuple[str, str], dict[str, Any]] = {}
    if not blockers:
        for row in selected:
            deb = row["deb"]
            identity = (deb["filename"], deb["sha256"])
            if identity in copied:
                continue
            source = Path(deb["path"])
            destination = args.output_repository / deb["filename"]
            if destination.exists() and sha256(destination) != deb["sha256"]:
                blockers.append(
                    {"reason": "output-filename-collision", "deb": deb}
                )
                break
            shutil.copyfile(source, destination)
            copied[identity] = deb

    if not blockers:
        scan = run(
            ["dpkg-scanpackages", "--multiversion", "."],
            cwd=args.output_repository,
        )
        if scan.returncode:
            blockers.append(
                {"reason": "dpkg-scanpackages-failed", "stderr": scan.stderr}
            )
        else:
            (args.output_repository / "Packages").write_text(
                scan.stdout, encoding="utf-8"
            )
            release = run(
                ["apt-ftparchive", "release", "."],
                cwd=args.output_repository,
            )
            if release.returncode:
                blockers.append(
                    {"reason": "apt-ftparchive-failed", "stderr": release.stderr}
                )
            else:
                (args.output_repository / "Release").write_text(
                    release.stdout, encoding="utf-8"
                )

    output_files = [
        {
            "filename": path.name,
            "size": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in sorted(args.output_repository.glob("*"))
        if path.is_file()
    ]
    status_counts: dict[str, int] = defaultdict(int)
    for row in expected:
        status_counts[row["mapping_status"]] += 1
    summary = {
        "schema": 2,
        "policy": "one-exact-final-deb-route-per-reference-package",
        "normalized_map_complete": normalized.get("summary", {}).get("complete"),
        "reference_package_count": len(reference.get("packages", [])),
        "expected_route_count": len(expected),
        "selected_route_count": len(selected),
        "excluded_reference_package_count": len(excluded),
        "mapping_status_counts": dict(sorted(status_counts.items())),
        "input_debian_deb_count": sum(
            candidate["origin"] == "debian-reference" for candidate in candidates
        ),
        "input_custom_deb_count": sum(
            candidate["origin"] == "custom-exact" for candidate in candidates
        ),
        "output_unique_deb_count": len(copied),
        "blocker_count": len(blockers),
        "repository_file_count": len(output_files),
        "final_repository_ready": (
            normalized.get("summary", {}).get("complete") is True
            and len(selected) == len(expected)
            and not blockers
        ),
    }
    manifest = {
        "summary": summary,
        "selected_routes": selected,
        "excluded_reference_packages": excluded,
        "blockers": blockers,
        "repository_files": output_files,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "final-package-authority.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "blockers.json").write_text(
        json.dumps(blockers, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "excluded.json").write_text(
        json.dumps(excluded, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    with (args.output_dir / "selected-routes.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        fields = [
            "reference_package",
            "reference_version",
            "mapping_status",
            "source",
            "source_version",
            "target_package",
            "target_version",
            "target_architecture",
            "custom_candidate",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in selected:
            writer.writerow({field: row.get(field, "") for field in fields})
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["final_repository_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
