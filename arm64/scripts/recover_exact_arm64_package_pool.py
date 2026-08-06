#!/usr/bin/env python3
"""Recover a package-for-package ARM64 pool from existing .deb artifacts.

Each candidate is accepted only when it maps to one immutable AMD64 reference
package under an explicit architecture rule, has an exact source version, uses
arm64/all architecture as required, and contains no x86 ELF payload. The script
never substitutes a newer/older source and never hides an uncovered package.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


REPLACEMENTS = {
    "binutils-x86-64-linux-gnu": "binutils-aarch64-linux-gnu",
    "grub-pc": "grub-efi-arm64",
    "grub-pc-bin": "grub-efi-arm64-bin",
    "linux-image-5.10.0-23-amd64": "linux-image-5.10.0-23-arm64",
    "linux-image-amd64": "linux-image-arm64",
}

EXCLUSIONS = {
    "amd64-microcode": "x86 CPU microcode",
    "intel-microcode": "Intel CPU microcode",
    "iucode-tool": "Intel microcode utility",
    "libdrm-intel1": "Intel-only DRM userspace driver",
    "libmfx1": "Intel Media SDK runtime",
    "libquadmath0": "not built for Debian ARM64",
    "libxatracker2": "not built for Debian ARM64",
    "xserver-xorg-video-intel": "Intel-only Xorg driver",
    "xserver-xorg-video-vmware": "x86 VMware Xorg driver",
}

BINNMU_RE = re.compile(r"\+b\d+$")
SOURCE_RE = re.compile(r"^\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*$")
ELF_NAMES = {3: "i386", 40: "arm32", 62: "x86_64", 183: "aarch64", 247: "bpf"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deb_field(path: Path, field: str) -> str:
    process = subprocess.run(
        ["dpkg-deb", "-f", str(path), field],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode:
        return ""
    return process.stdout.strip()


def strip_binnmu(version: str) -> str:
    return BINNMU_RE.sub("", version)


def parse_source(value: str, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, strip_binnmu(version)
    match = SOURCE_RE.fullmatch(value)
    if not match:
        return value.strip(), strip_binnmu(version)
    return match.group(1), match.group(2) or strip_binnmu(version)


def elf_machine(path: Path) -> int | None:
    try:
        with path.open("rb") as handle:
            header = handle.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    if header[5] == 1:
        return struct.unpack("<H", header[18:20])[0]
    if header[5] == 2:
        return struct.unpack(">H", header[18:20])[0]
    return -1


def audit_payload(deb: Path) -> dict[str, Any]:
    x86: list[dict[str, Any]] = []
    foreign: list[dict[str, Any]] = []
    machines: dict[str, int] = {}
    with tempfile.TemporaryDirectory(prefix="arm64-deb-audit-") as temporary:
        root = Path(temporary)
        process = subprocess.run(
            ["dpkg-deb", "-x", str(deb), str(root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode:
            return {
                "extract_error": process.stderr.decode("utf-8", "replace")[-2000:],
                "x86": [],
                "foreign": [],
                "machines": {},
                "passed": False,
            }
        for directory, _, filenames in os.walk(root, followlinks=False):
            for filename in filenames:
                path = Path(directory) / filename
                if path.is_symlink():
                    continue
                machine = elf_machine(path)
                if machine is None:
                    continue
                name = ELF_NAMES.get(machine, f"machine-{machine}")
                machines[name] = machines.get(name, 0) + 1
                record = {
                    "path": str(path.relative_to(root)),
                    "machine": name,
                    "size": path.stat().st_size,
                }
                if machine in {3, 62}:
                    x86.append(record)
                elif machine not in {0, 183, 247}:
                    foreign.append(record)
    return {
        "x86": x86,
        "foreign": foreign,
        "machines": dict(sorted(machines.items())),
        "passed": not x86 and not foreign,
    }


def reference_targets(reference: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for package in reference.get("packages", []):
        original = package["package"]
        if original in EXCLUSIONS:
            rows.append(
                {
                    **package,
                    "target_package": None,
                    "target_architecture": None,
                    "disposition": "exclude",
                    "reason": EXCLUSIONS[original],
                }
            )
            continue
        if package["architecture"] == "all":
            target_name = original
            target_arch = "all"
            disposition = "reuse-all"
        else:
            target_name = REPLACEMENTS.get(original, original)
            target_arch = "arm64"
            disposition = "arch-replace" if original in REPLACEMENTS else "native-arm64"
        rows.append(
            {
                **package,
                "target_package": target_name,
                "target_architecture": target_arch,
                "disposition": disposition,
                "reason": "",
            }
        )
    return rows


def candidate_metadata(path: Path) -> dict[str, Any]:
    package = deb_field(path, "Package")
    version = deb_field(path, "Version")
    architecture = deb_field(path, "Architecture")
    source_field = deb_field(path, "Source")
    source, source_version = parse_source(source_field, package, version)
    return {
        "path": str(path),
        "filename": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "package": package,
        "version": version,
        "architecture": architecture,
        "source_field": source_field,
        "source": source,
        "source_version": source_version,
    }


def match_quality(target: dict[str, Any], candidate: dict[str, Any]) -> tuple[int, str]:
    if candidate["package"] != target["target_package"]:
        return 0, "package-name"
    if candidate["architecture"] != target["target_architecture"]:
        return 0, "architecture"
    if candidate["source"] != target["source"]:
        return 0, "source-name"
    if candidate["source_version"] != target["source_version"]:
        return 0, "source-version"
    if candidate["version"] == target["version"]:
        return 3, "exact-binary-and-source-version"
    if strip_binnmu(candidate["version"]) == strip_binnmu(target["version"]):
        return 2, "exact-source-version-architecture-binnmu"
    # Architecture replacement metapackages can have a binary version distinct
    # from the removed AMD64 package while still coming from the exact source.
    if target["disposition"] == "arch-replace":
        return 1, "exact-source-version-architecture-replacement"
    return 0, "binary-version"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--repository-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    targets = reference_targets(reference)
    candidate_paths = sorted(args.candidate_dir.rglob("*.deb"))
    metadata: list[dict[str, Any]] = []
    invalid_debs: list[dict[str, Any]] = []
    for index, path in enumerate(candidate_paths, 1):
        row = candidate_metadata(path)
        if not all((row["package"], row["version"], row["architecture"])):
            invalid_debs.append({**row, "reason": "invalid-deb-control"})
            continue
        metadata.append(row)
        if index % 100 == 0:
            print(f"indexed {index}/{len(candidate_paths)} candidate debs", flush=True)

    by_package: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in metadata:
        by_package[row["package"]].append(row)

    args.repository_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    selected: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    payload_audit_cache: dict[str, dict[str, Any]] = {}

    for target in targets:
        if target["disposition"] == "exclude":
            exclusions.append(target)
            continue
        candidates = []
        for candidate in by_package.get(target["target_package"], []):
            quality, reason = match_quality(target, candidate)
            if quality:
                candidates.append((quality, reason, candidate))
        if not candidates:
            blockers.append(
                {
                    "reference_package": target["package"],
                    "reference_version": target["version"],
                    "reference_architecture": target["architecture"],
                    "source": target["source"],
                    "source_version": target["source_version"],
                    "target_package": target["target_package"],
                    "target_architecture": target["target_architecture"],
                    "disposition": target["disposition"],
                    "reason": "no-exact-source-version-candidate",
                    "available_candidates": [
                        {
                            key: row[key]
                            for key in (
                                "filename",
                                "version",
                                "architecture",
                                "source",
                                "source_version",
                            )
                        }
                        for row in by_package.get(target["target_package"], [])[:30]
                    ],
                }
            )
            continue

        candidates.sort(
            key=lambda item: (item[0], item[2]["version"], item[2]["sha256"]),
            reverse=True,
        )
        highest = candidates[0][0]
        finalists = [item for item in candidates if item[0] == highest]
        identities = {
            (
                item[2]["version"],
                item[2]["architecture"],
                item[2]["source"],
                item[2]["source_version"],
                item[2]["sha256"],
            )
            for item in finalists
        }
        # Multiple byte-identical files are harmless; different package bytes at
        # the same authoritative identity are ambiguous and fail closed.
        sha_set = {item[2]["sha256"] for item in finalists}
        if len(sha_set) != 1:
            blockers.append(
                {
                    "reference_package": target["package"],
                    "target_package": target["target_package"],
                    "reason": "ambiguous-exact-candidate-bytes",
                    "candidates": [item[2] for item in finalists],
                }
            )
            continue
        quality, match_reason, candidate = finalists[0]
        audit = payload_audit_cache.get(candidate["sha256"])
        if audit is None:
            audit = audit_payload(Path(candidate["path"]))
            payload_audit_cache[candidate["sha256"]] = audit
        if not audit["passed"]:
            blockers.append(
                {
                    "reference_package": target["package"],
                    "target_package": target["target_package"],
                    "reason": "candidate-payload-architecture-audit-failed",
                    "candidate": candidate,
                    "payload_audit": audit,
                }
            )
            continue

        destination_name = candidate["filename"]
        destination = args.repository_dir / destination_name
        if destination.exists() and sha256_file(destination) != candidate["sha256"]:
            destination_name = f"{candidate['sha256'][:16]}-{candidate['filename']}"
            destination = args.repository_dir / destination_name
        shutil.copyfile(candidate["path"], destination)
        selected.append(
            {
                "reference_package": target["package"],
                "reference_version": target["version"],
                "reference_architecture": target["architecture"],
                "source": target["source"],
                "source_version": target["source_version"],
                "target_package": target["target_package"],
                "target_architecture": target["target_architecture"],
                "disposition": target["disposition"],
                "match_quality": quality,
                "match_reason": match_reason,
                "candidate": {
                    **candidate,
                    "repository_filename": destination_name,
                },
                "payload_audit": audit,
            }
        )

    if not blockers:
        packages = subprocess.run(
            ["dpkg-scanpackages", "--multiversion", "."],
            cwd=args.repository_dir,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if packages.returncode:
            blockers.append(
                {
                    "reason": "dpkg-scanpackages-failed",
                    "stderr": packages.stderr[-4000:],
                }
            )
        else:
            (args.repository_dir / "Packages").write_text(
                packages.stdout, encoding="utf-8"
            )

    disposition_counts: dict[str, int] = {}
    match_counts: dict[str, int] = {}
    for row in selected:
        disposition_counts[row["disposition"]] = (
            disposition_counts.get(row["disposition"], 0) + 1
        )
        match_counts[row["match_reason"]] = match_counts.get(row["match_reason"], 0) + 1
    summary = {
        "schema": 1,
        "policy": "exact-reference-source-version-and-no-x86-elf",
        "reference_package_count": len(targets),
        "candidate_deb_count": len(metadata),
        "invalid_deb_count": len(invalid_debs),
        "selected_package_count": len(selected),
        "excluded_package_count": len(exclusions),
        "blocker_count": len(blockers),
        "disposition_counts": dict(sorted(disposition_counts.items())),
        "match_counts": dict(sorted(match_counts.items())),
        "repository_ready": not blockers,
    }
    (args.output_dir / "recovery.json").write_text(
        json.dumps(
            {
                "summary": summary,
                "selected": selected,
                "exclusions": exclusions,
                "blockers": blockers,
                "invalid_debs": invalid_debs,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "blockers.json").write_text(
        json.dumps(blockers, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    with (args.output_dir / "coverage.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        fields = [
            "reference_package",
            "reference_version",
            "reference_architecture",
            "source",
            "source_version",
            "target_package",
            "target_architecture",
            "disposition",
            "match_reason",
            "candidate_version",
            "candidate_sha256",
            "repository_filename",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in selected:
            writer.writerow(
                {
                    "reference_package": row["reference_package"],
                    "reference_version": row["reference_version"],
                    "reference_architecture": row["reference_architecture"],
                    "source": row["source"],
                    "source_version": row["source_version"],
                    "target_package": row["target_package"],
                    "target_architecture": row["target_architecture"],
                    "disposition": row["disposition"],
                    "match_reason": row["match_reason"],
                    "candidate_version": row["candidate"]["version"],
                    "candidate_sha256": row["candidate"]["sha256"],
                    "repository_filename": row["candidate"]["repository_filename"],
                }
            )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["repository_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
