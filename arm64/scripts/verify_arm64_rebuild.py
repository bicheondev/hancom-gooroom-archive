#!/usr/bin/env python3
"""Fail-closed verification for one exact-source ARM64 rebuild artifact set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ELF_MACHINE_NAMES = {
    0: "none",
    3: "x86",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
    247: "bpf",
}
SOURCE_FIELD_RE = re.compile(r"^\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deb_field(path: Path, field: str) -> str:
    process = subprocess.run(
        ["dpkg-deb", "-f", str(path), field],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"dpkg-deb failed for {path.name} field {field}: {process.stderr.strip()}"
        )
    return process.stdout.strip()


def parse_source_field(value: str, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, version
    match = SOURCE_FIELD_RE.fullmatch(value)
    if not match:
        return value, version
    return match.group(1), match.group(2) or version


def elf_machine(path: Path) -> int | None:
    try:
        with path.open("rb") as handle:
            header = handle.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    byte_order = header[5]
    if byte_order == 1:
        return struct.unpack("<H", header[18:20])[0]
    if byte_order == 2:
        return struct.unpack(">H", header[18:20])[0]
    return -1


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def expected_native_packages(
    reference: dict[str, Any], source: str, source_version: str
) -> dict[str, str]:
    return {
        row["package"]: row["version"]
        for row in reference.get("packages", [])
        if row.get("source") == source
        and row.get("source_version") == source_version
        and row.get("architecture") == "amd64"
    }


def locate_lock_row(lock: dict[str, Any], source: str, source_version: str) -> dict[str, Any]:
    matches = [
        row
        for row in lock.get("sources", [])
        if row.get("source") == source
        and row.get("source_version") == source_version
        and row.get("status") == "resolved"
        and row.get("selected")
    ]
    if not matches:
        raise RuntimeError(f"no resolved lock for {source} {source_version}")
    identities = {
        (
            row["selected"].get("repository_full_name"),
            row["selected"].get("commit_sha"),
            row["selected"].get("tree_sha"),
        )
        for row in matches
    }
    if len(identities) != 1:
        raise RuntimeError(f"ambiguous exact lock for {source} {source_version}: {identities}")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-version", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lock = load_json(args.lock)
    reference = load_json(args.reference)
    lock_row = locate_lock_row(lock, args.source, args.source_version)
    selected = lock_row["selected"]
    expected = expected_native_packages(reference, args.source, args.source_version)

    errors: list[str] = []
    warnings: list[str] = []
    packages: list[dict[str, Any]] = []
    produced_names: set[str] = set()
    x86_payloads: list[dict[str, Any]] = []
    non_aarch64_elfs: list[dict[str, Any]] = []

    debs = sorted(args.directory.glob("*.deb"))
    if not debs:
        errors.append("no .deb files were produced")

    with tempfile.TemporaryDirectory(prefix="arm64-rebuild-verify-") as temporary:
        temp_root = Path(temporary)
        for index, deb in enumerate(debs):
            package = deb_field(deb, "Package")
            version = deb_field(deb, "Version")
            architecture = deb_field(deb, "Architecture")
            source_field = deb_field(deb, "Source")
            binary_source, binary_source_version = parse_source_field(
                source_field, package, version
            )

            if package in produced_names:
                errors.append(f"duplicate binary package output: {package}")
            produced_names.add(package)
            if architecture not in {"arm64", "all"}:
                errors.append(f"{deb.name}: unexpected architecture {architecture}")
            if binary_source != args.source:
                errors.append(
                    f"{deb.name}: binary Source {binary_source} != {args.source}"
                )
            if binary_source_version != args.source_version:
                errors.append(
                    f"{deb.name}: binary source version {binary_source_version} "
                    f"!= {args.source_version}"
                )
            expected_version = expected.get(package)
            if expected_version is not None and version != expected_version:
                errors.append(
                    f"{deb.name}: version {version} != ISO version {expected_version}"
                )
            elif expected_version is None and version != args.source_version:
                warnings.append(
                    f"extra output {package} has version {version}; source version is "
                    f"{args.source_version}"
                )

            extract_root = temp_root / f"{index:03d}-{package}"
            extract_root.mkdir(parents=True)
            subprocess.run(
                ["dpkg-deb", "-x", str(deb), str(extract_root)], check=True
            )
            payload_entries = 0
            machines: dict[str, int] = {}
            package_x86: list[str] = []
            package_other: list[dict[str, Any]] = []
            for root, _, files in os.walk(extract_root):
                for filename in files:
                    payload_entries += 1
                    path = Path(root) / filename
                    if path.is_symlink():
                        continue
                    machine = elf_machine(path)
                    if machine is None:
                        continue
                    name = ELF_MACHINE_NAMES.get(machine, f"machine-{machine}")
                    machines[name] = machines.get(name, 0) + 1
                    relative = str(path.relative_to(extract_root))
                    if machine in {3, 62}:
                        package_x86.append(relative)
                        x86_payloads.append(
                            {"package": package, "path": relative, "machine": name}
                        )
                    elif machine != 183:
                        record = {"path": relative, "machine": name}
                        package_other.append(record)
                        non_aarch64_elfs.append({"package": package, **record})

            if package_x86:
                errors.append(
                    f"{deb.name}: contains x86 ELF payloads: {', '.join(package_x86[:8])}"
                )
            packages.append(
                {
                    "filename": deb.name,
                    "sha256": sha256_file(deb),
                    "size": deb.stat().st_size,
                    "package": package,
                    "version": version,
                    "architecture": architecture,
                    "source_field": source_field,
                    "parsed_source": binary_source,
                    "parsed_source_version": binary_source_version,
                    "expected_from_iso": package in expected,
                    "payload_entry_count": payload_entries,
                    "elf_machine_counts": machines,
                    "x86_payloads": package_x86,
                    "non_aarch64_elfs": package_other,
                }
            )

    missing = sorted(set(expected) - produced_names)
    if missing:
        errors.append(
            "missing ISO architecture-dependent binary packages: " + ", ".join(missing)
        )

    build_lock_path = args.directory / "build-lock.json"
    build_lock: dict[str, Any] | None = None
    if build_lock_path.exists():
        build_lock = load_json(build_lock_path)
        checks = {
            "source": args.source,
            "source_version": args.source_version,
            "repository": selected.get("repository_full_name"),
            "commit_sha": selected.get("commit_sha"),
            "tree_sha": selected.get("tree_sha"),
            "target_architecture": "arm64",
        }
        for field, expected_value in checks.items():
            if build_lock.get(field) != expected_value:
                errors.append(
                    f"build-lock {field}={build_lock.get(field)!r} "
                    f"!= {expected_value!r}"
                )
    else:
        errors.append("build-lock.json is missing")

    source_evidence_path = args.directory / "source-lock-evidence.json"
    source_evidence: dict[str, Any] | None = None
    if source_evidence_path.exists():
        source_evidence = load_json(source_evidence_path)
        if source_evidence.get("verified_commit_sha") != selected.get("commit_sha"):
            errors.append("verified Git commit does not match the exact source lock")
        if source_evidence.get("verified_tree_sha") != selected.get("tree_sha"):
            errors.append("verified Git tree does not match the exact source lock")
    else:
        errors.append("source-lock-evidence.json is missing")

    result = {
        "schema": 1,
        "policy": "exact-iso-version-native-arm64-no-x86-elf",
        "source": args.source,
        "source_version": args.source_version,
        "repository_full_name": selected.get("repository_full_name"),
        "commit_sha": selected.get("commit_sha"),
        "tree_sha": selected.get("tree_sha"),
        "expected_native_binary_versions": expected,
        "produced_package_count": len(packages),
        "packages": packages,
        "missing_expected_packages": missing,
        "x86_payloads": x86_payloads,
        "non_aarch64_elfs": non_aarch64_elfs,
        "build_lock": build_lock,
        "source_lock_evidence": source_evidence,
        "warnings": warnings,
        "errors": errors,
        "passed": not errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
