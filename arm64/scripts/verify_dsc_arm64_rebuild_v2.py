#!/usr/bin/env python3
"""Verify ARM64 DEBs built from an exact signed vendor .dsc lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any


SOURCE_RE = re.compile(r"^\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*$")
MACHINES = {3: "x86", 40: "arm32", 62: "x86_64", 183: "aarch64", 247: "bpf"}


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def field(path: Path, name: str) -> str:
    process = subprocess.run(
        ["dpkg-deb", "-f", str(path), name],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode:
        return ""
    return process.stdout.strip()


def parse_source(value: str, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, version
    match = SOURCE_RE.fullmatch(value)
    if not match:
        return value, version
    return match.group(1), match.group(2) or version


def elf_machine(path: Path) -> int | None:
    try:
        header = path.read_bytes()[:20]
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    if header[5] == 1:
        return struct.unpack("<H", header[18:20])[0]
    if header[5] == 2:
        return struct.unpack(">H", header[18:20])[0]
    return -1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-version", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lock = load(args.lock)
    reference = load(args.reference)
    matches = [
        row
        for row in lock.get("sources", [])
        if row.get("source") == args.source
        and row.get("source_version") == args.source_version
        and row.get("status") == "resolved"
        and (row.get("selected") or {}).get("type") == "dsc"
    ]
    errors: list[str] = []
    if len(matches) != 1:
        errors.append(f"expected one exact DSC lock, found {len(matches)}")
        selected: dict[str, Any] = {}
    else:
        selected = matches[0]["selected"]
        if selected.get("signature_valid") is not True:
            errors.append("DSC signature was not verified in the source lock")
        if selected.get("declared_source") != args.source:
            errors.append("locked DSC source name mismatch")
        if selected.get("declared_version") != args.source_version:
            errors.append("locked DSC source version mismatch")

    expected = {
        row["package"]: row["version"]
        for row in reference.get("packages", [])
        if row.get("source") == args.source
        and row.get("source_version") == args.source_version
        and row.get("architecture") == "amd64"
    }
    if not expected:
        errors.append("reference contains no architecture-dependent binary package")

    package_records: list[dict[str, Any]] = []
    produced: set[str] = set()
    x86_payloads: list[dict[str, Any]] = []
    foreign_payloads: list[dict[str, Any]] = []
    debs = sorted(args.directory.glob("*.deb"))
    if not debs:
        errors.append("no DEB output was produced")

    with tempfile.TemporaryDirectory(prefix="verify-dsc-arm64-") as temporary:
        temp = Path(temporary)
        for index, deb in enumerate(debs):
            package = field(deb, "Package")
            version = field(deb, "Version")
            architecture = field(deb, "Architecture")
            source_field = field(deb, "Source")
            source, source_version = parse_source(source_field, package, version)
            record: dict[str, Any] = {
                "filename": deb.name,
                "size": deb.stat().st_size,
                "sha256": sha256(deb),
                "package": package,
                "version": version,
                "architecture": architecture,
                "source": source,
                "source_version": source_version,
                "elf_machine_counts": {},
                "x86_payloads": [],
                "foreign_payloads": [],
            }
            if not package:
                errors.append(f"{deb.name}: missing Package field")
                package_records.append(record)
                continue
            if package in produced:
                errors.append(f"duplicate binary package: {package}")
            produced.add(package)
            if architecture not in {"arm64", "all"}:
                errors.append(f"{deb.name}: unexpected architecture {architecture}")
            if package in expected and architecture != "arm64":
                errors.append(f"{deb.name}: required native package is not arm64")
            if source != args.source:
                errors.append(f"{deb.name}: Source {source} != {args.source}")
            if source_version != args.source_version:
                errors.append(
                    f"{deb.name}: source version {source_version} != {args.source_version}"
                )
            if package in expected and version != expected[package]:
                errors.append(
                    f"{deb.name}: version {version} != ISO version {expected[package]}"
                )

            root = temp / f"{index:03d}-{package}"
            root.mkdir()
            subprocess.run(["dpkg-deb", "-x", str(deb), str(root)], check=True)
            counts: dict[str, int] = {}
            for walk_root, _, files in os.walk(root):
                for name in files:
                    path = Path(walk_root) / name
                    if path.is_symlink():
                        continue
                    machine = elf_machine(path)
                    if machine is None:
                        continue
                    machine_name = MACHINES.get(machine, f"machine-{machine}")
                    counts[machine_name] = counts.get(machine_name, 0) + 1
                    relative = str(path.relative_to(root))
                    payload = {"package": package, "path": relative, "machine": machine_name}
                    if machine in {3, 62}:
                        record["x86_payloads"].append(relative)
                        x86_payloads.append(payload)
                    elif machine not in {0, 183, 247}:
                        record["foreign_payloads"].append(
                            {"path": relative, "machine": machine_name}
                        )
                        foreign_payloads.append(payload)
            record["elf_machine_counts"] = counts
            package_records.append(record)

    missing = sorted(set(expected) - produced)
    if missing:
        errors.append("missing required native packages: " + ", ".join(missing))
    if x86_payloads:
        errors.append(f"x86 ELF payload count: {len(x86_payloads)}")
    if foreign_payloads:
        errors.append(f"foreign ELF payload count: {len(foreign_payloads)}")

    build_lock_path = args.directory / "build-lock.json"
    build_lock = load(build_lock_path) if build_lock_path.exists() else None
    if not build_lock:
        errors.append("build-lock.json is missing")
    else:
        checks = {
            "source": args.source,
            "source_version": args.source_version,
            "provenance": "vendor-apt-exact-signed-dsc",
            "dsc_sha256": selected.get("dsc_sha256"),
            "target_architecture": "arm64",
        }
        for key, expected_value in checks.items():
            if build_lock.get(key) != expected_value:
                errors.append(
                    f"build-lock {key}={build_lock.get(key)!r} != {expected_value!r}"
                )

    result = {
        "schema": 1,
        "policy": "exact-signed-dsc-version-and-no-x86-elf",
        "source": args.source,
        "source_version": args.source_version,
        "dsc_sha256": selected.get("dsc_sha256"),
        "expected_native_binary_versions": expected,
        "packages": package_records,
        "missing_packages": missing,
        "x86_payloads": x86_payloads,
        "foreign_payloads": foreign_payloads,
        "build_lock": build_lock,
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
