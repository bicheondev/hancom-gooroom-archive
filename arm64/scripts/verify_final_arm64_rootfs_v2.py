#!/usr/bin/env python3
"""Verify final ARM64 rootfs against the exact final package authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
from pathlib import Path
from typing import Any, Iterable


SOURCE_RE = re.compile(r"^\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*$")
VENDOR_VERSION_RE = re.compile(r"(?:^|[+~.:-])(?:grm|han)\d", re.IGNORECASE)
MACHINES = {3: "x86", 40: "arm32", 62: "x86_64", 183: "aarch64", 247: "bpf"}


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_deb822(text: str) -> Iterable[dict[str, str]]:
    stanza: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if stanza:
                yield stanza
                stanza = {}
                current = None
            continue
        if line[0].isspace():
            if current:
                stanza[current] += "\n" + line[1:]
            continue
        if ":" not in line:
            continue
        current, value = line.split(":", 1)
        stanza[current] = value.lstrip()
    if stanza:
        yield stanza


def parse_source(value: str | None, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, version
    match = SOURCE_RE.fullmatch(value)
    if not match:
        return value, version
    return match.group(1), match.group(2) or version


def installed(rootfs: Path) -> dict[str, dict[str, Any]]:
    status = rootfs / "var/lib/dpkg/status"
    if not status.exists():
        raise RuntimeError("rootfs has no dpkg status database")
    result = {}
    for stanza in parse_deb822(status.read_text(encoding="utf-8", errors="replace")):
        if stanza.get("Status") != "install ok installed":
            continue
        package = stanza.get("Package")
        version = stanza.get("Version")
        architecture = stanza.get("Architecture")
        if not package or not version or not architecture:
            continue
        source, source_version = parse_source(
            stanza.get("Source"), package, version
        )
        result[package] = {
            "package": package,
            "version": version,
            "architecture": architecture,
            "source": source,
            "source_version": source_version,
            "essential": stanza.get("Essential", "").lower() == "yes",
        }
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def expected_packages(authority: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for route in authority.get("selected_routes", []):
        package = route["target_package"]
        identity = {
            "version": route["target_version"],
            "architecture": route["target_architecture"],
            "mapping_status": route["mapping_status"],
            "reference_packages": [route["reference_package"]],
            "reference_versions": [route["reference_version"]],
            "source": route["source"],
            "source_version": route["source_version"],
            "require_source_identity": bool(route["require_source_identity"]),
        }
        if package in result:
            existing = result[package]
            if (
                existing["version"] != identity["version"]
                or existing["architecture"] != identity["architecture"]
            ):
                raise RuntimeError(f"conflicting expected target package: {package}")
            existing["reference_packages"].append(route["reference_package"])
            existing["reference_versions"].append(route["reference_version"])
        else:
            result[package] = identity
    return result


def kernel_evidence(rootfs: Path) -> list[dict[str, Any]]:
    rows = []
    boot = rootfs / "boot"
    if not boot.exists():
        return rows
    for path in sorted(boot.iterdir()):
        if not path.is_file() or not path.name.startswith(
            ("vmlinuz-", "initrd.img-", "config-", "System.map-")
        ):
            continue
        process = subprocess.run(
            ["file", "-b", str(path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        rows.append(
            {
                "path": str(path.relative_to(rootfs)),
                "size": path.stat().st_size,
                "sha256": sha256(path),
                "file": process.stdout.strip(),
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    authority = load(args.authority)
    if authority.get("summary", {}).get("final_repository_ready") is not True:
        raise SystemExit("final package authority is not ready")
    expected = expected_packages(authority)
    actual = installed(args.rootfs)
    errors: list[str] = []
    warnings: list[str] = []

    missing = sorted(set(expected) - set(actual))
    mismatches = []
    for package in sorted(set(expected) & set(actual)):
        want = expected[package]
        have = actual[package]
        package_errors = []
        if have["version"] != want["version"]:
            package_errors.append(
                f"version {have['version']} != {want['version']}"
            )
        if have["architecture"] != want["architecture"]:
            package_errors.append(
                f"architecture {have['architecture']} != {want['architecture']}"
            )
        if want["require_source_identity"]:
            if have["source"] != want["source"]:
                package_errors.append(
                    f"source {have['source']} != {want['source']}"
                )
            if have["source_version"] != want["source_version"]:
                package_errors.append(
                    f"source version {have['source_version']} != {want['source_version']}"
                )
        if package_errors:
            mismatches.append(
                {"package": package, "expected": want, "installed": have, "errors": package_errors}
            )

    extras = []
    forbidden_extras = []
    for package in sorted(set(actual) - set(expected)):
        row = actual[package]
        allowed = (
            row["architecture"] in {"arm64", "all"}
            and not VENDOR_VERSION_RE.search(row["version"])
            and not VENDOR_VERSION_RE.search(row["source_version"])
        )
        record = {**row, "classification": "arm64-dependency-addition" if allowed else "forbidden-extra"}
        extras.append(record)
        if not allowed:
            forbidden_extras.append(record)

    excluded_installed = []
    for excluded in authority.get("excluded_reference_packages", []):
        package = excluded["reference_package"]
        if package in actual:
            excluded_installed.append(
                {"exclusion": excluded, "installed": actual[package]}
            )

    if missing:
        errors.append(f"missing expected target packages: {len(missing)}")
    if mismatches:
        errors.append(f"target package identity mismatches: {len(mismatches)}")
    if forbidden_extras:
        errors.append(f"forbidden extra packages: {len(forbidden_extras)}")
    if excluded_installed:
        errors.append(
            f"architecture-excluded reference packages are installed: {len(excluded_installed)}"
        )
    if extras and not forbidden_extras:
        warnings.append(
            f"ARM64 dependency additions installed from dated Debian snapshot: {len(extras)}"
        )

    x86_elfs = []
    foreign_elfs = []
    machine_counts: dict[str, int] = defaultdict(int)
    regular_count = 0
    regular_bytes = 0
    skip_roots = {"proc", "sys", "dev", "run", "mnt"}
    for walk_root, directories, files in os.walk(args.rootfs, followlinks=False):
        root = Path(walk_root)
        relative_root = root.relative_to(args.rootfs)
        if relative_root.parts and relative_root.parts[0] in skip_roots:
            directories[:] = []
            continue
        if relative_root == Path("."):
            directories[:] = [directory for directory in directories if directory not in skip_roots]
        for filename in files:
            path = root / filename
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            if not stat.S_ISREG(mode):
                continue
            regular_count += 1
            try:
                regular_bytes += path.stat().st_size
            except OSError:
                pass
            machine = elf_machine(path)
            if machine is None:
                continue
            name = MACHINES.get(machine, f"machine-{machine}")
            machine_counts[name] += 1
            record = {
                "path": str(path.relative_to(args.rootfs)),
                "machine": name,
                "size": path.stat().st_size,
            }
            if machine in {3, 62}:
                x86_elfs.append(record)
            elif machine not in {0, 183, 247}:
                foreign_elfs.append(record)
    if x86_elfs:
        errors.append(f"x86 ELF payloads remain: {len(x86_elfs)}")
    if foreign_elfs:
        errors.append(f"unsupported foreign ELF payloads remain: {len(foreign_elfs)}")
    if machine_counts.get("aarch64", 0) == 0:
        errors.append("rootfs contains no AArch64 ELF")

    kernels = kernel_evidence(args.rootfs)
    kernel_images = [row for row in kernels if row["path"].startswith("boot/vmlinuz-")]
    initrds = [row for row in kernels if row["path"].startswith("boot/initrd.img-")]
    if not kernel_images:
        errors.append("no kernel image under /boot")
    if not initrds:
        errors.append("no initramfs under /boot")

    summary = {
        "schema": 2,
        "policy": "final-package-authority-plus-dated-arm64-dependency-additions",
        "expected_target_package_count": len(expected),
        "installed_package_count": len(actual),
        "missing_count": len(missing),
        "mismatch_count": len(mismatches),
        "arm64_dependency_addition_count": len(extras) - len(forbidden_extras),
        "forbidden_extra_count": len(forbidden_extras),
        "excluded_installed_count": len(excluded_installed),
        "elf_machine_counts": dict(sorted(machine_counts.items())),
        "x86_elf_count": len(x86_elfs),
        "foreign_elf_count": len(foreign_elfs),
        "regular_file_count": regular_count,
        "regular_file_bytes": regular_bytes,
        "kernel_image_count": len(kernel_images),
        "initramfs_count": len(initrds),
        "passed": not errors,
    }
    result = {
        "summary": summary,
        "missing_packages": missing,
        "mismatches": mismatches,
        "extra_packages": extras,
        "forbidden_extra_packages": forbidden_extras,
        "excluded_installed": excluded_installed,
        "x86_elfs": x86_elfs,
        "foreign_elfs": foreign_elfs,
        "kernel_evidence": kernels,
        "warnings": warnings,
        "errors": errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if summary["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
