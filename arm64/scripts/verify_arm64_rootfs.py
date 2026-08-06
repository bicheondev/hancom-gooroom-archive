#!/usr/bin/env python3
"""Verify an assembled Hancom Gooroom package-layer rootfs fail closed."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import subprocess
from pathlib import Path
from typing import Any, Iterable


ELF_MACHINES = {
    0: "none",
    3: "x86",
    40: "arm32",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
    247: "bpf",
}
ALLOWED_NON_HOST_ELF = {0, 247}


def load_json(path: Path) -> dict[str, Any]:
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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elf_machine(path: Path) -> int | None:
    try:
        with path.open("rb") as handle:
            header = handle.read(20)
    except (OSError, PermissionError):
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    if header[5] == 1:
        return struct.unpack("<H", header[18:20])[0]
    if header[5] == 2:
        return struct.unpack(">H", header[18:20])[0]
    return -1


def expected_packages(materialization: dict[str, Any]) -> dict[str, dict[str, Any]]:
    expected: dict[str, dict[str, Any]] = {}
    for row in materialization.get("verified_packages", []):
        control = row.get("control") or {}
        package = control.get("package")
        version = control.get("version")
        architecture = control.get("architecture")
        if not package or not version or not architecture:
            continue
        existing = expected.get(package)
        identity = (version, architecture)
        if existing and (existing["version"], existing["architecture"]) != identity:
            raise RuntimeError(
                f"conflicting expected package identities for {package}: "
                f"{existing['version']}/{existing['architecture']} and "
                f"{version}/{architecture}"
            )
        expected[package] = {
            "version": version,
            "architecture": architecture,
            "deb_filename": control.get("filename"),
            "deb_sha256": control.get("sha256"),
        }
    return expected


def installed_packages(rootfs: Path) -> dict[str, dict[str, Any]]:
    status_path = rootfs / "var/lib/dpkg/status"
    if not status_path.exists():
        raise RuntimeError("rootfs has no /var/lib/dpkg/status")
    rows: dict[str, dict[str, Any]] = {}
    for stanza in parse_deb822(status_path.read_text(encoding="utf-8", errors="replace")):
        if not stanza.get("Status", "").startswith("install ok installed"):
            continue
        package = stanza.get("Package")
        if not package:
            continue
        rows[package] = {
            "version": stanza.get("Version", ""),
            "architecture": stanza.get("Architecture", ""),
            "essential": stanza.get("Essential", "").lower() == "yes",
            "status": stanza.get("Status", ""),
        }
    return rows


def kernel_evidence(rootfs: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    boot = rootfs / "boot"
    if not boot.exists():
        return records
    for path in sorted(boot.iterdir()):
        if not path.is_file() or not (
            path.name.startswith("vmlinuz-")
            or path.name.startswith("initrd.img-")
            or path.name.startswith("config-")
        ):
            continue
        process = subprocess.run(
            ["file", "-b", str(path)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        records.append(
            {
                "path": str(path.relative_to(rootfs)),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "file": process.stdout.strip(),
            }
        )
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--materialization", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    materialization = load_json(args.materialization)
    expected = expected_packages(materialization)
    installed = installed_packages(args.rootfs)
    errors: list[str] = []
    warnings: list[str] = []

    missing = sorted(set(expected) - set(installed))
    extra = sorted(set(installed) - set(expected))
    version_mismatches = []
    architecture_mismatches = []
    for package in sorted(set(expected) & set(installed)):
        if expected[package]["version"] != installed[package]["version"]:
            version_mismatches.append(
                {
                    "package": package,
                    "expected": expected[package]["version"],
                    "installed": installed[package]["version"],
                }
            )
        expected_arch = expected[package]["architecture"]
        installed_arch = installed[package]["architecture"]
        if expected_arch != installed_arch:
            architecture_mismatches.append(
                {
                    "package": package,
                    "expected": expected_arch,
                    "installed": installed_arch,
                }
            )

    if missing:
        errors.append(f"missing installed packages: {len(missing)}")
    if extra:
        errors.append(f"unexpected installed packages: {len(extra)}")
    if version_mismatches:
        errors.append(f"package version mismatches: {len(version_mismatches)}")
    if architecture_mismatches:
        errors.append(
            f"package architecture mismatches: {len(architecture_mismatches)}"
        )

    machine_counts: dict[str, int] = {}
    x86_elfs: list[dict[str, Any]] = []
    foreign_elfs: list[dict[str, Any]] = []
    unreadable_files: list[str] = []
    regular_file_count = 0
    total_regular_bytes = 0
    skip_top = {"proc", "sys", "dev", "run", "mnt"}

    for root, directories, files in os.walk(args.rootfs, followlinks=False):
        root_path = Path(root)
        try:
            relative_root = root_path.relative_to(args.rootfs)
        except ValueError:
            continue
        if relative_root.parts and relative_root.parts[0] in skip_top:
            directories[:] = []
            continue
        directories[:] = [
            directory
            for directory in directories
            if not (relative_root == Path(".") and directory in skip_top)
        ]
        for filename in files:
            path = root_path / filename
            try:
                mode = path.lstat().st_mode
            except OSError:
                unreadable_files.append(str(path.relative_to(args.rootfs)))
                continue
            if not stat.S_ISREG(mode):
                continue
            regular_file_count += 1
            try:
                total_regular_bytes += path.stat().st_size
            except OSError:
                pass
            machine = elf_machine(path)
            if machine is None:
                continue
            name = ELF_MACHINES.get(machine, f"machine-{machine}")
            machine_counts[name] = machine_counts.get(name, 0) + 1
            record = {
                "path": str(path.relative_to(args.rootfs)),
                "machine": name,
                "size": path.stat().st_size,
            }
            if machine in {3, 62}:
                x86_elfs.append(record)
            elif machine != 183 and machine not in ALLOWED_NON_HOST_ELF:
                foreign_elfs.append(record)

    if x86_elfs:
        errors.append(f"x86 ELF files remain in ARM64 rootfs: {len(x86_elfs)}")
    if foreign_elfs:
        errors.append(
            f"unsupported foreign-architecture ELF files remain: {len(foreign_elfs)}"
        )
    if unreadable_files:
        warnings.append(f"unreadable files during scan: {len(unreadable_files)}")
    if machine_counts.get("aarch64", 0) == 0:
        errors.append("rootfs contains no AArch64 ELF files")

    kernels = kernel_evidence(args.rootfs)
    kernel_images = [row for row in kernels if row["path"].startswith("boot/vmlinuz-")]
    initrds = [row for row in kernels if row["path"].startswith("boot/initrd.img-")]
    if not kernel_images:
        errors.append("no ARM64 kernel image was found under /boot")
    if not initrds:
        errors.append("no initramfs was found under /boot")

    machine_id = args.rootfs / "etc/machine-id"
    if machine_id.exists() and machine_id.read_text(errors="ignore").strip():
        warnings.append("/etc/machine-id is populated; live-image finalizer must clear it")

    summary = {
        "schema": 1,
        "policy": "exact-dpkg-set-and-no-x86-elf-before-live-overlay",
        "expected_package_count": len(expected),
        "installed_package_count": len(installed),
        "missing_package_count": len(missing),
        "extra_package_count": len(extra),
        "version_mismatch_count": len(version_mismatches),
        "architecture_mismatch_count": len(architecture_mismatches),
        "regular_file_count": regular_file_count,
        "regular_file_bytes": total_regular_bytes,
        "elf_machine_counts": dict(sorted(machine_counts.items())),
        "x86_elf_count": len(x86_elfs),
        "foreign_elf_count": len(foreign_elfs),
        "kernel_image_count": len(kernel_images),
        "initramfs_count": len(initrds),
        "passed": not errors,
    }
    result = {
        "summary": summary,
        "missing_packages": missing,
        "extra_packages": extra,
        "version_mismatches": version_mismatches,
        "architecture_mismatches": architecture_mismatches,
        "x86_elfs": x86_elfs,
        "foreign_elfs": foreign_elfs,
        "unreadable_files": unreadable_files,
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
