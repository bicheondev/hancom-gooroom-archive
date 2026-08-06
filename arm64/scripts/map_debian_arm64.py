#!/usr/bin/env python3
"""Map the AMD64 binary lock to source-identical Debian ARM64 packages.

Exact binary versions are preferred. A different terminal Debian binNMU suffix
(`+bN`) is accepted only when the source package name and source version are
identical to the AMD64 reference; binNMU numbers are architecture-specific.
"""

from __future__ import annotations

import argparse
import csv
import functools
import json
import re
import subprocess
from pathlib import Path
from typing import Any


REPLACE = {
    "binutils-x86-64-linux-gnu": (
        "binutils-aarch64-linux-gnu",
        "AArch64 binutils replacement",
    ),
    "grub-pc": ("grub-efi-arm64", "ARM64 UEFI bootloader replacement"),
    "grub-pc-bin": ("grub-efi-arm64-bin", "ARM64 UEFI modules replacement"),
}

OMIT = {
    "amd64-microcode": "x86-64 CPU microcode is not applicable to ARM64",
    "intel-microcode": "Intel CPU microcode is not applicable to ARM64",
    "iucode-tool": "Intel microcode utility is not applicable to ARM64",
    "libdrm-intel1": "Intel-only DRM userspace driver is not built for ARM64",
    "libmfx1": "Intel Media SDK runtime is not built for ARM64; ARM64 dependants are built without it",
    "libquadmath0": "GCC quadmath runtime is not built for Debian ARM64; ARM64 libgfortran has architecture-specific dependencies",
    "libxatracker2": "XA tracker is not built for Debian ARM64 and is only pulled by the omitted VMware Xorg driver",
    "xserver-xorg-video-intel": "Intel-only Xorg driver is not applicable to ARM64",
    "xserver-xorg-video-vmware": "x86 VMware Xorg driver is not applicable to the ARM64 virtio-gpu target",
}

CUSTOM_REPLACE = {
    "linux-image-5.10.0-23-amd64": (
        "linux-image-5.10.0-23-arm64",
        "rebuild the exact linux 5.10.179-1+grm3u1 source for ARM64",
    ),
    "linux-image-amd64": (
        "linux-image-arm64",
        "replace the AMD64 kernel metapackage after the exact kernel rebuild",
    ),
}

BINNMU_RE = re.compile(r"\+b\d+$")
SOURCE_RE = re.compile(r"^\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*$")


def strip_binnmu(version: str) -> str:
    return BINNMU_RE.sub("", version)


def parse_stanzas(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if current:
                rows.append(current)
                current = {}
                key = None
            continue
        if line[0].isspace() and key:
            current[key] += "\n" + line[1:]
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        current[key] = value.lstrip()
    if current:
        rows.append(current)
    return rows


def record_source(record: dict[str, str], package_name: str) -> tuple[str, str]:
    binary_version = record.get("Version", "")
    value = record.get("Source")
    if not value:
        return package_name, strip_binnmu(binary_version)
    match = SOURCE_RE.fullmatch(value)
    if not match:
        return value.strip(), strip_binnmu(binary_version)
    return match.group(1), match.group(2) or strip_binnmu(binary_version)


def query_records(conf: Path, package_name: str) -> tuple[list[dict[str, str]], str]:
    process = subprocess.run(
        ["apt-cache", "-c", str(conf), "show", f"{package_name}:arm64"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode:
        return [], process.stderr.strip()
    records = [
        record
        for record in parse_stanzas(process.stdout)
        if record.get("Architecture") in {"arm64", "all"}
    ]
    return records, ""


def debian_version_cmp(left: str, right: str) -> int:
    if left == right:
        return 0
    process = subprocess.run(
        ["dpkg", "--compare-versions", left, "gt", right], check=False
    )
    return 1 if process.returncode == 0 else -1


def select_package(
    conf: Path,
    package_name: str,
    wanted_binary_version: str,
    wanted_source: str,
    wanted_source_version: str,
) -> tuple[str | None, str, str]:
    records, error = query_records(conf, package_name)
    exact: list[dict[str, str]] = []
    source_equal: list[dict[str, str]] = []

    for record in records:
        source_name, source_version = record_source(record, package_name)
        if (source_name, source_version) != (wanted_source, wanted_source_version):
            continue
        version = record.get("Version", "")
        if version == wanted_binary_version:
            exact.append(record)
        elif strip_binnmu(version) == strip_binnmu(wanted_binary_version):
            source_equal.append(record)

    if exact:
        return wanted_binary_version, "exact", ""
    if source_equal:
        source_equal.sort(
            key=functools.cmp_to_key(
                lambda left, right: debian_version_cmp(
                    left.get("Version", ""), right.get("Version", "")
                )
            ),
            reverse=True,
        )
        selected = source_equal[0].get("Version", "")
        return selected, "source-exact-binnmu", ""
    return None, "missing", error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--apt-config", type=Path, required=True)
    parser.add_argument("--snapshot", action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    custom = {
        (source["source"], source["source_version"])
        for source in reference["sources"]
        if source.get("custom_candidate")
    }
    rows: list[dict[str, Any]] = []

    for package in sorted(reference["packages"], key=lambda item: item["package"]):
        row: dict[str, Any] = {
            "package": package["package"],
            "amd64_version": package["version"],
            "amd64_architecture": package["architecture"],
            "source": package["source"],
            "source_version": package["source_version"],
            "arm64_package": "",
            "arm64_version": "",
            "status": "",
            "reason": "",
        }

        if package["architecture"] == "all":
            row.update(
                status="reuse-exact-all",
                arm64_package=package["package"],
                arm64_version=package["version"],
                reason="Architecture: all payload is preserved from the AMD64 reference",
            )
        elif package["package"] in CUSTOM_REPLACE:
            replacement, reason = CUSTOM_REPLACE[package["package"]]
            row.update(
                status="custom-arch-replace",
                arm64_package=replacement,
                arm64_version=package["version"],
                reason=reason,
            )
        elif (package["source"], package["source_version"]) in custom:
            row.update(
                status="custom-rebuild",
                arm64_package=package["package"],
                arm64_version=package["version"],
                reason="exact +grm/+han source commit must be rebuilt for ARM64",
            )
        elif package["package"] in OMIT:
            row.update(status="arch-omit", reason=OMIT[package["package"]])
        else:
            replacement = package["package"]
            reason_prefix = ""
            replacement_status = ""
            if package["package"] in REPLACE:
                replacement, reason_prefix = REPLACE[package["package"]]
                replacement_status = "arch-replace-"

            selected, mode, error = select_package(
                args.apt_config,
                replacement,
                package["version"],
                package["source"],
                package["source_version"],
            )
            row["arm64_package"] = replacement
            if selected is None:
                row.update(
                    status="missing-arch-replacement"
                    if replacement_status
                    else "missing-exact-arm64",
                    arm64_version=package["version"],
                    reason=(reason_prefix + "; " if reason_prefix else "")
                    + "no ARM64 binary from the exact Debian source version"
                    + (f": {error}" if error else ""),
                )
            elif mode == "exact":
                row.update(
                    status="exact-arch-replace" if replacement_status else "exact-arm64",
                    arm64_version=selected,
                    reason=(reason_prefix + "; " if reason_prefix else "")
                    + "exact binary and source version found",
                )
            else:
                row.update(
                    status="source-exact-arch-binnmu"
                    if replacement_status
                    else "source-exact-binnmu",
                    arm64_version=selected,
                    reason=(reason_prefix + "; " if reason_prefix else "")
                    + "source version is exact; terminal +bN differs by architecture",
                )
        rows.append(row)

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    summary = {
        "schema": 2,
        "snapshots": args.snapshot,
        "package_count": len(rows),
        "status_counts": dict(sorted(counts.items())),
        "strict_unresolved_count": sum(
            count for status, count in counts.items() if status.startswith("missing-")
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "debian-arm64-map.json").write_text(
        json.dumps({"summary": summary, "packages": rows}, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "debian-arm64-map-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    unresolved = [row for row in rows if row["status"].startswith("missing-")]
    (args.output_dir / "debian-arm64-unresolved.json").write_text(
        json.dumps(unresolved, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    with (args.output_dir / "debian-arm64-map.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)

    print(json.dumps(summary, indent=2))
    return 2 if unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main())
