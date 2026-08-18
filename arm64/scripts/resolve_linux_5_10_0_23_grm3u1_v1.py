#!/usr/bin/env python3
"""Resolve linux-image-5.10.0-23-arm64 5.10.179-1+grm3u1.

The resolver compares the exact Hancom Gooroom AMD64 kernel package with the
matching Debian AMD64 package at the payload level.  Only when every
architecture-relevant payload file is identical may the matching Debian ARM64
package be version-promoted to the Gooroom revision.  Documentation-only
changes are recorded but do not affect the kernel equivalence decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VENDOR_PACKAGE = "linux-image-5.10.0-23-amd64"
ARM64_PACKAGE = "linux-image-5.10.0-23-arm64"
BASE_VERSION = "5.10.179-1"
TARGET_VERSION = "5.10.179-1+grm3u1"


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str
    mode: int
    size: int | None = None
    sha256: str | None = None
    link_target: str | None = None
    file_type: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "path": self.path,
                "kind": self.kind,
                "mode": oct(self.mode),
                "size": self.size,
                "sha256": self.sha256,
                "link_target": self.link_target,
                "file_type": self.file_type,
            }.items()
            if value is not None
        }


def run(arguments: list[str], *, check: bool = True, text: bool = True) -> subprocess.CompletedProcess[Any]:
    result = subprocess.run(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        check=False,
    )
    if check and result.returncode:
        stdout = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", "replace")
        stderr = result.stderr if isinstance(result.stderr, str) else result.stderr.decode("utf-8", "replace")
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(arguments)}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    return result


def deb_field(path: Path, field: str) -> str:
    return run(["dpkg-deb", "-f", str(path), field]).stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_type(path: Path) -> str:
    return run(["file", "-b", str(path)]).stdout.strip()


def extract_deb(deb: Path, destination: Path) -> tuple[Path, Path]:
    root = destination / "root"
    control = destination / "control"
    root.mkdir(parents=True, exist_ok=True)
    control.mkdir(parents=True, exist_ok=True)
    run(["dpkg-deb", "-x", str(deb), str(root)])
    run(["dpkg-deb", "-e", str(deb), str(control)])
    return root, control


def inventory(root: Path) -> dict[str, Entry]:
    entries: dict[str, Entry] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            entries[relative] = Entry(
                path=relative,
                kind="symlink",
                mode=mode,
                link_target=os.readlink(path),
            )
        elif path.is_file():
            entries[relative] = Entry(
                path=relative,
                kind="file",
                mode=mode,
                size=metadata.st_size,
                sha256=sha256_file(path),
                file_type=file_type(path),
            )
        elif path.is_dir():
            entries[relative] = Entry(path=relative, kind="directory", mode=mode)
        else:
            entries[relative] = Entry(path=relative, kind="other", mode=mode)
    return entries


def documentation_path(path: str) -> bool:
    return (
        path.startswith("usr/share/doc/")
        or path.startswith("usr/share/bug/")
        or path.startswith("usr/share/lintian/overrides/")
    )


def compare_inventories(vendor: dict[str, Entry], debian: dict[str, Entry]) -> list[dict[str, Any]]:
    differences: list[dict[str, Any]] = []
    for relative in sorted(set(vendor) | set(debian)):
        left = vendor.get(relative)
        right = debian.get(relative)
        if left == right:
            continue
        record: dict[str, Any] = {
            "path": relative,
            "documentation_only": documentation_path(relative),
        }
        if left is None:
            record["status"] = "debian-only"
            record["debian"] = right.as_json() if right else None
        elif right is None:
            record["status"] = "vendor-only"
            record["vendor"] = left.as_json()
        else:
            record["status"] = "different"
            record["vendor"] = left.as_json()
            record["debian"] = right.as_json()
        differences.append(record)
    return differences


def parse_control(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line
            continue
        if ":" not in line:
            current = None
            continue
        key, value = line.split(":", 1)
        current = key.strip()
        fields[current] = value.strip()
    return fields


def normalized_control(fields: dict[str, str]) -> dict[str, str]:
    ignored = {
        "Version",
        "Installed-Size",
        "Source",
        "Build-Ids",
        "Built-Using",
        "Date",
    }
    return {key: value for key, value in fields.items() if key not in ignored}


def validate_deb(path: Path, package: str, version: str, architecture: str) -> dict[str, Any]:
    observed = {
        "package": deb_field(path, "Package"),
        "version": deb_field(path, "Version"),
        "architecture": deb_field(path, "Architecture"),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }
    expected = {
        "package": package,
        "version": version,
        "architecture": architecture,
    }
    for key, value in expected.items():
        if observed[key] != value:
            raise RuntimeError(f"{path}: expected {key}={value!r}, observed {observed[key]!r}")
    return observed


def replace_control_version(control: Path, version: str) -> None:
    text = control.read_text(encoding="utf-8")
    replaced, count = re.subn(r"(?m)^Version:\s*.*$", f"Version: {version}", text, count=1)
    if count != 1:
        raise RuntimeError(f"could not replace exactly one Version field in {control}")
    provenance_fields = (
        "X-Hancom-Gooroom-Reconstruction: Debian-payload-promoted-after-exact-amd64-equivalence\n"
        f"X-Hancom-Gooroom-Base-Version: {BASE_VERSION}\n"
    )
    if not replaced.endswith("\n"):
        replaced += "\n"
    replaced += provenance_fields
    control.write_text(replaced, encoding="utf-8")


def repack_arm64(debian_arm64: Path, output: Path) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kernel-arm64-repack-") as temporary_directory:
        root = Path(temporary_directory) / "root"
        run(["dpkg-deb", "-R", str(debian_arm64), str(root)])
        replace_control_version(root / "DEBIAN" / "control", TARGET_VERSION)
        run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(output)])
    return validate_deb(output, ARM64_PACKAGE, TARGET_VERSION, "arm64")


def scan_arm64_payload(deb: Path, output: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kernel-arm64-scan-") as temporary_directory:
        root = Path(temporary_directory) / "root"
        run(["dpkg-deb", "-x", str(deb), str(root)])
        rows: list[dict[str, Any]] = []
        forbidden: list[dict[str, Any]] = []
        arm_payloads = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            description = file_type(path)
            relative = path.relative_to(root).as_posix()
            if "ELF " not in description and "PE32" not in description and "ARM64" not in description:
                continue
            row = {"path": relative, "file_type": description}
            rows.append(row)
            lower = description.lower()
            if "x86-64" in lower or "intel 80386" in lower or "i386" in lower:
                forbidden.append(row)
            if "aarch64" in lower or "arm64" in lower:
                arm_payloads += 1
        result = {
            "schema": 1,
            "scanned_binary_payloads": rows,
            "scanned_binary_payload_count": len(rows),
            "arm64_payload_count": arm_payloads,
            "forbidden_payloads": forbidden,
            "forbidden_payload_count": len(forbidden),
            "passed": len(forbidden) == 0 and arm_payloads > 0,
        }
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if not result["passed"]:
            raise RuntimeError("promoted kernel package failed ARM64 payload scan")
        return result


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor-amd64-deb", required=True, type=Path)
    parser.add_argument("--debian-amd64-deb", required=True, type=Path)
    parser.add_argument("--debian-arm64-deb", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--promoted-deb", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    output = arguments.output_directory
    output.mkdir(parents=True, exist_ok=True)

    package_records = {
        "vendor_amd64": validate_deb(
            arguments.vendor_amd64_deb,
            VENDOR_PACKAGE,
            TARGET_VERSION,
            "amd64",
        ),
        "debian_amd64": validate_deb(
            arguments.debian_amd64_deb,
            VENDOR_PACKAGE,
            BASE_VERSION,
            "amd64",
        ),
        "debian_arm64": validate_deb(
            arguments.debian_arm64_deb,
            ARM64_PACKAGE,
            BASE_VERSION,
            "arm64",
        ),
    }

    with tempfile.TemporaryDirectory(prefix="kernel-equivalence-") as temporary_directory:
        temporary = Path(temporary_directory)
        vendor_root, vendor_control_dir = extract_deb(arguments.vendor_amd64_deb, temporary / "vendor")
        debian_root, debian_control_dir = extract_deb(arguments.debian_amd64_deb, temporary / "debian")
        vendor_inventory = inventory(vendor_root)
        debian_inventory = inventory(debian_root)
        differences = compare_inventories(vendor_inventory, debian_inventory)
        substantive = [record for record in differences if not record["documentation_only"]]

        vendor_control = parse_control(vendor_control_dir / "control")
        debian_control = parse_control(debian_control_dir / "control")
        normalized_vendor_control = normalized_control(vendor_control)
        normalized_debian_control = normalized_control(debian_control)
        control_differences = {
            "vendor_only": {
                key: normalized_vendor_control[key]
                for key in sorted(set(normalized_vendor_control) - set(normalized_debian_control))
            },
            "debian_only": {
                key: normalized_debian_control[key]
                for key in sorted(set(normalized_debian_control) - set(normalized_vendor_control))
            },
            "different": {
                key: {
                    "vendor": normalized_vendor_control[key],
                    "debian": normalized_debian_control[key],
                }
                for key in sorted(set(normalized_vendor_control) & set(normalized_debian_control))
                if normalized_vendor_control[key] != normalized_debian_control[key]
            },
        }

    payload_equivalent = len(substantive) == 0
    (output / "payload-differences.json").write_text(
        json.dumps(differences, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "control-differences.json").write_text(
        json.dumps(control_differences, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    promoted_record: dict[str, Any] | None = None
    arm64_scan: dict[str, Any] | None = None
    if payload_equivalent:
        promoted_record = repack_arm64(arguments.debian_arm64_deb, arguments.promoted_deb)
        arm64_scan = scan_arm64_payload(arguments.promoted_deb, output / "arm64-payload-scan.json")

    summary = {
        "schema": 1,
        "source": "linux",
        "base_version": BASE_VERSION,
        "target_version": TARGET_VERSION,
        "target_package": ARM64_PACKAGE,
        "comparison_policy": {
            "authority": "exact-vendor-amd64-payload-versus-exact-debian-amd64-payload",
            "documentation_paths_ignored_for_kernel_equivalence": True,
            "metadata_only_version_promotion_allowed": True,
            "source_archive_recovered": False,
        },
        "packages": package_records,
        "payload_path_count": {
            "vendor": len(vendor_inventory),
            "debian": len(debian_inventory),
        },
        "difference_count": len(differences),
        "documentation_difference_count": len(differences) - len(substantive),
        "substantive_difference_count": len(substantive),
        "substantive_difference_paths": [record["path"] for record in substantive],
        "amd64_payload_equivalent": payload_equivalent,
        "promotion_allowed": payload_equivalent,
        "promoted_package": promoted_record,
        "arm64_payload_scan": arm64_scan,
        "resolution": (
            "promoted-exact-debian-arm64-payload-after-amd64-equivalence"
            if payload_equivalent
            else "blocked-vendor-amd64-payload-differs-from-debian"
        ),
    }
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    checksums: list[str] = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            checksums.append(f"{sha256_file(path)}  {path.relative_to(output).as_posix()}")
    if arguments.promoted_deb.is_file():
        checksums.append(f"{sha256_file(arguments.promoted_deb)}  ../{arguments.promoted_deb.name}")
    (output / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))
    return 0 if payload_equivalent else 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise
    except Exception as error:
        print(f"fatal: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
