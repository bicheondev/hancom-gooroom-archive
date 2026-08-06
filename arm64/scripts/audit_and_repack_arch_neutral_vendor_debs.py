#!/usr/bin/env python3
"""Audit exact AMD64 vendor DEBs and repack only architecture-neutral payloads.

The original DEB is authoritative. A repack is produced only when:

* Package, Version, Architecture, size and SHA-256 match the ISO-derived vendor
  binary lock;
* every payload entry is scanned and no x86/foreign native ELF is present;
* the rebuilt package differs in control Architecture only;
* payload paths, file types, modes, uid/gid, symlink targets and regular-file
  SHA-256 values are identical before and after repacking.

This does not pretend that a source package was recovered. It creates a distinct
`exact-binary-payload-repack` authority suitable only for packages whose shipped
payload is already architecture-neutral.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ELF_NAMES = {0: "none", 3: "x86", 40: "arm32", 62: "x86_64", 183: "aarch64", 247: "bpf"}
CONTROL_FIELDS = (
    "Package",
    "Version",
    "Architecture",
    "Source",
    "Depends",
    "Pre-Depends",
    "Recommends",
    "Suggests",
    "Breaks",
    "Conflicts",
    "Replaces",
    "Provides",
    "Multi-Arch",
    "Essential",
    "Section",
    "Priority",
    "Installed-Size",
    "Description",
)


def run(command: list[str], *, check: bool = True, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        **kwargs,
    )
    if check and process.returncode:
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(command)}\n"
            f"stdout:\n{process.stdout[-4000:]}\nstderr:\n{process.stderr[-4000:]}"
        )
    return process


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deb_field(path: Path, field: str) -> str:
    process = run(["dpkg-deb", "-f", str(path), field], check=False)
    return process.stdout.strip() if process.returncode == 0 else ""


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


def tree_manifest(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root))):
        relative = str(path.relative_to(root))
        if relative == "DEBIAN" or relative.startswith("DEBIAN/"):
            continue
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        row: dict[str, Any] = {
            "path": relative,
            "mode": mode,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
        }
        if stat.S_ISREG(metadata.st_mode):
            row.update(type="file", size=metadata.st_size, sha256=sha256_file(path))
        elif stat.S_ISDIR(metadata.st_mode):
            row.update(type="directory")
        elif stat.S_ISLNK(metadata.st_mode):
            row.update(type="symlink", target=os.readlink(path))
        elif stat.S_ISFIFO(metadata.st_mode):
            row.update(type="fifo")
        elif stat.S_ISCHR(metadata.st_mode):
            row.update(type="char", device=metadata.st_rdev)
        elif stat.S_ISBLK(metadata.st_mode):
            row.update(type="block", device=metadata.st_rdev)
        else:
            row.update(type="other", raw_mode=metadata.st_mode)
        rows.append(row)
    return rows


def control_manifest(root: Path) -> dict[str, Any]:
    control_dir = root / "DEBIAN"
    rows: dict[str, Any] = {}
    if not control_dir.exists():
        return rows
    for path in sorted(control_dir.iterdir()):
        if not path.is_file() or path.name == "control":
            continue
        rows[path.name] = {
            "mode": stat.S_IMODE(path.stat().st_mode),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
    return rows


def replace_architecture(control_path: Path) -> tuple[str, str]:
    text = control_path.read_text(encoding="utf-8", errors="strict")
    matches = list(re.finditer(r"^Architecture:\s*(\S+)\s*$", text, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError(f"expected one Architecture field, found {len(matches)}")
    old = matches[0].group(1)
    if old != "amd64":
        raise RuntimeError(f"original control architecture is {old}, not amd64")
    updated = text[: matches[0].start()] + "Architecture: arm64" + text[matches[0].end() :]
    control_path.write_text(updated, encoding="utf-8")
    return text, updated


def locate_deb(directory: Path, package: str, version: str) -> Path:
    matches: list[Path] = []
    for path in directory.rglob("*.deb"):
        if deb_field(path, "Package") == package and deb_field(path, "Version") == version:
            matches.append(path)
    if len(matches) != 1:
        raise RuntimeError(f"{package} {version}: expected one DEB, found {len(matches)}")
    return matches[0]


def vendor_lock_index(document: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in document.get("packages", []):
        key = (row.get("package"), row.get("version"), row.get("architecture"))
        if not all(key):
            continue
        if key in result:
            raise RuntimeError(f"duplicate vendor lock identity: {key}")
        result[key] = row
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--blockers", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--vendor-lock", type=Path, required=True)
    parser.add_argument("--vendor-debs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repack-dir", type=Path, required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("run as root so extracted ownership metadata is preserved")

    blockers = json.loads(args.blockers.read_text(encoding="utf-8"))
    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    vendor_document = json.loads(args.vendor_lock.read_text(encoding="utf-8"))
    vendor_index = vendor_lock_index(vendor_document)
    reference_packages = {
        (row["package"], row["version"]): row for row in reference.get("packages", [])
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.repack_dir.mkdir(parents=True, exist_ok=True)
    source_rows: list[dict[str, Any]] = []

    for blocker in blockers:
        source = blocker["source"]
        source_version = blocker["source_version"]
        if source in {"linux", "qtbase-opensource-src"}:
            continue
        binaries: list[dict[str, Any]] = []
        for package in blocker.get("binary_packages", []):
            reference_row = reference_packages.get((package, next(
                (row["version"] for row in reference.get("packages", [])
                 if row["package"] == package and row["source"] == source
                 and row["source_version"] == source_version),
                "",
            )))
            if not reference_row or reference_row.get("architecture") != "amd64":
                continue
            version = reference_row["version"]
            original = locate_deb(args.vendor_debs, package, version)
            lock_row = vendor_index.get((package, version, "amd64"))
            errors: list[str] = []
            if not lock_row or lock_row.get("status") != "verified":
                errors.append("missing-verified-vendor-lock")
            expected_size = int(lock_row.get("actual_size", -1)) if lock_row else -1
            expected_sha256 = lock_row.get("actual_sha256") if lock_row else None
            actual_size = original.stat().st_size
            actual_sha256 = sha256_file(original)
            if actual_size != expected_size:
                errors.append(f"size-mismatch:{actual_size}!={expected_size}")
            if actual_sha256 != expected_sha256:
                errors.append(f"sha256-mismatch:{actual_sha256}!={expected_sha256}")
            if deb_field(original, "Architecture") != "amd64":
                errors.append("control-architecture-not-amd64")
            if deb_field(original, "Package") != package or deb_field(original, "Version") != version:
                errors.append("control-identity-mismatch")

            with tempfile.TemporaryDirectory(prefix=f"vendor-repack-{package}-") as temporary:
                root = Path(temporary) / "root"
                run(["dpkg-deb", "-R", str(original), str(root)])
                payload_before = tree_manifest(root)
                controls_before = control_manifest(root)
                elf_rows: list[dict[str, Any]] = []
                for item in payload_before:
                    if item["type"] != "file":
                        continue
                    path = root / item["path"]
                    machine = elf_machine(path)
                    if machine is not None:
                        elf_rows.append({
                            "path": item["path"],
                            "machine": machine,
                            "machine_name": ELF_NAMES.get(machine, f"machine-{machine}"),
                            "sha256": item["sha256"],
                            "size": item["size"],
                        })
                architecture_neutral = not elf_rows and not errors
                output_path: Path | None = None
                repack_sha256 = None
                repack_size = None
                payload_after: list[dict[str, Any]] | None = None
                controls_after: dict[str, Any] | None = None
                changed_control_fields: dict[str, Any] = {}
                if architecture_neutral:
                    original_control = {field: deb_field(original, field) for field in CONTROL_FIELDS}
                    control_text_before, control_text_after = replace_architecture(root / "DEBIAN/control")
                    output_path = args.repack_dir / f"{package}_{version}_arm64.deb"
                    run(["dpkg-deb", "--build", "--root-owner-group", str(root), str(output_path)])
                    if deb_field(output_path, "Package") != package:
                        errors.append("repack-package-mismatch")
                    if deb_field(output_path, "Version") != version:
                        errors.append("repack-version-mismatch")
                    if deb_field(output_path, "Architecture") != "arm64":
                        errors.append("repack-architecture-mismatch")
                    repacked_control = {field: deb_field(output_path, field) for field in CONTROL_FIELDS}
                    for field in CONTROL_FIELDS:
                        if original_control[field] != repacked_control[field]:
                            changed_control_fields[field] = {
                                "original": original_control[field],
                                "repacked": repacked_control[field],
                            }
                    if set(changed_control_fields) != {"Architecture"}:
                        errors.append(
                            "unexpected-control-field-changes:"
                            + ",".join(sorted(changed_control_fields))
                        )
                    second_root = Path(temporary) / "second"
                    run(["dpkg-deb", "-R", str(output_path), str(second_root)])
                    payload_after = tree_manifest(second_root)
                    controls_after = control_manifest(second_root)
                    if payload_before != payload_after:
                        errors.append("payload-tree-metadata-or-content-changed")
                    if controls_before != controls_after:
                        errors.append("maintainer-script-or-control-auxiliary-changed")
                    repack_size = output_path.stat().st_size
                    repack_sha256 = sha256_file(output_path)
                    if errors:
                        output_path.unlink(missing_ok=True)
                        output_path = None

            binaries.append({
                "package": package,
                "version": version,
                "original_architecture": "amd64",
                "original_filename": original.name,
                "original_size": actual_size,
                "original_sha256": actual_sha256,
                "vendor_url": lock_row.get("url") if lock_row else None,
                "payload_entry_count": len(payload_before),
                "elf_count": len(elf_rows),
                "elf_files": elf_rows,
                "architecture_neutral": architecture_neutral,
                "changed_control_fields": changed_control_fields,
                "repacked_filename": output_path.name if output_path else None,
                "repacked_size": repack_size if output_path else None,
                "repacked_sha256": repack_sha256 if output_path else None,
                "payload_identity_preserved": bool(output_path and payload_after == payload_before),
                "control_auxiliary_identity_preserved": bool(output_path and controls_after == controls_before),
                "errors": errors,
                "status": "repacked" if output_path else ("native-payload" if elf_rows else "blocked"),
            })

        source_status = "repacked" if binaries and all(row["status"] == "repacked" for row in binaries) else "blocked"
        source_rows.append({
            "source": source,
            "source_version": source_version,
            "role": blocker.get("role"),
            "status": source_status,
            "binary_packages": binaries,
        })

    summary = {
        "schema": 1,
        "policy": "exact-binary-payload-repack-only-when-no-elf-and-payload-identical",
        "source_count": len(source_rows),
        "repacked_source_count": sum(row["status"] == "repacked" for row in source_rows),
        "blocked_source_count": sum(row["status"] != "repacked" for row in source_rows),
        "binary_count": sum(len(row["binary_packages"]) for row in source_rows),
        "repacked_binary_count": sum(
            binary["status"] == "repacked"
            for row in source_rows
            for binary in row["binary_packages"]
        ),
        "native_payload_binary_count": sum(
            binary["status"] == "native-payload"
            for row in source_rows
            for binary in row["binary_packages"]
        ),
    }
    document = {"summary": summary, "sources": source_rows}
    (args.output_dir / "payload-repack-lock.json").write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "blocked.json").write_text(
        json.dumps([row for row in source_rows if row["status"] != "repacked"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
