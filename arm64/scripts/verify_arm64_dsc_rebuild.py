#!/usr/bin/env python3
"""Verify ARM64 binary packages built from an exact signed DSC authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any


AARCH64_ELF_MACHINE = 183
SOURCE_FIELD_RE = re.compile(r"^\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*$")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deb_field(path: Path, field: str) -> str:
    process = subprocess.run(
        ["dpkg-deb", "-f", str(path), field],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return process.stdout.strip()


def parse_source_field(value: str, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, version
    match = SOURCE_FIELD_RE.fullmatch(value)
    if not match:
        return value.strip(), version
    return match.group(1), match.group(2) or version


def elf_machine(path: Path) -> int | None:
    try:
        with path.open("rb") as handle:
            header = handle.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    data_encoding = header[5]
    if data_encoding == 1:
        return struct.unpack("<H", header[18:20])[0]
    if data_encoding == 2:
        return struct.unpack(">H", header[18:20])[0]
    return -1


def normalized_files(rows: list[dict[str, Any]]) -> list[tuple[str, int, str]]:
    return sorted(
        (
            str(row.get("filename", "")),
            int(row.get("size", -1)),
            str(row.get("sha256", "")).lower(),
        )
        for row in rows
    )


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
    matches = [
        row
        for row in lock.get("sources", [])
        if row.get("source") == args.source
        and row.get("source_version") == args.source_version
        and row.get("status") == "resolved"
        and isinstance(row.get("selected"), dict)
        and row["selected"].get("type") == "dsc"
    ]
    errors: list[str] = []
    warnings: list[str] = []
    if len(matches) != 1:
        errors.append(
            f"expected one exact DSC source lock, found {len(matches)}"
        )
        selected: dict[str, Any] = {}
    else:
        selected = matches[0]["selected"]

    if selected:
        if selected.get("signature_verified") is not True:
            errors.append("selected DSC authority is not signature-verified")
        if selected.get("signed_source") != args.source:
            errors.append("selected DSC signed Source does not match")
        if selected.get("signed_version") != args.source_version:
            errors.append("selected DSC signed Version does not match")
        if not isinstance(selected.get("dsc"), dict):
            errors.append("selected DSC authority has no DSC record")
        if not selected.get("files"):
            errors.append("selected DSC authority has no source payload files")

    reference_packages = [
        row
        for row in reference.get("packages", [])
        if row.get("source") == args.source
        and row.get("source_version") == args.source_version
    ]
    required_native = sorted(
        {
            row["package"]
            for row in reference_packages
            if row.get("architecture") == "amd64"
        }
    )
    reference_versions = {
        row["package"]: row["version"] for row in reference_packages
    }
    if not required_native:
        errors.append("reference contains no AMD64-native binary package for this source")

    build_lock_path = args.directory / "build-lock.json"
    source_evidence_path = args.directory / "source-lock-evidence.json"
    if not build_lock_path.exists():
        errors.append("build-lock.json is missing")
        build_lock: dict[str, Any] = {}
    else:
        build_lock = load_json(build_lock_path)
    if not source_evidence_path.exists():
        errors.append("source-lock-evidence.json is missing")
        source_evidence: dict[str, Any] = {}
    else:
        source_evidence = load_json(source_evidence_path)

    selected_dsc = selected.get("dsc", {}) if selected else {}
    selected_files = selected.get("files", []) if selected else []
    for document_name, document in (
        ("build lock", build_lock),
        ("source evidence", source_evidence),
    ):
        if document:
            if document.get("source_type") != "dsc":
                errors.append(f"{document_name} source_type is not dsc")
            if document.get("source") != args.source:
                errors.append(f"{document_name} Source does not match")
            if document.get("source_version") != args.source_version:
                errors.append(f"{document_name} Version does not match")

    if build_lock:
        build_dsc = build_lock.get("dsc", {})
        if build_dsc.get("sha256") != selected_dsc.get("sha256"):
            errors.append("build lock DSC SHA-256 does not match selected authority")
        if normalized_files(build_lock.get("source_files", [])) != normalized_files(
            selected_files
        ):
            errors.append("build lock source payload list does not match selected authority")
        if build_lock.get("target_architecture") != "arm64":
            errors.append("build lock target architecture is not arm64")

    if source_evidence:
        evidence_dsc = source_evidence.get("dsc", {})
        if evidence_dsc.get("sha256") != selected_dsc.get("sha256"):
            errors.append("source evidence DSC SHA-256 does not match selected authority")
        if normalized_files(source_evidence.get("files", [])) != normalized_files(
            selected_files
        ):
            errors.append("source evidence payload list does not match selected authority")
        if source_evidence.get("dsc_signature_valid") is not True:
            errors.append("source evidence does not record a valid DSC signature")
        if not re.fullmatch(
            r"[0-9a-f]{64}",
            str(source_evidence.get("source_key_bundle_sha256", "")),
        ):
            errors.append("source evidence has no valid source-key bundle SHA-256")

    deb_paths = sorted(args.directory.glob("*.deb"))
    if not deb_paths:
        errors.append("no .deb package was produced")

    package_rows: list[dict[str, Any]] = []
    produced_native: dict[str, list[dict[str, Any]]] = {}
    for deb in deb_paths:
        try:
            package = deb_field(deb, "Package")
            version = deb_field(deb, "Version")
            architecture = deb_field(deb, "Architecture")
            source_field = deb_field(deb, "Source")
        except subprocess.CalledProcessError as exception:
            errors.append(f"cannot read control metadata from {deb.name}: {exception}")
            continue
        source, source_version = parse_source_field(source_field, package, version)
        row = {
            "filename": deb.name,
            "size": deb.stat().st_size,
            "sha256": sha256_file(deb),
            "package": package,
            "version": version,
            "architecture": architecture,
            "source_field": source_field,
            "parsed_source": source,
            "parsed_source_version": source_version,
            "elf_machine_counts": {},
        }
        if version != args.source_version:
            errors.append(
                f"{deb.name}: Version {version} != exact source version {args.source_version}"
            )
        if architecture not in {"arm64", "all"}:
            errors.append(f"{deb.name}: unexpected architecture {architecture}")
        if source != args.source:
            errors.append(f"{deb.name}: Source {source} != {args.source}")
        if source_version != args.source_version:
            errors.append(
                f"{deb.name}: Source version {source_version} != {args.source_version}"
            )
        expected_binary_version = reference_versions.get(package)
        if expected_binary_version and version != expected_binary_version:
            errors.append(
                f"{deb.name}: binary version {version} != AMD64 reference {expected_binary_version}"
            )

        with tempfile.TemporaryDirectory(prefix="arm64-dsc-deb-") as temporary:
            root = Path(temporary)
            process = subprocess.run(
                ["dpkg-deb", "-x", str(deb), str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if process.returncode != 0:
                errors.append(f"{deb.name}: dpkg-deb extraction failed")
            else:
                counts: dict[int, int] = {}
                for path in root.rglob("*"):
                    if not path.is_file() or path.is_symlink():
                        continue
                    machine = elf_machine(path)
                    if machine is None:
                        continue
                    counts[machine] = counts.get(machine, 0) + 1
                    if machine != AARCH64_ELF_MACHINE:
                        errors.append(
                            f"{deb.name}: foreign ELF machine {machine} at {path.relative_to(root)}"
                        )
                row["elf_machine_counts"] = {
                    str(machine): count for machine, count in sorted(counts.items())
                }

        package_rows.append(row)
        if architecture == "arm64":
            produced_native.setdefault(package, []).append(row)

    for package in required_native:
        rows = produced_native.get(package, [])
        if len(rows) != 1:
            errors.append(
                f"required ARM64 package {package}: expected one output, found {len(rows)}"
            )
    extra_native = sorted(set(produced_native) - set(required_native))
    if extra_native:
        warnings.append(
            "additional architecture-dependent packages were built: "
            + ", ".join(extra_native)
        )

    if (args.directory / "SHA256SUMS").exists():
        process = subprocess.run(
            ["sha256sum", "--check", "SHA256SUMS"],
            cwd=args.directory,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.returncode != 0:
            errors.append("SHA256SUMS verification failed")
    else:
        warnings.append("SHA256SUMS is missing")

    summary = {
        "schema": 1,
        "source_type": "dsc",
        "source": args.source,
        "source_version": args.source_version,
        "required_native_packages": required_native,
        "produced_deb_count": len(package_rows),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "passed": not errors,
    }
    result = {
        **summary,
        "selected_authority": selected,
        "packages": package_rows,
        "errors": errors,
        "warnings": warnings,
        "build_lock": build_lock,
        "source_lock_evidence": source_evidence,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
