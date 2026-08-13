#!/usr/bin/env python3
"""Verify native ARM64 packages built from the reconstructed gooroom-guide tree."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

SOURCE = "gooroom-guide"
VERSION = "0.5.3+grm3u1+han3u1"
ELF_MAGIC = b"\x7fELF"
AARCH64_LOADER = "ld-linux-aarch64.so.1"


def run(arguments: list[str]) -> str:
    completed = subprocess.run(
        arguments,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n{completed.stdout}"
        )
    return completed.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def is_elf(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open("rb") as stream:
        return stream.read(4) == ELF_MAGIC


def deb_field(deb: Path, field: str) -> str:
    completed = subprocess.run(
        ["dpkg-deb", "-f", str(deb), field],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def parse_source(value: str, package: str) -> str:
    if value:
        return value.split(" ", 1)[0]
    return package.removesuffix("-dbgsym")


def elf_header(path: Path) -> dict[str, str]:
    result = {"machine": "", "type": ""}
    for line in run(["readelf", "-hW", str(path)]).splitlines():
        if line.lstrip().startswith("Machine:"):
            result["machine"] = line.split(":", 1)[1].strip()
        elif line.lstrip().startswith("Type:"):
            result["type"] = line.split(":", 1)[1].strip().split()[0]
    return result


def elf_interpreter(path: Path) -> str | None:
    output = run(["readelf", "-lW", str(path)])
    match = re.search(r"Requesting program interpreter:\s*([^]]+)\]", output)
    return match.group(1).strip() if match else None


def dynamic_identity(path: Path) -> dict[str, list[str]]:
    output = run(["readelf", "-dW", str(path)])
    return {
        "needed": re.findall(r"Shared library: \[([^]]+)\]", output),
        "soname": re.findall(r"Library soname: \[([^]]+)\]", output),
    }


def manifest(root: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        row: dict[str, Any] = {
            "path": relative,
            "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
            "size": len(payload),
            "sha256": sha256_bytes(payload),
            "elf": payload.startswith(ELF_MAGIC),
        }
        if path.name.endswith(".gz"):
            try:
                clear = gzip.decompress(payload)
            except OSError:
                pass
            else:
                row["decompressed_size"] = len(clear)
                row["decompressed_sha256"] = sha256_bytes(clear)
        rows[relative] = row
    return rows


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deb-dir", type=Path, required=True)
    parser.add_argument("--reference-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    deb_dir = args.deb_dir.resolve()
    reference = json.loads(args.reference_lock.read_text(encoding="utf-8"))
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(output / "extracted", ignore_errors=True)

    errors: list[str] = []
    warnings: list[str] = []
    if reference.get("source") != SOURCE or reference.get("source_version") != VERSION:
        raise SystemExit("reference source identity mismatch")
    target_rows = reference.get("target_payload_manifest")
    if not isinstance(target_rows, list) or not target_rows:
        raise SystemExit("target payload manifest is absent")
    target_manifest = {row["path"]: row for row in target_rows}

    debs: list[dict[str, Any]] = []
    elf_rows: list[dict[str, Any]] = []
    wrong_architecture: list[dict[str, Any]] = []
    main_roots: list[Path] = []
    debug_roots: list[Path] = []

    for deb in sorted(deb_dir.glob("*.deb")):
        package = deb_field(deb, "Package")
        version = deb_field(deb, "Version")
        architecture = deb_field(deb, "Architecture")
        source = parse_source(deb_field(deb, "Source"), package)
        if version != VERSION:
            errors.append(f"wrong version in {deb.name}: {version}")
        if architecture != "arm64":
            errors.append(f"wrong architecture in {deb.name}: {architecture}")
        if source != SOURCE:
            errors.append(f"wrong source in {deb.name}: {source}")
        root = output / "extracted" / package
        root.mkdir(parents=True, exist_ok=True)
        run(["dpkg-deb", "-x", str(deb), str(root)])
        if package == SOURCE:
            main_roots.append(root)
        if package == SOURCE + "-dbgsym":
            debug_roots.append(root)
        debs.append(
            {
                "filename": deb.name,
                "package": package,
                "source": source,
                "source_version": VERSION,
                "version": version,
                "architecture": architecture,
                "size": deb.stat().st_size,
                "sha256": sha256_file(deb),
            }
        )
        for path in sorted(root.rglob("*")):
            if not is_elf(path):
                continue
            relative = path.relative_to(root).as_posix()
            header = elf_header(path)
            description = run(["file", "-b", str(path)])
            row = {
                "package": package,
                "path": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "file": description,
                "machine": header["machine"],
                "elf_type": header["type"],
            }
            elf_rows.append(row)
            if header["machine"] != "AArch64" or "x86-64" in description or "Intel 80386" in description:
                wrong_architecture.append(row)

    if len(debs) != 2:
        errors.append(f"expected two DEB artifacts, found {len(debs)}")
    if len(main_roots) != 1:
        errors.append(f"expected one main package, found {len(main_roots)}")
    if len(debug_roots) != 1:
        errors.append(f"expected one dbgsym package, found {len(debug_roots)}")

    payload_checks: list[dict[str, Any]] = []
    runtime_checks: list[dict[str, Any]] = []
    if len(main_roots) == 1:
        root = main_roots[0]
        candidate = manifest(root)
        expected_paths = set(target_manifest)
        actual_paths = set(candidate)
        if actual_paths != expected_paths:
            errors.append(
                "main package file set mismatch: "
                f"missing={sorted(expected_paths - actual_paths)} extra={sorted(actual_paths - expected_paths)}"
            )
        for relative in sorted(expected_paths & actual_paths):
            expected = target_manifest[relative]
            actual = candidate[relative]
            if expected.get("mode") != actual.get("mode"):
                errors.append(
                    f"payload mode changed: {relative}: "
                    f"{expected.get('mode')} != {actual.get('mode')}"
                )
            if bool(expected.get("elf")) != bool(actual.get("elf")):
                errors.append(f"ELF classification changed: {relative}")
                continue
            if not expected.get("elf"):
                raw_identical = expected.get("sha256") == actual.get("sha256")
                decompressed_identical = (
                    expected.get("decompressed_sha256") is not None
                    and expected.get("decompressed_sha256") == actual.get("decompressed_sha256")
                )
                accepted = raw_identical or decompressed_identical
                payload_checks.append(
                    {
                        "path": relative,
                        "raw_identical": raw_identical,
                        "decompressed_identical": decompressed_identical,
                        "verified": accepted,
                    }
                )
                if not accepted:
                    errors.append(f"architecture-neutral payload mismatch: {relative}")
                continue

            path = root / relative
            header = elf_header(path)
            interpreter = elf_interpreter(path)
            dynamic = dynamic_identity(path)
            target_dynamic = expected.get("dynamic", {})
            row = {
                "path": relative,
                "machine": header["machine"],
                "elf_type": header["type"],
                "expected_elf_type": expected.get("elf_header", {}).get("type"),
                "interpreter": interpreter,
                "interpreter_basename": os.path.basename(interpreter) if interpreter else None,
                "needed": dynamic["needed"],
                "expected_needed": target_dynamic.get("needed", []),
                "soname": dynamic["soname"],
                "expected_soname": target_dynamic.get("soname", []),
            }
            row["verified"] = (
                row["machine"] == "AArch64"
                and row["elf_type"] == row["expected_elf_type"]
                and row["interpreter_basename"] == AARCH64_LOADER
                and row["needed"] == row["expected_needed"]
                and row["soname"] == row["expected_soname"]
            )
            runtime_checks.append(row)
            if not row["verified"]:
                errors.append(f"runtime ELF identity mismatch: {relative}")

    verified = (
        len(debs) == 2
        and len(main_roots) == 1
        and len(debug_roots) == 1
        and not wrong_architecture
        and not errors
        and bool(runtime_checks)
        and all(row["verified"] for row in runtime_checks)
        and all(row["verified"] for row in payload_checks)
    )
    summary = {
        "schema": 2,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": "verified-reconstructed-git-tree",
        "target_architecture": "arm64",
        "deb_artifacts": sorted(debs, key=lambda row: row["package"]),
        "elf_payloads": elf_rows,
        "wrong_architecture_executables": wrong_architecture,
        "main_package_count": len(main_roots),
        "debug_package_count": len(debug_roots),
        "payload_checks": payload_checks,
        "runtime_checks": runtime_checks,
        "verification_errors": errors,
        "verification_warnings": warnings,
        "verified": verified,
    }
    write_json(output / "deb-artifacts.json", summary["deb_artifacts"])
    write_json(output / "elf-payloads.json", elf_rows)
    write_json(output / "verification-summary.json", summary)
    shutil.rmtree(output / "extracted", ignore_errors=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
