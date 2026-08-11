#!/usr/bin/env python3
"""Verify Debian binaries built from an exact recovered source archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

AARCH64 = 183
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def field(path: Path, name: str) -> str:
    process = run(["dpkg-deb", "-f", str(path), name])
    if process.returncode:
        raise SystemExit(
            f"dpkg-deb failed for {path} field {name}: {process.stderr}"
        )
    return process.stdout.strip()


def parse_source(value: str, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, version
    match = re.fullmatch(r"\s*([^\s(]+)(?:\s*\(([^)]+)\))?\s*", value)
    if match is None:
        raise SystemExit(f"malformed Source field: {value!r}")
    return match.group(1), match.group(2) or version


def elf_machine(path: Path) -> int | None:
    try:
        with path.open("rb") as stream:
            header = stream.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    byteorder = {1: "little", 2: "big"}.get(header[5])
    if byteorder is None:
        return -1
    return int.from_bytes(header[18:20], byteorder)


def is_pe(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(2) == b"MZ"
    except OSError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--artifact-name", default="")
    args = parser.parse_args()

    debs = sorted(args.output_dir.glob("*.deb"))
    if not debs:
        raise SystemExit(f"no Debian binary packages in {args.output_dir}")

    package_rows: list[dict[str, Any]] = []
    payload_rows: list[dict[str, Any]] = []
    foreign_rows: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="verify-arm64-source-archive-") as temp:
        temp_root = Path(temp)
        for index, deb in enumerate(debs):
            package = field(deb, "Package")
            version = field(deb, "Version")
            architecture = field(deb, "Architecture")
            source_field = field(deb, "Source")
            source, source_version = parse_source(
                source_field, package=package, version=version
            )
            if source != args.source:
                raise SystemExit(
                    f"source mismatch for {deb.name}: {source!r} != {args.source!r}"
                )
            if source_version != args.version:
                raise SystemExit(
                    f"source version mismatch for {deb.name}: "
                    f"{source_version!r} != {args.version!r}"
                )
            if version != args.version:
                raise SystemExit(
                    f"binary version mismatch for {deb.name}: "
                    f"{version!r} != {args.version!r}"
                )
            if architecture not in {"arm64", "all"}:
                raise SystemExit(
                    f"wrong package architecture for {deb.name}: {architecture}"
                )

            root = temp_root / f"package-{index}"
            root.mkdir()
            process = run(["dpkg-deb", "-x", str(deb), str(root)])
            if process.returncode:
                raise SystemExit(
                    f"unable to extract {deb.name}: {process.stderr}"
                )

            package_foreign = 0
            package_aarch64 = 0
            for path in sorted(root.rglob("*")):
                try:
                    mode = path.lstat().st_mode
                except OSError:
                    continue
                if not stat.S_ISREG(mode) or path.is_symlink():
                    continue
                relative = "/" + path.relative_to(root).as_posix()
                machine = elf_machine(path)
                if machine is not None:
                    row = {
                        "package": package,
                        "path": relative,
                        "kind": "ELF",
                        "machine": machine,
                        "sha256": sha256(path),
                        "size": path.stat().st_size,
                    }
                    payload_rows.append(row)
                    if machine == AARCH64:
                        package_aarch64 += 1
                    else:
                        package_foreign += 1
                        foreign_rows.append(row)
                elif is_pe(path):
                    row = {
                        "package": package,
                        "path": relative,
                        "kind": "PE",
                        "machine": None,
                        "sha256": sha256(path),
                        "size": path.stat().st_size,
                    }
                    payload_rows.append(row)
                    foreign_rows.append(row)
                    package_foreign += 1

            package_rows.append(
                {
                    "package": package,
                    "version": version,
                    "architecture": architecture,
                    "source": source,
                    "source_version": source_version,
                    "filename": deb.name,
                    "size": deb.stat().st_size,
                    "sha256": sha256(deb),
                    "aarch64_payload_count": package_aarch64,
                    "foreign_payload_count": package_foreign,
                }
            )

    passed = not foreign_rows
    result = {
        "schema": 1,
        "policy": "exact-source-archive-native-arm64-build-no-foreign-payload",
        "source": args.source,
        "source_version": args.version,
        "build_mode": "exact-recovered-debian-source-archive-native-arm64",
        "source_status": "exact-source-archive-recovered-from-signed-apt-authority",
        "byte_identity_claimed": False,
        "artifact_name": args.artifact_name,
        "actions_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "actions_run_url": (
            f"{os.environ.get('GITHUB_SERVER_URL', '')}/"
            f"{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/"
            f"{os.environ.get('GITHUB_RUN_ID', '')}"
        ),
        "build_outcome": "success",
        "verify_outcome": "success" if passed else "failed",
        "verification_passed": passed,
        "passed": passed,
        "wrong_architecture_executable_count": len(foreign_rows),
        "foreign_payload_count": len(foreign_rows),
        "package_count": len(package_rows),
        "packages": package_rows,
        "payloads": payload_rows,
        "foreign_payloads": foreign_rows,
    }
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if not passed:
        raise SystemExit(
            f"foreign or non-AArch64 payloads were found: {len(foreign_rows)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
