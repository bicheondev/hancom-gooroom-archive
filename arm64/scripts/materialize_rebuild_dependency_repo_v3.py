#!/usr/bin/env python3
"""Materialize a verified local APT repository from persistent rebuild assets.

Every `.deb` is downloaded from the persistent release lock, checked against
its locked size and SHA-256, and re-checked with `dpkg-deb`. The generated
`Packages` index is deterministic and its SHA-256 is the retry identity used to
prevent repeating dependency builds against an unchanged package set.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
from email.utils import formatdate
from pathlib import Path
from typing import Any


USER_AGENT = "hancom-gooroom-arm64-dependency-repository/3"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def md5_file(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".partial")
    error: Exception | None = None
    for attempt in range(1, 6):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=300) as response, partial.open(
                "wb"
            ) as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            partial.replace(destination)
            return
        except Exception as exception:
            error = exception
            partial.unlink(missing_ok=True)
            if attempt < 5:
                time.sleep(2 ** (attempt - 1))
    assert error is not None
    raise error


def deb_field(path: Path, field: str) -> str:
    process = subprocess.run(
        ["dpkg-deb", "-f", str(path), field],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return process.stdout.strip()


def package_identity(row: dict[str, Any]) -> tuple[int, str]:
    return int(row["size"]), str(row["sha256"]).lower()


def write_release(output_dir: Path) -> None:
    files = [output_dir / "Packages", output_dir / "Packages.gz"]
    lines = [
        "Origin: Hancom Gooroom ARM64",
        "Label: Exact native rebuild dependency repository",
        "Suite: stable",
        "Codename: hancom-gooroom-3.3-arm64-rebuilds",
        "Version: 3",
        "Architectures: arm64 all",
        "Components: main",
        f"Date: {formatdate(0, usegmt=True)}",
        "Description: Hash-locked exact ARM64 rebuild packages",
        "MD5Sum:",
    ]
    for path in files:
        lines.append(f" {md5_file(path)} {path.stat().st_size} {path.name}")
    lines.append("SHA256:")
    for path in files:
        lines.append(f" {sha256_file(path)} {path.stat().st_size} {path.name}")
    (output_dir / "Release").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    for command in ("dpkg-deb", "dpkg-scanpackages"):
        if shutil.which(command) is None:
            raise SystemExit(f"required command is missing: {command}")

    document = load_json(args.release_lock)
    release_summary = document.get("summary", {})
    if release_summary.get("complete") is not True:
        raise SystemExit("persistent rebuild release lock is not complete")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    package_rows: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    filename_identities: dict[str, tuple[int, str]] = {}

    for row in document.get("packages", []):
        architecture = row.get("architecture")
        if architecture not in {"arm64", "all"}:
            blockers.append(
                {
                    "package": row.get("package"),
                    "filename": row.get("filename"),
                    "reason": "non-arm64-package-in-rebuild-release",
                    "architecture": architecture,
                }
            )
            continue
        asset = row.get("release_asset") if isinstance(row.get("release_asset"), dict) else {}
        filename = Path(str(row.get("filename") or asset.get("name") or "")).name
        url = asset.get("browser_download_url")
        sha256 = str(row.get("sha256", "")).lower()
        size = row.get("size")
        if not filename or not url or size is None or len(sha256) != 64:
            blockers.append(
                {
                    "package": row.get("package"),
                    "reason": "persistent-release-record-incomplete",
                }
            )
            continue
        identity = (int(size), sha256)
        previous = filename_identities.get(filename)
        if previous and previous != identity:
            blockers.append(
                {
                    "filename": filename,
                    "reason": "conflicting-release-filename-identity",
                    "first_identity": previous,
                    "second_identity": identity,
                }
            )
            continue
        filename_identities[filename] = identity
        destination = args.output_dir / filename
        try:
            download(url, destination)
        except Exception as exception:
            blockers.append(
                {
                    "filename": filename,
                    "reason": "persistent-release-download-failed",
                    "error": f"{type(exception).__name__}: {exception}",
                }
            )
            continue
        if destination.stat().st_size != identity[0] or sha256_file(destination) != identity[1]:
            blockers.append(
                {"filename": filename, "reason": "persistent-release-hash-mismatch"}
            )
            destination.unlink(missing_ok=True)
            continue

        try:
            actual_package = deb_field(destination, "Package")
            actual_version = deb_field(destination, "Version")
            actual_architecture = deb_field(destination, "Architecture")
            actual_source = deb_field(destination, "Source")
        except subprocess.CalledProcessError as exception:
            blockers.append(
                {
                    "filename": filename,
                    "reason": "dpkg-control-read-failed",
                    "error": str(exception),
                }
            )
            destination.unlink(missing_ok=True)
            continue
        if (
            actual_package != row.get("package")
            or actual_version != row.get("version")
            or actual_architecture != architecture
        ):
            blockers.append(
                {
                    "filename": filename,
                    "reason": "dpkg-control-identity-mismatch",
                    "expected": {
                        "package": row.get("package"),
                        "version": row.get("version"),
                        "architecture": architecture,
                    },
                    "actual": {
                        "package": actual_package,
                        "version": actual_version,
                        "architecture": actual_architecture,
                    },
                }
            )
            destination.unlink(missing_ok=True)
            continue
        digest = asset.get("digest")
        if digest and digest != f"sha256:{sha256}":
            blockers.append(
                {
                    "filename": filename,
                    "reason": "release-api-digest-mismatch",
                    "release_digest": digest,
                }
            )
            destination.unlink(missing_ok=True)
            continue

        package_rows.append(
            {
                "package": actual_package,
                "version": actual_version,
                "architecture": actual_architecture,
                "source_field": actual_source,
                "filename": filename,
                "size": identity[0],
                "sha256": identity[1],
                "source": row.get("source"),
                "source_version": row.get("source_version"),
                "source_type": row.get("source_type", "git"),
                "tree_sha": row.get("tree_sha"),
                "dsc_sha256": row.get("dsc_sha256"),
                "release_asset_id": asset.get("id"),
                "release_url": url,
            }
        )

    if blockers:
        for path in args.output_dir.glob("*.deb"):
            path.unlink(missing_ok=True)
    else:
        process = subprocess.run(
            ["dpkg-scanpackages", "--multiversion", ".", "/dev/null"],
            cwd=args.output_dir,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        (args.output_dir / "Packages").write_text(process.stdout, encoding="utf-8")
        with (args.output_dir / "Packages").open("rb") as source, gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=(args.output_dir / "Packages.gz").open("wb"),
            mtime=0,
            compresslevel=9,
        ) as output:
            shutil.copyfileobj(source, output)
        write_release(args.output_dir)

    package_rows.sort(key=lambda row: (row["package"], row["version"], row["architecture"]))
    packages_sha256 = (
        sha256_file(args.output_dir / "Packages")
        if (args.output_dir / "Packages").exists()
        else None
    )
    release_lock_sha256 = sha256_file(args.release_lock)
    summary = {
        "schema": 3,
        "policy": "persistent-release-assets-to-hash-locked-local-apt-repository",
        "release_tag": release_summary.get("release_tag"),
        "release_lock_sha256": release_lock_sha256,
        "package_count": len(package_rows),
        "packages_sha256": packages_sha256,
        "blocker_count": len(blockers),
        "ready": bool(package_rows) and not blockers,
        "source_type_counts": {
            source_type: sum(row["source_type"] == source_type for row in package_rows)
            for source_type in sorted({row["source_type"] for row in package_rows})
        },
    }
    lock = {"summary": summary, "packages": package_rows, "blockers": blockers}
    (args.output_dir / "dependency-repository-lock.json").write_text(
        json.dumps(lock, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    # Preserve the original top-level summary fields for workflow shell
    # consumers while also exposing the complete lock shape expected by the
    # dependency retry selector. This is intentionally redundant and hashed.
    summary_document = {
        **summary,
        "summary": summary,
        "packages": package_rows,
        "blockers": blockers,
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary_document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "blockers.json").write_text(
        json.dumps(blockers, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if not blockers:
        checksums = []
        for path in sorted(args.output_dir.iterdir(), key=lambda item: item.name):
            if path.is_file() and path.name != "SHA256SUMS":
                checksums.append(f"{sha256_file(path)}  {path.name}")
        (args.output_dir / "SHA256SUMS").write_text(
            "\n".join(checksums) + "\n", encoding="utf-8"
        )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
