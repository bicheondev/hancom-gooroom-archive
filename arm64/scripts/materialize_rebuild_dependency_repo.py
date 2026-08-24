#!/usr/bin/env python3
"""Materialize the verified rebuild package release as a local APT repo."""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(row: dict[str, Any], staging: Path) -> dict[str, Any]:
    asset = row.get("release_asset") or {}
    url = asset.get("browser_download_url")
    filename = Path(row.get("filename", "")).name
    if not url or not filename:
        return {**row, "status": "missing-release-url-or-filename"}
    destination = staging / filename
    partial = destination.with_suffix(destination.suffix + ".partial")
    error = ""
    for attempt in range(1, 6):
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "hancom-gooroom-arm64-build-deps/1"},
            )
            with urllib.request.urlopen(request, timeout=240) as response, partial.open(
                "wb"
            ) as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            actual_size = partial.stat().st_size
            actual_sha256 = sha256_file(partial)
            if actual_size != int(row["size"]):
                raise RuntimeError(
                    f"size mismatch {actual_size} != {int(row['size'])}"
                )
            if actual_sha256 != row["sha256"]:
                raise RuntimeError(
                    f"sha256 mismatch {actual_sha256} != {row['sha256']}"
                )
            partial.replace(destination)
            return {
                **row,
                "status": "downloaded",
                "local_path": str(destination),
                "actual_size": actual_size,
                "actual_sha256": actual_sha256,
                "attempts": attempt,
            }
        except Exception as exception:
            error = f"{type(exception).__name__}: {exception}"
            partial.unlink(missing_ok=True)
            if attempt < 5:
                time.sleep(2 ** (attempt - 1))
    return {**row, "status": "download-failed", "error": error, "attempts": 5}


def deb_field(path: Path, field: str) -> str:
    process = subprocess.run(
        ["dpkg-deb", "-f", str(path), field],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return process.stdout.strip()


def write_repo(repo: Path) -> None:
    process = subprocess.run(
        ["dpkg-scanpackages", "--multiversion", "."],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    packages = process.stdout
    (repo / "Packages").write_text(packages, encoding="utf-8")
    raw = (repo / "Packages.gz").open("wb")
    try:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as output:
            output.write(packages.encode("utf-8"))
    finally:
        raw.close()
    release = subprocess.run(
        ["apt-ftparchive", "release", "."],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    (repo / "Release").write_text(release, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--repository-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    document = load_json(args.release_lock)
    if document.get("summary", {}).get("complete") is not True:
        raise SystemExit("rebuild release lock is not complete")
    rows = [
        row
        for row in document.get("packages", [])
        if row.get("architecture") in {"arm64", "all"}
    ]
    if not rows:
        raise SystemExit("rebuild release lock contains no package assets")

    args.repository_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    staging = args.output_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)

    results = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, args.workers)
    ) as executor:
        futures = [executor.submit(download, row, staging) for row in rows]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print(f"{result['status']}: {result.get('filename')}", file=sys.stderr)

    verified = []
    errors = []
    filenames: dict[str, str] = {}
    for row in results:
        if row.get("status") != "downloaded":
            errors.append(row)
            continue
        path = Path(row["local_path"])
        try:
            control = {
                "package": deb_field(path, "Package"),
                "version": deb_field(path, "Version"),
                "architecture": deb_field(path, "Architecture"),
                "source": deb_field(path, "Source"),
            }
        except Exception as exception:
            errors.append(
                {
                    **row,
                    "status": "deb-control-read-failed",
                    "error": f"{type(exception).__name__}: {exception}",
                }
            )
            continue
        expected = (row.get("package"), row.get("version"), row.get("architecture"))
        actual = (control["package"], control["version"], control["architecture"])
        if actual != expected:
            errors.append(
                {
                    **row,
                    "status": "deb-control-mismatch",
                    "expected": expected,
                    "actual": actual,
                }
            )
            continue
        previous = filenames.get(path.name)
        if previous and previous != row["sha256"]:
            errors.append(
                {
                    **row,
                    "status": "filename-collision",
                    "previous_sha256": previous,
                }
            )
            continue
        filenames[path.name] = row["sha256"]
        shutil.copyfile(path, args.repository_dir / path.name)
        verified.append({**row, "status": "verified", "control": control})

    if not errors:
        write_repo(args.repository_dir)
    summary = {
        "schema": 1,
        "policy": "verified-persistent-rebuild-assets-as-build-dependency-repo",
        "release_tag": document.get("summary", {}).get("release_tag"),
        "planned_count": len(rows),
        "verified_count": len(verified),
        "error_count": len(errors),
        "ready": bool(verified) and not errors,
    }
    output = {"summary": summary, "packages": verified, "errors": errors}
    (args.output_dir / "dependency-repository.json").write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
