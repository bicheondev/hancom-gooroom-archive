#!/usr/bin/env python3
"""Materialize the persistent rebuild cache and lock the resulting APT index.

This wraps the strict v1 downloader/control verifier, then records the exact
Packages/Release hashes used by subsequent source rebuild retries. A retry is
allowed only when this Packages hash differs from the hash used by the latest
failed attempt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import materialize_rebuild_dependency_repo as base


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_wrapper_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--repository-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    namespace, _ = parser.parse_known_args()
    return namespace


def file_record(path: Path) -> dict[str, Any]:
    return {
        "filename": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def main() -> int:
    args = parse_wrapper_args()
    rc = base.main()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.output_dir / "summary.json"
    document_path = args.output_dir / "dependency-repository.json"
    summary = (
        json.loads(summary_path.read_text(encoding="utf-8"))
        if summary_path.exists()
        else {
            "schema": 1,
            "ready": False,
            "error_count": 1,
            "errors": ["base materializer did not write summary.json"],
        }
    )
    document = (
        json.loads(document_path.read_text(encoding="utf-8"))
        if document_path.exists()
        else {"summary": summary, "packages": [], "errors": []}
    )

    release_lock_sha256 = (
        sha256_file(args.release_lock) if args.release_lock.exists() else None
    )
    repository_files: list[dict[str, Any]] = []
    if args.repository_dir.exists():
        for path in sorted(args.repository_dir.iterdir()):
            if path.is_file():
                repository_files.append(file_record(path))
    by_name = {row["filename"]: row for row in repository_files}
    packages_record = by_name.get("Packages")
    release_record = by_name.get("Release")

    ready = bool(summary.get("ready")) and rc == 0
    if ready and (packages_record is None or release_record is None):
        ready = False
        document.setdefault("errors", []).append(
            {
                "reason": "generated-apt-index-missing",
                "packages_exists": packages_record is not None,
                "release_exists": release_record is not None,
            }
        )

    v2_summary = {
        **summary,
        "schema": 2,
        "policy": "verified-release-assets-plus-locked-generated-apt-index",
        "release_lock_sha256": release_lock_sha256,
        "packages_sha256": packages_record["sha256"] if packages_record else None,
        "packages_size": packages_record["size"] if packages_record else None,
        "release_sha256": release_record["sha256"] if release_record else None,
        "release_size": release_record["size"] if release_record else None,
        "repository_file_count": len(repository_files),
        "ready": ready,
    }
    v2_document = {
        **document,
        "summary": v2_summary,
        "repository_files": repository_files,
    }
    summary_path.write_text(
        json.dumps(v2_summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    document_path.write_text(
        json.dumps(v2_document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(v2_summary, ensure_ascii=False, indent=2))
    return 0 if ready else (rc or 2)


if __name__ == "__main__":
    raise SystemExit(main())
