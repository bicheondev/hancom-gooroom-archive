#!/usr/bin/env python3
"""Promote verified gooroom-greeter han3u2 source and native ARM64 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

SOURCE = "gooroom-greeter"
VERSION = "0.3.1+grm3u1+han3u2"


def load(path: Path) -> dict[str, Any] | list[Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def checksums(directory: Path, filename: str) -> None:
    rows = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != filename:
            rows.append(f"{sha(path)}  {path.relative_to(directory).as_posix()}\n")
    (directory / filename).write_text("".join(rows), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-artifact", type=Path, required=True)
    parser.add_argument("--arm64-artifact", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-url", required=True)
    args = parser.parse_args()

    source_dir = args.source_artifact.resolve()
    arm_dir = args.arm64_artifact.resolve()
    repository = args.repository_root.resolve()
    reconstruction = load(source_dir / "reconstruction-lock.json")
    equivalence = load(source_dir / "amd64-equivalence-summary.json")
    build_lock = load(arm_dir / "build-lock.json")
    verification = load(arm_dir / "verification-summary.json")
    debs = load(arm_dir / "deb-artifacts.json")
    if not equivalence.get("verified") or not verification.get("verified"):
        raise SystemExit("promotion requires verified AMD64 source equivalence and ARM64 build")
    if reconstruction.get("source_version") != VERSION:
        raise SystemExit("reconstruction version mismatch")

    result_dir = repository / "arm64/locks/rebuild-results/gooroom-greeter/0.3.1_grm3u1_han3u2"
    evidence_dir = repository / "arm64/locks/gooroom-greeter-han3u2-reconstruction/latest"
    source_locks = repository / "arm64/locks/reconstructed-sources/source-locks.json"
    shutil.rmtree(result_dir, ignore_errors=True)
    shutil.rmtree(evidence_dir, ignore_errors=True)
    result_dir.mkdir(parents=True)
    evidence_dir.mkdir(parents=True)

    evidence_files = {
        "reconstruction-lock.json": source_dir / "reconstruction-lock.json",
        "reconstruction.patch": source_dir / "reconstruction.patch",
        "target-binary-lock.json": source_dir / "target-binary-lock.json",
        "amd64-equivalence-summary.json": source_dir / "amd64-equivalence-summary.json",
        "amd64-elf-comparison.json": source_dir / "amd64-elf-comparison.json",
        "amd64-differences.json": source_dir / "amd64-differences.json",
        "arm64-build-lock.json": arm_dir / "build-lock.json",
        "arm64-verification-summary.json": arm_dir / "verification-summary.json",
    }
    for name, origin in evidence_files.items():
        if not origin.is_file():
            raise SystemExit(f"promotion evidence missing: {origin}")
        shutil.copy2(origin, evidence_dir / name)
    checksums(evidence_dir, "LOCKSUMS.sha256")

    result = {
        "schema": 4,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": "verified-reconstructed-git-tree",
        "repository_full_name": reconstruction["base_source"]["repository_full_name"],
        "commit_sha": reconstruction["base_source"]["commit_sha"],
        "tree_sha": reconstruction["reconstruction"]["tree_sha"],
        "dsc_filename": None,
        "dsc_sha256": None,
        "authority_provenance": "locked-amd64-binary-changelog-plus-public-change-id-and-structural-amd64-equivalence",
        "actions_run_id": args.run_id,
        "actions_run_url": args.run_url,
        "batch": "gooroom-greeter-han3u2-source-reconstruction",
        "build_outcome": "success",
        "build_exit_code": "0",
        "verify_outcome": "success",
        "required_native_packages": [SOURCE],
        "reused_all_packages": [],
        "job_passed": True,
        "verification_passed": True,
        "passed": True,
        "deb_artifacts": debs,
        "verification_errors": [],
        "verification_warnings": [
            "Vendor and independent AMD64 .text bytes differ; source acceptance is based on exact shipped changelog, surviving public Gerrit delta, exact non-ELF payload, and ELF ABI/resource/relocation/symbol/DWARF equivalence."
        ],
        "build_lock": build_lock,
        "source_lock_evidence": {
            "schema": 4,
            "base_repository": reconstruction["base_source"]["repository_full_name"],
            "base_commit_sha": reconstruction["base_source"]["commit_sha"],
            "base_tree_sha": reconstruction["base_source"]["tree_sha"],
            "reconstructed_tree_sha": reconstruction["reconstruction"]["tree_sha"],
            "source_archive_sha256": reconstruction["reconstruction"]["archive_sha256"],
            "target_binary_sha256": reconstruction["target_binary_authority"]["sha256"],
            "patch_authority": reconstruction["patch_authority"],
            "amd64_equivalence": equivalence,
        },
        "verification_summary": verification,
        "evidence_paths": {
            "reconstruction": "arm64/locks/gooroom-greeter-han3u2-reconstruction/latest/reconstruction-lock.json",
            "amd64_equivalence": "arm64/locks/gooroom-greeter-han3u2-reconstruction/latest/amd64-equivalence-summary.json",
            "arm64_verification": "arm64/locks/gooroom-greeter-han3u2-reconstruction/latest/arm64-verification-summary.json",
        },
    }
    write(result_dir / "result.json", result)
    checksums(result_dir, "SHA256SUMS")

    document: dict[str, Any]
    if source_locks.exists():
        document = load(source_locks)  # type: ignore[assignment]
    else:
        document = {
            "schema": 1,
            "policy": "independently-verified-reconstructed-source-overlays",
            "sources": [],
        }
    rows = [
        row for row in document.get("sources", [])
        if not (row.get("source") == SOURCE and row.get("source_version") == VERSION)
    ]
    rows.append({
        "source": SOURCE,
        "source_version": VERSION,
        "status": "resolved",
        "provenance": "verified-reconstructed-source",
        "selected": {
            "type": "reconstructed-git-tree",
            "provenance": "locked-amd64-binary-changelog-plus-public-change-id-and-structural-amd64-equivalence",
            "repository_full_name": reconstruction["base_source"]["repository_full_name"],
            "commit_sha": reconstruction["base_source"]["commit_sha"],
            "tree_sha": reconstruction["reconstruction"]["tree_sha"],
            "ref_kind": "reconstructed-tree",
            "ref_name": VERSION,
            "match_scope": "binary-changelog-and-public-change-id-reconstruction",
            "declared_source": SOURCE,
            "declared_version": VERSION,
            "source_archive_sha256": reconstruction["reconstruction"]["archive_sha256"],
        },
        "verification": {
            "passed": True,
            "actions_run_id": args.run_id,
            "actions_run_url": args.run_url,
            "amd64_structural_equivalence_verified": True,
            "native_arm64_build_verified": True,
            "evidence_path": "arm64/locks/gooroom-greeter-han3u2-reconstruction/latest/reconstruction-lock.json",
        },
    })
    document["sources"] = sorted(rows, key=lambda row: (row["source"], row["source_version"]))
    document["source_count"] = len(document["sources"])
    write(source_locks, document)
    print(json.dumps({"result": str(result_dir), "source_locks": str(source_locks)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
