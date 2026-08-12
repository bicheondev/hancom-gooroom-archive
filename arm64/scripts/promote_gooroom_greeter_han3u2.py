#!/usr/bin/env python3
"""Promote verified gooroom-greeter han3u2 source and native ARM64 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

SOURCE = "gooroom-greeter"
VERSION = "0.3.1+grm3u1+han3u2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def checksums(directory: Path, filename: str) -> None:
    rows = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != filename:
            rows.append(f"{sha(path)}  {path.relative_to(directory).as_posix()}\n")
    (directory / filename).write_text("".join(rows), encoding="utf-8")


def normalize_deb_artifacts(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise SystemExit(f"{label} must be a non-empty array")

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    required = (
        "package",
        "version",
        "architecture",
        "filename",
        "sha256",
        "size",
        "source",
        "source_version",
    )
    for index, raw in enumerate(value):
        location = f"{label}[{index}]"
        if not isinstance(raw, dict):
            raise SystemExit(f"{location} must be an object")
        row = dict(raw)
        row.setdefault("source", SOURCE)
        row.setdefault("source_version", VERSION)

        missing = [field for field in required if row.get(field) in (None, "")]
        if missing:
            raise SystemExit(f"{location} missing required fields: {missing}")
        if row["source"] != SOURCE:
            raise SystemExit(f"{location} source mismatch")
        if row["source_version"] != VERSION:
            raise SystemExit(f"{location} source version mismatch")
        if row["version"] != VERSION:
            raise SystemExit(f"{location} binary version mismatch")
        if row["architecture"] != "arm64":
            raise SystemExit(f"{location} architecture is not arm64")
        if not SHA256_RE.fullmatch(str(row["sha256"])):
            raise SystemExit(f"{location} SHA-256 is invalid")
        try:
            row["size"] = int(row["size"])
        except (TypeError, ValueError) as error:
            raise SystemExit(f"{location} size is not an integer") from error
        if row["size"] <= 0:
            raise SystemExit(f"{location} size must be positive")

        identity = tuple(row[field] for field in required)
        if identity in seen:
            raise SystemExit(f"{location} duplicates an earlier package record")
        seen.add(identity)
        normalized.append(row)

    normalized.sort(
        key=lambda row: (
            row["package"],
            row["version"],
            row["architecture"],
            row["filename"],
            row["sha256"],
        )
    )
    return normalized


def deb_identities(value: list[dict[str, Any]]) -> set[tuple[Any, ...]]:
    fields = (
        "package",
        "version",
        "architecture",
        "filename",
        "sha256",
        "size",
        "source",
        "source_version",
    )
    return {tuple(row[field] for field in fields) for row in value}


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
    verification_raw = load(arm_dir / "verification-summary.json")
    debs_raw = load(arm_dir / "deb-artifacts.json")
    if not isinstance(reconstruction, dict):
        raise SystemExit("reconstruction lock must be an object")
    if not isinstance(equivalence, dict):
        raise SystemExit("AMD64 equivalence summary must be an object")
    if not isinstance(build_lock, dict):
        raise SystemExit("ARM64 build lock must be an object")
    if not isinstance(verification_raw, dict):
        raise SystemExit("ARM64 verification summary must be an object")
    if not equivalence.get("verified") or not verification_raw.get("verified"):
        raise SystemExit(
            "promotion requires verified AMD64 source equivalence and ARM64 build"
        )
    if reconstruction.get("source_version") != VERSION:
        raise SystemExit("reconstruction version mismatch")
    if build_lock.get("source") != SOURCE or build_lock.get("source_version") != VERSION:
        raise SystemExit("ARM64 build-lock source identity mismatch")
    if verification_raw.get("source") != SOURCE:
        raise SystemExit("ARM64 verification source mismatch")
    if verification_raw.get("source_version") != VERSION:
        raise SystemExit("ARM64 verification source version mismatch")
    if verification_raw.get("wrong_architecture_executables") != []:
        raise SystemExit("ARM64 verification contains foreign executable payloads")

    debs = normalize_deb_artifacts(debs_raw, "deb-artifacts.json")
    verification_debs = normalize_deb_artifacts(
        verification_raw.get("deb_artifacts"),
        "verification-summary.json.deb_artifacts",
    )
    if deb_identities(debs) != deb_identities(verification_debs):
        raise SystemExit(
            "deb-artifacts.json disagrees with verification-summary.json"
        )
    verification = dict(verification_raw)
    verification["deb_artifacts"] = verification_debs

    result_dir = (
        repository
        / "arm64/locks/rebuild-results/gooroom-greeter/0.3.1_grm3u1_han3u2"
    )
    evidence_dir = (
        repository
        / "arm64/locks/gooroom-greeter-han3u2-reconstruction/latest"
    )
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
        "repository_full_name": reconstruction["base_source"][
            "repository_full_name"
        ],
        "commit_sha": reconstruction["base_source"]["commit_sha"],
        "tree_sha": reconstruction["reconstruction"]["tree_sha"],
        "dsc_filename": None,
        "dsc_sha256": None,
        "authority_provenance": (
            "locked-amd64-binary-changelog-plus-public-change-id-and-"
            "structural-amd64-equivalence"
        ),
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
            "Vendor and independent AMD64 .text bytes differ; source acceptance "
            "is based on exact shipped changelog, surviving public Gerrit delta, "
            "exact non-ELF payload, and ELF ABI/resource/relocation/symbol/DWARF "
            "equivalence."
        ],
        "build_lock": build_lock,
        "source_lock_evidence": {
            "schema": 4,
            "base_repository": reconstruction["base_source"][
                "repository_full_name"
            ],
            "base_commit_sha": reconstruction["base_source"]["commit_sha"],
            "base_tree_sha": reconstruction["base_source"]["tree_sha"],
            "reconstructed_tree_sha": reconstruction["reconstruction"]["tree_sha"],
            "source_archive_sha256": reconstruction["reconstruction"][
                "archive_sha256"
            ],
            "target_binary_sha256": reconstruction["target_binary_authority"][
                "sha256"
            ],
            "patch_authority": reconstruction["patch_authority"],
            "amd64_equivalence": equivalence,
        },
        "verification_summary": verification,
        "evidence_paths": {
            "reconstruction": (
                "arm64/locks/gooroom-greeter-han3u2-reconstruction/latest/"
                "reconstruction-lock.json"
            ),
            "amd64_equivalence": (
                "arm64/locks/gooroom-greeter-han3u2-reconstruction/latest/"
                "amd64-equivalence-summary.json"
            ),
            "arm64_verification": (
                "arm64/locks/gooroom-greeter-han3u2-reconstruction/latest/"
                "arm64-verification-summary.json"
            ),
        },
    }
    write(result_dir / "result.json", result)
    checksums(result_dir, "SHA256SUMS")

    document: dict[str, Any]
    if source_locks.exists():
        loaded = load(source_locks)
        if not isinstance(loaded, dict):
            raise SystemExit("source locks must be an object")
        document = loaded
    else:
        document = {
            "schema": 1,
            "policy": "independently-verified-reconstructed-source-overlays",
            "sources": [],
        }
    rows = [
        row
        for row in document.get("sources", [])
        if not (
            row.get("source") == SOURCE and row.get("source_version") == VERSION
        )
    ]
    rows.append(
        {
            "source": SOURCE,
            "source_version": VERSION,
            "status": "resolved",
            "provenance": "verified-reconstructed-source",
            "selected": {
                "type": "reconstructed-git-tree",
                "provenance": (
                    "locked-amd64-binary-changelog-plus-public-change-id-and-"
                    "structural-amd64-equivalence"
                ),
                "repository_full_name": reconstruction["base_source"][
                    "repository_full_name"
                ],
                "commit_sha": reconstruction["base_source"]["commit_sha"],
                "tree_sha": reconstruction["reconstruction"]["tree_sha"],
                "ref_kind": "reconstructed-tree",
                "ref_name": VERSION,
                "match_scope": "binary-changelog-and-public-change-id-reconstruction",
                "declared_source": SOURCE,
                "declared_version": VERSION,
                "source_archive_sha256": reconstruction["reconstruction"][
                    "archive_sha256"
                ],
            },
            "verification": {
                "passed": True,
                "actions_run_id": args.run_id,
                "actions_run_url": args.run_url,
                "amd64_structural_equivalence_verified": True,
                "native_arm64_build_verified": True,
                "evidence_path": (
                    "arm64/locks/gooroom-greeter-han3u2-reconstruction/latest/"
                    "reconstruction-lock.json"
                ),
            },
        }
    )
    document["sources"] = sorted(
        rows, key=lambda row: (row["source"], row["source_version"])
    )
    document["source_count"] = len(document["sources"])
    write(source_locks, document)
    print(
        json.dumps(
            {"result": str(result_dir), "source_locks": str(source_locks)},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
