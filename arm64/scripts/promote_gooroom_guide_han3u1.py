#!/usr/bin/env python3
"""Promote verified Hancom Gooroom 3.3 guide reconstruction and ARM64 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

SOURCE = "gooroom-guide"
VERSION = "0.5.3+grm3u1+han3u1"
BASE_REPOSITORY = "hancomgooroom/gooroom-guide"
BASE_COMMIT = "c788c29119d43bb97c554973f6dabbc41a9abe79"
BASE_TREE = "0d4bb01b49c69e33208a47c0aff47545291ee646"
TARGET_SHA256 = "80b2fa518e934f79c624a9aafdd44add1524389b2b3b899f1a4ffcb7fdf99142"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_checksums(directory: Path, filename: str) -> None:
    rows: list[str] = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != filename:
            rows.append(
                f"{sha256(path)}  {path.relative_to(directory).as_posix()}\n"
            )
    (directory / filename).write_text("".join(rows), encoding="utf-8")


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be an object")
    return value


def normalize_debs(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise SystemExit(f"{label} must be a non-empty array")
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
    rows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for index, raw in enumerate(value):
        location = f"{label}[{index}]"
        if not isinstance(raw, dict):
            raise SystemExit(f"{location} must be an object")
        row = dict(raw)
        missing = [field for field in fields if row.get(field) in (None, "")]
        if missing:
            raise SystemExit(f"{location} missing fields: {missing}")
        if row["source"] != SOURCE or row["source_version"] != VERSION:
            raise SystemExit(f"{location} source identity mismatch")
        if row["version"] != VERSION or row["architecture"] != "arm64":
            raise SystemExit(f"{location} binary identity mismatch")
        if not SHA256_RE.fullmatch(str(row["sha256"])):
            raise SystemExit(f"{location} invalid SHA-256")
        try:
            row["size"] = int(row["size"])
        except (TypeError, ValueError) as error:
            raise SystemExit(f"{location} invalid size") from error
        if row["size"] <= 0:
            raise SystemExit(f"{location} size must be positive")
        identity = tuple(row[field] for field in fields)
        if identity in seen:
            raise SystemExit(f"{location} duplicates an earlier DEB")
        seen.add(identity)
        rows.append(row)
    rows.sort(
        key=lambda row: (
            row["package"],
            row["version"],
            row["architecture"],
            row["filename"],
            row["sha256"],
        )
    )
    return rows


def deb_identities(rows: list[dict[str, Any]]) -> set[tuple[Any, ...]]:
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
    return {tuple(row[field] for field in fields) for row in rows}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-artifact", type=Path, required=True)
    parser.add_argument("--arm64-artifact", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--artifact-digest", required=True)
    args = parser.parse_args()

    source_dir = args.source_artifact.resolve()
    arm_dir = args.arm64_artifact.resolve()
    repository = args.repository_root.resolve()

    reconstruction = require_dict(
        load(source_dir / "reconstruction-lock.json"), "reconstruction"
    )
    equivalence = require_dict(
        load(source_dir / "amd64-equivalence-summary.json"), "AMD64 equivalence"
    )
    build_lock = require_dict(load(arm_dir / "build-lock.json"), "build lock")
    verification_raw = require_dict(
        load(arm_dir / "verification-summary.json"), "ARM64 verification"
    )
    debs_raw = load(arm_dir / "deb-artifacts.json")

    if reconstruction.get("source") != SOURCE:
        raise SystemExit("reconstruction source mismatch")
    if reconstruction.get("source_version") != VERSION:
        raise SystemExit("reconstruction version mismatch")
    if reconstruction.get("source_status") != "verified-reconstructed-git-tree":
        raise SystemExit("reconstruction status mismatch")
    base = require_dict(reconstruction.get("base_source"), "base source")
    if (
        base.get("repository_full_name") != BASE_REPOSITORY
        or base.get("commit_sha") != BASE_COMMIT
        or base.get("tree_sha") != BASE_TREE
    ):
        raise SystemExit("public base identity mismatch")
    target = require_dict(
        reconstruction.get("target_binary_authority"), "target binary authority"
    )
    if target.get("sha256") != TARGET_SHA256:
        raise SystemExit("target binary authority mismatch")
    claims = require_dict(reconstruction.get("claims"), "reconstruction claims")
    if claims.get("lost_original_source_archive_recovered") is not False:
        raise SystemExit("lost original source archive must remain unrecovered")
    if claims.get("reconstructed_source_claimed") is not True:
        raise SystemExit("reconstructed source claim is absent")
    if claims.get("exact_shipped_static_assets_used_as_source_inputs") is not True:
        raise SystemExit("exact static-asset source claim is absent")

    if equivalence.get("source") != SOURCE or equivalence.get("source_version") != VERSION:
        raise SystemExit("AMD64 equivalence identity mismatch")
    if equivalence.get("verified") is not True:
        raise SystemExit("AMD64 equivalence did not pass")
    if equivalence.get("normalized_elf_identity") is not True:
        raise SystemExit("normalized AMD64 ELF identity did not pass")
    if equivalence.get("non_elf_payload_identity") is not True:
        raise SystemExit("non-ELF AMD64 payload identity did not pass")
    if equivalence.get("fatal_difference_count") != 0:
        raise SystemExit("AMD64 equivalence contains fatal differences")

    if build_lock.get("source") != SOURCE or build_lock.get("source_version") != VERSION:
        raise SystemExit("ARM64 build-lock source identity mismatch")
    if build_lock.get("target_architecture") != "arm64":
        raise SystemExit("ARM64 build-lock architecture mismatch")
    if verification_raw.get("source") != SOURCE:
        raise SystemExit("ARM64 verification source mismatch")
    if verification_raw.get("source_version") != VERSION:
        raise SystemExit("ARM64 verification version mismatch")
    if verification_raw.get("verified") is not True:
        raise SystemExit("ARM64 verification did not pass")
    if verification_raw.get("wrong_architecture_executables") != []:
        raise SystemExit("foreign executable payload survived ARM64 verification")
    if verification_raw.get("main_package_count") != 1:
        raise SystemExit("main package count mismatch")
    if verification_raw.get("debug_package_count") != 1:
        raise SystemExit("debug package count mismatch")
    runtime_checks = verification_raw.get("runtime_checks")
    if not isinstance(runtime_checks, list) or len(runtime_checks) != 1:
        raise SystemExit("expected exactly one runtime ELF verification")
    if any(not isinstance(row, dict) or row.get("verified") is not True for row in runtime_checks):
        raise SystemExit("runtime ELF verification did not pass")

    debs = normalize_debs(debs_raw, "deb-artifacts.json")
    verification_debs = normalize_debs(
        verification_raw.get("deb_artifacts"),
        "verification-summary.json.deb_artifacts",
    )
    if deb_identities(debs) != deb_identities(verification_debs):
        raise SystemExit("ARM64 DEB evidence files disagree")
    if {row["package"] for row in debs} != {SOURCE, SOURCE + "-dbgsym"}:
        raise SystemExit("unexpected ARM64 binary package set")
    verification = dict(verification_raw)
    verification["deb_artifacts"] = verification_debs

    result_dir = (
        repository
        / "arm64/locks/rebuild-results/gooroom-guide/0.5.3_grm3u1_han3u1"
    )
    evidence_dir = (
        repository / "arm64/locks/gooroom-guide-han3u1-reconstruction/latest"
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
        "amd64-target-manifest.json": source_dir / "amd64-target-manifest.json",
        "amd64-candidate-manifest.json": source_dir / "amd64-candidate-manifest.json",
        "amd64-elf-comparison.json": source_dir / "amd64-elf-comparison.json",
        "amd64-non-elf-comparison.json": source_dir / "amd64-non-elf-comparison.json",
        "amd64-differences.json": source_dir / "amd64-differences.json",
        "arm64-build-lock.json": arm_dir / "build-lock.json",
        "arm64-verification-summary.json": arm_dir / "verification-summary.json",
        "arm64-deb-artifacts.json": arm_dir / "deb-artifacts.json",
        "arm64-elf-payloads.json": arm_dir / "elf-payloads.json",
    }
    for name, origin in evidence_files.items():
        if not origin.is_file():
            raise SystemExit(f"promotion evidence missing: {origin}")
        shutil.copy2(origin, evidence_dir / name)
    write_checksums(evidence_dir, "LOCKSUMS.sha256")

    warnings: list[str] = []
    if equivalence.get("raw_elf_identity") is not True:
        warnings.append(
            "Raw AMD64 ELF bytes differed, but identity was established after "
            "removing only the locked build-id/debug-link/comment metadata sections."
        )
    warnings.append(
        "The lost original 0.5.3 source archive was not recovered. The accepted "
        "authority is a bounded reconstruction over the exact public 0.5.1 tree, "
        "using the shipped architecture-neutral guide assets and exact changelog."
    )

    provenance = (
        "exact-public-0.5.1-tree-plus-bounded-cleanup-plus-shipped-static-guide-"
        "assets-plus-normalized-amd64-elf-identity"
    )
    reconstruction_detail = require_dict(
        reconstruction.get("reconstruction"), "reconstruction detail"
    )
    exact_payload = require_dict(
        reconstruction.get("exact_payload_relationship"), "exact payload relationship"
    )
    result = {
        "schema": 4,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": "verified-reconstructed-git-tree",
        "repository_full_name": BASE_REPOSITORY,
        "commit_sha": BASE_COMMIT,
        "tree_sha": reconstruction_detail["tree_sha"],
        "dsc_filename": None,
        "dsc_sha256": None,
        "authority_provenance": provenance,
        "actions_run_id": args.run_id,
        "actions_run_url": args.run_url,
        "artifact_id": args.artifact_id,
        "artifact_name": args.artifact_name,
        "artifact_digest": args.artifact_digest,
        "batch": "gooroom-guide-han3u1-source-reconstruction",
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
        "verification_warnings": warnings,
        "build_lock": build_lock,
        "source_lock_evidence": {
            "schema": 4,
            "base_repository": BASE_REPOSITORY,
            "base_commit_sha": BASE_COMMIT,
            "base_tree_sha": BASE_TREE,
            "base_source_version": base["source_version"],
            "reconstructed_tree_sha": reconstruction_detail["tree_sha"],
            "source_archive_sha256": reconstruction_detail["archive_sha256"],
            "target_binary_sha256": TARGET_SHA256,
            "changed_paths": reconstruction_detail["changed_paths"],
            "packaged_changelog_evidence": reconstruction[
                "packaged_changelog_evidence"
            ],
            "exact_payload_relationship": exact_payload,
            "amd64_equivalence": equivalence,
            "original_source_archive_recovered": False,
        },
        "verification_summary": verification,
        "evidence_paths": {
            "reconstruction": (
                "arm64/locks/gooroom-guide-han3u1-reconstruction/latest/"
                "reconstruction-lock.json"
            ),
            "amd64_equivalence": (
                "arm64/locks/gooroom-guide-han3u1-reconstruction/latest/"
                "amd64-equivalence-summary.json"
            ),
            "arm64_verification": (
                "arm64/locks/gooroom-guide-han3u1-reconstruction/latest/"
                "arm64-verification-summary.json"
            ),
        },
    }
    write(result_dir / "result.json", result)
    write_checksums(result_dir, "SHA256SUMS")

    if source_locks.exists():
        document = require_dict(load(source_locks), "source locks")
    else:
        document = {
            "schema": 1,
            "policy": "independently-verified-reconstructed-source-overlays",
            "sources": [],
        }
    current_rows = document.get("sources")
    if not isinstance(current_rows, list):
        raise SystemExit("source locks sources must be an array")
    rows = [
        row
        for row in current_rows
        if not (
            isinstance(row, dict)
            and row.get("source") == SOURCE
            and row.get("source_version") == VERSION
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
                "provenance": provenance,
                "repository_full_name": BASE_REPOSITORY,
                "commit_sha": BASE_COMMIT,
                "tree_sha": reconstruction_detail["tree_sha"],
                "ref_kind": "reconstructed-tree",
                "ref_name": VERSION,
                "match_scope": (
                    "exact-public-base-plus-bounded-source-cleanup-plus-shipped-"
                    "static-assets-plus-normalized-amd64-elf"
                ),
                "declared_source": SOURCE,
                "declared_version": VERSION,
                "source_archive_sha256": reconstruction_detail["archive_sha256"],
            },
            "verification": {
                "passed": True,
                "actions_run_id": args.run_id,
                "actions_run_url": args.run_url,
                "amd64_normalized_elf_identity_verified": True,
                "amd64_non_elf_payload_identity_verified": True,
                "native_arm64_build_verified": True,
                "exact_shipped_static_assets_verified": True,
                "original_source_archive_recovered": False,
                "evidence_path": (
                    "arm64/locks/gooroom-guide-han3u1-reconstruction/latest/"
                    "reconstruction-lock.json"
                ),
            },
        }
    )
    document["sources"] = sorted(
        rows,
        key=lambda row: (str(row.get("source", "")), str(row.get("source_version", ""))),
    )
    document["source_count"] = len(document["sources"])
    write(source_locks, document)
    print(
        json.dumps(
            {
                "result": str(result_dir),
                "evidence": str(evidence_dir),
                "source_locks": str(source_locks),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
