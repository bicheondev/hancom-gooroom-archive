#!/usr/bin/env python3
"""Promote verified applauncher han3u2 source and native ARM64 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

SOURCE = "gooroom-applauncher-applet"
VERSION = "0.4.0+grm3u1+han3u2"
REPOSITORY = "gooroom/gooroom-applauncher-applet"
BASE_COMMIT = "f2b5bf5909289796360a64526110d55e41c6f41f"
BASE_TREE = "946068a768ee6d648a79a3a8c294dcbdc64992df"
CANDIDATE_COMMIT = "20a1b11b624099bf9522f2de7104f4bf776e0a2e"
CANDIDATE_TREE = "b46c94d465fcae8779a060373ea70650ad484351"
RECONSTRUCTED_TREE = "9b0cacfee8fb3118e4c497e590e2a310d8bc5c29"
SOURCE_ARCHIVE_SHA256 = (
    "d92d75a144924fe84c5d2ccfa9794ccec7125f1640c00aaf3fffc783c6c877e7"
)
TARGET_DEB_SHA256 = (
    "97d4ad82497333615de5eea8fa4d64fd9538f000dccaee5acb1f6f26f44edc00"
)
SOURCE_RUN_ID = "31251842558"
SOURCE_ARTIFACT_ID = "9020244055"
SOURCE_ARTIFACT_NAME = "gooroom-applauncher-han3u2-source-lineage-31251842558"
SOURCE_ARTIFACT_DIGEST = (
    "sha256:0fca7ce9c9ee09ea4c4f137aa525c2a1f8fd55b480e96e866d6afd94998b6d71"
)


def load(path: Path) -> dict[str, Any] | list[Any]:
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
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def checksums(directory: Path, filename: str) -> None:
    rows = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != filename:
            rows.append(
                f"{sha256(path)}  {path.relative_to(directory).as_posix()}\n"
            )
    (directory / filename).write_text("".join(rows), encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def safe_extract(archive: Path, destination: Path) -> None:
    destination_resolved = destination.resolve()
    with tarfile.open(archive, "r:*") as stream:
        for member in stream.getmembers():
            member_path = (destination / member.name).resolve()
            require(
                member_path == destination_resolved
                or destination_resolved in member_path.parents,
                f"unsafe source archive member: {member.name}",
            )
        stream.extractall(destination)


def git_tree_sha(archive: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="applauncher-source-tree-") as temp:
        root = Path(temp)
        safe_extract(archive, root)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        completed = subprocess.run(
            ["git", "-C", str(root), "write-tree"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        return completed.stdout.strip()


def validate_source_artifact(source_dir: Path) -> dict[str, Any]:
    required = [
        "verification.json",
        "verification-summary.md",
        "source-evidence.json",
        "source-lineage-lock.json",
        "hancom-theme-reconstruction.json",
        "hancom-indicator-reconstruction.json",
        "reconstructed-source.tar.gz",
        "public-drag-drop.patch",
        "target-payload-overlay.patch",
        "input-lock.json",
    ]
    for name in required:
        require((source_dir / name).is_file(), f"source evidence missing: {name}")

    verification = load(source_dir / "verification.json")
    require(isinstance(verification, dict), "verification must be an object")
    require(verification.get("verification_complete") is True, "verification incomplete")
    require(verification.get("source_relationship_valid") is True, "source relationship failed")
    require(verification.get("source_lineage_validated") is True, "source lineage failed")
    require(verification.get("elf_semantic_match") is True, "ELF semantic mismatch")
    require(verification.get("normalized_elf_identity") is True, "normalized ELF mismatch")
    require(
        verification.get("elf_nondeterministic_metadata_only") is True,
        "unexpected runtime ELF differences",
    )
    require(
        verification.get("payload_reproducible_identity") is True,
        "non-ELF payload is not reproducible",
    )
    claims = verification.get("claims")
    require(isinstance(claims, dict), "verification claims missing")
    require(
        claims.get("functional_elf_identity_claimed") is True,
        "functional ELF identity was not established",
    )
    require(
        claims.get("byte_identity_claimed") is False,
        "raw DEB identity must not be overstated",
    )
    reproducibility = verification.get("elf_reproducibility")
    require(isinstance(reproducibility, dict), "ELF reproducibility evidence missing")
    require(
        reproducibility.get("unexpected_differing_byte_count") == 0,
        "unexpected ELF bytes differ",
    )
    require(
        reproducibility.get("differing_sections")
        == [".gnu_debuglink", ".note.gnu.build-id"],
        "ELF differences escaped the allowed metadata sections",
    )
    target_package = verification.get("target_package")
    require(isinstance(target_package, dict), "target package evidence missing")
    require(
        target_package.get("sha256") == TARGET_DEB_SHA256,
        "target DEB authority mismatch",
    )

    source_evidence = load(source_dir / "source-evidence.json")
    require(isinstance(source_evidence, dict), "source evidence must be an object")
    require(source_evidence.get("repository") == REPOSITORY, "repository mismatch")
    require(
        source_evidence.get("candidate_commit") == CANDIDATE_COMMIT,
        "candidate commit mismatch",
    )
    require(
        source_evidence.get("candidate_tree") == CANDIDATE_TREE,
        "candidate tree mismatch",
    )
    require(
        source_evidence.get("candidate_parent") == BASE_COMMIT,
        "candidate parent mismatch",
    )
    require(
        source_evidence.get("reconstructed_source_archive_sha256")
        == SOURCE_ARCHIVE_SHA256,
        "source archive lock mismatch",
    )

    lineage = load(source_dir / "source-lineage-lock.json")
    require(isinstance(lineage, dict), "lineage lock must be an object")
    require(lineage.get("public_base", {}).get("commit") == BASE_COMMIT, "base commit mismatch")
    require(lineage.get("public_base", {}).get("tree") == BASE_TREE, "base tree mismatch")
    require(
        lineage.get("public_candidate", {}).get("commit") == CANDIDATE_COMMIT,
        "lineage candidate mismatch",
    )
    require(
        lineage.get("target", {}).get("sha256") == TARGET_DEB_SHA256,
        "lineage target mismatch",
    )

    theme = load(source_dir / "hancom-theme-reconstruction.json")
    indicator = load(source_dir / "hancom-indicator-reconstruction.json")
    require(
        isinstance(theme, dict) and theme.get("reconstruction_complete") is True,
        "theme reconstruction incomplete",
    )
    require(
        isinstance(indicator, dict)
        and indicator.get("reconstruction_complete") is True,
        "indicator reconstruction incomplete",
    )

    archive = source_dir / "reconstructed-source.tar.gz"
    require(sha256(archive) == SOURCE_ARCHIVE_SHA256, "source archive SHA-256 mismatch")
    require(git_tree_sha(archive) == RECONSTRUCTED_TREE, "reconstructed Git tree mismatch")

    return {
        "verification": verification,
        "source_evidence": source_evidence,
        "lineage": lineage,
        "theme": theme,
        "indicator": indicator,
    }


def validate_arm64_artifact(arm_dir: Path) -> dict[str, Any]:
    for name in [
        "verification-summary.json",
        "deb-artifacts.json",
        "build-lock.json",
        "SHA256SUMS",
    ]:
        require((arm_dir / name).is_file(), f"ARM64 evidence missing: {name}")
    verification = load(arm_dir / "verification-summary.json")
    build_lock = load(arm_dir / "build-lock.json")
    debs = load(arm_dir / "deb-artifacts.json")
    require(isinstance(verification, dict), "ARM64 verification must be an object")
    require(isinstance(build_lock, dict), "ARM64 build lock must be an object")
    require(isinstance(debs, list), "ARM64 DEB list must be an array")
    require(verification.get("verified") is True, "ARM64 package verification failed")
    require(verification.get("source") == SOURCE, "ARM64 verification source mismatch")
    require(verification.get("source_version") == VERSION, "ARM64 version mismatch")
    require(
        verification.get("wrong_architecture_executables") == [],
        "foreign executable survived ARM64 verification",
    )
    require(verification.get("main_package_count") == 1, "main package count mismatch")
    module = verification.get("runtime_module")
    require(isinstance(module, dict), "runtime module evidence missing")
    require(module.get("missing_exports") == [], "required runtime exports missing")
    require(
        module.get("gresource_sha256")
        == "2abe1443baba5103770ecf92c27dab0d5b5c5443f503ec3ab6c4287b7b77c3a8",
        "ARM64 GResource digest mismatch",
    )
    require(build_lock.get("source") == SOURCE, "build-lock source mismatch")
    require(build_lock.get("source_version") == VERSION, "build-lock version mismatch")
    require(
        build_lock.get("reconstructed_tree_sha") == RECONSTRUCTED_TREE,
        "build-lock tree mismatch",
    )
    require(
        build_lock.get("source_archive_sha256") == SOURCE_ARCHIVE_SHA256,
        "build-lock archive mismatch",
    )
    require(
        any(
            row.get("package") == SOURCE
            and row.get("version") == VERSION
            and row.get("architecture") == "arm64"
            for row in debs
            if isinstance(row, dict)
        ),
        "main ARM64 DEB is absent",
    )
    return {
        "verification": verification,
        "build_lock": build_lock,
        "debs": debs,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-artifact", type=Path, required=True)
    parser.add_argument("--arm64-artifact", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--arm64-artifact-id", required=True)
    parser.add_argument("--arm64-artifact-name", required=True)
    parser.add_argument("--arm64-artifact-digest", required=True)
    args = parser.parse_args()

    source_dir = args.source_artifact.resolve()
    arm_dir = args.arm64_artifact.resolve()
    repository = args.repository_root.resolve()
    source = validate_source_artifact(source_dir)
    arm = validate_arm64_artifact(arm_dir)

    result_dir = (
        repository
        / "arm64/locks/rebuild-results/gooroom-applauncher-applet/0.4.0_grm3u1_han3u2"
    )
    evidence_dir = (
        repository
        / "arm64/locks/gooroom-applauncher-han3u2-reconstruction/latest"
    )
    source_locks = repository / "arm64/locks/reconstructed-sources/source-locks.json"
    shutil.rmtree(result_dir, ignore_errors=True)
    shutil.rmtree(evidence_dir, ignore_errors=True)
    result_dir.mkdir(parents=True)
    evidence_dir.mkdir(parents=True)

    evidence_files = {
        "verification.json": source_dir / "verification.json",
        "verification-summary.md": source_dir / "verification-summary.md",
        "source-evidence.json": source_dir / "source-evidence.json",
        "source-lineage-lock.json": source_dir / "source-lineage-lock.json",
        "hancom-theme-reconstruction.json": source_dir / "hancom-theme-reconstruction.json",
        "hancom-indicator-reconstruction.json": source_dir / "hancom-indicator-reconstruction.json",
        "public-drag-drop.patch": source_dir / "public-drag-drop.patch",
        "target-payload-overlay.patch": source_dir / "target-payload-overlay.patch",
        "reconstructed-source.tar.gz": source_dir / "reconstructed-source.tar.gz",
        "arm64-build-lock.json": arm_dir / "build-lock.json",
        "arm64-verification-summary.json": arm_dir / "verification-summary.json",
        "arm64-deb-artifacts.json": arm_dir / "deb-artifacts.json",
    }
    for name, origin in evidence_files.items():
        require(origin.is_file(), f"promotion evidence missing: {origin}")
        shutil.copy2(origin, evidence_dir / name)

    artifact_lock = {
        "schema": 2,
        "source_verification_artifact": {
            "run_id": SOURCE_RUN_ID,
            "artifact_id": SOURCE_ARTIFACT_ID,
            "artifact_name": SOURCE_ARTIFACT_NAME,
            "artifact_digest": SOURCE_ARTIFACT_DIGEST,
        },
        "native_arm64_artifact": {
            "run_id": args.run_id,
            "artifact_id": args.arm64_artifact_id,
            "artifact_name": args.arm64_artifact_name,
            "artifact_digest": args.arm64_artifact_digest,
        },
    }
    write(evidence_dir / "artifact-lock.json", artifact_lock)
    checksums(evidence_dir, "LOCKSUMS.sha256")

    result = {
        "schema": 4,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": "verified-reconstructed-git-tree",
        "repository_full_name": REPOSITORY,
        "commit_sha": CANDIDATE_COMMIT,
        "tree_sha": RECONSTRUCTED_TREE,
        "dsc_filename": None,
        "dsc_sha256": None,
        "authority_provenance": (
            "public-direct-parent-drag-drop-lineage-plus-binary-constrained-"
            "hancom-theme-indicator-reconstruction-and-reproducible-amd64-elf"
        ),
        "actions_run_id": args.run_id,
        "actions_run_url": args.run_url,
        "artifact_id": args.arm64_artifact_id,
        "artifact_name": args.arm64_artifact_name,
        "artifact_digest": args.arm64_artifact_digest,
        "batch": "gooroom-applauncher-han3u2-source-reconstruction",
        "build_outcome": "success",
        "build_exit_code": "0",
        "verify_outcome": "success",
        "required_native_packages": [SOURCE],
        "reused_all_packages": [],
        "job_passed": True,
        "verification_passed": True,
        "passed": True,
        "deb_artifacts": arm["debs"],
        "verification_errors": [],
        "verification_warnings": [
            "Raw AMD64 ELF and DEB bytes differ only because GNU Build ID and the mechanically derived .gnu_debuglink metadata differ; normalized runtime ELF and all non-ELF payloads are identical."
        ],
        "build_lock": arm["build_lock"],
        "source_lock_evidence": {
            "schema": 4,
            "base_repository": REPOSITORY,
            "base_commit_sha": BASE_COMMIT,
            "base_tree_sha": BASE_TREE,
            "candidate_commit_sha": CANDIDATE_COMMIT,
            "candidate_tree_sha": CANDIDATE_TREE,
            "reconstructed_tree_sha": RECONSTRUCTED_TREE,
            "source_archive_sha256": SOURCE_ARCHIVE_SHA256,
            "target_binary_sha256": TARGET_DEB_SHA256,
            "source_verification_run_id": SOURCE_RUN_ID,
            "source_relationship_valid": True,
            "functional_elf_identity": True,
            "normalized_elf_identity": True,
            "non_elf_payload_identity": True,
            "raw_byte_identity_claimed": False,
            "allowed_nondeterministic_sections": [
                ".gnu_debuglink",
                ".note.gnu.build-id",
            ],
        },
        "verification_summary": arm["verification"],
        "evidence_paths": {
            "source_verification": (
                "arm64/locks/gooroom-applauncher-han3u2-reconstruction/latest/verification.json"
            ),
            "source_lineage": (
                "arm64/locks/gooroom-applauncher-han3u2-reconstruction/latest/source-lineage-lock.json"
            ),
            "reconstructed_source": (
                "arm64/locks/gooroom-applauncher-han3u2-reconstruction/latest/reconstructed-source.tar.gz"
            ),
            "arm64_verification": (
                "arm64/locks/gooroom-applauncher-han3u2-reconstruction/latest/arm64-verification-summary.json"
            ),
        },
    }
    write(result_dir / "result.json", result)
    write(result_dir / "artifact-lock.json", artifact_lock)
    checksums(result_dir, "SHA256SUMS")

    if source_locks.exists():
        document = load(source_locks)
        require(isinstance(document, dict), "reconstructed source lock is malformed")
    else:
        document = {
            "schema": 1,
            "policy": "independently-verified-reconstructed-source-overlays",
            "sources": [],
        }
    existing = document.get("sources", [])
    require(isinstance(existing, list), "reconstructed source rows are malformed")
    rows = [
        row
        for row in existing
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
                "provenance": (
                    "public-direct-parent-drag-drop-lineage-plus-binary-"
                    "constrained-hancom-theme-indicator-reconstruction"
                ),
                "repository_full_name": REPOSITORY,
                "commit_sha": CANDIDATE_COMMIT,
                "tree_sha": RECONSTRUCTED_TREE,
                "ref_kind": "reconstructed-tree",
                "ref_name": VERSION,
                "match_scope": (
                    "public-direct-parent-lineage-and-strict-reproducible-"
                    "amd64-functional-equivalence"
                ),
                "declared_source": SOURCE,
                "declared_version": VERSION,
                "source_archive_sha256": SOURCE_ARCHIVE_SHA256,
            },
            "verification": {
                "passed": True,
                "actions_run_id": args.run_id,
                "actions_run_url": args.run_url,
                "source_verification_run_id": SOURCE_RUN_ID,
                "amd64_structural_equivalence_verified": True,
                "amd64_normalized_elf_identity_verified": True,
                "non_elf_payload_identity_verified": True,
                "native_arm64_build_verified": True,
                "raw_byte_identity_claimed": False,
                "evidence_path": (
                    "arm64/locks/gooroom-applauncher-han3u2-reconstruction/latest/verification.json"
                ),
            },
        }
    )
    document["sources"] = sorted(
        rows,
        key=lambda row: (str(row["source"]), str(row["source_version"])),
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
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
