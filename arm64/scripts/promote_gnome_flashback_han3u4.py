#!/usr/bin/env python3
"""Promote verified gnome-flashback han3u4 reconstruction and ARM64 evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

SOURCE = "gnome-flashback"
VERSION = "3.38.0-2+grm3u2+han3u4"
BASE_REPOSITORY = "hancomgooroom/gnome-flashback"
BASE_COMMIT = "df5e1ec84df0cbb1dc9c1ce4f8a7ed366cd50db7"
BASE_TREE = "a5961872b3538a33b1ece5c76d0cf67506c71e2b"
PUBLIC_REPOSITORY = "gooroom/gnome-flashback"
PUBLIC_COMMIT = "68a47d769b0f15b84c532746ced1f8ae538ab545"
PUBLIC_TREE = "830a852c6272843c4c23da7e80b3b3961d4aeb38"
RESULT_VERSION_PATH = "3.38.0-2_grm3u2_han3u4"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_PACKAGES = {
    "gnome-flashback": "arm64",
    "gnome-flashback-common": "all",
    "gnome-session-flashback": "all",
}


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be an object")
    return value


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
            rows.append(f"{sha256(path)}  {path.relative_to(directory).as_posix()}\n")
    (directory / filename).write_text("".join(rows), encoding="utf-8")


def normalize_debs(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise SystemExit(f"{label} must be a non-empty array")
    required_fields = (
        "package", "version", "architecture", "source", "source_version",
        "filename", "size", "sha256",
    )
    rows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for index, raw in enumerate(value):
        location = f"{label}[{index}]"
        if not isinstance(raw, dict):
            raise SystemExit(f"{location} must be an object")
        row = dict(raw)
        missing = [field for field in required_fields if row.get(field) in (None, "")]
        if missing:
            raise SystemExit(f"{location} missing fields: {missing}")
        if row["source"] != SOURCE or row["source_version"] != VERSION or row["version"] != VERSION:
            raise SystemExit(f"{location} source/version mismatch")
        if not SHA256_RE.fullmatch(str(row["sha256"])):
            raise SystemExit(f"{location} has invalid SHA-256")
        try:
            row["size"] = int(row["size"])
        except (TypeError, ValueError) as error:
            raise SystemExit(f"{location} has invalid size") from error
        if row["size"] <= 0:
            raise SystemExit(f"{location} size must be positive")
        identity = tuple(row[field] for field in required_fields)
        if identity in seen:
            raise SystemExit(f"{location} duplicates an earlier DEB")
        seen.add(identity)
        rows.append(row)
    rows.sort(key=lambda row: (row["package"], row["architecture"], row["filename"]))
    return rows


def required_deb_map(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for row in rows:
        package = str(row["package"])
        if package in EXPECTED_PACKAGES:
            if package in selected:
                raise SystemExit(f"duplicate required DEB: {package}")
            selected[package] = row
        elif not package.endswith("-dbgsym"):
            raise SystemExit(f"unexpected ARM64 package: {package}")
    if set(selected) != set(EXPECTED_PACKAGES):
        raise SystemExit(
            f"required ARM64 package set mismatch: expected={sorted(EXPECTED_PACKAGES)} "
            f"actual={sorted(selected)}"
        )
    for package, architecture in EXPECTED_PACKAGES.items():
        if selected[package]["architecture"] != architecture:
            raise SystemExit(
                f"wrong architecture for {package}: {selected[package]['architecture']}"
            )
    return selected


def copy_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise SystemExit(f"promotion evidence missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def copy_tree_if_present(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    if not source.is_dir():
        raise SystemExit(f"expected evidence directory: {source}")
    shutil.copytree(source, destination)


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

    reconstruction = require_dict(load(source_dir / "reconstruction-lock.json"), "reconstruction")
    amd64 = require_dict(load(source_dir / "amd64-equivalence-summary.json"), "AMD64 equivalence")
    target_binary = require_dict(load(source_dir / "target-binary-lock.json"), "target binary lock")
    build_lock = require_dict(load(arm_dir / "build-lock.json"), "ARM64 build lock")
    arm64 = require_dict(load(arm_dir / "verification-summary.json"), "ARM64 verification")
    debs = normalize_debs(load(arm_dir / "deb-artifacts.json"), "deb-artifacts.json")
    selected_debs = required_deb_map(debs)

    if reconstruction.get("source") != SOURCE or reconstruction.get("source_version") != VERSION:
        raise SystemExit("reconstruction source identity mismatch")
    if reconstruction.get("source_status") != "verified-reconstructed-git-tree":
        raise SystemExit("reconstruction status is not verified")
    base = require_dict(reconstruction.get("base_source"), "base source")
    if (
        base.get("repository_full_name") != BASE_REPOSITORY
        or base.get("commit_sha") != BASE_COMMIT
        or base.get("tree_sha") != BASE_TREE
    ):
        raise SystemExit("Hancom public base identity mismatch")
    equivalent = require_dict(
        reconstruction.get("public_equivalent_source"), "public equivalent source"
    )
    if (
        equivalent.get("repository_full_name") != PUBLIC_REPOSITORY
        or equivalent.get("commit_sha") != PUBLIC_COMMIT
        or equivalent.get("tree_sha") != PUBLIC_TREE
    ):
        raise SystemExit("Gooroom equivalent lineage identity mismatch")
    patches = equivalent.get("patches")
    if not isinstance(patches, list) or len(patches) != 7:
        raise SystemExit("expected seven public equivalent patches")
    unique = require_dict(reconstruction.get("unique_reconstruction"), "unique reconstruction")
    if not isinstance(unique.get("changed_paths"), list) or len(unique["changed_paths"]) != 4:
        raise SystemExit("bounded unique reconstruction path set mismatch")
    embedded = require_dict(
        reconstruction.get("embedded_resource_relationship"), "embedded resources"
    )
    if embedded.get("resource_count") != 16:
        raise SystemExit("embedded GResource count mismatch")
    if embedded.get("all_other_resources_public_base_identical") is not True:
        raise SystemExit("public-base GResource relationship did not pass")
    claims = require_dict(reconstruction.get("claims"), "reconstruction claims")
    if claims.get("lost_original_source_archive_recovered") is not False:
        raise SystemExit("lost original source archive must remain unrecovered")
    if claims.get("reconstructed_source_claimed") is not True:
        raise SystemExit("reconstructed source claim is absent")
    if claims.get("exact_shipped_embedded_css_used_as_source_input") is not True:
        raise SystemExit("exact shipped embedded CSS claim is absent")
    if claims.get("amd64_equivalence_verified") is not True:
        raise SystemExit("AMD64 equivalence claim is absent")
    if claims.get("native_arm64_build_verified") is not False:
        raise SystemExit("source artifact must predate native ARM64 verification")
    if claims.get("promotion_allowed") is not False:
        raise SystemExit("source artifact must not pre-authorize promotion")
    reconstruction_detail = require_dict(reconstruction.get("reconstruction"), "reconstruction detail")
    tree_sha = str(reconstruction_detail.get("tree_sha", ""))
    archive_sha = str(reconstruction_detail.get("archive_sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", tree_sha):
        raise SystemExit("reconstructed tree SHA is invalid")
    if not SHA256_RE.fullmatch(archive_sha):
        raise SystemExit("source archive SHA-256 is invalid")

    if amd64.get("source") != SOURCE or amd64.get("source_version") != VERSION:
        raise SystemExit("AMD64 equivalence identity mismatch")
    if amd64.get("target_architecture") != "amd64" or amd64.get("verified") is not True:
        raise SystemExit("AMD64 equivalence did not pass")
    if amd64.get("compared_binary_package_count") != 3:
        raise SystemExit("AMD64 package comparison count mismatch")
    if amd64.get("control_fields_identical") is not True:
        raise SystemExit("AMD64 control identity did not pass")
    if amd64.get("auxiliary_control_members_identical") is not True:
        raise SystemExit("AMD64 auxiliary control identity did not pass")
    if amd64.get("same_payload_path_sets") is not True:
        raise SystemExit("AMD64 payload path identity did not pass")
    if amd64.get("non_elf_payload_identity") is not True:
        raise SystemExit("AMD64 non-ELF payload identity did not pass")
    if amd64.get("normalized_elf_identity") is not True or amd64.get("elf_file_count") != 5:
        raise SystemExit("AMD64 normalized ELF identity did not pass")
    if amd64.get("fatal_difference_count") != 0:
        raise SystemExit("AMD64 equivalence contains fatal differences")

    if target_binary.get("source") != SOURCE or target_binary.get("source_version") != VERSION:
        raise SystemExit("target binary lock identity mismatch")
    targets = target_binary.get("packages")
    if not isinstance(targets, list) or len(targets) != 3:
        raise SystemExit("target binary authority package count mismatch")

    if build_lock.get("source") != SOURCE or build_lock.get("source_version") != VERSION:
        raise SystemExit("ARM64 build lock identity mismatch")
    if build_lock.get("target_architecture") != "arm64":
        raise SystemExit("ARM64 build lock architecture mismatch")
    if build_lock.get("reconstructed_tree_sha") != tree_sha:
        raise SystemExit("ARM64 build used a different reconstructed tree")
    if build_lock.get("source_archive_sha256") != archive_sha:
        raise SystemExit("ARM64 build used a different source archive")

    if arm64.get("source") != SOURCE or arm64.get("source_version") != VERSION:
        raise SystemExit("ARM64 verification identity mismatch")
    if arm64.get("target_architecture") != "arm64" or arm64.get("verified") is not True:
        raise SystemExit("ARM64 verification did not pass")
    if arm64.get("expected_package_count") != 3 or arm64.get("compared_package_count") != 3:
        raise SystemExit("ARM64 package comparison count mismatch")
    if arm64.get("wrong_architecture_executables") != []:
        raise SystemExit("foreign executable payload survived ARM64 verification")
    package_results = arm64.get("package_results")
    if not isinstance(package_results, list) or len(package_results) != 3:
        raise SystemExit("ARM64 package result set mismatch")
    if any(not isinstance(row, dict) or row.get("verified") is not True for row in package_results):
        raise SystemExit("one or more ARM64 packages failed verification")
    runtime_checks = arm64.get("runtime_elf_checks")
    if not isinstance(runtime_checks, list) or len(runtime_checks) != 5:
        raise SystemExit("expected five runtime ELF comparisons")
    if any(not isinstance(row, dict) or row.get("verified") is not True for row in runtime_checks):
        raise SystemExit("one or more ARM64 ELF checks failed")
    resource_rows = [row for row in runtime_checks if row.get("target_gresource_sha256")]
    if len(resource_rows) != 1 or resource_rows[0].get("gresource_identity") is not True:
        raise SystemExit("embedded GResource identity did not pass on ARM64")

    if not args.artifact_name or not args.artifact_id:
        raise SystemExit("ARM64 artifact metadata is incomplete")
    if not args.artifact_digest.startswith("sha256:"):
        raise SystemExit("ARM64 artifact digest is not a SHA-256 digest")

    result_dir = repository / "arm64/locks/rebuild-results" / SOURCE / RESULT_VERSION_PATH
    evidence_dir = repository / "arm64/locks/gnome-flashback-han3u4-reconstruction/latest"
    source_locks = repository / "arm64/locks/reconstructed-sources/source-locks.json"
    shutil.rmtree(result_dir, ignore_errors=True)
    shutil.rmtree(evidence_dir, ignore_errors=True)
    result_dir.mkdir(parents=True)
    evidence_dir.mkdir(parents=True)

    source_files = [
        "reconstruction-lock.json",
        "reconstruction.patch",
        "target-binary-lock.json",
        "vendor-artifact-metadata.json",
        "amd64-equivalence-summary.json",
        "amd64-package-comparisons.json",
        "amd64-differences.json",
    ]
    arm_files = [
        "build-lock.json",
        "verification-summary.json",
        "deb-artifacts.json",
        "package-comparisons.json",
        "non-elf-comparisons.json",
        "elf-comparisons.json",
        "elf-payloads.json",
        "wrong-architecture-elfs.json",
    ]
    for name in source_files:
        copy_file(source_dir / name, evidence_dir / name)
    for name in arm_files:
        copy_file(arm_dir / name, evidence_dir / f"arm64-{name}")
    copy_tree_if_present(source_dir / "amd64-manifests", evidence_dir / "amd64-manifests")
    copy_tree_if_present(source_dir / "amd64-comparisons", evidence_dir / "amd64-comparisons")
    write_checksums(evidence_dir, "LOCKSUMS.sha256")

    provenance = (
        "exact-public-han3u1-tree-plus-seven-public-gooroom-equivalent-patches-"
        "plus-four-binary-constrained-hancom-deltas-plus-exact-embedded-css-"
        "plus-normalized-amd64-elf-identity"
    )
    warnings = [
        "The lost original han3u4 source archive was not recovered. The accepted authority is a bounded reconstruction over exact public Hancom and Gooroom lineages, constrained by the immutable shipped AMD64 packages.",
    ]
    if amd64.get("raw_elf_identity") is not True:
        warnings.append(
            "Raw AMD64 ELF bytes differed only in explicitly normalized build metadata; normalized ELF bytes, controls, paths, modes, symlinks, and non-ELF payloads were identical."
        )

    result = {
        "schema": 4,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": "verified-reconstructed-git-tree",
        "repository_full_name": BASE_REPOSITORY,
        "commit_sha": BASE_COMMIT,
        "tree_sha": tree_sha,
        "dsc_filename": None,
        "dsc_sha256": None,
        "authority_provenance": provenance,
        "actions_run_id": args.run_id,
        "actions_run_url": args.run_url,
        "artifact_id": args.artifact_id,
        "artifact_name": args.artifact_name,
        "artifact_digest": args.artifact_digest,
        "batch": "gnome-flashback-han3u4-source-reconstruction",
        "build_outcome": "success",
        "build_exit_code": "0",
        "verify_outcome": "success",
        "required_native_packages": ["gnome-flashback"],
        "reused_all_packages": ["gnome-flashback-common", "gnome-session-flashback"],
        "job_passed": True,
        "verification_passed": True,
        "passed": True,
        "deb_artifacts": debs,
        "required_deb_artifacts": [selected_debs[name] for name in sorted(selected_debs)],
        "verification_errors": [],
        "verification_warnings": warnings,
        "build_lock": build_lock,
        "source_lock_evidence": {
            "schema": 4,
            "base_repository": BASE_REPOSITORY,
            "base_commit_sha": BASE_COMMIT,
            "base_tree_sha": BASE_TREE,
            "base_source_version": base.get("source_version"),
            "public_equivalent_repository": PUBLIC_REPOSITORY,
            "public_equivalent_commit_sha": PUBLIC_COMMIT,
            "public_equivalent_tree_sha": PUBLIC_TREE,
            "reconstructed_tree_sha": tree_sha,
            "source_archive_sha256": archive_sha,
            "target_binary_authority": targets,
            "packaged_changelog": reconstruction.get("packaged_changelog"),
            "embedded_resource_relationship": embedded,
            "unique_reconstruction": unique,
            "amd64_equivalence": amd64,
            "original_source_archive_recovered": False,
        },
        "verification_summary": arm64,
        "evidence_paths": {
            "reconstruction": "arm64/locks/gnome-flashback-han3u4-reconstruction/latest/reconstruction-lock.json",
            "amd64_equivalence": "arm64/locks/gnome-flashback-han3u4-reconstruction/latest/amd64-equivalence-summary.json",
            "arm64_verification": "arm64/locks/gnome-flashback-han3u4-reconstruction/latest/arm64-verification-summary.json",
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
    current = document.get("sources")
    if not isinstance(current, list):
        raise SystemExit("source locks sources must be an array")
    rows = [
        row for row in current
        if not (
            isinstance(row, dict)
            and row.get("source") == SOURCE
            and row.get("source_version") == VERSION
        )
    ]
    rows.append({
        "provenance": "verified-reconstructed-source",
        "selected": {
            "type": "reconstructed-git-tree",
            "provenance": provenance,
            "repository_full_name": BASE_REPOSITORY,
            "commit_sha": BASE_COMMIT,
            "tree_sha": tree_sha,
            "ref_kind": "reconstructed-tree",
            "ref_name": VERSION,
            "match_scope": (
                "exact-public-hancom-base-plus-public-gooroom-equivalent-patches-"
                "plus-binary-constrained-unique-deltas-plus-exact-gresource-"
                "plus-normalized-amd64-elf"
            ),
            "declared_source": SOURCE,
            "declared_version": VERSION,
            "source_archive_sha256": archive_sha,
        },
        "source": SOURCE,
        "source_version": VERSION,
        "status": "resolved",
        "verification": {
            "passed": True,
            "actions_run_id": args.run_id,
            "actions_run_url": args.run_url,
            "amd64_control_identity_verified": True,
            "amd64_non_elf_payload_identity_verified": True,
            "amd64_normalized_elf_identity_verified": True,
            "exact_shipped_embedded_css_verified": True,
            "native_arm64_build_verified": True,
            "arm64_dynamic_and_export_identity_verified": True,
            "arm64_embedded_gresource_identity_verified": True,
            "original_source_archive_recovered": False,
            "evidence_path": "arm64/locks/gnome-flashback-han3u4-reconstruction/latest/reconstruction-lock.json",
        },
    })
    document["sources"] = sorted(
        rows,
        key=lambda row: (str(row.get("source", "")), str(row.get("source_version", ""))),
    )
    document["source_count"] = len(document["sources"])
    write(source_locks, document)

    print(json.dumps({
        "result": str(result_dir),
        "evidence": str(evidence_dir),
        "source_locks": str(source_locks),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
