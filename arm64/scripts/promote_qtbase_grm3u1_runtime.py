#!/usr/bin/env python3
"""Promote the independently verified QtBase grm3u1 ARM64 runtime subset.

This script deliberately separates package-layer promotion from original-source
recovery.  The lost vendor source archive remains unrecovered.  Promotion is
allowed only because all of the following immutable authorities agree:

* the bounded reconstructed source archive;
* exact AMD64 control, path, non-ELF and ELF byte equivalence to the vendor DEBs;
* a native ARM64 build with no foreign executable payloads.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

SOURCE = "qtbase-opensource-src"
VERSION = "5.15.2+dfsg-9+grm3u1"
RESULT_VERSION_PATH = "5.15.2_dfsg-9_grm3u1"
SOURCE_STATUS = "verified-reconstructed-amd64-equivalent"
SOURCE_TYPE = "verified-reconstructed-source-archive"
RECONSTRUCTION_AUTHORITY_SHA256 = (
    "9fbdf150d47b7c9238e957d084711e085d5b89d4671a7da0b0978084f80cb16a"
)
SOURCE_TREE_MANIFEST_SHA256 = (
    "a1e7255812863928d939d3625a52d48d1b9cb5c980d8273da4cc382c8dec2814"
)
RECONSTRUCTED_DSC_SHA256 = (
    "9fda2d887f257801d9d99a3a000130ec1b90a93c76cc4e129009ecf747a6c9c8"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SOURCE_MEMBERS = {
    "qtbase-opensource-src_5.15.2+dfsg-9+grm3u1.debian.tar.xz": (
        261056,
        "415e2bb465a4461449eab1f7ac1049d36cc4640ed5d296f238e4cf92d4b6de1b",
    ),
    "qtbase-opensource-src_5.15.2+dfsg-9+grm3u1.dsc": (
        4595,
        RECONSTRUCTED_DSC_SHA256,
    ),
    "qtbase-opensource-src_5.15.2+dfsg.orig.tar.xz": (
        48055144,
        "9ed5e0ab96a04daec5383a5e642d0308ca8246359a4c857a73a5c58d806237bb",
    ),
}

REQUIRED_PACKAGES = (
    "libqt5core5a",
    "libqt5dbus5",
    "libqt5gui5",
    "libqt5network5",
    "libqt5printsupport5",
    "libqt5sql5",
    "libqt5test5",
    "libqt5widgets5",
    "libqt5xml5",
)

EXPECTED_ARM64_PACKAGES = {
    "libqt5core5a": (
        1679736,
        "b37ed010ec1d04f2e398e128a654a04620e97b5005e392409b5a52769c27cf93",
    ),
    "libqt5dbus5": (
        217592,
        "b673ed942e245ee1ae13dd9d2ac590f7ce6dca74e3b377651ce7f796f1ca2dc6",
    ),
    "libqt5gui5": (
        2969672,
        "bd7c9f28f6019b63d29c6493b14a592c4a0b9217e7c9425dc2f68ade80b9d01a",
    ),
    "libqt5network5": (
        621724,
        "c47a93a11d6aab9d46993461f107c6c81eb9b6b803eb158422444a24c3cc55fb",
    ),
    "libqt5printsupport5": (
        214944,
        "f19d45692f13074138623b8d1394593280106173bed434925a3911d5b79e2f8e",
    ),
    "libqt5sql5": (
        140428,
        "71cd82fa63be880c68d4cfb18565b25851cbbceb29fc2f2e1b1e4a6724bfcb57",
    ),
    "libqt5test5": (
        156540,
        "06982fc1cd1f2cc66f1eb3d8fb13b0a7cec31f6c8849647bfe9fdc32ed01f9f7",
    ),
    "libqt5widgets5": (
        2228780,
        "2617ce3f667b2da28fb36c08a57cdf0d6f8a930ad50399706a1fd60135543303",
    ),
    "libqt5xml5": (
        144808,
        "5685a90ca7667ae05d0d8371f7dc3b1e613f0c12d087f8f714b779ab8ef5d4ed",
    ),
}

UPSTREAM_ARTIFACTS = {
    "source": {
        "run_id": "31497018080",
        "artifact_id": "9103425191",
        "artifact_name": "qtbase-5.15.2-dfsg-9-grm3u1-reconstructed-source",
        "digest": "sha256:d369c4984048ad79e5674e3b83e7d765cbea86eabd849f141e1e27d4ba261178",
    },
    "amd64_equivalence": {
        "run_id": "32021983414",
        "artifact_id": "9287099998",
        "artifact_name": "qtbase-grm3u1-amd64-equivalence-32021983414",
        "digest": "sha256:22eae6c1d1b12c01ab108cc0f4bcf97e6c07522d7208ddb297a1c20be7d7bb39",
    },
    "arm64_build": {
        "run_id": "31564958386",
        "artifact_id": "9129122860",
        "artifact_name": "qtbase-opensource-src-reconstructed-exact-arm64-31564958386",
        "digest": "sha256:19e814bb5e290bda74cab2686ed75e69430c35a8fef18538d9761079fc28bc1f",
    },
}


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SystemExit(f"{label} must be an array")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_checksums(directory: Path, filename: str = "LOCKSUMS.sha256") -> None:
    rows: list[str] = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != filename:
            rows.append(f"{sha256(path)}  ./{path.relative_to(directory).as_posix()}\n")
    (directory / filename).write_text("".join(rows), encoding="utf-8")


def verify_checksum_manifest(root: Path, manifest_name: str) -> None:
    manifest = root / manifest_name
    if not manifest.is_file():
        raise SystemExit(f"checksum manifest missing: {manifest}")
    seen: set[str] = set()
    for number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            digest, raw_name = line.split(None, 1)
        except ValueError as error:
            raise SystemExit(f"malformed {manifest_name} line {number}") from error
        name = raw_name.strip()
        if name.startswith("*"):
            name = name[1:]
        if name.startswith("./"):
            name = name[2:]
        candidate = Path(name)
        if candidate.is_absolute() or ".." in candidate.parts or not name:
            raise SystemExit(f"unsafe checksum path in {manifest_name}: {raw_name!r}")
        if name in seen:
            raise SystemExit(f"duplicate checksum path in {manifest_name}: {name}")
        seen.add(name)
        path = root / candidate
        if not path.is_file():
            raise SystemExit(f"checksummed file missing: {path}")
        if not SHA256_RE.fullmatch(digest) or sha256(path) != digest:
            raise SystemExit(f"checksum mismatch: {path}")


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def deb_field(path: Path, field: str, *, optional: bool = False) -> str:
    process = run(["dpkg-deb", "-f", str(path), field])
    if process.returncode:
        if optional:
            return ""
        raise SystemExit(f"dpkg-deb {field} failed for {path}: {process.stderr.strip()}")
    return process.stdout.strip()


def locate_unique(root: Path, relative: str) -> Path:
    direct = root / relative
    if direct.is_file():
        return direct
    matches = [path for path in root.rglob(Path(relative).name) if path.is_file()]
    matches = [path for path in matches if path.as_posix().endswith(relative)]
    if len(matches) != 1:
        raise SystemExit(f"{relative}: expected one file below {root}, got {len(matches)}")
    return matches[0]


def verify_source_artifact(root: Path) -> dict[str, Any]:
    verify_checksum_manifest(root, "LOCKSUMS.sha256")
    authority_path = locate_unique(root, "evidence/authority.json")
    if sha256(authority_path) != RECONSTRUCTION_AUTHORITY_SHA256:
        raise SystemExit("reconstruction authority SHA-256 mismatch")
    authority = require_dict(load(authority_path), "source reconstruction authority")
    if authority.get("source") != SOURCE or authority.get("source_version") != VERSION:
        raise SystemExit("source reconstruction identity mismatch")
    if authority.get("source_status") != "reconstructed-not-recovered-original-source":
        raise SystemExit("unexpected reconstruction status")
    if authority.get("byte_identity_claimed") is not False:
        raise SystemExit("source reconstruction must not claim archive byte identity")
    if authority.get("promotion_allowed") is not False:
        raise SystemExit("original reconstruction authority must remain non-promotable")
    claims = require_dict(authority.get("claims"), "source reconstruction claims")
    if claims.get("lost_original_source_archive_recovered") is not False:
        raise SystemExit("lost original source archive must remain unrecovered")
    if claims.get("only_vendor_declared_code_patch_added") is not True:
        raise SystemExit("bounded vendor-declared patch claim is absent")
    if claims.get("cve_patch_semantics_verified") is not True:
        raise SystemExit("CVE patch semantic verification is absent")
    reconstruction = require_dict(authority.get("reconstruction"), "reconstruction")
    if reconstruction.get("round_trip_verified") is not True:
        raise SystemExit("reconstructed source round trip did not pass")
    if reconstruction.get("source_tree_manifest_sha256") != SOURCE_TREE_MANIFEST_SHA256:
        raise SystemExit("source tree manifest SHA-256 mismatch")
    if reconstruction.get("reconstructed_dsc_sha256") != RECONSTRUCTED_DSC_SHA256:
        raise SystemExit("reconstructed DSC SHA-256 mismatch")

    members = require_list(reconstruction.get("archive_members"), "archive members")
    member_map = {
        str(row.get("filename")): (int(row.get("size", -1)), str(row.get("sha256", "")))
        for row in members
        if isinstance(row, dict)
    }
    if member_map != SOURCE_MEMBERS:
        raise SystemExit("reconstructed source archive member authority mismatch")
    for filename, (size, digest) in SOURCE_MEMBERS.items():
        path = locate_unique(root, f"source-archive/{filename}")
        if path.stat().st_size != size or sha256(path) != digest:
            raise SystemExit(f"reconstructed source member mismatch: {filename}")
    manifest_path = locate_unique(root, "evidence/source-tree-manifest.tsv")
    if sha256(manifest_path) != SOURCE_TREE_MANIFEST_SHA256:
        raise SystemExit("source tree manifest file mismatch")
    return authority


def verify_amd64_equivalence(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    verify_checksum_manifest(root, "LOCKSUMS.sha256")
    reconstruction_path = locate_unique(root, "reconstruction-authority.json")
    if sha256(reconstruction_path) != RECONSTRUCTION_AUTHORITY_SHA256:
        raise SystemExit("equivalence artifact used a different reconstruction authority")

    authority = require_dict(load(locate_unique(root, "authority.json")), "equivalence authority")
    expected = {
        "source": SOURCE,
        "source_version": VERSION,
        "source_status": SOURCE_STATUS,
        "original_source_archive_recovered": False,
        "target_package_count": len(REQUIRED_PACKAGES),
        "elf_file_count": 40,
        "vendor_lock_verified": True,
        "amd64_equivalence_verified": True,
        "native_arm64_build_verified": True,
        "promotion_allowed": False,
        "iso_assembly_allowed": False,
    }
    for field, value in expected.items():
        if authority.get(field) != value:
            raise SystemExit(f"equivalence authority mismatch for {field}")
    if authority.get("reconstruction_authority_sha256") != RECONSTRUCTION_AUTHORITY_SHA256:
        raise SystemExit("equivalence reconstruction authority digest mismatch")

    summary = require_dict(load(locate_unique(root, "evidence/summary.json")), "equivalence summary")
    boolean_fields = (
        "verified",
        "vendor_lock_verified",
        "required_packages_present",
        "control_fields_identical",
        "auxiliary_control_members_identical",
        "same_payload_path_sets",
        "non_elf_payload_identity",
        "normalized_elf_identity",
        "raw_elf_identity",
    )
    if summary.get("source") != SOURCE or summary.get("source_version") != VERSION:
        raise SystemExit("AMD64 equivalence summary identity mismatch")
    if summary.get("target_architecture") != "amd64":
        raise SystemExit("AMD64 equivalence target mismatch")
    for field in boolean_fields:
        if summary.get(field) is not True:
            raise SystemExit(f"AMD64 equivalence did not pass: {field}")
    if summary.get("required_package_count") != len(REQUIRED_PACKAGES):
        raise SystemExit("AMD64 required package count mismatch")
    if summary.get("target_package_count") != len(REQUIRED_PACKAGES):
        raise SystemExit("AMD64 target package count mismatch")
    if summary.get("compared_package_count") != len(REQUIRED_PACKAGES):
        raise SystemExit("AMD64 compared package count mismatch")
    if summary.get("elf_file_count") != 40 or summary.get("fatal_difference_count") != 0:
        raise SystemExit("AMD64 ELF equivalence count mismatch")
    package_results = require_list(summary.get("package_results"), "AMD64 package results")
    package_map = {
        str(row.get("package")): row
        for row in package_results
        if isinstance(row, dict)
    }
    if set(package_map) != set(REQUIRED_PACKAGES):
        raise SystemExit("AMD64 package result set mismatch")
    for package in REQUIRED_PACKAGES:
        row = package_map[package]
        if row.get("verified") is not True or row.get("fatal_difference_count") != 0:
            raise SystemExit(f"AMD64 package failed equivalence: {package}")
        for field in (
            "control_fields_identical",
            "auxiliary_control_members_identical",
            "same_payload_path_set",
            "non_elf_payload_identity",
            "normalized_elf_identity",
            "raw_elf_identity",
        ):
            if row.get(field) is not True:
                raise SystemExit(f"AMD64 package {package} failed {field}")
    differences = load(locate_unique(root, "evidence/differences.json"))
    if differences != []:
        raise SystemExit("AMD64 equivalence contains differences")
    return authority, summary


def normalize_arm64_packages(result: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    packages = require_list(result.get("packages"), "ARM64 packages")
    selected: dict[str, dict[str, Any]] = {}
    for raw in packages:
        if not isinstance(raw, dict):
            continue
        package = str(raw.get("package", ""))
        if package not in REQUIRED_PACKAGES:
            continue
        if package in selected:
            raise SystemExit(f"duplicate ARM64 package record: {package}")
        row = dict(raw)
        filename = str(row.get("filename", ""))
        path = locate_unique(root, filename)
        expected_size, expected_digest = EXPECTED_ARM64_PACKAGES[package]
        required_fields = {
            "version": VERSION,
            "architecture": "arm64",
            "source": SOURCE,
            "source_version": VERSION,
            "size": expected_size,
            "sha256": expected_digest,
        }
        for field, value in required_fields.items():
            if row.get(field) != value:
                raise SystemExit(f"ARM64 package authority mismatch: {package}.{field}")
        if path.stat().st_size != expected_size or sha256(path) != expected_digest:
            raise SystemExit(f"ARM64 package bytes mismatch: {package}")
        source_field = deb_field(path, "Source", optional=True).split(" ", 1)[0]
        if (
            deb_field(path, "Package") != package
            or deb_field(path, "Version") != VERSION
            or deb_field(path, "Architecture") != "arm64"
            or source_field != SOURCE
        ):
            raise SystemExit(f"ARM64 package control mismatch: {package}")
        selected[package] = {
            "package": package,
            "version": VERSION,
            "architecture": "arm64",
            "source": SOURCE,
            "source_version": VERSION,
            "filename": filename,
            "size": expected_size,
            "sha256": expected_digest,
        }
    if set(selected) != set(REQUIRED_PACKAGES):
        raise SystemExit(
            f"required ARM64 runtime set mismatch: expected={list(REQUIRED_PACKAGES)} "
            f"actual={sorted(selected)}"
        )
    return [selected[package] for package in REQUIRED_PACKAGES]


def verify_arm64_build(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    verify_checksum_manifest(root, "SHA256SUMS")
    result = require_dict(load(locate_unique(root, "result.json")), "ARM64 result")
    expected = {
        "source": SOURCE,
        "source_version": VERSION,
        "source_status": "reconstructed-not-recovered-original-source",
        "build_outcome": "success",
        "verify_outcome": "success",
        "verification_passed": True,
        "passed": True,
        "wrong_architecture_executable_count": 0,
        "foreign_payload_count": 0,
        "package_count": 52,
    }
    for field, value in expected.items():
        if result.get(field) != value:
            raise SystemExit(f"ARM64 build authority mismatch for {field}")
    return result, normalize_arm64_packages(result, root)


def prepare(args: argparse.Namespace) -> int:
    source_root = args.source_artifact.resolve()
    equivalence_root = args.equivalence_artifact.resolve()
    arm64_root = args.arm64_artifact.resolve()
    output = args.output_dir.resolve()
    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)

    source_authority = verify_source_artifact(source_root)
    equivalence_authority, equivalence_summary = verify_amd64_equivalence(equivalence_root)
    arm64_result, selected = verify_arm64_build(arm64_root)

    runtime = output / "runtime"
    runtime.mkdir()
    for row in selected:
        shutil.copy2(locate_unique(arm64_root, row["filename"]), runtime / row["filename"])

    source_archive = require_dict(source_authority.get("reconstruction"), "reconstruction")
    prepared = {
        "schema": 1,
        "policy": (
            "bounded-reconstructed-source-plus-exact-vendor-amd64-byte-equivalence-"
            "plus-native-arm64-no-foreign-payload-runtime-subset"
        ),
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": SOURCE_TYPE,
        "source_status": SOURCE_STATUS,
        "original_source_archive_recovered": False,
        "reconstruction_authority_sha256": RECONSTRUCTION_AUTHORITY_SHA256,
        "source_tree_manifest_sha256": SOURCE_TREE_MANIFEST_SHA256,
        "reconstructed_dsc": source_archive.get("reconstructed_dsc"),
        "reconstructed_dsc_sha256": RECONSTRUCTED_DSC_SHA256,
        "source_archive_members": [
            {"filename": name, "size": value[0], "sha256": value[1]}
            for name, value in sorted(SOURCE_MEMBERS.items())
        ],
        "amd64_equivalence_verified": True,
        "amd64_equivalent_package_count": len(REQUIRED_PACKAGES),
        "amd64_equivalent_elf_count": equivalence_summary.get("elf_file_count"),
        "amd64_fatal_difference_count": equivalence_summary.get("fatal_difference_count"),
        "native_arm64_build_verified": True,
        "arm64_foreign_payload_count": arm64_result.get("foreign_payload_count"),
        "selected_runtime_package_count": len(selected),
        "selected_runtime_packages": selected,
        "package_layer_promotion_allowed": True,
        "iso_assembly_allowed": False,
        "upstream_artifacts": UPSTREAM_ARTIFACTS,
        "equivalence_verification_run_id": equivalence_authority.get("verification_run_id"),
        "arm64_verification_run_id": arm64_result.get("actions_run_id"),
    }
    write_json(output / "package-promotion-authority.json", prepared)
    write_json(output / "selected-runtime-debs.json", selected)
    write_json(output / "amd64-equivalence-summary.json", equivalence_summary)
    write_json(
        output / "arm64-runtime-verification.json",
        {
            "schema": 1,
            "verified": True,
            "source": SOURCE,
            "source_version": VERSION,
            "target_architecture": "arm64",
            "expected_package_count": len(selected),
            "compared_package_count": len(selected),
            "foreign_payload_count": 0,
            "wrong_architecture_executables": [],
            "deb_artifacts": selected,
        },
    )
    write_checksums(output, "LOCKSUMS.sha256")
    print(json.dumps({
        "prepared": True,
        "source": SOURCE,
        "source_version": VERSION,
        "package_count": len(selected),
        "output_dir": str(output),
    }, indent=2))
    return 0


def seal(args: argparse.Namespace) -> int:
    prepared_root = args.prepared_dir.resolve()
    repository = args.repository_root.resolve()
    verify_checksum_manifest(prepared_root, "LOCKSUMS.sha256")
    authority = require_dict(
        load(prepared_root / "package-promotion-authority.json"),
        "prepared package authority",
    )
    selected = require_list(
        load(prepared_root / "selected-runtime-debs.json"),
        "selected runtime packages",
    )
    runtime_verification = require_dict(
        load(prepared_root / "arm64-runtime-verification.json"),
        "ARM64 runtime verification",
    )
    if authority.get("source") != SOURCE or authority.get("source_version") != VERSION:
        raise SystemExit("prepared package authority identity mismatch")
    if authority.get("source_type") != SOURCE_TYPE or authority.get("source_status") != SOURCE_STATUS:
        raise SystemExit("prepared package source status mismatch")
    if authority.get("original_source_archive_recovered") is not False:
        raise SystemExit("original source recovery claim changed during sealing")
    if authority.get("package_layer_promotion_allowed") is not True:
        raise SystemExit("package promotion is not authorized")
    if authority.get("iso_assembly_allowed") is not False:
        raise SystemExit("QtBase package promotion must not authorize ISO assembly")
    if len(selected) != len(REQUIRED_PACKAGES):
        raise SystemExit("prepared runtime package count mismatch")
    if runtime_verification.get("verified") is not True:
        raise SystemExit("prepared ARM64 runtime verification did not pass")
    if runtime_verification.get("wrong_architecture_executables") != []:
        raise SystemExit("prepared runtime verification contains foreign executables")

    artifact_digest = str(args.artifact_digest)
    if artifact_digest.startswith("sha256:"):
        artifact_digest_value = artifact_digest.split(":", 1)[1]
    else:
        artifact_digest_value = artifact_digest
    if not SHA256_RE.fullmatch(artifact_digest_value):
        raise SystemExit("uploaded artifact digest is not SHA-256")
    if not str(args.artifact_id).isdigit() or not str(args.run_id).isdigit():
        raise SystemExit("uploaded artifact or run ID is invalid")
    if not args.artifact_name:
        raise SystemExit("uploaded artifact name is empty")

    result_dir = (
        repository / "arm64/locks/rebuild-results" / SOURCE / RESULT_VERSION_PATH
    )
    evidence_dir = repository / "arm64/locks/qtbase-grm3u1-package-promotion/latest"
    shutil.rmtree(result_dir, ignore_errors=True)
    shutil.rmtree(evidence_dir, ignore_errors=True)
    result_dir.mkdir(parents=True)
    evidence_dir.mkdir(parents=True)

    compact_verification = {
        "schema": 1,
        "verified": True,
        "policy": authority["policy"],
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": SOURCE_TYPE,
        "source_status": SOURCE_STATUS,
        "target_architecture": "arm64",
        "original_source_archive_recovered": False,
        "reconstructed_source_archive_verified": True,
        "amd64_equivalence_verified": True,
        "native_arm64_build_verified": True,
        "package_layer_promotion_allowed": True,
        "iso_assembly_allowed": False,
        "expected_package_count": len(selected),
        "compared_package_count": len(selected),
        "foreign_payload_count": 0,
        "wrong_architecture_executables": [],
        "deb_artifacts": selected,
        "verification_errors": [],
    }
    result = {
        "schema": 4,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": SOURCE_TYPE,
        "source_status": SOURCE_STATUS,
        "provenance": SOURCE_TYPE,
        "batch": "qtbase-grm3u1-verified-runtime-promotion",
        "build_mode": (
            "signed-debian-base-plus-vendor-declared-single-patch-native-arm64"
        ),
        "original_source_archive_recovered": False,
        "byte_identity_claimed": False,
        "package_layer_promotion_allowed": True,
        "iso_assembly_allowed": False,
        "reconstruction_authority_sha256": RECONSTRUCTION_AUTHORITY_SHA256,
        "source_tree_manifest_sha256": SOURCE_TREE_MANIFEST_SHA256,
        "dsc_filename": "qtbase-opensource-src_5.15.2+dfsg-9+grm3u1.dsc",
        "dsc_sha256": RECONSTRUCTED_DSC_SHA256,
        "actions_run_id": str(args.run_id),
        "actions_run_url": str(args.run_url),
        "artifact_name": str(args.artifact_name),
        "artifact_id": str(args.artifact_id),
        "artifact_digest": f"sha256:{artifact_digest_value}",
        "artifact_url": str(args.artifact_url),
        "build_outcome": "success",
        "verify_outcome": "success",
        "job_passed": True,
        "verification_passed": True,
        "passed": True,
        "deb_artifacts": selected,
        "required_deb_artifacts": selected,
        "verification_errors": [],
        "verification_warnings": [
            "The original vendor source archive remains unrecovered; this authority promotes only the independently verified ARM64 runtime package subset.",
            "Package-layer promotion does not authorize final ISO assembly by itself.",
        ],
        "verification_summary": compact_verification,
        "source_lock_evidence": {
            "reconstruction_authority_sha256": RECONSTRUCTION_AUTHORITY_SHA256,
            "source_tree_manifest_sha256": SOURCE_TREE_MANIFEST_SHA256,
            "reconstructed_dsc_sha256": RECONSTRUCTED_DSC_SHA256,
            "source_artifact": UPSTREAM_ARTIFACTS["source"],
            "amd64_equivalence_artifact": UPSTREAM_ARTIFACTS["amd64_equivalence"],
            "arm64_build_artifact": UPSTREAM_ARTIFACTS["arm64_build"],
        },
    }
    sealed_authority = {
        **authority,
        "schema": 2,
        "promotion_run_id": str(args.run_id),
        "promotion_run_url": str(args.run_url),
        "promoted_artifact": {
            "artifact_name": str(args.artifact_name),
            "artifact_id": str(args.artifact_id),
            "artifact_digest": f"sha256:{artifact_digest_value}",
            "artifact_url": str(args.artifact_url),
        },
        "result_path": str(result_dir.relative_to(repository) / "result.json"),
    }

    for filename in (
        "amd64-equivalence-summary.json",
        "arm64-runtime-verification.json",
        "selected-runtime-debs.json",
    ):
        shutil.copy2(prepared_root / filename, evidence_dir / filename)
    write_json(evidence_dir / "package-promotion-authority.json", sealed_authority)
    write_json(evidence_dir / "verification-summary.json", compact_verification)
    write_checksums(evidence_dir, "LOCKSUMS.sha256")
    write_json(result_dir / "result.json", result)
    write_checksums(result_dir, "LOCKSUMS.sha256")
    print(json.dumps({
        "sealed": True,
        "result": str(result_dir / "result.json"),
        "evidence": str(evidence_dir),
        "package_count": len(selected),
    }, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--source-artifact", type=Path, required=True)
    prepare_parser.add_argument("--equivalence-artifact", type=Path, required=True)
    prepare_parser.add_argument("--arm64-artifact", type=Path, required=True)
    prepare_parser.add_argument("--output-dir", type=Path, required=True)
    prepare_parser.set_defaults(function=prepare)

    seal_parser = subparsers.add_parser("seal")
    seal_parser.add_argument("--prepared-dir", type=Path, required=True)
    seal_parser.add_argument("--repository-root", type=Path, required=True)
    seal_parser.add_argument("--run-id", required=True)
    seal_parser.add_argument("--run-url", required=True)
    seal_parser.add_argument("--artifact-name", required=True)
    seal_parser.add_argument("--artifact-id", required=True)
    seal_parser.add_argument("--artifact-digest", required=True)
    seal_parser.add_argument("--artifact-url", required=True)
    seal_parser.set_defaults(function=seal)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.function(args))


if __name__ == "__main__":
    raise SystemExit(main())
