#!/usr/bin/env python3
"""Promote the verified QtBase grm3u1 ARM64 runtime package set.

This promotion is deliberately source-archive based.  It never fabricates a
Git commit or tree for the reconstructed Debian source package.  Promotion is
accepted only when all of the following independent authorities agree:

* the persisted AMD64 equivalence authority;
* the current reconstruction authority and its source-tree manifest;
* the previously verified native ARM64 artifact authority;
* an independent rescan of every promoted DEB payload.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, NoReturn

SOURCE = "qtbase-opensource-src"
VERSION = "5.15.2+dfsg-9+grm3u1"
SOURCE_TYPE = "verified-reconstructed-source-archive"
SELECTED_TYPE = "reconstructed-source-archive"
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
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ELF_RE = re.compile(r"\bELF (?:32|64)-bit\b", re.IGNORECASE)
AARCH64_RE = re.compile(r"(?:ARM aarch64|AArch64)", re.IGNORECASE)
X86_RE = re.compile(r"(?:x86-64|Intel 80386|i[3-6]86)", re.IGNORECASE)


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable to read JSON {path}: {exc}")
    require(isinstance(value, dict), f"JSON document must be an object: {path}")
    return value


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(*argv: str, cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        fail(f"required command is missing: {argv[0]}")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        fail(f"command failed ({' '.join(argv)}): {detail}")
    return result.stdout.strip()


def parse_source_field(value: str, package: str, version: str) -> tuple[str, str]:
    text = value.strip()
    if not text:
        return package, version
    match = re.fullmatch(r"([^\s(]+)(?:\s*\(([^)]+)\))?", text)
    require(match is not None, f"unable to parse DEB Source field: {value!r}")
    return match.group(1), match.group(2) or version


def verify_lock_sums(root: Path) -> None:
    sums = root / "LOCKSUMS.sha256"
    if not sums.is_file():
        return
    run("sha256sum", "--check", "--strict", sums.name, cwd=root)


def verify_artifact_sums(root: Path) -> None:
    sums = root / "SHA256SUMS"
    require(sums.is_file(), f"ARM64 artifact checksum manifest is missing: {sums}")
    run("sha256sum", "--check", "--strict", sums.name, cwd=root)


def verify_equivalence(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    verify_lock_sums(root)
    authority = load(root / "authority.json")
    summary = load(root / "summary.json")
    require(authority.get("source") == SOURCE, "equivalence authority source mismatch")
    require(
        authority.get("source_version") == VERSION,
        "equivalence authority version mismatch",
    )
    require(
        authority.get("source_status") == "verified-reconstructed-amd64-equivalent",
        "AMD64 equivalence authority has not reached the verified state",
    )
    require(authority.get("original_source_archive_recovered") is False, "original source claim changed")
    require(authority.get("amd64_equivalence_verified") is True, "AMD64 equivalence is not verified")
    require(authority.get("native_arm64_build_verified") is True, "ARM64 build gate is not verified")
    require(authority.get("vendor_lock_verified") is True, "vendor lock is not verified")
    require(authority.get("promotion_allowed") is False, "equivalence authority must remain fail closed")
    require(summary.get("verified") is True, "equivalence summary did not pass")
    for field in (
        "control_fields_identical",
        "auxiliary_control_members_identical",
        "same_payload_path_sets",
        "non_elf_payload_identity",
        "normalized_elf_identity",
        "vendor_lock_verified",
        "required_packages_present",
        "all_target_candidates_present",
    ):
        require(summary.get(field) is True, f"equivalence summary field is not true: {field}")
    require(int(summary.get("fatal_difference_count", -1)) == 0, "fatal AMD64 differences remain")
    require(int(summary.get("required_package_count", -1)) == len(REQUIRED_PACKAGES), "required package count mismatch")
    return authority, summary


def verify_reconstruction(
    path: Path, equivalence: dict[str, Any]
) -> tuple[dict[str, Any], str, str, list[dict[str, Any]]]:
    authority = load(path)
    digest = sha256(path)
    require(
        digest == equivalence.get("reconstruction_authority_sha256"),
        "current reconstruction authority differs from AMD64 equivalence input",
    )
    require(authority.get("source") == SOURCE, "reconstruction source mismatch")
    require(authority.get("source_version") == VERSION, "reconstruction version mismatch")
    require(
        authority.get("source_status") == "reconstructed-not-recovered-original-source",
        "unexpected reconstruction status",
    )
    require(authority.get("byte_identity_claimed") is False, "raw source identity must not be claimed")
    claims = authority.get("claims") if isinstance(authority.get("claims"), dict) else {}
    require(claims.get("only_vendor_declared_code_patch_added") is True, "reconstruction delta is not bounded")
    require(claims.get("lost_original_source_archive_recovered") is False, "original source recovery claim changed")
    reconstruction = authority.get("reconstruction")
    require(isinstance(reconstruction, dict), "reconstruction detail is missing")
    tree_manifest = str(reconstruction.get("source_tree_manifest_sha256", ""))
    dsc_sha256 = str(reconstruction.get("reconstructed_dsc_sha256", ""))
    members = reconstruction.get("archive_members")
    require(HEX64.fullmatch(tree_manifest) is not None, "source tree manifest hash is invalid")
    require(HEX64.fullmatch(dsc_sha256) is not None, "reconstructed DSC hash is invalid")
    require(isinstance(members, list) and members, "reconstructed archive members are missing")
    normalized_members: list[dict[str, Any]] = []
    for row in members:
        require(isinstance(row, dict), "malformed reconstructed archive member")
        filename = str(row.get("filename", ""))
        member_digest = str(row.get("sha256", ""))
        try:
            size = int(row.get("size"))
        except (TypeError, ValueError):
            fail(f"invalid reconstructed archive member size: {row}")
        require(filename and size > 0 and HEX64.fullmatch(member_digest) is not None, f"invalid reconstructed archive member: {row}")
        normalized_members.append({"filename": filename, "size": size, "sha256": member_digest})
    normalized_members.sort(key=lambda row: row["filename"])
    return authority, tree_manifest, dsc_sha256, normalized_members


def verify_arm64_authority(
    path: Path,
    artifact_result: dict[str, Any],
    reconstruction_digest: str,
) -> dict[str, Any]:
    authority = load(path)
    require(authority.get("source") == SOURCE, "ARM64 authority source mismatch")
    require(authority.get("source_version") == VERSION, "ARM64 authority version mismatch")
    require(authority.get("native_arm64_build_verified") is True, "native ARM64 build is not verified")
    require(int(authority.get("foreign_payload_count", -1)) == 0, "ARM64 authority reports foreign payloads")
    require(
        authority.get("reconstruction_authority_sha256") == reconstruction_digest,
        "ARM64 build used a different reconstruction authority",
    )
    require(
        str(authority.get("verified_artifact_id", "")),
        "verified ARM64 artifact id is missing",
    )
    require(
        authority.get("verified_artifact_name") == artifact_result.get("artifact_name"),
        "ARM64 artifact name disagrees with result",
    )
    require(
        HEX64.fullmatch(str(authority.get("verified_artifact_sha256", ""))) is not None,
        "verified ARM64 artifact ZIP hash is missing or invalid",
    )
    return authority


def scan_deb(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    require(path.is_file(), f"required ARM64 package is missing: {path.name}")
    actual_sha = sha256(path)
    actual_size = path.stat().st_size
    require(actual_sha == expected.get("sha256"), f"package hash mismatch: {path.name}")
    require(actual_size == int(expected.get("size", -1)), f"package size mismatch: {path.name}")

    package = run("dpkg-deb", "-f", str(path), "Package")
    version = run("dpkg-deb", "-f", str(path), "Version")
    architecture = run("dpkg-deb", "-f", str(path), "Architecture")
    source_field = run("dpkg-deb", "-f", str(path), "Source")
    parsed_source, parsed_version = parse_source_field(source_field, package, version)
    require(package == expected.get("package"), f"package name mismatch in {path.name}")
    require(version == VERSION == expected.get("version"), f"package version mismatch in {path.name}")
    require(architecture == "arm64", f"runtime package is not ARM64: {path.name}")
    require(parsed_source == SOURCE, f"package source mismatch in {path.name}: {parsed_source}")
    require(parsed_version == VERSION, f"package source version mismatch in {path.name}: {parsed_version}")

    elf_count = 0
    aarch64_count = 0
    foreign: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="qtbase-arm64-promote-") as temporary:
        root = Path(temporary)
        run("dpkg-deb", "-x", str(path), str(root))
        for payload in sorted(root.rglob("*")):
            if not payload.is_file() or payload.is_symlink():
                continue
            description = run("file", "-b", str(payload))
            if not ELF_RE.search(description):
                continue
            elf_count += 1
            if AARCH64_RE.search(description) and not X86_RE.search(description):
                aarch64_count += 1
            else:
                foreign.append(
                    {
                        "path": str(payload.relative_to(root)),
                        "description": description,
                    }
                )
    require(not foreign, f"foreign ELF payloads in {path.name}: {foreign}")
    return {
        "package": package,
        "version": version,
        "architecture": architecture,
        "source": SOURCE,
        "source_version": VERSION,
        "filename": path.name,
        "size": actual_size,
        "sha256": actual_sha,
        "executable_elf_count": elf_count,
        "aarch64_payload_count": aarch64_count,
        "foreign_payload_count": 0,
    }


def canonical_package_identity(rows: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    return sorted(
        (
            row.get("package"),
            row.get("version"),
            row.get("architecture"),
            row.get("filename"),
            int(row.get("size", 0)),
            row.get("sha256"),
            row.get("source"),
            row.get("source_version"),
        )
        for row in rows
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--equivalence-lock-dir", type=Path, required=True)
    parser.add_argument("--reconstruction-authority", type=Path, required=True)
    parser.add_argument("--arm64-authority", type=Path, required=True)
    parser.add_argument("--arm64-artifact-dir", type=Path, required=True)
    parser.add_argument("--artifact-zip-sha256", required=True)
    parser.add_argument("--promotion-run-id", required=True)
    parser.add_argument("--promotion-run-url", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    require(args.promotion_run_id.isdigit(), "promotion run id must be numeric")
    require(
        args.promotion_run_url.endswith(f"/actions/runs/{args.promotion_run_id}"),
        "promotion run URL does not match run id",
    )
    require(HEX64.fullmatch(args.artifact_zip_sha256) is not None, "artifact ZIP SHA-256 is invalid")

    equivalence, equivalence_summary = verify_equivalence(args.equivalence_lock_dir)
    reconstruction, source_identity, dsc_sha256, archive_members = verify_reconstruction(
        args.reconstruction_authority, equivalence
    )
    reconstruction_digest = sha256(args.reconstruction_authority)

    artifact_root = args.arm64_artifact_dir
    require(artifact_root.is_dir(), f"ARM64 artifact directory is missing: {artifact_root}")
    verify_artifact_sums(artifact_root)
    artifact_result = load(artifact_root / "result.json")
    artifact_result["artifact_zip_sha256"] = args.artifact_zip_sha256
    require(artifact_result.get("source") == SOURCE, "ARM64 artifact result source mismatch")
    require(artifact_result.get("source_version") == VERSION, "ARM64 artifact result version mismatch")
    require(artifact_result.get("passed") is True, "ARM64 artifact result did not pass")
    require(artifact_result.get("verification_passed") is True, "ARM64 artifact verification did not pass")
    require(artifact_result.get("native_arm64_build_verified") is True, "ARM64 artifact is not marked native")
    require(int(artifact_result.get("foreign_payload_count", -1)) == 0, "ARM64 artifact reports foreign payloads")
    require(
        artifact_result.get("required_packages") == list(REQUIRED_PACKAGES),
        "ARM64 artifact required package order or identity changed",
    )

    arm64_authority = verify_arm64_authority(
        args.arm64_authority, artifact_result, reconstruction_digest
    )
    require(
        arm64_authority.get("verified_artifact_sha256") == args.artifact_zip_sha256,
        "downloaded ARM64 artifact ZIP differs from persisted authority",
    )

    all_rows = artifact_result.get("packages")
    require(isinstance(all_rows, list), "ARM64 artifact package manifest is missing")
    by_name: dict[str, dict[str, Any]] = {}
    for row in all_rows:
        if not isinstance(row, dict) or not row.get("package"):
            continue
        package = str(row["package"])
        require(package not in by_name, f"duplicate ARM64 package record: {package}")
        by_name[package] = row

    records: list[dict[str, Any]] = []
    for package in REQUIRED_PACKAGES:
        require(package in by_name, f"required runtime package absent from ARM64 manifest: {package}")
        expected = by_name[package]
        filename = str(expected.get("filename", ""))
        require(filename, f"required runtime package filename is missing: {package}")
        records.append(scan_deb(artifact_root / filename, expected))
    records.sort(key=lambda row: row["package"])
    require(len(records) == len(REQUIRED_PACKAGES), "promoted runtime package count mismatch")

    output = args.output_dir
    artifact_out = output / "artifact"
    evidence_out = output / "evidence"
    artifact_out.mkdir(parents=True, exist_ok=True)
    evidence_out.mkdir(parents=True, exist_ok=True)
    for row in records:
        shutil.copy2(artifact_root / row["filename"], artifact_out / row["filename"])

    equivalence_authority_sha = sha256(args.equivalence_lock_dir / "authority.json")
    equivalence_summary_sha = sha256(args.equivalence_lock_dir / "summary.json")
    arm64_authority_sha = sha256(args.arm64_authority)

    archive_member_set_sha256 = hashlib.sha256(
        json.dumps(archive_members, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    selected = {
        "type": SELECTED_TYPE,
        "provenance": "signed-debian-base-plus-vendor-declared-single-patch-plus-exact-amd64-equivalence",
        "declared_source": SOURCE,
        "declared_version": VERSION,
        "ref_kind": "reconstructed-debian-source-archive",
        "ref_name": VERSION,
        "match_scope": "exact-reconstructed-dsc-and-source-tree-manifest-plus-amd64-normalized-elf-identity",
        "source_tree_manifest_sha256": source_identity,
        "source_archive_member_set_sha256": archive_member_set_sha256,
        "dsc": {
            "filename": reconstruction["reconstruction"]["reconstructed_dsc"],
            "sha256": dsc_sha256,
            "signature_verified": False,
            "reconstructed": True,
        },
        "archive_members": archive_members,
        "reconstruction_authority_sha256": reconstruction_digest,
        "amd64_equivalence_authority_sha256": equivalence_authority_sha,
        "native_arm64_authority_sha256": arm64_authority_sha,
    }

    verification = {
        "schema": 1,
        "policy": "persisted-amd64-equivalence-plus-native-arm64-artifact-independent-runtime-rescan",
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": SOURCE_TYPE,
        "source_authority_sha256": source_identity,
        "target_architecture": "arm64",
        "required_packages": list(REQUIRED_PACKAGES),
        "required_package_count": len(REQUIRED_PACKAGES),
        "packages": records,
        "deb_artifacts": records,
        "wrong_architecture_executables": [],
        "wrong_architecture_executable_count": 0,
        "foreign_payload_count": 0,
        "amd64_equivalence_verified": True,
        "amd64_equivalence_authority_sha256": equivalence_authority_sha,
        "amd64_equivalence_summary_sha256": equivalence_summary_sha,
        "native_arm64_build_verified": True,
        "original_source_archive_recovered": False,
        "verification_errors": [],
        "verification_warnings": [],
        "passed": True,
        "verified": True,
    }
    require(
        canonical_package_identity(verification["packages"])
        == canonical_package_identity(records),
        "internal package manifest mismatch",
    )

    build_lock = {
        "schema": 1,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": SOURCE_TYPE,
        "source_authority_sha256": source_identity,
        "target_architecture": "arm64",
        "build_mode": "preserved-native-arm64-reconstructed-source-artifact",
        "original_build_run_id": str(artifact_result.get("actions_run_id", "")),
        "original_artifact_id": str(arm64_authority.get("verified_artifact_id", "")),
        "original_artifact_name": arm64_authority.get("verified_artifact_name"),
        "original_artifact_zip_sha256": args.artifact_zip_sha256,
        "reconstruction_authority_sha256": reconstruction_digest,
        "amd64_equivalence_authority_sha256": equivalence_authority_sha,
    }
    source_evidence = {
        "schema": 1,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": SOURCE_TYPE,
        "selected": selected,
        "reconstruction_authority": reconstruction,
        "equivalence_authority": equivalence,
        "equivalence_summary": equivalence_summary,
        "arm64_authority": arm64_authority,
        "passed": True,
    }

    result = {
        "schema": 4,
        "batch": "qtbase-grm3u1-verified-reconstructed-source-archive-promotion",
        "actions_run_id": args.promotion_run_id,
        "actions_run_url": args.promotion_run_url,
        "artifact_name": args.artifact_name,
        "authority_provenance": selected["provenance"],
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": SOURCE_TYPE,
        "source_authority_sha256": source_identity,
        "dsc_sha256": dsc_sha256,
        "original_source_archive_recovered": False,
        "byte_identity_claimed": False,
        "build_outcome": "success",
        "build_exit_code": "0",
        "verify_outcome": "success",
        "job_passed": True,
        "verification_passed": True,
        "passed": True,
        "required_native_packages": list(REQUIRED_PACKAGES),
        "reused_all_packages": [],
        "deb_artifacts": records,
        "verification_errors": [],
        "verification_warnings": [],
        "verification": verification,
        "verification_summary": verification,
        "build_lock": build_lock,
        "source_lock_evidence": source_evidence,
        "promotion": {
            "equivalence_lock_dir": args.equivalence_lock_dir.as_posix(),
            "reconstruction_authority": args.reconstruction_authority.as_posix(),
            "arm64_authority": args.arm64_authority.as_posix(),
            "original_arm64_artifact_directory": artifact_root.as_posix(),
            "independent_runtime_deb_rescan": True,
            "promoted_package_count": len(records),
        },
    }

    source_lock = {
        "schema": 1,
        "policy": "independently-verified-reconstructed-source-archive-overlays",
        "source_count": 1,
        "sources": [
            {
                "source": SOURCE,
                "source_version": VERSION,
                "status": "resolved",
                "provenance": "verified-reconstructed-source-archive",
                "selected": selected,
                "verification": {
                    "passed": True,
                    "result_path": (
                        "arm64/locks/rebuild-results/qtbase-opensource-src/"
                        "5.15.2_dfsg-9_grm3u1/result.json"
                    ),
                    "actions_run_id": args.promotion_run_id,
                    "actions_run_url": args.promotion_run_url,
                    "amd64_equivalence_verified": True,
                    "amd64_equivalence_authority_sha256": equivalence_authority_sha,
                    "native_arm64_build_verified": True,
                    "native_arm64_authority_sha256": arm64_authority_sha,
                    "source_tree_manifest_sha256": source_identity,
                    "original_source_archive_recovered": False,
                },
            }
        ],
    }

    write(output / "result.json", result)
    write(output / "source-locks.json", source_lock)
    write(artifact_out / "verification.json", verification)
    write(artifact_out / "job-result.json", result)
    write(artifact_out / "build-lock.json", build_lock)
    write(artifact_out / "source-lock-evidence.json", source_evidence)
    write(evidence_out / "promotion-summary.json", {
        "schema": 1,
        "source": SOURCE,
        "source_version": VERSION,
        "source_authority_sha256": source_identity,
        "promoted_package_count": len(records),
        "amd64_equivalence_verified": True,
        "native_arm64_build_verified": True,
        "original_source_archive_recovered": False,
        "passed": True,
    })

    manifest_rows = []
    for path in sorted(artifact_out.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            manifest_rows.append(f"{sha256(path)}  ./{path.relative_to(artifact_out).as_posix()}")
    (artifact_out / "SHA256SUMS").write_text("\n".join(manifest_rows) + "\n", encoding="utf-8")
    verify_artifact_sums(artifact_out)
    print(json.dumps({
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": SOURCE_TYPE,
        "source_authority_sha256": source_identity,
        "promoted_packages": [row["package"] for row in records],
        "passed": True,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
