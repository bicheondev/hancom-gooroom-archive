#!/usr/bin/env python3
"""Promote a verified reconstructed libsecurity ARM64 package result.

The exact Debian packaging authority is retained as the current Git identity.
The XSM implementation is explicitly recorded as a binary-history-constrained
reconstruction, never as recovered original source or byte-identical output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SOURCE = "gooroom-libsecurity-extensions"
VERSION = "0.1.7+grm3u1"
PACKAGING_REPOSITORY = "gooroom/gooroom-libsecurity-extensions"
PACKAGING_COMMIT = "4990bab95ae1dcaa29f38836da83edfa0969ed73"
PACKAGING_TREE = "e1dce97d3cd69331047c01940b2593a0eaf2307a"
PUBLIC_REPOSITORY = "ultract/X.org-Security-Module"
PUBLIC_COMMIT = "fb0a3de9cab9b9f5b89aabd7943a5b5f13f37ab7"
PUBLIC_TREE = "aef0ff9c73f625763b3822c7cfa7179799f26637"
PUBLIC_XSM_SHA256 = "6ba6fbf4468d0b7f72a15483c43226ffcf686a0cde95998a8bd117aad91d0ddb"
FINAL_AMD64_COMMIT = "40d69bd620b022aa4ecb6f7d968c87e7f8df5a28"
FINAL_AMD64_BLOB = "416fbb7260c30d5075b1da6dd32aa8d81ef4a49f"
FINAL_AMD64_SHA256 = "d28c255bb00061b0df60f977e9c022a01e8d98e957b1cbcd145aaa3940aa37c8"
FINAL_AMD64_SIZE = 27072
SOURCE_STATUS = "reconstructed-not-recovered-original-source"
BUILD_MODE = "native-arm64-binary-history-constrained-reconstruction"
PAYLOAD_PATH = "/usr/lib/xorg/modules/extensions/xsm.so"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"unable to read JSON authority {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"JSON authority is not an object: {path}")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_value(document: dict[str, Any], key: str, expected: Any, label: str) -> None:
    actual = document.get(key)
    require(actual == expected, f"{label} mismatch: {actual!r} != {expected!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--authority-path", required=True)
    parser.add_argument("--manifest-path", required=True)
    parser.add_argument("--result-path", type=Path, required=True)
    args = parser.parse_args()

    require(args.run_id.isdigit(), "workflow run id must be numeric")
    expected_url_suffix = f"/actions/runs/{args.run_id}"
    require(args.run_url.endswith(expected_url_suffix), "workflow run URL does not match run id")

    evidence = args.evidence_dir
    build_lock = load(evidence / "build-lock.json")
    source_evidence = load(evidence / "source-lock-evidence.json")
    manifest = load(evidence / "reconstruction-manifest.json")

    require_value(build_lock, "source", SOURCE, "build-lock source")
    require_value(build_lock, "source_version", VERSION, "build-lock version")
    require_value(build_lock, "target_architecture", "arm64", "build-lock architecture")
    require_value(build_lock, "build_mode", BUILD_MODE, "build-lock mode")
    require_value(build_lock, "source_status", SOURCE_STATUS, "build-lock source status")
    require_value(build_lock, "byte_identity_claimed", False, "build-lock byte claim")
    require_value(build_lock, "wrong_architecture_executable_count", 0, "wrong architecture count")
    require_value(build_lock, "verified", True, "build-lock verification")

    packaging = build_lock.get("packaging")
    require(isinstance(packaging, dict), "build-lock packaging authority is missing")
    require_value(packaging, "repository", PACKAGING_REPOSITORY, "packaging repository")
    require_value(packaging, "commit", PACKAGING_COMMIT, "packaging commit")
    require_value(packaging, "tree", PACKAGING_TREE, "packaging tree")

    public = build_lock.get("public_implementation")
    require(isinstance(public, dict), "public implementation authority is missing")
    require_value(public, "repository", PUBLIC_REPOSITORY, "public repository")
    require_value(public, "commit", PUBLIC_COMMIT, "public commit")
    require_value(public, "tree", PUBLIC_TREE, "public tree")
    require_value(public, "xsm_c_sha256", PUBLIC_XSM_SHA256, "public xsm.c SHA-256")

    final_amd64 = build_lock.get("final_amd64_binary")
    require(isinstance(final_amd64, dict), "final AMD64 binary authority is missing")
    require_value(final_amd64, "commit", FINAL_AMD64_COMMIT, "final AMD64 commit")
    require_value(final_amd64, "blob", FINAL_AMD64_BLOB, "final AMD64 blob")
    require_value(final_amd64, "sha256", FINAL_AMD64_SHA256, "final AMD64 SHA-256")
    require_value(final_amd64, "size", FINAL_AMD64_SIZE, "final AMD64 size")

    package = build_lock.get("package")
    require(isinstance(package, dict), "ARM64 package lock is missing")
    require_value(package, "architecture", "arm64", "package architecture")
    package_name = str(package.get("filename", ""))
    package_path = evidence / package_name
    require(package_name == f"{SOURCE}_{VERSION}_arm64.deb", "unexpected package filename")
    require(package_path.is_file(), f"verified ARM64 package is missing: {package_path}")
    require_value(package, "size", package_path.stat().st_size, "package size")
    require_value(package, "sha256", sha256(package_path), "package SHA-256")
    require(HEX64.fullmatch(str(package.get("sha256", ""))) is not None, "invalid package SHA-256")

    payload = build_lock.get("payload")
    require(isinstance(payload, dict), "AArch64 payload lock is missing")
    require_value(payload, "path", PAYLOAD_PATH, "payload path")
    require_value(payload, "machine", "AArch64", "payload machine")
    require(HEX64.fullmatch(str(payload.get("sha256", ""))) is not None, "invalid payload SHA-256")

    require_value(source_evidence, "source", SOURCE, "source evidence source")
    require_value(source_evidence, "source_version", VERSION, "source evidence version")
    require_value(source_evidence, "repository", PACKAGING_REPOSITORY, "source evidence repository")
    require_value(source_evidence, "verified_commit_sha", PACKAGING_COMMIT, "source evidence commit")
    require_value(source_evidence, "verified_tree_sha", PACKAGING_TREE, "source evidence tree")
    require_value(
        source_evidence,
        "public_implementation_repository",
        PUBLIC_REPOSITORY,
        "source evidence public repository",
    )
    require_value(
        source_evidence,
        "public_implementation_commit",
        PUBLIC_COMMIT,
        "source evidence public commit",
    )
    require_value(
        source_evidence,
        "public_implementation_tree",
        PUBLIC_TREE,
        "source evidence public tree",
    )
    require_value(
        source_evidence,
        "final_amd64_binary_sha256",
        FINAL_AMD64_SHA256,
        "source evidence final AMD64 SHA-256",
    )
    require_value(
        source_evidence,
        "source_status",
        "binary-history-constrained-reconstruction",
        "source evidence status",
    )

    require_value(manifest, "source_status", SOURCE_STATUS, "manifest source status")
    require_value(manifest, "byte_identity_claimed", False, "manifest byte claim")
    manifest_packaging = manifest.get("exact_packaging")
    require(isinstance(manifest_packaging, dict), "manifest packaging authority is missing")
    require_value(manifest_packaging, "repository", PACKAGING_REPOSITORY, "manifest packaging repository")
    require_value(manifest_packaging, "commit", PACKAGING_COMMIT, "manifest packaging commit")
    require_value(manifest_packaging, "tree", PACKAGING_TREE, "manifest packaging tree")
    require_value(manifest_packaging, "source_version", VERSION, "manifest packaging version")
    output_source_sha256 = str(manifest.get("output_source_sha256", ""))
    require(HEX64.fullmatch(output_source_sha256) is not None, "manifest output source is not SHA-256 locked")

    package_record = {
        "filename": package_name,
        "package": SOURCE,
        "source": SOURCE,
        "source_version": VERSION,
        "version": VERSION,
        "architecture": "arm64",
        "sha256": package["sha256"],
        "size": package["size"],
        "x86_payload_count": 0,
        "foreign_payload_count": 0,
    }
    result = {
        "schema": 4,
        "batch": "reconstructed-libsecurity",
        "actions_run_id": args.run_id,
        "actions_run_url": args.run_url,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": "git",
        "authority_provenance": (
            "github-exact-packaging-with-binary-history-constrained-module-reconstruction"
        ),
        "repository_full_name": PACKAGING_REPOSITORY,
        "commit_sha": PACKAGING_COMMIT,
        "tree_sha": PACKAGING_TREE,
        "required_native_packages": [SOURCE],
        "reused_all_packages": [],
        "build_outcome": "success",
        "build_exit_code": "0",
        "verify_outcome": "success",
        "passed": True,
        "verification_passed": True,
        "build_mode": BUILD_MODE,
        "source_status": SOURCE_STATUS,
        "byte_identity_claimed": False,
        "deb_artifacts": [package_record],
        "verification": {
            "passed": True,
            "policy": (
                "exact-package-version-and-packaging-authority-plus-"
                "binary-history-constrained-module-reconstruction"
            ),
            "packages": [package_record],
            "payload": payload,
            "wrong_architecture_executable_count": 0,
        },
        "build_lock": {
            "source": SOURCE,
            "source_version": VERSION,
            "source_type": "git",
            "repository": PACKAGING_REPOSITORY,
            "commit_sha": PACKAGING_COMMIT,
            "tree_sha": PACKAGING_TREE,
            "build_mode": BUILD_MODE,
            "source_status": SOURCE_STATUS,
            "byte_identity_claimed": False,
        },
        "source_lock_evidence": {
            "source_type": "git",
            "repository": PACKAGING_REPOSITORY,
            "verified_commit_sha": PACKAGING_COMMIT,
            "verified_tree_sha": PACKAGING_TREE,
            "public_implementation_repository": PUBLIC_REPOSITORY,
            "public_implementation_commit": PUBLIC_COMMIT,
            "public_implementation_tree": PUBLIC_TREE,
            "final_amd64_binary_sha256": FINAL_AMD64_SHA256,
        },
        "reconstruction": {
            "authority_path": args.authority_path,
            "manifest_path": args.manifest_path,
            "source_status": SOURCE_STATUS,
            "byte_identity_claimed": False,
            "public_implementation": public,
            "final_amd64_binary": final_amd64,
            "output_source_sha256": output_source_sha256,
        },
    }

    args.result_path.parent.mkdir(parents=True, exist_ok=True)
    args.result_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
