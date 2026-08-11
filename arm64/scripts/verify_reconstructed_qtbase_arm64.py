#!/usr/bin/env python3
"""Verify ARM64 QtBase packages built from the locked grm3u1 reconstruction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SOURCE = "qtbase-opensource-src"
VERSION = "5.15.2+dfsg-9+grm3u1"
REQUIRED_PACKAGES = {
    "libqt5core5a",
    "libqt5dbus5",
    "libqt5gui5",
    "libqt5network5",
    "libqt5printsupport5",
    "libqt5sql5",
    "libqt5test5",
    "libqt5widgets5",
    "libqt5xml5",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"JSON document is not an object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--reconstruction-authority", type=Path, required=True)
    parser.add_argument("--generic-verifier", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--artifact-name", default="")
    args = parser.parse_args()

    require(args.reconstruction_authority.is_file(), "reconstruction authority is missing")
    require(args.generic_verifier.is_file(), "generic ARM64 verifier is missing")
    authority = load(args.reconstruction_authority)
    require(authority.get("source") == SOURCE, "reconstruction authority source mismatch")
    require(authority.get("source_version") == VERSION, "reconstruction authority version mismatch")
    require(
        authority.get("source_status") == "reconstructed-not-recovered-original-source",
        "reconstruction authority status mismatch",
    )
    require(authority.get("byte_identity_claimed") is False, "invalid original byte identity claim")
    require(authority.get("promotion_allowed") is False, "source reconstruction was pre-promoted")
    claims = authority.get("claims")
    require(isinstance(claims, dict), "reconstruction claims are missing")
    require(claims.get("exact_package_name_and_version") is True, "exact source identity was not proven")
    require(claims.get("exact_vendor_changelog_preserved") is True, "vendor changelog was not preserved")
    require(claims.get("only_vendor_declared_code_patch_added") is True, "single-patch reconstruction was not proven")
    require(claims.get("lost_original_source_archive_recovered") is False, "invalid original-source recovery claim")

    with tempfile.TemporaryDirectory(prefix="verify-reconstructed-qtbase-") as temporary:
        generic_result = Path(temporary) / "generic-result.json"
        process = subprocess.run(
            [
                "python3",
                str(args.generic_verifier),
                "--source",
                SOURCE,
                "--version",
                VERSION,
                "--output-dir",
                str(args.output_dir),
                "--result",
                str(generic_result),
                "--artifact-name",
                args.artifact_name,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode:
            raise SystemExit(
                f"generic ARM64 verification failed ({process.returncode})\n"
                f"stdout:\n{process.stdout[-8000:]}\n"
                f"stderr:\n{process.stderr[-8000:]}"
            )
        generic = load(generic_result)

    require(generic.get("passed") is True, "generic ARM64 verification did not pass")
    require(generic.get("verification_passed") is True, "generic verification flag is false")
    require(int(generic.get("foreign_payload_count", 0) or 0) == 0, "foreign payload survived")
    packages = generic.get("packages")
    require(isinstance(packages, list), "verified package list is missing")
    by_name = {str(row.get("package", "")): row for row in packages if isinstance(row, dict)}
    missing = sorted(REQUIRED_PACKAGES - set(by_name))
    require(not missing, f"required QtBase packages are missing: {missing}")
    for name in sorted(REQUIRED_PACKAGES):
        row = by_name[name]
        require(row.get("version") == VERSION, f"wrong version for {name}")
        require(row.get("source") == SOURCE, f"wrong source for {name}")
        require(row.get("source_version") == VERSION, f"wrong source version for {name}")
        require(row.get("architecture") == "arm64", f"wrong architecture for {name}")
        require(int(row.get("foreign_payload_count", 0) or 0) == 0, f"foreign payload in {name}")
        require(HEX64.fullmatch(str(row.get("sha256", ""))) is not None, f"invalid package SHA-256 for {name}")

    payloads = generic.get("payloads")
    require(isinstance(payloads, list), "payload verification list is missing")
    core_payloads = [
        row
        for row in payloads
        if isinstance(row, dict)
        and row.get("package") == "libqt5core5a"
        and row.get("path") == "/usr/lib/aarch64-linux-gnu/libQt5Core.so.5.15.2"
    ]
    require(len(core_payloads) == 1, "exact libQt5Core payload was not uniquely verified")
    require(core_payloads[0].get("machine") == 183, "libQt5Core payload is not AArch64")

    authority_digest = sha256(args.reconstruction_authority)
    result = dict(generic)
    result.update(
        {
            "schema": 2,
            "policy": "vendor-declared-single-patch-source-reconstruction-native-arm64-no-foreign-payload",
            "source": SOURCE,
            "source_version": VERSION,
            "build_mode": "signed-debian-base-plus-vendor-changelog-plus-cve-patch-native-arm64",
            "source_status": "reconstructed-not-recovered-original-source",
            "authority_provenance": "exact-vendor-binary-changelog-plus-signed-debian-base-and-security-patch",
            "byte_identity_claimed": False,
            "artifact_name": args.artifact_name,
            "actions_run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "actions_run_url": (
                f"{os.environ.get('GITHUB_SERVER_URL', '')}/"
                f"{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/"
                f"{os.environ.get('GITHUB_RUN_ID', '')}"
            ),
            "reconstruction_authority": {
                "path": args.reconstruction_authority.as_posix(),
                "sha256": authority_digest,
                "policy": authority.get("policy"),
                "base_dsc_sha256": authority.get("base_authority", {}).get("dsc_sha256"),
                "security_dsc_sha256": authority.get("security_patch_authority", {}).get("dsc_sha256"),
                "cve_patch_sha256": authority.get("security_patch_authority", {}).get("patch", {}).get("sha256"),
                "vendor_deb_sha256": authority.get("vendor_binary_authority", {}).get("sha256"),
                "reconstructed_dsc_sha256": authority.get("reconstruction", {}).get("reconstructed_dsc_sha256"),
            },
            "required_package_count": len(REQUIRED_PACKAGES),
            "required_packages": sorted(REQUIRED_PACKAGES),
            "verified_core_payload": core_payloads[0],
            "original_source_archive_recovered": False,
            "native_arm64_build_verified": True,
            "promotion_allowed": False,
        }
    )
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
