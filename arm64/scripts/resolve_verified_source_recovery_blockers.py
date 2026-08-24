#!/usr/bin/env python3
"""Close source-recovery blockers only with strict persisted ARM64 evidence.

The original blocker authority remains immutable.  This script emits a filtered
runtime gate for coverage reporting.  A blocker is removed only when a recorded
rebuild proves the exact package/source/version identity, exact packaging Git
identity, the locked final AMD64 payload identity, a binary-history-constrained
source reconstruction, and a verified AArch64 package with no foreign ELF.
"""

from __future__ import annotations

import argparse
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RECONSTRUCTION_STATUS = "reconstructed-not-recovered-original-source"
RECONSTRUCTION_MODE = "native-arm64-binary-history-constrained-reconstruction"
RECONSTRUCTION_PROVENANCE = (
    "github-exact-packaging-with-binary-history-constrained-module-reconstruction"
)


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON document is not an object: {path}")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def latest_results(root: Path) -> dict[tuple[str, str], tuple[Path, dict[str, Any]]]:
    results: dict[tuple[str, str], tuple[Path, dict[str, Any]]] = {}
    if not root.is_dir():
        raise SystemExit(f"rebuild result root is missing: {root}")
    for path in sorted(root.rglob("result.json")):
        try:
            row = load(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        source = str(row.get("source", ""))
        version = str(row.get("source_version", ""))
        if not source or not version:
            continue
        try:
            run_id = int(str(row.get("actions_run_id", "0")))
        except ValueError:
            run_id = 0
        previous = results.get((source, version))
        if previous is None:
            previous_run_id = -1
        else:
            try:
                previous_run_id = int(str(previous[1].get("actions_run_id", "0")))
            except ValueError:
                previous_run_id = -1
        if run_id >= previous_run_id:
            results[(source, version)] = (path, row)
    return results


def claims_reconstruction(result: dict[str, Any]) -> bool:
    return any(
        (
            result.get("source_status") == RECONSTRUCTION_STATUS,
            result.get("build_mode") == RECONSTRUCTION_MODE,
            result.get("authority_provenance") == RECONSTRUCTION_PROVENANCE,
        )
    )


def verify_resolution(
    blocker: dict[str, Any], result_path: Path, result: dict[str, Any]
) -> dict[str, Any] | None:
    source = str(blocker.get("source", ""))
    version = str(blocker.get("source_version", ""))
    require(source and version, f"malformed source-recovery blocker: {blocker!r}")

    if not claims_reconstruction(result):
        return None

    label = f"{source} {version} reconstruction evidence"
    require(result.get("source") == source, f"{label}: source mismatch")
    require(result.get("source_version") == version, f"{label}: version mismatch")
    require(result.get("passed") is True, f"{label}: build result did not pass")
    require(
        result.get("verification_passed") is True,
        f"{label}: verification_passed is not true",
    )
    require(result.get("build_outcome") == "success", f"{label}: build failed")
    require(result.get("verify_outcome") == "success", f"{label}: verify failed")
    require(
        result.get("source_status") == RECONSTRUCTION_STATUS,
        f"{label}: source status mismatch",
    )
    require(result.get("build_mode") == RECONSTRUCTION_MODE, f"{label}: mode mismatch")
    require(
        result.get("authority_provenance") == RECONSTRUCTION_PROVENANCE,
        f"{label}: provenance mismatch",
    )
    require(result.get("byte_identity_claimed") is False, f"{label}: invalid byte claim")

    packaging = blocker.get("exact_packaging_authority")
    require(isinstance(packaging, dict), f"{label}: blocker packaging authority missing")
    repository = str(packaging.get("repository_full_name", ""))
    commit = str(packaging.get("commit_sha", ""))
    tree = str(packaging.get("tree_sha", ""))
    amd64_sha = str(packaging.get("sha256", ""))
    require("/" in repository, f"{label}: invalid packaging repository")
    require(HEX40.fullmatch(commit) is not None, f"{label}: invalid packaging commit")
    require(HEX40.fullmatch(tree) is not None, f"{label}: invalid packaging tree")
    require(HEX64.fullmatch(amd64_sha) is not None, f"{label}: invalid AMD64 SHA-256")
    require(result.get("repository_full_name") == repository, f"{label}: repository mismatch")
    require(result.get("commit_sha") == commit, f"{label}: commit mismatch")
    require(result.get("tree_sha") == tree, f"{label}: tree mismatch")

    build_lock = result.get("build_lock")
    require(isinstance(build_lock, dict), f"{label}: build lock missing")
    require(build_lock.get("source") == source, f"{label}: build-lock source mismatch")
    require(build_lock.get("source_version") == version, f"{label}: build-lock version mismatch")
    require(build_lock.get("repository") == repository, f"{label}: build-lock repository mismatch")
    require(build_lock.get("commit_sha") == commit, f"{label}: build-lock commit mismatch")
    require(build_lock.get("tree_sha") == tree, f"{label}: build-lock tree mismatch")
    require(build_lock.get("build_mode") == RECONSTRUCTION_MODE, f"{label}: build-lock mode mismatch")
    require(build_lock.get("source_status") == RECONSTRUCTION_STATUS, f"{label}: build-lock status mismatch")
    require(build_lock.get("byte_identity_claimed") is False, f"{label}: build-lock byte claim")

    source_evidence = result.get("source_lock_evidence")
    require(isinstance(source_evidence, dict), f"{label}: source-lock evidence missing")
    require(source_evidence.get("repository") == repository, f"{label}: source-lock repository mismatch")
    require(source_evidence.get("verified_commit_sha") == commit, f"{label}: source-lock commit mismatch")
    require(source_evidence.get("verified_tree_sha") == tree, f"{label}: source-lock tree mismatch")
    require(
        source_evidence.get("final_amd64_binary_sha256") == amd64_sha,
        f"{label}: locked AMD64 binary mismatch",
    )

    public = blocker.get("public_source_anchor")
    require(isinstance(public, dict), f"{label}: public source anchor missing")
    require(
        source_evidence.get("public_implementation_repository")
        == public.get("repository_full_name"),
        f"{label}: public repository mismatch",
    )
    require(
        source_evidence.get("public_implementation_commit") == public.get("commit_sha"),
        f"{label}: public commit mismatch",
    )
    require(
        source_evidence.get("public_implementation_tree") == public.get("tree_sha"),
        f"{label}: public tree mismatch",
    )

    reconstruction = result.get("reconstruction")
    require(isinstance(reconstruction, dict), f"{label}: reconstruction lock missing")
    require(
        reconstruction.get("source_status") == RECONSTRUCTION_STATUS,
        f"{label}: reconstruction status mismatch",
    )
    require(
        reconstruction.get("byte_identity_claimed") is False,
        f"{label}: reconstruction byte claim",
    )
    output_source_sha256 = str(reconstruction.get("output_source_sha256", ""))
    require(
        HEX64.fullmatch(output_source_sha256) is not None,
        f"{label}: reconstructed source is not SHA-256 locked",
    )

    verification = result.get("verification")
    require(isinstance(verification, dict), f"{label}: verification object missing")
    require(verification.get("passed") is True, f"{label}: verification did not pass")
    require(
        int(verification.get("wrong_architecture_executable_count", 0) or 0) == 0,
        f"{label}: wrong-architecture executable survived",
    )
    payload = verification.get("payload")
    require(isinstance(payload, dict), f"{label}: payload verification missing")
    require(payload.get("machine") == "AArch64", f"{label}: payload is not AArch64")
    require(
        payload.get("path") == "/usr/lib/xorg/modules/extensions/xsm.so",
        f"{label}: unexpected reconstructed payload path",
    )
    require(
        HEX64.fullmatch(str(payload.get("sha256", ""))) is not None,
        f"{label}: payload is not SHA-256 locked",
    )

    packages = verification.get("packages")
    require(isinstance(packages, list) and packages, f"{label}: no verified packages")
    for package in packages:
        require(isinstance(package, dict), f"{label}: malformed package record")
        require(package.get("source") == source, f"{label}: package source mismatch")
        require(package.get("source_version") == version, f"{label}: package source version mismatch")
        require(package.get("version") == version, f"{label}: package version mismatch")
        require(package.get("architecture") in {"arm64", "all"}, f"{label}: package architecture mismatch")
        require(int(package.get("x86_payload_count", 0) or 0) == 0, f"{label}: x86 payload survived")
        require(int(package.get("foreign_payload_count", 0) or 0) == 0, f"{label}: foreign payload survived")
        require(HEX64.fullmatch(str(package.get("sha256", ""))) is not None, f"{label}: package SHA-256 invalid")

    return {
        "source": source,
        "source_version": version,
        "status": "resolved-by-verified-reconstruction",
        "original_blocker_status": blocker.get("status"),
        "result_path": result_path.as_posix(),
        "actions_run_id": str(result.get("actions_run_id", "")),
        "actions_run_url": result.get("actions_run_url"),
        "packaging_repository": repository,
        "packaging_commit_sha": commit,
        "packaging_tree_sha": tree,
        "final_amd64_binary_sha256": amd64_sha,
        "reconstructed_source_sha256": output_source_sha256,
        "arm64_package_sha256": packages[0].get("sha256"),
        "arm64_payload_sha256": payload.get("sha256"),
        "arm64_payload_machine": payload.get("machine"),
        "byte_identity_claimed": False,
        "policy": "exact-packaging-and-binary-history-constrained-native-arm64-reconstruction",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--blockers", type=Path, required=True)
    parser.add_argument("--rebuild-results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resolutions-output", type=Path, required=True)
    args = parser.parse_args()

    document = load(args.blockers)
    blockers = document.get("sources")
    require(isinstance(blockers, list), "source-recovery authority lacks a sources array")
    declared = document.get("blocker_count")
    if declared is not None:
        require(int(declared) == len(blockers), "source-recovery blocker_count mismatch")

    results = latest_results(args.rebuild_results)
    remaining: list[dict[str, Any]] = []
    resolutions: list[dict[str, Any]] = []
    for blocker in blockers:
        source = str(blocker.get("source", ""))
        version = str(blocker.get("source_version", ""))
        result_entry = results.get((source, version))
        if result_entry is None:
            remaining.append(blocker)
            continue
        resolution = verify_resolution(blocker, result_entry[0], result_entry[1])
        if resolution is None:
            remaining.append(blocker)
        else:
            resolutions.append(resolution)

    filtered = deepcopy(document)
    filtered.update(
        {
            "schema": max(int(filtered.get("schema", 1)), 2),
            "policy": (
                "exact-version-source-recovery-required-unless-closed-by-"
                "strict-verified-native-arm64-reconstruction"
            ),
            "original_blocker_count": len(blockers),
            "blocker_count": len(remaining),
            "resolved_count": len(resolutions),
            "sources": remaining,
            "resolved": resolutions,
        }
    )
    resolution_document = {
        "schema": 1,
        "policy": filtered["policy"],
        "original_blocker_authority": args.blockers.as_posix(),
        "original_blocker_count": len(blockers),
        "remaining_blocker_count": len(remaining),
        "resolved_count": len(resolutions),
        "resolutions": resolutions,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.resolutions_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(filtered, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.resolutions_output.write_text(
        json.dumps(resolution_document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(resolution_document, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
