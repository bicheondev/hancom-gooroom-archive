#!/usr/bin/env python3
"""Finalize exact-source authority with independently verified overlays.

The ordinary source merger intentionally fails closed when multiple exact Git
commits declare the same Debian source/version but produce different trees. A
specific tree may be selected only after a persisted native ARM64 build result
proves that exact authority. Reconstructed source overlays are handled
separately so they can never be mistaken for a public exact-version Git tag.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

HEX40 = re.compile(r"^[0-9a-f]{40}$")
UNRESOLVED_STATUSES = {
    "unresolved-exact-source",
    "ambiguous-exact-signed-source",
    "ambiguous-exact-git-source",
}


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def identity(selected: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(selected.get("repository_full_name", "")),
        str(selected.get("commit_sha", "")),
        str(selected.get("tree_sha", "")),
    )


def require_git_identity(
    selected: dict[str, Any], source: str, version: str
) -> tuple[str, str, str]:
    if selected.get("type", "git") != "git":
        raise SystemExit(f"verified build overlay is not a Git authority: {(source, version)}")
    if selected.get("declared_source") != source:
        raise SystemExit(f"verified build declared source mismatch: {(source, version)}")
    if selected.get("declared_version") != version:
        raise SystemExit(f"verified build declared version mismatch: {(source, version)}")
    repository, commit, tree = identity(selected)
    if "/" not in repository or not HEX40.fullmatch(commit) or not HEX40.fullmatch(tree):
        raise SystemExit(f"invalid verified Git authority: {(source, version)}")
    return repository, commit, tree


def verification_passed(result: dict[str, Any]) -> bool:
    if result.get("passed") is not True:
        return False
    if result.get("verification_passed") is True:
        return True
    verification = result.get("verification")
    return isinstance(verification, dict) and verification.get("passed") is True


def verify_result_file(
    result_path: Path,
    source: str,
    version: str,
    selected: dict[str, Any],
) -> dict[str, Any]:
    if not result_path.is_file():
        raise SystemExit(f"verified build result is missing: {result_path}")
    result = load(result_path)
    repository, commit, tree = require_git_identity(selected, source, version)
    if result.get("source") != source or result.get("source_version") != version:
        raise SystemExit(f"build result identity mismatch: {result_path}")
    if not verification_passed(result):
        raise SystemExit(f"build result did not pass: {result_path}")

    result_identity = (
        str(result.get("repository_full_name", "")),
        str(result.get("commit_sha", "")),
        str(result.get("tree_sha", "")),
    )
    if result_identity != (repository, commit, tree):
        raise SystemExit(f"build result Git identity mismatch: {result_path}")

    verification = result.get("verification")
    if isinstance(verification, dict):
        verification_identity = (
            str(verification.get("repository_full_name", repository)),
            str(verification.get("commit_sha", commit)),
            str(verification.get("tree_sha", tree)),
        )
        if verification_identity != (repository, commit, tree):
            raise SystemExit(f"verification Git identity mismatch: {result_path}")

    build_lock = result.get("build_lock")
    if isinstance(build_lock, dict):
        build_identity = (
            str(build_lock.get("repository", repository)),
            str(build_lock.get("commit_sha", commit)),
            str(build_lock.get("tree_sha", tree)),
        )
        if build_identity != (repository, commit, tree):
            raise SystemExit(f"build lock Git identity mismatch: {result_path}")
        if build_lock.get("source", source) != source:
            raise SystemExit(f"build lock source mismatch: {result_path}")
        if build_lock.get("source_version", version) != version:
            raise SystemExit(f"build lock version mismatch: {result_path}")

    source_evidence = result.get("source_lock_evidence")
    if isinstance(source_evidence, dict):
        evidence_identity = (
            str(source_evidence.get("repository", repository)),
            str(source_evidence.get("verified_commit_sha", commit)),
            str(source_evidence.get("verified_tree_sha", tree)),
        )
        if evidence_identity != (repository, commit, tree):
            raise SystemExit(f"source-lock evidence mismatch: {result_path}")

    packages: list[dict[str, Any]] = []
    if isinstance(verification, dict) and isinstance(verification.get("packages"), list):
        packages = verification["packages"]
    elif isinstance(result.get("deb_artifacts"), list):
        packages = result["deb_artifacts"]
    if not packages:
        raise SystemExit(f"build result contains no verified package payloads: {result_path}")
    for package in packages:
        package_version = package.get("version")
        if package_version != version:
            raise SystemExit(f"verified package version mismatch in {result_path}: {package}")
        architecture = package.get("architecture")
        if architecture not in {"arm64", "all"}:
            raise SystemExit(f"non-ARM64 package in verified result {result_path}: {package}")
        package_source = package.get("source") or package.get("parsed_source")
        if package_source not in (None, "", source):
            raise SystemExit(f"verified package source mismatch in {result_path}: {package}")
        package_source_version = package.get("source_version") or package.get(
            "parsed_source_version"
        )
        if package_source_version not in (None, "", version):
            raise SystemExit(
                f"verified package source version mismatch in {result_path}: {package}"
            )
        if int(package.get("x86_payload_count", 0) or 0) != 0:
            raise SystemExit(f"x86 payload survived in {result_path}: {package}")
        if int(package.get("foreign_payload_count", 0) or 0) != 0:
            raise SystemExit(f"foreign payload survived in {result_path}: {package}")

    return {
        "result_path": result_path.as_posix(),
        "actions_run_id": str(result.get("actions_run_id", "")),
        "actions_run_url": result.get("actions_run_url"),
        "artifact_name": result.get("artifact_name"),
        "verified_package_count": len(packages),
        "passed": True,
    }


def positions(rows: list[dict[str, Any]]) -> dict[tuple[str, str], int]:
    result: dict[tuple[str, str], int] = {}
    for index, row in enumerate(rows):
        key = (str(row.get("source", "")), str(row.get("source_version", "")))
        if not all(key):
            raise SystemExit(f"malformed source authority row at index {index}")
        if key in result:
            raise SystemExit(f"duplicate source authority row: {key}")
        result[key] = index
    return result


def apply_verified_build_overlays(
    rows: list[dict[str, Any]],
    overlay_path: Path | None,
) -> list[dict[str, Any]]:
    if overlay_path is None:
        return []
    document = load(overlay_path)
    overlays = document.get("sources")
    if not isinstance(overlays, list):
        raise SystemExit("verified build lock must contain a sources array")
    index = positions(rows)
    applied: list[dict[str, Any]] = []
    for overlay in overlays:
        source = str(overlay.get("source", ""))
        version = str(overlay.get("source_version", ""))
        key = (source, version)
        if key not in index:
            raise SystemExit(f"verified build source is absent from base authority: {key}")
        if overlay.get("status") != "resolved" or not isinstance(
            overlay.get("selected"), dict
        ):
            raise SystemExit(f"verified build source is not resolved: {key}")
        verification = overlay.get("verification")
        if not isinstance(verification, dict) or verification.get("passed") is not True:
            raise SystemExit(f"verified build overlay did not pass: {key}")
        result_value = verification.get("result_path")
        if not result_value:
            raise SystemExit(f"verified build overlay lacks result_path: {key}")
        selected = deepcopy(overlay["selected"])
        result_evidence = verify_result_file(
            Path(str(result_value)), source, version, selected
        )

        original = rows[index[key]]
        merged = deepcopy(original)
        merged.update(
            {
                "status": "resolved",
                "provenance": overlay.get(
                    "provenance", "verified-native-arm64-build-exact-git"
                ),
                "selected": selected,
                "verified_build_evidence": {
                    **deepcopy(verification),
                    **result_evidence,
                    "authority_lock": overlay_path.as_posix(),
                    "original_status": original.get("status"),
                    "original_provenance": original.get("provenance"),
                },
            }
        )
        rows[index[key]] = merged
        applied.append(
            {
                "source": source,
                "source_version": version,
                "repository_full_name": selected["repository_full_name"],
                "commit_sha": selected["commit_sha"],
                "tree_sha": selected["tree_sha"],
                "result_path": str(result_value),
            }
        )
    return applied


def apply_reconstructed_overlays(
    rows: list[dict[str, Any]],
    overlay_path: Path | None,
) -> list[dict[str, Any]]:
    if overlay_path is None:
        return []
    document = load(overlay_path)
    overlays = document.get("sources")
    if not isinstance(overlays, list):
        raise SystemExit("reconstructed source lock must contain a sources array")
    index = positions(rows)
    applied: list[dict[str, Any]] = []
    for overlay in overlays:
        source = str(overlay.get("source", ""))
        version = str(overlay.get("source_version", ""))
        key = (source, version)
        if key not in index:
            raise SystemExit(f"reconstructed source is absent from base authority: {key}")
        if overlay.get("status") != "resolved" or not isinstance(
            overlay.get("selected"), dict
        ):
            raise SystemExit(f"reconstructed source is not resolved: {key}")
        verification = overlay.get("verification")
        if not isinstance(verification, dict) or verification.get("passed") is not True:
            raise SystemExit(f"reconstructed source verification did not pass: {key}")
        selected = deepcopy(overlay["selected"])
        if selected.get("type") != "reconstructed-git-tree":
            raise SystemExit(f"unexpected reconstructed source type: {key}")
        if selected.get("declared_source") != source:
            raise SystemExit(f"reconstructed declared source mismatch: {key}")
        if selected.get("declared_version") != version:
            raise SystemExit(f"reconstructed declared version mismatch: {key}")
        repository, commit, tree = identity(selected)
        if "/" not in repository or not HEX40.fullmatch(commit) or not HEX40.fullmatch(tree):
            raise SystemExit(f"invalid reconstructed source identity: {key}")
        archive_sha = str(selected.get("source_archive_sha256", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", archive_sha):
            raise SystemExit(f"reconstructed archive is not SHA-256 locked: {key}")

        original = rows[index[key]]
        merged = deepcopy(original)
        merged.update(
            {
                "status": "resolved",
                "provenance": overlay.get(
                    "provenance", "verified-reconstructed-source"
                ),
                "selected": selected,
                "reconstruction_evidence": {
                    **deepcopy(verification),
                    "authority_lock": overlay_path.as_posix(),
                    "original_status": original.get("status"),
                    "original_provenance": original.get("provenance"),
                },
            }
        )
        rows[index[key]] = merged
        applied.append(
            {
                "source": source,
                "source_version": version,
                "repository_full_name": repository,
                "base_commit_sha": commit,
                "reconstructed_tree_sha": tree,
                "source_archive_sha256": archive_sha,
            }
        )
    return applied


def summarize(
    rows: list[dict[str, Any]],
    previous: dict[str, Any],
    verified: list[dict[str, Any]],
    reconstructed: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    unresolved = [row for row in rows if row.get("status") in UNRESOLVED_STATUSES]
    rebuild_blockers = [
        row
        for row in unresolved
        if row.get("role") == "rebuild-arm64"
        and row.get("source") != "linux-signed-amd64"
    ]
    summary = deepcopy(previous)
    summary.update(
        {
            "schema": max(int(summary.get("schema", 1)), 4),
            "policy": (
                "exact-signed-dsc-then-exact-git-then-verified-build-"
                "selection-then-verified-reconstruction"
            ),
            "source_target_count": len(rows),
            "resolved_count": sum(row.get("status") == "resolved" for row in rows),
            "signed_dsc_resolved_count": sum(
                row.get("status") == "resolved"
                and isinstance(row.get("selected"), dict)
                and row["selected"].get("type") == "dsc"
                for row in rows
            ),
            "git_resolved_count": sum(
                row.get("status") == "resolved"
                and isinstance(row.get("selected"), dict)
                and row["selected"].get("type", "git") == "git"
                for row in rows
            ),
            "verified_build_git_resolved_count": len(verified),
            "reconstructed_resolved_count": len(reconstructed),
            "arch_replace_count": sum(
                row.get("status") == "arch-replace" for row in rows
            ),
            "unresolved_count": len(unresolved),
            "rebuild_blocker_count": len(rebuild_blockers),
            "build_allowed": not rebuild_blockers,
            "verified_build_overlays": verified,
            "reconstructed_overlays": reconstructed,
        }
    )
    return summary, unresolved, rebuild_blockers


def write_tsv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "source",
        "source_version",
        "role",
        "status",
        "provenance",
        "selected_type",
        "repository_full_name",
        "commit_sha",
        "tree_sha",
        "dsc_sha256",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in rows:
            selected = row.get("selected") if isinstance(row.get("selected"), dict) else {}
            dsc = selected.get("dsc") if isinstance(selected.get("dsc"), dict) else {}
            writer.writerow(
                {
                    "source": row.get("source", ""),
                    "source_version": row.get("source_version", ""),
                    "role": row.get("role", ""),
                    "status": row.get("status", ""),
                    "provenance": row.get("provenance", ""),
                    "selected_type": selected.get("type", ""),
                    "repository_full_name": selected.get("repository_full_name", ""),
                    "commit_sha": selected.get("commit_sha", ""),
                    "tree_sha": selected.get("tree_sha", ""),
                    "dsc_sha256": dsc.get("sha256", ""),
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-lock", type=Path, required=True)
    parser.add_argument("--verified-build-lock", type=Path)
    parser.add_argument("--reconstructed-locks", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    base = load(args.base_lock)
    rows = deepcopy(base.get("sources"))
    if not isinstance(rows, list):
        raise SystemExit("base authority must contain a sources array")

    verified = apply_verified_build_overlays(rows, args.verified_build_lock)
    reconstructed = apply_reconstructed_overlays(rows, args.reconstructed_locks)
    summary, unresolved, rebuild_blockers = summarize(
        rows,
        base.get("summary", {}) if isinstance(base.get("summary"), dict) else {},
        verified,
        reconstructed,
    )

    result = deepcopy(base)
    result["summary"] = summary
    result["sources"] = rows
    result["source_overlays"] = {
        "schema": 1,
        "verified_build_authority": (
            args.verified_build_lock.as_posix() if args.verified_build_lock else None
        ),
        "reconstructed_authority": (
            args.reconstructed_locks.as_posix() if args.reconstructed_locks else None
        ),
        "verified_build_applied": verified,
        "reconstructed_applied": reconstructed,
    }

    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "effective-source-lock.json", result)
    write_json(output / "effective-source-lock-summary.json", summary)
    write_json(output / "effective-source-unresolved.json", unresolved)
    write_json(output / "effective-source-rebuild-blockers.json", rebuild_blockers)
    write_json(output / "source-overlay-report.json", result["source_overlays"])
    write_tsv(output / "effective-source-lock.tsv", rows)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not rebuild_blockers else 2


if __name__ == "__main__":
    raise SystemExit(main())
