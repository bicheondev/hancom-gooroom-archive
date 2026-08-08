#!/usr/bin/env python3
"""Summarize exact-source ARM64 port coverage without overstating completion."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

RECONSTRUCTED_SOURCE_TYPES = {
    "reconstructed-git-tree",
    "verified-reconstructed-git-tree",
}


def load_optional(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def nested_summary(document: dict[str, Any]) -> dict[str, Any]:
    value = document.get("summary")
    return value if isinstance(value, dict) else document


def latest_results(root: Path) -> dict[tuple[str, str], tuple[dict[str, Any], Path]]:
    rows: dict[tuple[str, str], tuple[dict[str, Any], Path, int]] = {}
    if not root.exists():
        return {}
    for path in root.rglob("result.json"):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        source = row.get("source")
        version = row.get("source_version")
        if not source or not version:
            continue
        try:
            run_id = int(str(row.get("actions_run_id", "0")))
        except ValueError:
            run_id = 0
        key = (source, version)
        previous = rows.get(key)
        if previous is None or run_id >= previous[2]:
            rows[key] = (row, path, run_id)
    return {key: (row, path) for key, (row, path, _) in rows.items()}


def normalize_source_type(value: Any) -> str:
    source_type = str(value or "git")
    if source_type in RECONSTRUCTED_SOURCE_TYPES:
        return "reconstructed-git-tree"
    return source_type


def authority_identity(source_row: dict[str, Any]) -> tuple[str, str] | None:
    selected = source_row.get("selected")
    if not isinstance(selected, dict):
        return None
    source_type = normalize_source_type(selected.get("type", "git"))
    if source_type == "git":
        value = selected.get("tree_sha")
        return ("git", value) if value else None
    if source_type == "reconstructed-git-tree":
        value = selected.get("tree_sha") or selected.get("reconstructed_tree_sha")
        return ("reconstructed-git-tree", value) if value else None
    if source_type == "dsc":
        dsc = selected.get("dsc") if isinstance(selected.get("dsc"), dict) else {}
        value = dsc.get("sha256")
        return ("dsc", value) if value else None
    return None


def result_identity(result: dict[str, Any]) -> tuple[str, str] | None:
    build_lock = result.get("build_lock") if isinstance(result.get("build_lock"), dict) else {}
    evidence = (
        result.get("source_lock_evidence")
        if isinstance(result.get("source_lock_evidence"), dict)
        else {}
    )
    source_type = normalize_source_type(
        result.get("source_type")
        or build_lock.get("source_type")
        or evidence.get("source_type")
        or "git"
    )
    if source_type == "git":
        value = (
            result.get("tree_sha")
            or build_lock.get("tree_sha")
            or evidence.get("tree_sha")
        )
        return ("git", value) if value else None
    if source_type == "reconstructed-git-tree":
        value = (
            result.get("tree_sha")
            or build_lock.get("reconstructed_tree_sha")
            or evidence.get("reconstructed_tree_sha")
        )
        return ("reconstructed-git-tree", value) if value else None
    if source_type == "dsc":
        dsc = build_lock.get("dsc") if isinstance(build_lock.get("dsc"), dict) else {}
        if not dsc:
            dsc = evidence.get("dsc") if isinstance(evidence.get("dsc"), dict) else {}
        value = result.get("dsc_sha256") or dsc.get("sha256")
        return ("dsc", value) if value else None
    return None


def embedded_verification_passed(result: dict[str, Any]) -> bool:
    if result.get("verification_passed") is True:
        return True
    for key in ("verification", "verification_summary"):
        value = result.get(key)
        if not isinstance(value, dict):
            continue
        summary = nested_summary(value)
        if any(summary.get(field) is True for field in ("passed", "verified")):
            return True
    return False


def verification_passed(result: dict[str, Any], result_path: Path) -> bool:
    if embedded_verification_passed(result):
        return True
    path = result_path.parent / "verification.json"
    if not path.exists():
        return False
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    summary = nested_summary(document)
    return any(summary.get(field) is True for field in ("passed", "verified"))


def source_status_rows(lock: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in lock.get("sources", []) if row.get("source")]


def package_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("package", "")),
        str(row.get("version") or row.get("reference_version") or ""),
        str(row.get("architecture") or row.get("reference_architecture") or ""),
    )


def bool_value(document: dict[str, Any], *keys: str) -> bool:
    summary = nested_summary(document)
    return any(summary.get(key) is True for key in keys)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--source-lock", type=Path, required=True)
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--normalized-map", type=Path, required=True)
    parser.add_argument("--rebuild-release-lock", type=Path, required=True)
    parser.add_argument("--acquisition-plan", type=Path, required=True)
    parser.add_argument("--rootfs-verification", type=Path)
    parser.add_argument("--iso-release-lock", type=Path)
    parser.add_argument("--installed-release-lock", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = load_optional(args.reference)
    source_lock = load_optional(args.source_lock)
    normalized = load_optional(args.normalized_map)
    release = load_optional(args.rebuild_release_lock)
    acquisition = load_optional(args.acquisition_plan)
    rootfs = load_optional(args.rootfs_verification)
    iso = load_optional(args.iso_release_lock)
    installed = load_optional(args.installed_release_lock)
    latest = latest_results(args.results_dir)

    source_rows = source_status_rows(source_lock)
    source_blockers = [
        {
            "source": row.get("source"),
            "source_version": row.get("source_version"),
            "role": row.get("role"),
            "status": row.get("status"),
            "provenance": row.get("provenance"),
            "reason": "exact-source-authority-unresolved",
        }
        for row in source_rows
        if row.get("status") not in {"resolved", "arch-replace"}
        and row.get("role") == "rebuild-arm64"
        and row.get("source") != "linux-signed-amd64"
    ]

    native_sources = [
        row
        for row in source_rows
        if row.get("status") == "resolved"
        and row.get("role") == "rebuild-arm64"
        and row.get("source") != "linux-signed-amd64"
    ]
    native_passed = []
    native_blockers = []
    for row in native_sources:
        key = (row.get("source"), row.get("source_version"))
        previous = latest.get(key)
        if previous is None:
            native_blockers.append(
                {
                    "source": key[0],
                    "source_version": key[1],
                    "reason": "no-native-arm64-attempt-recorded",
                    "authority": authority_identity(row),
                }
            )
            continue
        result, path = previous
        current_identity = authority_identity(row)
        previous_identity = result_identity(result)
        if current_identity != previous_identity:
            native_blockers.append(
                {
                    "source": key[0],
                    "source_version": key[1],
                    "reason": "latest-result-authority-is-stale",
                    "current_authority": current_identity,
                    "result_authority": previous_identity,
                    "actions_run_id": result.get("actions_run_id"),
                }
            )
            continue
        if result.get("passed") is not True or not verification_passed(result, path):
            native_blockers.append(
                {
                    "source": key[0],
                    "source_version": key[1],
                    "reason": "latest-exact-authority-build-not-verified",
                    "authority": current_identity,
                    "actions_run_id": result.get("actions_run_id"),
                    "build_outcome": result.get("build_outcome"),
                    "verify_outcome": result.get("verify_outcome"),
                }
            )
            continue
        native_passed.append(
            {
                "source": key[0],
                "source_version": key[1],
                "authority": current_identity,
                "actions_run_id": result.get("actions_run_id"),
                "actions_run_url": result.get("actions_run_url"),
            }
        )

    normalized_rows = normalized.get("packages", [])
    normalized_status_counts = Counter(
        str(row.get("status", "missing")) for row in normalized_rows
    )
    expected_rebuilt_packages = {
        (
            row.get("package"),
            row.get("reference_version") or row.get("version"),
            "arm64",
        )
        for row in normalized_rows
        if row.get("status") == "rebuild-arm64"
    }
    release_rows = release.get("packages", [])
    release_index = {package_key(row): row for row in release_rows}
    release_package_blockers = [
        {
            "package": key[0],
            "version": key[1],
            "architecture": key[2],
            "reason": "persistent-exact-rebuild-package-not-locked",
        }
        for key in sorted(expected_rebuilt_packages)
        if key not in release_index
    ]

    acquisition_summary = nested_summary(acquisition)
    acquisition_blockers = acquisition.get("blockers", [])
    if not isinstance(acquisition_blockers, list):
        acquisition_blockers = []
    acquisition_ready = acquisition_summary.get("ready_for_fetch") is True
    rootfs_ready = bool_value(
        rootfs,
        "passed",
        "repository_ready",
        "package_layer_ready",
    )
    live_iso_ready = bool_value(iso, "qemu_booted", "passed")
    installed_ready = bool_value(
        installed,
        "installed_gpt_system_qemu_booted",
        "passed",
    )

    source_authority_complete = not source_blockers and bool(source_rows)
    native_rebuilds_complete = (
        source_authority_complete
        and len(native_passed) == len(native_sources)
        and not native_blockers
    )
    release_complete = (
        nested_summary(release).get("complete") is True
        and not release_package_blockers
    )
    exact_package_layer_ready = (
        native_rebuilds_complete and release_complete and acquisition_ready
    )
    port_complete = installed_ready

    highest_phase = "reference-and-source-mapping"
    if source_authority_complete:
        highest_phase = "exact-source-authority"
    if native_rebuilds_complete:
        highest_phase = "verified-native-arm64-rebuilds"
    if release_complete:
        highest_phase = "persistent-exact-rebuild-packages"
    if acquisition_ready:
        highest_phase = "exact-package-acquisition-ready"
    if rootfs_ready:
        highest_phase = "verified-arm64-rootfs"
    if live_iso_ready:
        highest_phase = "qemu-booted-live-arm64-iso"
    if installed_ready:
        highest_phase = "qemu-booted-installed-arm64-system"

    source_summary = nested_summary(source_lock)
    release_summary = nested_summary(release)
    summary = {
        "schema": 2,
        "policy": "current-exact-authority-and-phase-gate-coverage",
        "reference_package_count": len(reference.get("packages", [])),
        "reference_source_count": len(reference.get("sources", [])),
        "source_target_count": source_summary.get("source_target_count", len(source_rows)),
        "source_resolved_count": source_summary.get(
            "resolved_count", sum(row.get("status") == "resolved" for row in source_rows)
        ),
        "git_source_count": source_summary.get("git_resolved_count", 0),
        "signed_dsc_source_count": source_summary.get("signed_dsc_resolved_count", 0),
        "source_blocker_count": len(source_blockers),
        "native_rebuild_source_count": len(native_sources),
        "native_rebuild_passed_count": len(native_passed),
        "native_rebuild_blocker_count": len(native_blockers),
        "normalized_package_count": len(normalized_rows),
        "normalized_status_counts": dict(sorted(normalized_status_counts.items())),
        "expected_rebuilt_package_count": len(expected_rebuilt_packages),
        "persistent_rebuilt_package_count": len(release_rows),
        "persistent_rebuilt_package_blocker_count": len(release_package_blockers),
        "persistent_release_complete": release_summary.get("complete") is True,
        "acquisition_ready": acquisition_ready,
        "acquisition_blocker_count": len(acquisition_blockers),
        "rootfs_ready": rootfs_ready,
        "live_iso_qemu_booted": live_iso_ready,
        "installed_system_qemu_booted": installed_ready,
        "source_authority_complete": source_authority_complete,
        "native_rebuilds_complete": native_rebuilds_complete,
        "exact_package_layer_ready": exact_package_layer_ready,
        "highest_completed_phase": highest_phase,
        "port_complete": port_complete,
    }
    result = {
        "summary": summary,
        "source_blockers": source_blockers,
        "native_rebuild_passes": native_passed,
        "native_rebuild_blockers": native_blockers,
        "persistent_rebuilt_package_blockers": release_package_blockers,
        "acquisition_blockers": acquisition_blockers,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "coverage.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "blockers.json").write_text(
        json.dumps(
            {
                "source": source_blockers,
                "native_rebuild": native_blockers,
                "persistent_rebuilt_packages": release_package_blockers,
                "acquisition": acquisition_blockers,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
