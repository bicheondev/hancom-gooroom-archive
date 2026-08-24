#!/usr/bin/env python3
"""Aggregate immutable ARM64 port evidence into one fail-closed dashboard."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            return value
    return None


def binary_inventory(row: dict[str, Any]) -> list[dict[str, str]]:
    packages = row.get("binary_packages", [])
    architectures = row.get("binary_architectures", [])
    result: list[dict[str, str]] = []
    if isinstance(packages, dict):
        packages = [
            {"package": name, **(value if isinstance(value, dict) else {})}
            for name, value in packages.items()
        ]
    if not isinstance(packages, list):
        return result
    arch_map: dict[str, str] = {}
    if isinstance(architectures, dict):
        arch_map = {str(key): str(value) for key, value in architectures.items()}
    elif isinstance(architectures, list):
        for index, architecture in enumerate(architectures):
            if isinstance(architecture, dict):
                name = first(
                    architecture, "package", "binary_package", "binary", "name"
                )
                arch = first(
                    architecture, "architecture", "arch", "binary_architecture"
                )
                if name and arch:
                    arch_map[str(name)] = str(arch)
            elif index < len(packages):
                package = packages[index]
                if isinstance(package, dict):
                    name = first(
                        package, "package", "binary_package", "binary", "name"
                    )
                else:
                    name = package
                if name:
                    arch_map[str(name)] = str(architecture)
    for package in packages:
        if isinstance(package, dict):
            name = first(package, "package", "binary_package", "binary", "name")
            arch = first(package, "architecture", "arch", "binary_architecture")
        else:
            name = package
            arch = None
        if name is None:
            continue
        name = str(name)
        arch = str(arch or arch_map.get(name) or "unknown")
        result.append({"package": name, "architecture": arch})
    return result


def wave_summaries(locks_root: Path) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for path in sorted(locks_root.glob("build-wave*/summary.json")):
        value = load(path)
        if value is None:
            continue
        summaries.append(
            {
                "path": str(path),
                "schema": value.get("schema"),
                "status": value.get("status"),
                "generated_at": value.get("generated_at"),
                "expected_sources": value.get("expected_sources", []),
                "recorded_sources": value.get("recorded_sources", []),
                "missing_sources": value.get("missing_sources", []),
                "failed_sources": value.get("failed_sources", []),
                "packages": value.get("packages", []),
                "reasons": value.get("reasons", []),
                "workflow_run": value.get("workflow_run"),
            }
        )
    return summaries


def boot_evidence(locks_root: Path, pattern: str) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(locks_root.glob(pattern)):
        value = load(path)
        if value is None:
            continue
        rows.append(
            {
                "path": str(path),
                "schema": value.get("schema"),
                "status": value.get("status"),
                "generated_at": value.get("generated_at"),
                "reasons": value.get("reasons", []),
                "readiness_marker_found": value.get(
                    "readiness_marker_found",
                    value.get("uefi_readiness_marker_found"),
                ),
                "assembly_exit_code": value.get("assembly_exit_code"),
                "boot_outcome": value.get("boot_outcome"),
                "workflow_run": value.get("workflow_run"),
            }
        )
    return rows


def source_archive_evidence(locks_root: Path) -> list[dict[str, Any]]:
    rows = []
    root = locks_root / "source-archives"
    if not root.is_dir():
        return rows
    for path in sorted(root.rglob("source-archive-lock.json")):
        value = load(path)
        if value:
            rows.append(
                {
                    "path": str(path),
                    "status": value.get("status"),
                    "source": value.get("source"),
                    "version": value.get("version"),
                    "dsc": value.get("dsc"),
                    "file_count": len(value.get("files", [])),
                }
            )
    for path in sorted(root.rglob("source-archive-probe.json")):
        value = load(path)
        if value:
            rows.append(
                {
                    "path": str(path),
                    "status": value.get("status"),
                    "source": value.get("source"),
                    "version": value.get("version"),
                    "candidate_count": value.get("candidate_count"),
                    "attempt_count": len(value.get("attempts", [])),
                    "apt_roots": value.get("apt_roots", []),
                }
            )
    return rows


def latest(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    return sorted(
        rows,
        key=lambda row: str(row.get("generated_at") or row.get("path") or ""),
    )[-1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    root = args.repo_root.resolve()
    locks_root = root / "arm64/locks"
    reference_path = locks_root / "reference/amd64-reference.json"
    effective_path = locks_root / "effective-sources/effective-source-lock.json"
    vendor_path = locks_root / "vendor-binaries/vendor-binary-lock.json"
    reference = load(reference_path) or {}
    effective = load(effective_path) or {}
    vendor = load(vendor_path) or {}

    source_rows: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    native_source_names: set[str] = set()
    exact_git_sources: set[str] = set()
    unresolved_native_sources: list[dict[str, Any]] = []
    for row in effective.get("sources", []):
        if not isinstance(row, dict):
            continue
        source = str(row.get("source") or "")
        version = str(row.get("source_version") or "")
        status = str(row.get("status") or "unknown")
        binaries = binary_inventory(row)
        native = [item for item in binaries if item["architecture"] != "all"]
        architecture_all = [
            item for item in binaries if item["architecture"] == "all"
        ]
        if native:
            native_source_names.add(source)
        selected = row.get("selected") if isinstance(row.get("selected"), dict) else None
        if status == "resolved" and selected and selected.get("commit_sha"):
            exact_git_sources.add(source)
        status_counts[status] += 1
        item = {
            "source": source,
            "source_version": version,
            "status": status,
            "role": row.get("role"),
            "native_binary_count": len(native),
            "architecture_all_binary_count": len(architecture_all),
            "native_binary_packages": native,
            "architecture_all_binary_packages": architecture_all,
            "selected": selected,
            "reason": row.get("reason"),
        }
        source_rows.append(item)
        if native and not (status == "resolved" and selected):
            unresolved_native_sources.append(item)

    waves = wave_summaries(locks_root)
    passed_sources: set[str] = set()
    failed_sources: set[str] = set()
    built_packages: list[dict[str, Any]] = []
    for wave in waves:
        for package in wave.get("packages", []):
            if not isinstance(package, dict):
                continue
            source = package.get("source")
            if not source:
                continue
            if package.get("status") == "passed":
                passed_sources.add(str(source))
            else:
                failed_sources.add(str(source))
            for built in package.get("built_packages", []):
                if isinstance(built, dict):
                    built_packages.append({"source": source, **built})
        failed_sources.update(str(value) for value in wave.get("failed_sources", []))
    failed_sources -= passed_sources

    unbuilt_resolved_native = sorted(
        source
        for source in native_source_names
        if source in exact_git_sources and source not in passed_sources
    )
    unresolved_native_names = sorted(
        item["source"] for item in unresolved_native_sources if item["source"]
    )

    minimal_rows = boot_evidence(
        locks_root, "minimal-boot*-attempt/summary.json"
    )
    stage0_rows = boot_evidence(locks_root, "stage0*-attempt/summary.json")
    minimal_latest = latest(minimal_rows)
    stage0_latest = latest(stage0_rows)
    archives = source_archive_evidence(locks_root)

    blockers: list[dict[str, Any]] = []
    if unresolved_native_names:
        blockers.append(
            {
                "type": "unresolved-native-source",
                "count": len(unresolved_native_names),
                "sources": unresolved_native_names,
            }
        )
    if failed_sources:
        blockers.append(
            {
                "type": "failed-native-build",
                "count": len(failed_sources),
                "sources": sorted(failed_sources),
            }
        )
    if unbuilt_resolved_native:
        blockers.append(
            {
                "type": "resolved-native-source-not-yet-built",
                "count": len(unbuilt_resolved_native),
                "sources": unbuilt_resolved_native,
            }
        )
    if not minimal_latest or minimal_latest.get("status") != "passed":
        blockers.append(
            {
                "type": "minimal-arm64-uefi-boot-not-passed",
                "evidence": minimal_latest,
            }
        )
    if not stage0_latest or stage0_latest.get("status") != "passed":
        blockers.append(
            {
                "type": "stage0-desktop-arm64-uefi-boot-not-passed",
                "evidence": stage0_latest,
            }
        )

    reference_iso = reference.get("reference_iso", {})
    vendor_summary = vendor.get("summary", {})
    complete = not blockers
    result = {
        "schema": "hancom-gooroom-3.3-arm64-port-state-audit-v1",
        "generated_at": now(),
        "status": "port-evidence-complete" if complete else "in-progress",
        "reference": {
            "iso_sha256": reference_iso.get("sha256"),
            "package_count": reference.get("package_count"),
            "source_count": reference.get("source_count"),
        },
        "vendor_binary_lock": {
            "verified_count": vendor_summary.get("verified_count"),
            "unresolved_count": vendor_summary.get("unresolved_count"),
        },
        "effective_source_lock": {
            "source_count": len(source_rows),
            "status_counts": dict(sorted(status_counts.items())),
            "exact_git_source_count": len(exact_git_sources),
            "native_source_count": len(native_source_names),
            "unresolved_native_source_count": len(unresolved_native_names),
        },
        "native_builds": {
            "passed_source_count": len(passed_sources),
            "passed_sources": sorted(passed_sources),
            "failed_source_count": len(failed_sources),
            "failed_sources": sorted(failed_sources),
            "resolved_unbuilt_source_count": len(unbuilt_resolved_native),
            "resolved_unbuilt_sources": unbuilt_resolved_native,
            "built_package_count": len(built_packages),
            "built_packages": built_packages,
            "waves": waves,
        },
        "boot_gates": {
            "minimal_latest": minimal_latest,
            "minimal_attempts": minimal_rows,
            "stage0_latest": stage0_latest,
            "stage0_attempts": stage0_rows,
        },
        "source_archives": archives,
        "blockers": blockers,
        "source_rows": source_rows,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "state.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Hancom Gooroom 3.3 ARM64 port state",
        "",
        f"Generated: `{result['generated_at']}`",
        f"Status: **{result['status']}**",
        "",
        "## Reference fidelity",
        "",
        f"- AMD64 reference ISO SHA-256: `{result['reference']['iso_sha256']}`",
        f"- Reference binary packages: `{result['reference']['package_count']}`",
        f"- Exact vendor binaries verified: `{result['vendor_binary_lock']['verified_count']}`",
        f"- Exact vendor binaries unresolved: `{result['vendor_binary_lock']['unresolved_count']}`",
        "",
        "## Exact source and native builds",
        "",
        f"- Effective source rows: `{result['effective_source_lock']['source_count']}`",
        f"- Exact Git sources: `{result['effective_source_lock']['exact_git_source_count']}`",
        f"- Native source rows: `{result['effective_source_lock']['native_source_count']}`",
        f"- Passed native source builds: `{result['native_builds']['passed_source_count']}`",
        f"- Failed native source builds: `{result['native_builds']['failed_source_count']}`",
        f"- Resolved but not yet built: `{result['native_builds']['resolved_unbuilt_source_count']}`",
        "",
        "## Boot gates",
        "",
        f"- Minimal ARM64 UEFI proof: `{(minimal_latest or {}).get('status', 'missing')}`",
        f"- Stage-0 desktop ARM64 UEFI: `{(stage0_latest or {}).get('status', 'missing')}`",
        "",
        "## Current blockers",
        "",
    ]
    if blockers:
        for blocker in blockers:
            line = f"- **{blocker['type']}**"
            if blocker.get("count") is not None:
                line += f": {blocker['count']}"
            lines.append(line)
            sources = blocker.get("sources", [])
            if sources:
                lines.append("  - " + ", ".join(f"`{source}`" for source in sources))
    else:
        lines.append("- None in the currently recorded gates.")
    lines.extend(
        [
            "",
            "> This dashboard reports only committed, checksum-backed evidence. "
            "It does not label the final ISO complete until every native source "
            "and both ARM64 UEFI boot gates pass.",
            "",
        ]
    )
    (args.output_dir / "STATE.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
