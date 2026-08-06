#!/usr/bin/env python3
"""Report exact-source and native-build coverage for the ARM64 port."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def latest_rebuild_results(
    root: Path,
) -> dict[tuple[str, str], dict[str, Any]]:
    results: dict[tuple[str, str], dict[str, Any]] = {}
    if not root.exists():
        return results
    for path in root.rglob("result.json"):
        try:
            row = load_json(path)
        except (OSError, ValueError):
            continue
        source = row.get("source")
        version = row.get("source_version")
        if not source or not version:
            continue
        key = (source, version)
        previous = results.get(key)
        try:
            run_id = int(str(row.get("actions_run_id", "0")))
        except ValueError:
            run_id = 0
        try:
            previous_run_id = (
                int(str(previous.get("actions_run_id", "0")))
                if previous
                else -1
            )
        except ValueError:
            previous_run_id = -1
        if previous is None or run_id >= previous_run_id:
            row["evidence_path"] = str(path)
            results[key] = row
    return results


def source_recovery_index(
    path: Path | None,
) -> dict[tuple[str, str], dict[str, Any]]:
    if path is None:
        return {}
    if not path.exists():
        raise SystemExit(f"source-recovery blocker file not found: {path}")
    document = load_json(path)
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for row in document.get("sources", []):
        source = row.get("source")
        version = row.get("source_version")
        if not source or not version:
            raise SystemExit(
                f"malformed source-recovery blocker without identity: {row!r}"
            )
        key = (str(source), str(version))
        if key in rows and rows[key] != row:
            raise SystemExit(f"conflicting source-recovery blockers for {key}")
        rows[key] = row
    declared_count = document.get("blocker_count")
    if declared_count is not None and int(declared_count) != len(rows):
        raise SystemExit(
            "source-recovery blocker_count does not match the number of rows"
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--source-lock", type=Path, required=True)
    parser.add_argument("--rebuild-plan", type=Path, required=True)
    parser.add_argument("--rebuild-results", type=Path, required=True)
    parser.add_argument("--source-recovery-blockers", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = load_json(args.reference)
    source_lock = load_json(args.source_lock)
    plan = load_json(args.rebuild_plan)
    result_evidence = latest_rebuild_results(args.rebuild_results)
    source_recovery = source_recovery_index(args.source_recovery_blockers)

    packages_by_source: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for package in reference.get("packages", []):
        key = (package["source"], package["source_version"])
        packages_by_source.setdefault(key, []).append(package)

    lock_rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in source_lock.get("sources", []):
        key = (row["source"], row["source_version"])
        lock_rows.setdefault(key, []).append(row)

    known_success = plan.get("known_success", {})
    targets = [
        source
        for source in reference.get("sources", [])
        if source.get("custom_candidate")
    ]
    rows: list[dict[str, Any]] = []

    for target in sorted(
        targets,
        key=lambda row: (row["source"], row["source_version"]),
    ):
        key = (target["source"], target["source_version"])
        packages = packages_by_source.get(key, [])
        amd64_packages = sorted(
            {
                package["package"]
                for package in packages
                if package["architecture"] == "amd64"
            }
        )
        all_packages = sorted(
            {
                package["package"]
                for package in packages
                if package["architecture"] == "all"
            }
        )
        role = "rebuild-arm64" if amd64_packages else "reuse-all"

        candidates = lock_rows.get(key, [])
        exact = [
            row
            for row in candidates
            if row.get("status") == "resolved"
            and row.get("selected")
            and row["selected"].get(
                "declared_source", target["source"]
            )
            == target["source"]
            and row["selected"].get(
                "declared_version", target["source_version"]
            )
            == target["source_version"]
        ]
        arch_replace = any(
            row.get("status") == "arch-replace" for row in candidates
        )
        distinct_git = {
            (
                row["selected"].get("repository_full_name"),
                row["selected"].get("commit_sha"),
                row["selected"].get("tree_sha"),
            )
            for row in exact
        }
        packaging_source_status = "unresolved"
        selected: dict[str, Any] | None = None
        if arch_replace:
            packaging_source_status = "arch-replace"
        elif len(distinct_git) == 1:
            packaging_source_status = "exact-locked"
            selected = exact[0]["selected"]
        elif len(distinct_git) > 1:
            packaging_source_status = "ambiguous-exact-lock"

        recovery_blocker = source_recovery.get(key)
        source_status = packaging_source_status
        if recovery_blocker is not None:
            source_status = "source-recovery-required"

        evidence = result_evidence.get(key)
        known = known_success.get(target["source"])
        build_status = "not-required" if role == "reuse-all" else "pending"
        build_evidence: Any = None
        if role == "rebuild-arm64":
            if recovery_blocker is not None:
                build_status = "source-recovery-required"
                build_evidence = {
                    "blocker_file": str(args.source_recovery_blockers),
                    "reason": recovery_blocker.get("reason"),
                    "audit_evidence": recovery_blocker.get("audit_evidence"),
                    "acceptance_gate": recovery_blocker.get(
                        "acceptance_gate"
                    ),
                }
            elif evidence:
                build_evidence = evidence.get("evidence_path")
                build_status = (
                    "passed" if evidence.get("passed") else "failed"
                )
            elif known == "native-arm64-build-passed":
                build_status = "passed-recorded"
                build_evidence = (
                    "arm64/rebuild-batches.json#known_success"
                )
            elif known:
                build_status = "compile-only"
                build_evidence = (
                    "arm64/rebuild-batches.json#known_success"
                )
            elif source_status not in {"exact-locked", "arch-replace"}:
                build_status = "source-blocked"
        elif known:
            build_status = "passed-recorded"
            build_evidence = "arm64/rebuild-batches.json#known_success"

        rows.append(
            {
                "source": target["source"],
                "source_version": target["source_version"],
                "role": role,
                "amd64_binary_packages": amd64_packages,
                "reused_all_packages": all_packages,
                "packaging_source_status": packaging_source_status,
                "source_status": source_status,
                "repository_full_name": (
                    selected.get("repository_full_name") if selected else None
                ),
                "commit_sha": (
                    selected.get("commit_sha") if selected else None
                ),
                "tree_sha": selected.get("tree_sha") if selected else None,
                "build_status": build_status,
                "build_evidence": build_evidence,
                "source_recovery_blocker": recovery_blocker,
            }
        )

    def count(**conditions: str) -> int:
        return sum(
            all(
                row.get(field) == value
                for field, value in conditions.items()
            )
            for row in rows
        )

    native_rows = [
        row for row in rows if row["role"] == "rebuild-arm64"
    ]
    source_blockers = [
        row
        for row in native_rows
        if row["source_status"] not in {"exact-locked", "arch-replace"}
    ]
    build_blockers = [
        row
        for row in native_rows
        if row["build_status"] not in {"passed", "passed-recorded"}
    ]
    source_recovery_rows = [
        row
        for row in native_rows
        if row["source_status"] == "source-recovery-required"
    ]
    failed = [
        row for row in native_rows if row["build_status"] == "failed"
    ]
    pending = [
        row for row in native_rows if row["build_status"] == "pending"
    ]
    compile_only = [
        row
        for row in native_rows
        if row["build_status"] == "compile-only"
    ]

    summary = {
        "schema": 2,
        "policy": (
            "exact-source-and-verified-native-arm64-before-iso-assembly-"
            "including-source-recovery-gates"
        ),
        "custom_source_count": len(rows),
        "reuse_all_source_count": count(role="reuse-all"),
        "native_rebuild_source_count": len(native_rows),
        "exact_packaging_source_locked_count": count(
            packaging_source_status="exact-locked"
        ),
        "exact_buildable_source_locked_count": count(
            source_status="exact-locked"
        ),
        "arch_replace_count": count(source_status="arch-replace"),
        "source_recovery_required_count": len(source_recovery_rows),
        "source_blocker_count": len(source_blockers),
        "native_build_passed_count": sum(
            row["build_status"] in {"passed", "passed-recorded"}
            for row in native_rows
        ),
        "native_build_failed_count": len(failed),
        "native_build_pending_count": len(pending),
        "native_compile_only_count": len(compile_only),
        "native_build_blocker_count": len(build_blockers),
        "package_layer_ready": not source_blockers and not build_blockers,
        "iso_assembly_allowed": not source_blockers and not build_blockers,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "coverage.json").write_text(
        json.dumps(
            {"summary": summary, "sources": rows},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "source-blockers.json").write_text(
        json.dumps(source_blockers, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "build-blockers.json").write_text(
        json.dumps(build_blockers, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "source-recovery-required.json").write_text(
        json.dumps(source_recovery_rows, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )

    with (args.output_dir / "coverage.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        fields = [
            "source",
            "source_version",
            "role",
            "packaging_source_status",
            "source_status",
            "build_status",
            "repository_full_name",
            "commit_sha",
            "tree_sha",
            "amd64_binary_packages",
            "reused_all_packages",
            "source_recovery_reason",
            "build_evidence",
        ]
        writer = csv.DictWriter(
            handle, fieldnames=fields, delimiter="\t"
        )
        writer.writeheader()
        for row in rows:
            serial = dict(row)
            serial["amd64_binary_packages"] = ",".join(
                row["amd64_binary_packages"]
            )
            serial["reused_all_packages"] = ",".join(
                row["reused_all_packages"]
            )
            blocker = row.get("source_recovery_blocker") or {}
            serial["source_recovery_reason"] = blocker.get("reason", "")
            if not isinstance(serial.get("build_evidence"), str):
                serial["build_evidence"] = json.dumps(
                    serial.get("build_evidence"),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            writer.writerow(
                {field: serial.get(field, "") for field in fields}
            )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
