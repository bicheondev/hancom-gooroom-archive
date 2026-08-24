#!/usr/bin/env python3
"""Summarize latest ARM64 workflow runs and committed phase gates."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


GATE_FILES = {
    "pipeline_lint": "arm64/audit/pipeline-lint/summary.json",
    "active_pipeline": "arm64/audit/active-pipeline/summary.json",
    "workflow_secrets": "arm64/audit/workflow-secrets/summary.json",
    "coverage": "arm64/status/summary.json",
    "rebuild_failures": "arm64/status/rebuild-failures/summary.json",
    "normalized_package_map": "arm64/locks/package-plan/summary.json",
    "rebuild_release": "arm64/locks/rebuild-release/summary.json",
    "acquisition_plan": "arm64/locks/acquisition-plan/summary.json",
    "rootfs": "arm64/locks/rootfs/verification.json",
    "iso_release": "arm64/locks/iso/release-lock.json",
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def gate_value(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "path": str(path)}
    try:
        document = load_json(path)
    except Exception as exception:
        return {
            "exists": True,
            "path": str(path),
            "parse_error": f"{type(exception).__name__}: {exception}",
        }
    summary = document.get("summary") if isinstance(document.get("summary"), dict) else document
    keys = (
        "passed",
        "complete",
        "build_allowed",
        "ready",
        "ready_for_fetch",
        "repository_ready",
        "package_layer_ready",
        "iso_assembly_allowed",
        "qemu_booted",
        "blocker_count",
        "source_blocker_count",
        "native_build_blocker_count",
        "failed_count",
        "dependency_resolution_failure_count",
        "resolved_count",
        "unresolved_count",
        "verified_deb_count",
        "release_tag",
        "actions_run_id",
        "actions_run_url",
    )
    return {
        "exists": True,
        "path": str(path),
        "values": {key: summary.get(key) for key in keys if key in summary},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflows", type=Path, required=True)
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    workflows_document = load_json(args.workflows)
    runs_document = load_json(args.runs)
    workflows = {
        int(row["id"]): row
        for row in workflows_document.get("workflows", [])
        if row.get("id") is not None
        and (
            str(row.get("path", "")).startswith(".github/workflows/arm64")
            or str(row.get("path", "")).endswith("inventory-v3.3-amd64.yml")
        )
    }

    latest_by_workflow: dict[int, dict[str, Any]] = {}
    for run in runs_document.get("workflow_runs", []):
        workflow_id = run.get("workflow_id")
        if workflow_id not in workflows:
            continue
        existing = latest_by_workflow.get(workflow_id)
        if existing is None or str(run.get("created_at", "")) > str(
            existing.get("created_at", "")
        ):
            latest_by_workflow[workflow_id] = run

    workflow_rows: list[dict[str, Any]] = []
    for workflow_id, workflow in sorted(
        workflows.items(), key=lambda item: str(item[1].get("name", ""))
    ):
        run = latest_by_workflow.get(workflow_id)
        workflow_rows.append(
            {
                "workflow_id": workflow_id,
                "name": workflow.get("name"),
                "path": workflow.get("path"),
                "state": workflow.get("state"),
                "latest_run": (
                    {
                        "id": run.get("id"),
                        "run_number": run.get("run_number"),
                        "event": run.get("event"),
                        "status": run.get("status"),
                        "conclusion": run.get("conclusion"),
                        "head_sha": run.get("head_sha"),
                        "created_at": run.get("created_at"),
                        "updated_at": run.get("updated_at"),
                        "html_url": run.get("html_url"),
                        "display_title": run.get("display_title"),
                    }
                    if run
                    else None
                ),
            }
        )

    status_counts = Counter(
        (row.get("latest_run") or {}).get("status", "no-run")
        for row in workflow_rows
    )
    conclusion_counts = Counter(
        (row.get("latest_run") or {}).get("conclusion") or "none"
        for row in workflow_rows
    )
    gates = {
        name: gate_value(args.repository_root / relative)
        for name, relative in GATE_FILES.items()
    }

    rootfs_ready = bool(
        gates["rootfs"].get("values", {}).get("passed") is True
    )
    iso_ready = bool(
        gates["iso_release"].get("values", {}).get("qemu_booted") is True
    )
    acquisition_ready = bool(
        gates["acquisition_plan"].get("values", {}).get("ready_for_fetch")
        is True
    )
    summary = {
        "schema": 1,
        "generated_at": args.generated_at,
        "branch": "arm64-port",
        "head_sha": args.head_sha,
        "active_arm64_workflow_count": len(workflow_rows),
        "latest_run_status_counts": dict(sorted(status_counts.items())),
        "latest_run_conclusion_counts": dict(sorted(conclusion_counts.items())),
        "acquisition_ready": acquisition_ready,
        "rootfs_ready": rootfs_ready,
        "qemu_booted_iso_ready": iso_ready,
        "highest_completed_phase": (
            "qemu-booted-iso"
            if iso_ready
            else "verified-rootfs"
            if rootfs_ready
            else "exact-package-acquisition"
            if acquisition_ready
            else "source-and-package-rebuilds"
        ),
    }
    result = {
        "summary": summary,
        "workflows": workflow_rows,
        "gates": gates,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "ci-state.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
