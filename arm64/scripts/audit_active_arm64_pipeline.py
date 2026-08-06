#!/usr/bin/env python3
"""Audit the active ARM64 workflow/script graph after one-shot maintenance.

This audit is intentionally independent of GitHub's workflow API. It examines
what the `arm64-port` branch would execute, rejects superseded v1 paths and
moving action tags, and records referenced local scripts that no longer exist.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml


REQUIRED_WORKFLOWS = {
    "arm64-inventory.yml",
    "arm64-debian-map.yml",
    "arm64-source-lock.yml",
    "arm64-baseline-rebuild-evidence.yml",
    "arm64-native-rebuild-batch-v2.yml",
    "arm64-native-rebuild-backlog.yml",
    "arm64-dependency-retry-v2.yml",
    "arm64-publish-rebuild-packages.yml",
    "arm64-normalize-package-map.yml",
    "arm64-package-acquisition-plan-v2.yml",
    "arm64-exact-rootfs-v2.yml",
    "arm64-final-live-iso.yml",
    "arm64-port-coverage.yml",
    "arm64-pipeline-lint.yml",
}
SUPERSEDED_WORKFLOWS = {
    "arm64-native-rebuild-batch.yml",
    "arm64-exact-rootfs.yml",
    "arm64-package-acquisition-plan.yml",
    "arm64-dependency-retry.yml",
    "arm64-package-smoke.yml",
}
SUPERSEDED_SCRIPTS = {
    "arm64/scripts/build_locked_source_arm64.sh",
    "arm64/scripts/finalize_arm64_live_rootfs.sh",
    "arm64/scripts/build_package_acquisition_plan.py",
    "arm64/scripts/prepare_rebuild_release_assets.py",
    "arm64/scripts/collect_native_rebuild_results.py",
}
REQUIRED_SCRIPTS = {
    "arm64/scripts/build_locked_source_arm64_v2.sh",
    "arm64/scripts/collect_native_rebuild_results_v2.py",
    "arm64/scripts/build_package_acquisition_plan_v2.py",
    "arm64/scripts/materialize_package_acquisition_plan_v2.py",
    "arm64/scripts/finalize_arm64_live_rootfs_v2.sh",
    "arm64/scripts/build_arm64_live_iso.sh",
    "arm64/scripts/test_arm64_iso_qemu.sh",
}
LOCAL_PATH_RE = re.compile(r"(?<![A-Za-z0-9_./-])(arm64/[A-Za-z0-9_./+-]+\.(?:py|sh|json))")
ACTION_RE = re.compile(r"^([^\s]+/[^\s]+)@([^\s]+)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def workflow_on(document: dict[str, Any]) -> Any:
    # PyYAML 1.1 treats the unquoted key `on` as boolean True.
    return document.get("on", document.get(True))


def normalize_on(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return sorted(str(item) for item in value)
    if isinstance(value, dict):
        return sorted(str(key) for key in value)
    return []


def collect_uses(value: Any, output: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "uses" and isinstance(child, str):
                output.append(child)
            collect_uses(child, output)
    elif isinstance(value, list):
        for child in value:
            collect_uses(child, output)


def collect_run_text(value: Any, output: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "run" and isinstance(child, str):
                output.append(child)
            collect_run_text(child, output)
    elif isinstance(value, list):
        for child in value:
            collect_run_text(child, output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    root = args.repository_root.resolve()
    workflow_dir = root / ".github/workflows"
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    workflows: list[dict[str, Any]] = []
    names: dict[str, list[str]] = defaultdict(list)
    local_references: dict[str, list[str]] = defaultdict(list)

    for path in sorted(workflow_dir.glob("*.yml")):
        relative = str(path.relative_to(root))
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exception:
            errors.append(
                {
                    "path": relative,
                    "reason": "yaml-parse-failed",
                    "error": f"{type(exception).__name__}: {exception}",
                }
            )
            continue
        if not isinstance(document, dict):
            errors.append({"path": relative, "reason": "workflow-not-a-mapping"})
            continue

        name = document.get("name")
        jobs = document.get("jobs")
        if not isinstance(name, str) or not name.strip():
            errors.append({"path": relative, "reason": "workflow-name-missing"})
            name = ""
        else:
            names[name].append(relative)
        if not isinstance(jobs, dict) or not jobs:
            errors.append({"path": relative, "reason": "workflow-jobs-missing"})

        uses: list[str] = []
        run_texts: list[str] = []
        collect_uses(document, uses)
        collect_run_text(document, run_texts)
        unpinned_actions: list[str] = []
        for action in uses:
            if action.startswith("./"):
                continue
            match = ACTION_RE.fullmatch(action)
            if match and not SHA_RE.fullmatch(match.group(2)):
                unpinned_actions.append(action)
        if unpinned_actions:
            errors.append(
                {
                    "path": relative,
                    "reason": "moving-or-non-sha-action-reference",
                    "actions": sorted(set(unpinned_actions)),
                }
            )

        referenced = sorted(
            {
                match.group(1).rstrip("'\"),;:")
                for text in run_texts
                for match in LOCAL_PATH_RE.finditer(text)
            }
        )
        for local_path in referenced:
            local_references[local_path].append(relative)
            if not (root / local_path).exists():
                errors.append(
                    {
                        "path": relative,
                        "reason": "referenced-local-file-missing",
                        "local_path": local_path,
                    }
                )

        filename = path.name
        if "maintenance" in filename:
            errors.append(
                {
                    "path": relative,
                    "reason": "one-shot-maintenance-workflow-still-active",
                }
            )
        workflows.append(
            {
                "filename": filename,
                "path": relative,
                "name": name,
                "events": normalize_on(workflow_on(document)),
                "job_count": len(jobs) if isinstance(jobs, dict) else 0,
                "uses": uses,
                "referenced_local_files": referenced,
            }
        )

    for name, paths in sorted(names.items()):
        if len(paths) > 1:
            errors.append(
                {
                    "reason": "duplicate-workflow-name",
                    "name": name,
                    "paths": paths,
                }
            )

    existing_workflows = {path.name for path in workflow_dir.glob("*.yml")}
    for filename in sorted(REQUIRED_WORKFLOWS - existing_workflows):
        errors.append(
            {
                "path": f".github/workflows/{filename}",
                "reason": "required-workflow-missing",
            }
        )
    for filename in sorted(SUPERSEDED_WORKFLOWS & existing_workflows):
        errors.append(
            {
                "path": f".github/workflows/{filename}",
                "reason": "superseded-workflow-still-present",
            }
        )
    for relative in sorted(REQUIRED_SCRIPTS):
        if not (root / relative).exists():
            errors.append({"path": relative, "reason": "required-script-missing"})
    for relative in sorted(SUPERSEDED_SCRIPTS):
        if (root / relative).exists():
            errors.append({"path": relative, "reason": "superseded-script-still-present"})

    # A required script should be referenced by at least one active workflow;
    # otherwise the file can silently bit-rot without a CI execution path.
    for relative in sorted(REQUIRED_SCRIPTS):
        if (root / relative).exists() and relative not in local_references:
            warnings.append(
                {
                    "path": relative,
                    "reason": "required-script-not-referenced-by-workflow-run-block",
                }
            )

    summary = {
        "schema": 1,
        "policy": "single-v2-path-no-moving-actions-no-maintenance-workflows",
        "workflow_count": len(workflows),
        "workflow_name_count": len(names),
        "referenced_local_file_count": len(local_references),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "passed": not errors,
    }
    result = {
        "summary": summary,
        "workflows": workflows,
        "local_references": dict(sorted(local_references.items())),
        "errors": errors,
        "warnings": warnings,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "active-pipeline.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "errors.json").write_text(
        json.dumps(errors, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
