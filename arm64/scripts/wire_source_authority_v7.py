#!/usr/bin/env python3
"""Idempotently apply the complete signed-DSC ARM64 pipeline integration."""

from __future__ import annotations

import argparse
from pathlib import Path

import wire_source_authority_v3 as w3
import wire_source_authority_v4 as w4
import wire_source_authority_v5 as w5
import wire_source_authority_v6 as w6


def add_required_script(audit: Path, value: str) -> None:
    if not audit.exists():
        return
    text = audit.read_text(encoding="utf-8")
    line = f'    "{value}",\n'
    if f'"{value}"' not in text:
        text = text.replace("REQUIRED_SCRIPTS = {\n", "REQUIRED_SCRIPTS = {\n" + line, 1)
    audit.write_text(text, encoding="utf-8")


def add_required_workflow(audit: Path, value: str) -> None:
    if not audit.exists():
        return
    text = audit.read_text(encoding="utf-8")
    line = f'    "{value}",\n'
    if f'"{value}"' not in text:
        text = text.replace("REQUIRED_WORKFLOWS = {\n", "REQUIRED_WORKFLOWS = {\n" + line, 1)
    audit.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.repository_root
    workflows = root / ".github/workflows"

    w3.patch_workflows(workflows)
    w3.append_keyring_dispatch(workflows)
    w3.guard_source_authority_dispatch(workflows)
    w3.patch_python_control_files(root)

    for path in sorted(workflows.glob("*.yml")):
        w4.replace_all(path)
    for path in (
        root / "arm64/scripts/wire_progress_dispatches.py",
        root / "arm64/scripts/audit_active_arm64_pipeline.py",
        root / "arm64/scripts/summarize_arm64_ci_state.py",
    ):
        w4.replace_all(path)

    for path in sorted(workflows.glob("*.yml")):
        w5.replace(path)
    for path in (
        root / "arm64/scripts/wire_progress_dispatches.py",
        root / "arm64/scripts/audit_active_arm64_pipeline.py",
    ):
        w5.replace(path)

    for path in sorted(workflows.glob("*.yml")):
        w6.replace(path)
    for path in (
        root / "arm64/scripts/wire_progress_dispatches.py",
        root / "arm64/scripts/audit_active_arm64_pipeline.py",
    ):
        w6.replace(path)
    w6.append_wayback_dispatch(workflows)

    audit = root / "arm64/scripts/audit_active_arm64_pipeline.py"
    for workflow in (
        "arm64-source-authority-v3.yml",
        "arm64-publish-rebuild-packages-v3.yml",
        "arm64-source-keyring-lock.yml",
        "arm64-wayback-source-recovery.yml",
    ):
        add_required_workflow(audit, workflow)
    for script in (
        "arm64/scripts/build_locked_source_arm64_v5.sh",
        "arm64/scripts/build_locked_dsc_source_arm64_v2.sh",
        "arm64/scripts/verify_arm64_rebuild_v3.py",
        "arm64/scripts/verify_arm64_dsc_rebuild.py",
        "arm64/scripts/collect_native_rebuild_results_v3.py",
        "arm64/scripts/classify_native_rebuild_failures_v3.py",
        "arm64/scripts/publish_rebuild_packages_v4.py",
        "arm64/scripts/build_package_acquisition_plan_v3.py",
        "arm64/scripts/merge_exact_source_authority_v3.py",
    ):
        add_required_script(audit, script)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
