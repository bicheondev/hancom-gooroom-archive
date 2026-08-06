#!/usr/bin/env python3
"""Finalize source-authority v3, persistent publisher v3, and acquisition v3 wiring."""

from __future__ import annotations

import argparse
from pathlib import Path

import wire_source_authority_v3 as base


EXTRA_REPLACEMENTS = {
    "arm64-publish-rebuild-packages.yml": "arm64-publish-rebuild-packages-v3.yml",
    "arm64/scripts/prepare_rebuild_release_assets.py": "arm64/scripts/publish_rebuild_packages_v3.py",
    "arm64/scripts/prepare_rebuild_release_assets_v2.py": "arm64/scripts/publish_rebuild_packages_v3.py",
    "arm64/scripts/build_package_acquisition_plan.py": "arm64/scripts/build_package_acquisition_plan_v3.py",
    "arm64/scripts/build_package_acquisition_plan_v2.py": "arm64/scripts/build_package_acquisition_plan_v3.py",
}


def replace_all(path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    for old, new in EXTRA_REPLACEMENTS.items():
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.repository_root
    workflow_dir = root / ".github/workflows"

    base.patch_workflows(workflow_dir)
    base.append_keyring_dispatch(workflow_dir)
    base.guard_source_authority_dispatch(workflow_dir)
    base.patch_python_control_files(root)

    for path in sorted(workflow_dir.glob("*.yml")):
        replace_all(path)
    for path in (
        root / "arm64/scripts/wire_progress_dispatches.py",
        root / "arm64/scripts/audit_active_arm64_pipeline.py",
        root / "arm64/scripts/summarize_arm64_ci_state.py",
    ):
        replace_all(path)

    audit = root / "arm64/scripts/audit_active_arm64_pipeline.py"
    if audit.exists():
        text = audit.read_text(encoding="utf-8")
        if '"arm64-publish-rebuild-packages-v3.yml"' not in text:
            text = text.replace(
                '    "arm64-publish-rebuild-packages.yml",\n',
                '    "arm64-publish-rebuild-packages-v3.yml",\n',
            )
        if '"arm64/scripts/build_package_acquisition_plan_v3.py"' not in text:
            text = text.replace(
                '    "arm64/scripts/build_package_acquisition_plan_v2.py",\n',
                '    "arm64/scripts/build_package_acquisition_plan_v3.py",\n',
            )
        audit.write_text(text, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
