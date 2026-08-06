#!/usr/bin/env python3
"""Apply the final hardened Git/DSC build and persistent publisher wiring."""

from __future__ import annotations

import argparse
from pathlib import Path

import wire_source_authority_v4 as base


REPLACEMENTS = {
    "arm64/scripts/build_locked_source_arm64_v4.sh": "arm64/scripts/build_locked_source_arm64_v5.sh",
    "arm64/scripts/build_locked_dsc_source_arm64.sh": "arm64/scripts/build_locked_dsc_source_arm64_v2.sh",
    "arm64/scripts/publish_rebuild_packages_v3.py": "arm64/scripts/publish_rebuild_packages_v4.py",
}


def replace(path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    for old, new in REPLACEMENTS.items():
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.repository_root

    # Run the complete v4 wiring first, then upgrade the exact components whose
    # hardening is intentionally implemented as thin compatibility layers.
    workflow_dir = root / ".github/workflows"
    base.base.patch_workflows(workflow_dir)
    base.base.append_keyring_dispatch(workflow_dir)
    base.base.guard_source_authority_dispatch(workflow_dir)
    base.base.patch_python_control_files(root)
    for path in sorted(workflow_dir.glob("*.yml")):
        base.replace_all(path)
    for path in (
        root / "arm64/scripts/wire_progress_dispatches.py",
        root / "arm64/scripts/audit_active_arm64_pipeline.py",
        root / "arm64/scripts/summarize_arm64_ci_state.py",
    ):
        base.replace_all(path)

    for path in sorted(workflow_dir.glob("*.yml")):
        replace(path)
    for path in (
        root / "arm64/scripts/wire_progress_dispatches.py",
        root / "arm64/scripts/audit_active_arm64_pipeline.py",
    ):
        replace(path)

    audit = root / "arm64/scripts/audit_active_arm64_pipeline.py"
    if audit.exists():
        text = audit.read_text(encoding="utf-8")
        for required in (
            '    "arm64/scripts/build_locked_source_arm64_v5.sh",\n',
            '    "arm64/scripts/build_locked_dsc_source_arm64_v2.sh",\n',
            '    "arm64/scripts/publish_rebuild_packages_v4.py",\n',
        ):
            if required.strip() not in text:
                text = text.replace("REQUIRED_SCRIPTS = {\n", "REQUIRED_SCRIPTS = {\n" + required, 1)
        audit.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
