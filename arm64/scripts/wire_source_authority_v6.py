#!/usr/bin/env python3
"""Complete result collection, classification, and Wayback authority chaining."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import wire_source_authority_v5 as base


TOKEN = "${{ github.token }}"
REPOSITORY = "${{ github.repository }}"
REPLACEMENTS = {
    "arm64/scripts/collect_native_rebuild_results.py": "arm64/scripts/collect_native_rebuild_results_v3.py",
    "arm64/scripts/collect_native_rebuild_results_v2.py": "arm64/scripts/collect_native_rebuild_results_v3.py",
    "arm64/scripts/classify_native_rebuild_failures.py": "arm64/scripts/classify_native_rebuild_failures_v3.py",
    "arm64/scripts/classify_native_rebuild_failures_v2.py": "arm64/scripts/classify_native_rebuild_failures_v3.py",
}


def ensure_actions_write(text: str) -> str:
    match = re.search(r"(?m)^permissions:\n((?:  [^\n]+\n)+)", text)
    if not match:
        return text
    lines = match.group(1).splitlines()
    output = []
    found = False
    for line in lines:
        if line.startswith("  actions:"):
            output.append("  actions: write")
            found = True
        else:
            output.append(line)
    if not found:
        output.append("  actions: write")
    replacement = "permissions:\n" + "\n".join(output) + "\n"
    return text[: match.start()] + replacement + text[match.end() :]


def replace(path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    for old, new in REPLACEMENTS.items():
        text = text.replace(old, new)
    text = re.sub(
        r"(?m)^(\s+GH_TOKEN:)\s+.*$",
        lambda match: f"{match.group(1)} {TOKEN}",
        text,
    )
    path.write_text(text, encoding="utf-8")


def append_wayback_dispatch(workflow_dir: Path) -> None:
    path = workflow_dir / "arm64-wayback-source-recovery.yml"
    if not path.exists():
        raise FileNotFoundError(path)
    text = ensure_actions_write(path.read_text(encoding="utf-8"))
    marker = "Dispatch merged source authority after Wayback release lock"
    if marker not in text:
        step = f"""
      - name: {marker}
        if: always()
        env:
          GH_TOKEN: {TOKEN}
        shell: bash
        run: |
          set -euxo pipefail
          test -f work/wayback-source-lock/wayback-source-release-lock.json
          for attempt in 1 2 3 4; do
            if gh workflow run arm64-source-authority-v3.yml \\
              --repo '{REPOSITORY}' \\
              --ref arm64-port; then
              exit 0
            fi
            sleep $((attempt * 5))
          done
          exit 1
"""
        text = text.rstrip() + "\n\n" + step.strip("\n") + "\n"
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.repository_root
    workflow_dir = root / ".github/workflows"

    # Apply all previous source/build/publish/acquisition hardening first.
    base.main_impl(root) if hasattr(base, "main_impl") else None
    # v5 exposes no main_impl, so reproduce its deterministic public helpers.
    base.base.base.patch_workflows(workflow_dir)
    base.base.base.append_keyring_dispatch(workflow_dir)
    base.base.base.guard_source_authority_dispatch(workflow_dir)
    base.base.base.patch_python_control_files(root)
    for path in sorted(workflow_dir.glob("*.yml")):
        base.base.replace_all(path)
    for path in (
        root / "arm64/scripts/wire_progress_dispatches.py",
        root / "arm64/scripts/audit_active_arm64_pipeline.py",
        root / "arm64/scripts/summarize_arm64_ci_state.py",
    ):
        base.base.replace_all(path)
    for path in sorted(workflow_dir.glob("*.yml")):
        base.replace(path)
    for path in (
        root / "arm64/scripts/wire_progress_dispatches.py",
        root / "arm64/scripts/audit_active_arm64_pipeline.py",
    ):
        base.replace(path)

    for path in sorted(workflow_dir.glob("*.yml")):
        replace(path)
    for path in (
        root / "arm64/scripts/wire_progress_dispatches.py",
        root / "arm64/scripts/audit_active_arm64_pipeline.py",
    ):
        replace(path)
    append_wayback_dispatch(workflow_dir)

    audit = root / "arm64/scripts/audit_active_arm64_pipeline.py"
    if audit.exists():
        text = audit.read_text(encoding="utf-8")
        for required in (
            '    "arm64/scripts/collect_native_rebuild_results_v3.py",\n',
            '    "arm64/scripts/classify_native_rebuild_failures_v3.py",\n',
        ):
            if required.strip() not in text:
                text = text.replace(
                    "REQUIRED_SCRIPTS = {\n",
                    "REQUIRED_SCRIPTS = {\n" + required,
                    1,
                )
        audit.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
