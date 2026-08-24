#!/usr/bin/env python3
"""Wire exact signed-DSC source authority through every native build path."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


TOKEN = "${{ github.token }}"
REPOSITORY = "${{ github.repository }}"


WORKFLOW_REPLACEMENTS = {
    "arm64/scripts/build_locked_source_arm64.sh": "arm64/scripts/build_locked_source_arm64_v4.sh",
    "arm64/scripts/build_locked_source_arm64_v2.sh": "arm64/scripts/build_locked_source_arm64_v4.sh",
    "arm64/scripts/build_locked_source_arm64_v3.sh": "arm64/scripts/build_locked_source_arm64_v4.sh",
    "arm64/scripts/verify_arm64_rebuild.py": "arm64/scripts/verify_arm64_rebuild_v3.py",
    "arm64/scripts/select_native_rebuild_batch.py": "arm64/scripts/select_native_rebuild_batch_v3.py",
    "arm64/scripts/select_next_native_rebuild_wave.py": "arm64/scripts/select_next_native_rebuild_wave_v3.py",
    "arm64/scripts/select_baseline_reverification.py": "arm64/scripts/select_baseline_reverification_v3.py",
    "arm64/scripts/select_dependency_retry_wave.py": "arm64/scripts/select_dependency_retry_wave_v3.py",
    "arm64/scripts/classify_native_rebuild_failures.py": "arm64/scripts/classify_native_rebuild_failures_v2.py",
    "arm64/locks/effective-sources/effective-source-lock.json": "arm64/locks/effective-sources-v3/effective-source-lock.json",
    "arm64-effective-source-lock.yml": "arm64-source-authority-v3.yml",
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


def sanitize_token_lines(text: str) -> str:
    return re.sub(
        r"(?m)^(\s+GH_TOKEN:)\s+.*$",
        lambda match: f"{match.group(1)} {TOKEN}",
        text,
    )


def patch_workflows(workflow_dir: Path) -> None:
    for path in sorted(workflow_dir.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for old, new in WORKFLOW_REPLACEMENTS.items():
            text = text.replace(old, new)
        text = text.replace(
            "git jq dpkg-dev ca-certificates python3 coreutils",
            "git curl gnupg gpgv jq dpkg-dev ca-certificates python3 coreutils",
        )
        text = text.replace(
            "git jq dpkg-dev ca-certificates",
            "git curl gnupg gpgv jq dpkg-dev ca-certificates",
        )
        text = text.replace(
            "git jq dpkg-dev",
            "git curl gnupg gpgv jq dpkg-dev",
        )
        text = sanitize_token_lines(text)
        path.write_text(text, encoding="utf-8")


def append_keyring_dispatch(workflow_dir: Path) -> None:
    path = workflow_dir / "arm64-source-keyring-lock.yml"
    if not path.exists():
        raise FileNotFoundError(path)
    text = sanitize_token_lines(ensure_actions_write(path.read_text(encoding="utf-8")))
    marker = "Dispatch source authority after public key lock"
    if marker not in text:
        step = f"""
      - name: {marker}
        if: always()
        env:
          GH_TOKEN: {TOKEN}
        shell: bash
        run: |
          set -euxo pipefail
          test -f arm64/keys/source-signing/gooroom-archive-public-keys.asc
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


def guard_source_authority_dispatch(workflow_dir: Path) -> None:
    path = workflow_dir / "arm64-source-authority-v3.yml"
    if not path.exists():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8")
    needle = "          test -f work/source-authority-v3/effective-source-lock.json\n"
    guard = """          test -f work/source-authority-v3/effective-source-lock.json
          signed_count="$(jq -r '.signed_dsc_resolved_count // 0' \\
            work/source-authority-v3/effective-source-lock-summary.json)"
          if [ "$signed_count" -gt 0 ] \\
             && [ ! -f arm64/keys/source-signing/gooroom-archive-public-keys.asc ]; then
            echo 'Signed DSC sources are locked, but the reference-ISO public key bundle is not committed yet.' >&2
            exit 0
          fi
"""
    if "Signed DSC sources are locked, but" not in text:
        if needle not in text:
            raise RuntimeError("source authority dispatch marker is missing")
        text = text.replace(needle, guard, 1)
    path.write_text(text, encoding="utf-8")


def patch_python_control_files(repository_root: Path) -> None:
    progress = repository_root / "arm64/scripts/wire_progress_dispatches.py"
    if progress.exists():
        text = progress.read_text(encoding="utf-8")
        for old, new in WORKFLOW_REPLACEMENTS.items():
            text = text.replace(old, new)
        progress.write_text(text, encoding="utf-8")

    summary = repository_root / "arm64/scripts/summarize_arm64_ci_state.py"
    if summary.exists():
        text = summary.read_text(encoding="utf-8")
        if '"source_authority_v3"' not in text:
            marker = 'GATE_FILES = {\n'
            text = text.replace(
                marker,
                marker
                + '    "source_authority_v3": "arm64/locks/effective-sources-v3/effective-source-lock-summary.json",\n',
                1,
            )
        summary.write_text(text, encoding="utf-8")

    audit = repository_root / "arm64/scripts/audit_active_arm64_pipeline.py"
    if audit.exists():
        text = audit.read_text(encoding="utf-8")
        if '"arm64-source-authority-v3.yml"' not in text:
            text = text.replace(
                '    "arm64-source-lock.yml",\n',
                '    "arm64-source-lock.yml",\n    "arm64-source-authority-v3.yml",\n',
                1,
            )
        additions = (
            '    "arm64/scripts/build_locked_source_arm64_v4.sh",\n'
            '    "arm64/scripts/build_locked_dsc_source_arm64.sh",\n'
            '    "arm64/scripts/verify_arm64_rebuild_v3.py",\n'
            '    "arm64/scripts/verify_arm64_dsc_rebuild.py",\n'
        )
        if '"arm64/scripts/build_locked_source_arm64_v4.sh"' not in text:
            text = text.replace(
                'REQUIRED_SCRIPTS = {\n',
                'REQUIRED_SCRIPTS = {\n' + additions,
                1,
            )
        audit.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.repository_root
    workflow_dir = root / ".github/workflows"
    patch_workflows(workflow_dir)
    append_keyring_dispatch(workflow_dir)
    guard_source_authority_dispatch(workflow_dir)
    patch_python_control_files(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
