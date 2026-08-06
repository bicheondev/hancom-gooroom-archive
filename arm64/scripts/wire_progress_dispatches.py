#!/usr/bin/env python3
"""Wire explicit workflow_dispatch progress edges without embedding secrets.

This script is stored outside workflow YAML so literal GitHub expressions are
not evaluated while the maintenance workflow runs. It also sanitizes every
existing GH_TOKEN line, repairing a partially applied earlier maintenance run.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


TOKEN_EXPRESSION = "${{ github.token }}"
REPOSITORY_EXPRESSION = "${{ github.repository }}"


def ensure_actions_write(text: str) -> str:
    match = re.search(r"(?m)^permissions:\n((?:  [^\n]+\n)+)", text)
    if not match:
        raise RuntimeError("workflow has no permissions block")
    block = match.group(1)
    lines = block.splitlines()
    output: list[str] = []
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
        lambda match: f"{match.group(1)} {TOKEN_EXPRESSION}",
        text,
    )


def dispatch_function() -> str:
    return f"""          dispatch() {{
            local workflow=\"$1\"
            shift
            for attempt in 1 2 3 4; do
              if gh workflow run \"$workflow\" \\
                --repo '{REPOSITORY_EXPRESSION}' \\
                --ref arm64-port \"$@\"; then
                return 0
              fi
              sleep $((attempt * 5))
            done
            return 1
          }}
"""


def append_step(workflow_dir: Path, filename: str, marker: str, step: str) -> None:
    path = workflow_dir / filename
    if not path.exists():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8")
    text = sanitize_token_lines(ensure_actions_write(text))
    if marker not in text:
        text = text.rstrip() + "\n\n" + step.strip("\n") + "\n"
    path.write_text(text, encoding="utf-8")


def env_header(name: str, condition: str = "always()") -> str:
    return f"""      - name: {name}
        if: {condition}
        env:
          GH_TOKEN: {TOKEN_EXPRESSION}
        shell: bash
        run: |
          set -euxo pipefail
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workflow-dir", type=Path, default=Path(".github/workflows")
    )
    args = parser.parse_args()
    workflow_dir = args.workflow_dir
    dispatch = dispatch_function()

    append_step(
        workflow_dir,
        "arm64-native-rebuild-backlog.yml",
        "Continue the unattempted rebuild backlog explicitly",
        env_header("Continue the unattempted rebuild backlog explicitly")
        + dispatch
        + """          passed=0
          if [ -f work/rebuild-results/summary.json ]; then
            passed="$(jq -r '.passed_count // 0' work/rebuild-results/summary.json)"
          fi
          if [ "$passed" -gt 0 ]; then
            dispatch arm64-publish-rebuild-packages.yml
          fi
          git fetch origin arm64-port
          git reset --hard origin/arm64-port
          lock=arm64/locks/sources-api-baseline/source-lock.json
          if [ -f arm64/locks/effective-sources/effective-source-lock.json ]; then
            lock=arm64/locks/effective-sources/effective-source-lock.json
          fi
          python3 arm64/scripts/select_next_native_rebuild_wave.py \\
            --lock "$lock" \\
            --reference arm64/locks/reference/amd64-reference.json \\
            --plan arm64/rebuild-batches.json \\
            --results arm64/locks/rebuild-results \\
            --limit 6 \\
            --output work/next-native-rebuild-wave.json
          if [ "$(jq -r '.summary.selected_count' work/next-native-rebuild-wave.json)" -gt 0 ]; then
            dispatch arm64-native-rebuild-backlog.yml -f limit=6
          fi
          dispatch arm64-port-coverage.yml || true
""",
    )

    append_step(
        workflow_dir,
        "arm64-baseline-rebuild-evidence.yml",
        "Publish newly reverified baseline packages explicitly",
        env_header("Publish newly reverified baseline packages explicitly")
        + dispatch
        + """          if [ -f work/rebuild-results/summary.json ] \\
             && [ "$(jq -r '.passed_count // 0' work/rebuild-results/summary.json)" -gt 0 ]; then
            dispatch arm64-publish-rebuild-packages.yml
          fi
          dispatch arm64-port-coverage.yml || true
""",
    )

    append_step(
        workflow_dir,
        "arm64-native-rebuild-batch-v2.yml",
        "Publish newly completed curated batch packages explicitly",
        env_header("Publish newly completed curated batch packages explicitly")
        + dispatch
        + """          if [ -f work/rebuild-results/summary.json ] \\
             && [ "$(jq -r '.passed_count // 0' work/rebuild-results/summary.json)" -gt 0 ]; then
            dispatch arm64-publish-rebuild-packages.yml
          fi
          dispatch arm64-port-coverage.yml || true
""",
    )

    append_step(
        workflow_dir,
        "arm64-dependency-retry-v2.yml",
        "Publish packages recovered by dependency retries explicitly",
        env_header("Publish packages recovered by dependency retries explicitly")
        + dispatch
        + """          if [ -f work/rebuild-results/summary.json ] \\
             && [ "$(jq -r '.passed_count // 0' work/rebuild-results/summary.json)" -gt 0 ]; then
            dispatch arm64-publish-rebuild-packages.yml
          fi
          dispatch arm64-port-coverage.yml || true
""",
    )

    append_step(
        workflow_dir,
        "arm64-publish-rebuild-packages.yml",
        "Dispatch package-cache consumers explicitly",
        env_header("Dispatch package-cache consumers explicitly")
        + dispatch
        + """          if [ -f work/rebuild-release/summary.json ] \\
             && jq -e '.complete == true' work/rebuild-release/summary.json >/dev/null; then
            dispatch arm64-dependency-retry-v2.yml -f limit=4
            dispatch arm64-package-acquisition-plan-v2.yml
          fi
          dispatch arm64-port-coverage.yml || true
""",
    )

    append_step(
        workflow_dir,
        "arm64-package-acquisition-plan-v2.yml",
        "Dispatch exact rootfs construction explicitly when ready",
        env_header("Dispatch exact rootfs construction explicitly when ready")
        + dispatch
        + """          if [ -f work/acquisition-plan/summary.json ] \\
             && jq -e '.ready_for_fetch == true' work/acquisition-plan/summary.json >/dev/null; then
            dispatch arm64-exact-rootfs-v2.yml
          fi
""",
    )

    append_step(
        workflow_dir,
        "arm64-exact-rootfs-v2.yml",
        "Dispatch final ISO construction explicitly after rootfs lock",
        env_header(
            "Dispatch final ISO construction explicitly after rootfs lock",
            "success()",
        )
        + dispatch
        + """          jq -e '.summary.passed == true' work/rootfs-evidence/verification.json
          test -f work/rootfs-evidence/artifact-lock.json
          dispatch arm64-final-live-iso.yml
""",
    )

    append_step(
        workflow_dir,
        "arm64-normalize-package-map.yml",
        "Dispatch acquisition planning after map normalization",
        env_header("Dispatch acquisition planning after map normalization")
        + dispatch
        + """          if [ -f work/normalized-package-map/summary.json ] \\
             && jq -e '.complete == true' work/normalized-package-map/summary.json >/dev/null; then
            dispatch arm64-package-acquisition-plan-v2.yml
          fi
""",
    )

    append_step(
        workflow_dir,
        "arm64-source-lock.yml",
        "Dispatch effective source authority merge explicitly",
        env_header("Dispatch effective source authority merge explicitly")
        + dispatch
        + """          if [ -f work/source-lock/source-lock.json ]; then
            dispatch arm64-effective-source-lock.yml
          fi
""",
    )

    append_step(
        workflow_dir,
        "arm64-effective-source-lock.yml",
        "Dispatch exact source consumers explicitly",
        env_header("Dispatch exact source consumers explicitly")
        + dispatch
        + """          if [ -f work/effective-source-lock/effective-source-lock.json ]; then
            dispatch arm64-baseline-rebuild-evidence.yml
            dispatch arm64-native-rebuild-backlog.yml -f limit=6
            dispatch arm64-port-coverage.yml
          fi
""",
    )

    # Sanitize every other active workflow too, even if it is not a progress
    # edge target. This removes any literal token left by a partially completed
    # unsafe maintenance run.
    for path in sorted(workflow_dir.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        sanitized = sanitize_token_lines(text)
        if sanitized != text:
            path.write_text(sanitized, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
