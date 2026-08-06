#!/usr/bin/env python3
"""Append the installed-system QEMU gate after final live-ISO success."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


TOKEN = "${{ github.token }}"
REPOSITORY = "${{ github.repository }}"
MARKER = "Dispatch installed-system boot validation explicitly"


def ensure_actions_write(text: str) -> str:
    match = re.search(r"(?m)^permissions:\n((?:  [^\n]+\n)+)", text)
    if not match:
        raise RuntimeError("workflow has no permissions block")
    lines = match.group(1).splitlines()
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", type=Path, required=True)
    args = parser.parse_args()

    text = ensure_actions_write(args.workflow.read_text(encoding="utf-8"))
    text = re.sub(
        r"(?m)^(\s+GH_TOKEN:)\s+.*$",
        lambda match: f"{match.group(1)} {TOKEN}",
        text,
    )
    if MARKER not in text:
        step = f"""
      - name: {MARKER}
        if: always()
        env:
          GH_TOKEN: {TOKEN}
        shell: bash
        run: |
          set -euxo pipefail
          if [ -f work/qemu-evidence/qemu-boot-result.json ] \\
             && jq -e '.passed == true and .marker_found == true' \\
               work/qemu-evidence/qemu-boot-result.json >/dev/null; then
            for attempt in 1 2 3 4; do
              if gh workflow run arm64-installed-system-boot.yml \\
                --repo '{REPOSITORY}' \\
                --ref arm64-port; then
                exit 0
              fi
              sleep $((attempt * 5))
            done
            exit 1
          fi
"""
        text = text.rstrip() + "\n\n" + step.strip("\n") + "\n"
    args.workflow.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
