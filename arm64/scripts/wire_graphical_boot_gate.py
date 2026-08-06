#!/usr/bin/env python3
"""Wire the graphical boot gate into final ISO and both QEMU probes."""

from __future__ import annotations

import argparse
from pathlib import Path


WORKFLOW_MARKER = "Configure Korean graphical boot validation"


def patch_qemu(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if "-device virtio-gpu-pci" not in text:
        needle = "  -device virtio-net-pci,netdev=net0\n"
        if needle not in text:
            raise RuntimeError(f"QEMU network device marker missing in {path}")
        text = text.replace(
            needle,
            needle
            + "  -device virtio-gpu-pci\n"
            + "  -device qemu-xhci,id=xhci\n"
            + "  -device usb-kbd,bus=xhci.0\n"
            + "  -device usb-tablet,bus=xhci.0\n",
            1,
        )
    path.write_text(text, encoding="utf-8")


def patch_workflow(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if "arm64/scripts/configure_graphical_boot_gate.sh" not in text:
        trigger = "      - 'arm64/scripts/finalize_arm64_live_rootfs_v2.sh'\n"
        if trigger in text:
            text = text.replace(
                trigger,
                trigger + "      - 'arm64/scripts/configure_graphical_boot_gate.sh'\n",
                1,
            )

    if WORKFLOW_MARKER not in text:
        needle = "      - name: Reverify exact packages and reject x86 payloads after overlay\n"
        if needle not in text:
            raise RuntimeError("final rootfs reverify step marker is missing")
        step = """      - name: Configure Korean graphical boot validation
        shell: bash
        run: |
          set -o pipefail
          sudo arm64/scripts/configure_graphical_boot_gate.sh \\
            work/live-rootfs \\
            work/live-finalization/graphical-boot-gate.json \\
            2>&1 | tee work/live-finalization/workflow-graphical-boot-gate.log
          sudo chown -R "$(id -u):$(id -g)" \\
            work/live-rootfs work/live-finalization

"""
        text = text.replace(needle, step + needle, 1)

    copy_line = (
        "          cp work/live-finalization/live-finalization.json "
        "work/final-evidence/\n"
    )
    if (
        "work/live-finalization/graphical-boot-gate.json"
        not in text[text.find("Assemble immutable final evidence") :]
    ):
        if copy_line not in text:
            raise RuntimeError("final evidence copy marker is missing")
        text = text.replace(
            copy_line,
            copy_line
            + "          cp work/live-finalization/graphical-boot-gate.json "
            + "work/final-evidence/\n",
            1,
        )
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--final-workflow", type=Path, required=True)
    parser.add_argument("--live-qemu", type=Path, required=True)
    parser.add_argument("--installed-qemu", type=Path, required=True)
    args = parser.parse_args()

    patch_workflow(args.final_workflow)
    patch_qemu(args.live_qemu)
    patch_qemu(args.installed_qemu)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
