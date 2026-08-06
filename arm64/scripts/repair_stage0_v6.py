#!/usr/bin/env python3
"""Apply bounded, evidence-driven repairs to the stage0-v6 pipeline.

This script is intentionally conservative. It may repair invocation/configuration
bugs and remove a package only when APT explicitly proves that package absent
and the package is in a small non-boot-critical allowlist. It never changes the
reference ISO hash, Debian snapshot, target architecture, boot-critical package
set, x86-ELF rejection, or QEMU success gates.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


OPTIONAL_PACKAGES = {
    "eog",
    "evince",
    "file-roller",
    "fonts-noto-color-emoji",
    "gedit",
    "gnome-calculator",
    "gnome-screenshot",
    "gnome-system-monitor",
    "linux-cpupower",
    "pciutils",
    "usbutils",
    "xserver-xorg-input-all",
    "xserver-xorg-video-all",
}

HOST_TOOL_PACKAGES = {
    "grub-mkstandalone": ("grub-common", "grub-efi-arm64-bin"),
    "mkfs.vfat": ("dosfstools",),
    "mcopy": ("mtools",),
    "mmd": ("mtools",),
    "mksquashfs": ("squashfs-tools",),
    "qemu-system-aarch64": ("qemu-system-arm",),
    "unsquashfs": ("squashfs-tools",),
    "xorriso": ("xorriso",),
}

BOOT_CRITICAL_PACKAGES = {
    "gdm3",
    "gnome-session",
    "gnome-shell",
    "initramfs-tools",
    "linux-image-arm64",
    "live-boot",
    "live-config",
    "systemd-sysv",
    "xserver-xorg",
}


def replace_once(text: str, old: str, new: str, change: dict[str, Any], kind: str) -> str:
    if old not in text:
        return text
    updated = text.replace(old, new, 1)
    if updated != text:
        change.setdefault("changes", []).append({"kind": kind})
    return updated


def ensure_base_only_mmdebstrap(text: str, changes: list[dict[str, Any]]) -> str:
    before = text
    lines = text.splitlines(keepends=True)
    result = []
    inside_call = False
    for line in lines:
        if '"mmdebstrap",' in line:
            inside_call = True
        if inside_call and (
            'bullseye-updates main contrib non-free' in line
            or 'bullseye-security main contrib non-free' in line
        ):
            continue
        result.append(line)
        if inside_call and line.strip() == "]":
            inside_call = False
    text = "".join(result)
    if text != before:
        changes.append({"kind": "mmdebstrap-base-snapshot-single-mirror"})
    return text


def ensure_resolv_conf(text: str, changes: list[dict[str, Any]]) -> str:
    old = '    shutil.copyfile("/etc/resolv.conf", rootfs / "etc/resolv.conf")\n'
    new = '''    rootfs_resolv = rootfs / "etc/resolv.conf"
    if rootfs_resolv.exists() or rootfs_resolv.is_symlink():
        rootfs_resolv.unlink()
    shutil.copyfile("/etc/resolv.conf", rootfs_resolv)
'''
    if old in text:
        text = text.replace(old, new, 1)
        changes.append({"kind": "replace-bootstrap-resolv-conf-symlink"})
    return text


def ensure_gdm_after_overlay(text: str, changes: list[dict[str, Any]]) -> str:
    exclusion_marker = '    "etc/xdg/autostart/orca",\n'
    if '    "etc/gdm3/daemon.conf",\n' not in text and exclusion_marker in text:
        text = text.replace(
            exclusion_marker,
            exclusion_marker + '    "etc/gdm3/daemon.conf",\n',
            1,
        )
        changes.append({"kind": "exclude-gdm-daemon-conf-from-amd64-overlay"})

    overlay_marker = '''    overlay_summary = apply_overlay(
        reference_rootfs,
        rootfs,
        args.evidence_dir / "reference-overlay.json",
    )

    # Regenerate caches after the architecture-neutral reference overlay.
'''
    replacement = '''    overlay_summary = apply_overlay(
        reference_rootfs,
        rootfs,
        args.evidence_dir / "reference-overlay.json",
    )

    gdm_config = rootfs / "etc/gdm3/daemon.conf"
    gdm_config.parent.mkdir(parents=True, exist_ok=True)
    gdm_config.write_text(
        "[daemon]\\n"
        "WaylandEnable=false\\n"
        "AutomaticLoginEnable=true\\n"
        "AutomaticLogin=gooroom\\n\\n"
        "[security]\\n\\n[xdmcp]\\n\\n[chooser]\\n\\n"
        "[debug]\\nEnable=false\\n",
        encoding="utf-8",
    )

    # Regenerate caches after the architecture-neutral reference overlay.
'''
    if 'gdm_config = rootfs / "etc/gdm3/daemon.conf"' not in text and overlay_marker in text:
        text = text.replace(overlay_marker, replacement, 1)
        changes.append({"kind": "write-gdm-live-config-after-reference-overlay"})

    if 'After=display-manager.service graphical.target\\n' in text:
        text = text.replace(
            'After=display-manager.service graphical.target\\n',
            'After=display-manager.service\\n',
            1,
        )
        changes.append({"kind": "remove-graphical-target-ordering-cycle"})
    return text


def ensure_efi_directory_creation(text: str, changes: list[dict[str, Any]]) -> str:
    old = '        run(["mmd", "-i", str(efi_img), "::/EFI", "::/EFI/BOOT"])\n'
    new = '''        run(["mmd", "-i", str(efi_img), "::/EFI"])
        run(["mmd", "-i", str(efi_img), "::/EFI/BOOT"])
'''
    if old in text:
        text = text.replace(old, new, 1)
        changes.append({"kind": "create-efi-directories-sequentially"})
    return text


def remove_proven_optional_packages(
    text: str, log: str, changes: list[dict[str, Any]]
) -> tuple[str, list[str], list[str]]:
    missing = set(re.findall(r"Unable to locate package\s+([^\s]+)", log))
    missing.update(
        re.findall(
            r"Package ['‘]?([^'’\s]+)['’]? has no installation candidate", log
        )
    )
    forbidden = sorted(missing & BOOT_CRITICAL_PACKAGES)
    removed = []
    for package in sorted(missing & OPTIONAL_PACKAGES):
        pattern = rf"(?<![A-Za-z0-9+_.-]){re.escape(package)}(?![A-Za-z0-9+_.-])"
        updated, count = re.subn(pattern, "", text)
        if count:
            text = updated
            removed.append(package)
    if removed:
        changes.append(
            {"kind": "remove-proven-unavailable-optional-packages", "packages": removed}
        )
    return text, sorted(missing), forbidden


def patch_mksquashfs_compatibility(
    text: str, log: str, changes: list[dict[str, Any]]
) -> str:
    if re.search(r"(?i)(unknown|unrecognised|invalid) option.*-mkfs-time", log):
        if '                "-mkfs-time",\n                "0",\n' in text:
            text = text.replace(
                '                "-mkfs-time",\n                "0",\n', "", 1
            )
            changes.append({"kind": "remove-unsupported-mksquashfs-mkfs-time"})
    if re.search(r"(?i)(unknown|unrecognised|invalid) option.*-all-time", log):
        if '                "-all-time",\n                "0",\n' in text:
            text = text.replace(
                '                "-all-time",\n                "0",\n', "", 1
            )
            changes.append({"kind": "remove-unsupported-mksquashfs-all-time"})
    return text


def patch_qemu_timeout_and_diagnostics(
    workflow: str, log: str, changes: list[dict[str, Any]]
) -> str:
    if (
        "HANCOM_GOOROOM_3_3_ARM64_STAGE0_V6_BOOT_OK" in log
        and "HANCOM_GOOROOM_3_3_ARM64_STAGE0_V6_GRAPHICAL_OK" not in log
    ):
        old = "          for _ in $(seq 1 240); do\n"
        new = "          for _ in $(seq 1 360); do\n"
        if old in workflow:
            workflow = workflow.replace(old, new, 1)
            changes.append({"kind": "extend-graphical-session-wait-to-30-minutes"})
    return workflow


def add_proven_host_tools(
    workflow: str, log: str, changes: list[dict[str, Any]]
) -> str:
    packages = set()
    for tool, tool_packages in HOST_TOOL_PACKAGES.items():
        patterns = (
            rf"{re.escape(tool)}: command not found",
            rf"{re.escape(tool)}: not found",
            rf"No such file or directory[^\n]*{re.escape(tool)}",
        )
        if any(re.search(pattern, log, re.IGNORECASE) for pattern in patterns):
            packages.update(tool_packages)
    if not packages:
        return workflow

    match = re.search(
        r"(sudo apt-get install -y --no-install-recommends \\\n)(.*?)(?=\n\s*python3 -m py_compile)",
        workflow,
        re.DOTALL,
    )
    if not match:
        return workflow
    block = match.group(0)
    additions = [
        package
        for package in sorted(packages)
        if re.search(
            rf"(?<![A-Za-z0-9+_.-]){re.escape(package)}(?![A-Za-z0-9+_.-])",
            block,
        )
        is None
    ]
    if not additions:
        return workflow
    replacement = block.rstrip() + " \\\n            " + " ".join(additions) + "\n"
    workflow = workflow[: match.start()] + replacement + workflow[match.end() :]
    changes.append({"kind": "add-proven-missing-host-tools", "packages": additions})
    return workflow


def error_context(log: str) -> list[dict[str, Any]]:
    lines = log.splitlines()
    pattern = re.compile(
        r"(?i)(BUILD ERROR|error|fatal|failed|failure|unable|cannot|not found|"
        r"no such file|unmet|broken|mismatch|traceback|exit code|timeout)"
    )
    records = []
    for index, line in enumerate(lines):
        if pattern.search(line):
            records.append(
                {
                    "line": index + 1,
                    "context": lines[max(0, index - 2) : min(len(lines), index + 4)],
                }
            )
    return records[-120:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--builder", type=Path, required=True)
    parser.add_argument("--workflow", type=Path, required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    log = args.log.read_text(encoding="utf-8", errors="replace")
    builder = args.builder.read_text(encoding="utf-8")
    workflow = args.workflow.read_text(encoding="utf-8")
    original_builder = builder
    original_workflow = workflow
    changes: list[dict[str, Any]] = []

    builder = ensure_base_only_mmdebstrap(builder, changes)
    builder = ensure_resolv_conf(builder, changes)
    builder = ensure_gdm_after_overlay(builder, changes)
    builder = ensure_efi_directory_creation(builder, changes)
    builder, missing_packages, forbidden_missing = remove_proven_optional_packages(
        builder, log, changes
    )
    builder = patch_mksquashfs_compatibility(builder, log, changes)
    workflow = add_proven_host_tools(workflow, log, changes)
    workflow = patch_qemu_timeout_and_diagnostics(workflow, log, changes)

    if forbidden_missing:
        changes.append(
            {
                "kind": "boot-critical-package-missing-blocker",
                "packages": forbidden_missing,
                "applied": False,
            }
        )

    builder_changed = builder != original_builder
    workflow_changed = workflow != original_workflow
    if builder_changed:
        args.builder.write_text(builder, encoding="utf-8")
    if workflow_changed:
        args.workflow.write_text(workflow, encoding="utf-8")

    report = {
        "schema": 1,
        "policy": "bounded-log-proven-stage0-repair",
        "attempt": args.attempt,
        "builder_changed": builder_changed,
        "workflow_changed": workflow_changed,
        "changed": builder_changed or workflow_changed,
        "changes": changes,
        "missing_packages": missing_packages,
        "boot_critical_missing_packages": forbidden_missing,
        "error_context": error_context(log),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
