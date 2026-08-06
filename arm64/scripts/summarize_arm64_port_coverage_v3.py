#!/usr/bin/env python3
"""Apply conservative final-phase gates to exact-authority coverage v2."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import summarize_arm64_port_coverage_v2 as base


def load(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def summary(document: dict) -> dict:
    value = document.get("summary")
    return value if isinstance(value, dict) else document


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--rootfs-verification", type=Path)
    parser.add_argument("--iso-release-lock", type=Path)
    parser.add_argument("--installed-release-lock", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args, _ = parser.parse_known_args()

    rc = base.main()
    coverage_path = args.output_dir / "coverage.json"
    if not coverage_path.exists():
        return rc or 2
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    result_summary = coverage["summary"]

    rootfs = summary(load(args.rootfs_verification))
    iso = summary(load(args.iso_release_lock))
    installed = summary(load(args.installed_release_lock))

    rootfs_ready = rootfs.get("passed") is True
    live_iso_ready = (
        iso.get("qemu_booted") is True
        or iso.get("live_iso_qemu_booted") is True
        or (
            iso.get("passed") is True
            and iso.get("marker_found") is True
        )
    )
    installed_ready = (
        installed.get("installed_gpt_system_qemu_booted") is True
        or installed.get("installed_system_qemu_booted") is True
    )

    highest_phase = "reference-and-source-mapping"
    if result_summary.get("source_authority_complete") is True:
        highest_phase = "exact-source-authority"
    if result_summary.get("native_rebuilds_complete") is True:
        highest_phase = "verified-native-arm64-rebuilds"
    if result_summary.get("persistent_release_complete") is True:
        highest_phase = "persistent-exact-rebuild-packages"
    if result_summary.get("acquisition_ready") is True:
        highest_phase = "exact-package-acquisition-ready"
    if rootfs_ready:
        highest_phase = "verified-arm64-rootfs"
    if live_iso_ready:
        highest_phase = "qemu-booted-live-arm64-iso"
    if installed_ready:
        highest_phase = "qemu-booted-installed-arm64-system"

    result_summary.update(
        {
            "schema": 3,
            "policy": "current-exact-authority-with-conservative-final-phase-gates",
            "rootfs_ready": rootfs_ready,
            "live_iso_qemu_booted": live_iso_ready,
            "installed_system_qemu_booted": installed_ready,
            "highest_completed_phase": highest_phase,
            "port_complete": installed_ready,
        }
    )
    coverage["summary"] = result_summary
    coverage_path.write_text(
        json.dumps(coverage, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(result_summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result_summary, ensure_ascii=False, indent=2))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
