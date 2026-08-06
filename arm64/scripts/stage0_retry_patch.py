#!/usr/bin/env python3
"""Create one narrowly-scoped retry of the stage-0 ISO builder.

The first stage-0 build always runs the unmodified, locked builder. A retry is
allowed only for host/archive availability defects that do not alter a locked
Hancom/Gooroom source, version or payload. Every change is written to a policy
JSON file and the temporary patched builder is retained in the evidence.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
from pathlib import Path

OPTIONAL_DEBIAN_PACKAGES = {
    "arc-icon-theme",
    "numix-icon-theme-circle",
    "papirus-icon-theme",
    "qemu-guest-agent",
    "spice-vdagent",
}

OPTIONAL_EXACT_OVERLAYS = {
    "arc-icon-theme",
    "arc-theme",
    "flat-remix-gtk-theme",
    "gedit-common",
    "gnome-control-center-data",
    "gnome-flashback-common",
    "gnome-panel-data",
    "gnome-session-flashback",
    "gnome-settings-daemon-common",
    "libgtk-3-common",
    "libgtk2.0-common",
    "libnma-common",
    "metacity-common",
    "nautilus-data",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def remove_shell_word(text: str, package: str) -> tuple[str, int]:
    pattern = re.compile(rf"(?<![A-Za-z0-9+_.-]){re.escape(package)}(?![A-Za-z0-9+_.-])")
    return pattern.subn("", text)


def remove_array_line(text: str, package: str) -> tuple[str, int]:
    pattern = re.compile(rf"(?m)^\s*{re.escape(package)}\s*$\n?")
    return pattern.subn("", text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--builder", type=Path, required=True)
    parser.add_argument("--stdout-log", type=Path, required=True)
    parser.add_argument("--stderr-log", type=Path, required=True)
    parser.add_argument("--patched-builder", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()

    original_bytes = args.builder.read_bytes()
    original = original_bytes.decode("utf-8")
    logs = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (args.stdout_log, args.stderr_log)
        if path.exists()
    )
    patched = original
    actions: list[dict[str, object]] = []

    missing = set(re.findall(r"E: Unable to locate package\s+([^\s]+)", logs))
    missing.update(re.findall(r"Package '([^']+)' has no installation candidate", logs))
    if missing:
        unsafe = sorted(missing - OPTIONAL_DEBIAN_PACKAGES)
        if unsafe:
            actions.append(
                {
                    "status": "blocked",
                    "reason": "unavailable package is not in the optional Debian allowlist",
                    "packages": unsafe,
                }
            )
        else:
            for package in sorted(missing):
                patched, count = remove_shell_word(patched, package)
                if count < 1:
                    raise SystemExit(f"failed to remove optional package token: {package}")
                actions.append(
                    {
                        "action": "omit-unavailable-optional-debian-package",
                        "package": package,
                        "replacement_count": count,
                    }
                )

    overlay_patterns = (
        r"reference architecture-all package missing:\s*([^\s]+)",
        r"verified vendor package missing:\s*([^\s]+)",
        r"architecture-specific executable found in architecture-all package:\s*([^\s]+)",
    )
    overlay_issues: set[str] = set()
    for pattern in overlay_patterns:
        overlay_issues.update(re.findall(pattern, logs))
    if overlay_issues:
        unsafe = sorted(overlay_issues - OPTIONAL_EXACT_OVERLAYS)
        if unsafe:
            actions.append(
                {
                    "status": "blocked",
                    "reason": "an exact Hancom/Gooroom overlay cannot be safely omitted",
                    "packages": unsafe,
                }
            )
        else:
            for package in sorted(overlay_issues):
                patched, count = remove_array_line(patched, package)
                if count != 1:
                    raise SystemExit(
                        f"expected one optional overlay array entry for {package}, found {count}"
                    )
                actions.append(
                    {
                        "action": "omit-unusable-optional-exact-overlay",
                        "package": package,
                        "replacement_count": count,
                    }
                )

    snapshot_transport_error = any(
        marker in logs
        for marker in (
            "Failed getting release file",
            "403  Forbidden",
            "Connection failed [IP:",
            "Could not connect to snapshot.debian.org",
        )
    )
    if snapshot_transport_error and "http://snapshot.debian.org" in patched:
        count = patched.count("http://snapshot.debian.org")
        patched = patched.replace(
            "http://snapshot.debian.org", "https://snapshot.debian.org"
        )
        actions.append(
            {
                "action": "upgrade-snapshot-transport-to-https",
                "replacement_count": count,
            }
        )

    if (
        ("FATAL ERROR: Failed to create thread" in logs or "Failed to create thread" in logs)
        and "mksquashfs" in patched
        and "-processors 2" not in patched
    ):
        patched, count = re.subn(
            r"(?m)^(\s*mksquashfs\b[^\n]*)(\s+-noappend\b)",
            r"\1 -processors 2\2",
            patched,
            count=1,
        )
        if count:
            actions.append(
                {
                    "action": "limit-mksquashfs-processors",
                    "processors": 2,
                }
            )

    blocked = [action for action in actions if action.get("status") == "blocked"]
    changed = patched != original
    status = "retry-authorized" if changed and not blocked else "retry-blocked"
    if not actions:
        status = "retry-blocked"
        actions.append(
            {
                "status": "blocked",
                "reason": "failure did not match a narrow availability-only retry policy",
            }
        )

    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=str(args.builder),
            tofile=str(args.patched_builder),
        )
    )
    policy = {
        "status": status,
        "original_builder": str(args.builder),
        "original_builder_sha256": sha256(original_bytes),
        "patched_builder_sha256": sha256(patched.encode("utf-8")),
        "actions": actions,
        "diff": diff,
    }
    args.policy.parent.mkdir(parents=True, exist_ok=True)
    args.policy.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")

    if status != "retry-authorized":
        return 10
    args.patched_builder.write_text(patched, encoding="utf-8")
    args.patched_builder.chmod(0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
