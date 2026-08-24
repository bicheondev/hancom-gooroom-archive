#!/usr/bin/env python3
"""Verify reconstructed gooroom-applauncher-applet ARM64 DEBs and payloads."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SOURCE = "gooroom-applauncher-applet"
VERSION = "0.4.0+grm3u1+han3u2"
REQUIRED_EXPORTS = {
    "applauncher_appitem_get_drag_surface",
    "applauncher_appitem_get_path",
}
TARGET_GRESOURCE_SHA256 = (
    "2abe1443baba5103770ecf92c27dab0d5b5c5443f503ec3ab6c4287b7b77c3a8"
)
TARGET_CHANGELOG_SHA256 = (
    "38309e587b48785b3242c9db5dfcefff36f7d5f377878da57e615cf325d8f8c7"
)
TARGET_ICON_SHA256 = (
    "3a1c906d4eef0caf3c86bb59e2d6efab60bccd601b0d20d1fa7a7bcf0ee4f761"
)


def command(arguments: list[str]) -> str:
    completed = subprocess.run(
        arguments,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"{completed.stdout}"
        )
    return completed.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def deb_field(deb: Path, field: str) -> str:
    completed = subprocess.run(
        ["dpkg-deb", "-f", str(deb), field],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def symbols(path: Path) -> set[str]:
    result: set[str] = set()
    for line in command(["readelf", "-WsW", str(path)]).splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8 or not parts[0].rstrip(":").isdigit():
            continue
        _, _, _, _, binding, visibility, index, name = parts
        if (
            index != "UND"
            and binding in {"GLOBAL", "WEAK", "GNU_UNIQUE"}
            and visibility in {"DEFAULT", "PROTECTED"}
        ):
            result.add(name)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deb-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    deb_dir = args.deb_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    debs: list[dict[str, Any]] = []
    elves: list[dict[str, Any]] = []
    wrong: list[dict[str, Any]] = []
    verification_errors: list[str] = []
    main_roots: list[Path] = []

    for deb in sorted(deb_dir.glob("*.deb")):
        package = deb_field(deb, "Package")
        version = deb_field(deb, "Version")
        architecture = deb_field(deb, "Architecture")
        source_field = deb_field(deb, "Source")
        declared_source = source_field.split(" ", 1)[0] if source_field else package.removesuffix("-dbgsym")
        if version != VERSION or architecture != "arm64" or declared_source != SOURCE:
            raise RuntimeError(
                "wrong package identity: "
                f"{package} {version} {architecture} source={declared_source}"
            )
        root = output / "extracted" / package
        root.mkdir(parents=True, exist_ok=True)
        command(["dpkg-deb", "-x", str(deb), str(root)])
        if package == SOURCE:
            main_roots.append(root)
        row = {
            "filename": deb.name,
            "package": package,
            "source": declared_source,
            "version": version,
            "architecture": architecture,
            "size": deb.stat().st_size,
            "sha256": sha256_file(deb),
        }
        debs.append(row)
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            with path.open("rb") as stream:
                magic = stream.read(4)
            if magic != b"\x7fELF":
                continue
            header = command(["readelf", "-hW", str(path)])
            description = command(["file", "-b", str(path)])
            elf = {
                "package": package,
                "path": path.relative_to(root).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "file": description,
                "machine": next(
                    (
                        match.group(1).strip()
                        for line in header.splitlines()
                        if (match := re.match(r"\s*Machine:\s*(.*)$", line))
                    ),
                    "",
                ),
            }
            elves.append(elf)
            if (
                "AArch64" not in header
                or "x86-64" in description
                or "Intel 80386" in description
            ):
                wrong.append(elf)

    if len(main_roots) != 1:
        verification_errors.append(
            f"expected exactly one {SOURCE} package, found {len(main_roots)}"
        )
    module_record: dict[str, Any] | None = None
    payload_checks: dict[str, Any] = {}
    if len(main_roots) == 1:
        root = main_roots[0]
        modules = sorted(root.rglob("libgooroom-applauncher-applet.so"))
        if len(modules) != 1:
            verification_errors.append(
                f"expected one runtime module, found {len(modules)}"
            )
        else:
            module = modules[0]
            exported = symbols(module)
            missing = sorted(REQUIRED_EXPORTS - exported)
            if missing:
                verification_errors.append(f"required exports missing: {missing}")
            with tempfile.TemporaryDirectory(prefix="applauncher-arm64-") as temp:
                resource = Path(temp) / "applauncher.gresource"
                command(
                    [
                        "objcopy",
                        "--dump-section",
                        f".gresource.applauncher_applet={resource}",
                        str(module),
                    ]
                )
                resource_sha = sha256_file(resource)
            if resource_sha != TARGET_GRESOURCE_SHA256:
                verification_errors.append(
                    "GResource digest mismatch: "
                    f"{resource_sha} != {TARGET_GRESOURCE_SHA256}"
                )
            module_record = {
                "path": module.relative_to(root).as_posix(),
                "size": module.stat().st_size,
                "sha256": sha256_file(module),
                "required_exports": sorted(REQUIRED_EXPORTS),
                "missing_exports": missing,
                "gresource_sha256": resource_sha,
            }

        changelog_matches = sorted(
            root.glob("usr/share/doc/gooroom-applauncher-applet/changelog*.gz")
        )
        if len(changelog_matches) != 1:
            verification_errors.append(
                f"expected one compressed changelog, found {len(changelog_matches)}"
            )
        else:
            changelog_sha = sha256_bytes(gzip.decompress(changelog_matches[0].read_bytes()))
            if changelog_sha != TARGET_CHANGELOG_SHA256:
                verification_errors.append(
                    "changelog digest mismatch: "
                    f"{changelog_sha} != {TARGET_CHANGELOG_SHA256}"
                )
            payload_checks["changelog_decompressed_sha256"] = changelog_sha

        icon = root / "usr/share/icons/hicolor/scalable/apps/gooroom-applauncher-applet.svg"
        if not icon.is_file():
            verification_errors.append("exact Hancom icon is missing")
        else:
            icon_sha = sha256_file(icon)
            if icon_sha != TARGET_ICON_SHA256:
                verification_errors.append(
                    f"icon digest mismatch: {icon_sha} != {TARGET_ICON_SHA256}"
                )
            payload_checks["icon_sha256"] = icon_sha

    verified = (
        len(main_roots) == 1
        and bool(elves)
        and not wrong
        and not verification_errors
        and module_record is not None
    )
    summary = {
        "schema": 2,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": "verified-reconstructed-git-tree",
        "target_architecture": "arm64",
        "deb_artifacts": debs,
        "elf_payloads": elves,
        "wrong_architecture_executables": wrong,
        "main_package_count": len(main_roots),
        "runtime_module": module_record,
        "payload_checks": payload_checks,
        "verification_errors": verification_errors,
        "verified": verified,
    }
    (output / "verification-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "deb-artifacts.json").write_text(
        json.dumps(debs, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
