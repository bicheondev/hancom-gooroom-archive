#!/usr/bin/env python3
"""Apply architecture-neutral Hancom Gooroom reference configuration/assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import struct
from pathlib import Path
from typing import Any, Iterable


DEFAULT_ROOTS = (
    "etc",
    "usr/local",
    "usr/share/backgrounds",
    "usr/share/calamares",
    "usr/share/desktop-base",
    "usr/share/fonts",
    "usr/share/gnome-background-properties",
    "usr/share/gooroom",
    "usr/share/hancom",
    "usr/share/icons",
    "usr/share/pixmaps",
    "usr/share/plymouth",
    "usr/share/themes",
    "var/lib/AccountsService",
    "var/lib/gdm",
    "var/lib/gdm3",
)
EXCLUDED_PREFIXES = (
    "etc/alternatives",
    "etc/ld.so.cache",
    "etc/machine-id",
    "etc/mtab",
    "etc/resolv.conf",
    "etc/ssh/ssh_host_",
    "etc/ssl/certs",
    "etc/udev/hwdb.bin",
    "var/lib/gdm/.cache",
    "var/lib/gdm3/.cache",
)
EXCLUDED_NAMES = {
    ".bash_history",
    ".lesshst",
    ".python_history",
    "random-seed",
    "icon-theme.cache",
    "gschemas.compiled",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elf_machine(path: Path) -> int | None:
    try:
        with path.open("rb") as handle:
            header = handle.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    if header[5] == 1:
        return struct.unpack("<H", header[18:20])[0]
    if header[5] == 2:
        return struct.unpack(">H", header[18:20])[0]
    return -1


def excluded(relative: str, name: str) -> str | None:
    normalized = relative.lstrip("/")
    if name in EXCLUDED_NAMES:
        return "generated-or-private-filename"
    for prefix in EXCLUDED_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "/") or normalized.startswith(prefix):
            return f"excluded-prefix:{prefix}"
    return None


def copy_metadata(source: Path, destination: Path, *, symlink: bool = False) -> None:
    source_stat = source.lstat()
    if not symlink:
        os.chmod(destination, stat.S_IMODE(source_stat.st_mode), follow_symlinks=False)
        os.utime(
            destination,
            ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns),
            follow_symlinks=False,
        )
    try:
        os.chown(
            destination,
            source_stat.st_uid,
            source_stat.st_gid,
            follow_symlinks=False,
        )
    except PermissionError:
        pass
    try:
        for attribute in os.listxattr(source, follow_symlinks=False):
            try:
                value = os.getxattr(source, attribute, follow_symlinks=False)
                os.setxattr(destination, attribute, value, follow_symlinks=False)
            except OSError:
                pass
    except OSError:
        pass


def ensure_directory(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    copy_metadata(source, destination)


def iter_overlay_entries(reference: Path, relative_root: str) -> Iterable[tuple[Path, str]]:
    source_root = reference / relative_root
    if not source_root.exists() and not source_root.is_symlink():
        return
    if source_root.is_symlink() or source_root.is_file():
        yield source_root, relative_root
        return
    yield source_root, relative_root
    for root, directories, files in os.walk(source_root, topdown=True, followlinks=False):
        root_path = Path(root)
        relative = root_path.relative_to(reference)
        symlink_directories = []
        retained_directories = []
        for directory in directories:
            path = root_path / directory
            if path.is_symlink():
                symlink_directories.append(directory)
            else:
                retained_directories.append(directory)
        directories[:] = retained_directories
        for directory in sorted(symlink_directories):
            path = root_path / directory
            yield path, str(path.relative_to(reference))
        for directory in sorted(retained_directories):
            path = root_path / directory
            yield path, str(path.relative_to(reference))
        for filename in sorted(files):
            path = root_path / filename
            yield path, str(path.relative_to(reference))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-rootfs", type=Path, required=True)
    parser.add_argument("--target-rootfs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", action="append", default=[])
    args = parser.parse_args()

    roots = tuple(args.root) if args.root else DEFAULT_ROOTS
    copied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    seen: set[str] = set()

    for relative_root in roots:
        normalized_root = relative_root.strip("/")
        for source, relative in iter_overlay_entries(args.reference_rootfs, normalized_root):
            relative = relative.strip("/")
            if relative in seen:
                continue
            seen.add(relative)
            reason = excluded(relative, source.name)
            if reason:
                skipped.append({"path": relative, "reason": reason})
                continue

            destination = args.target_rootfs / relative
            source_stat = source.lstat()
            if stat.S_ISDIR(source_stat.st_mode):
                ensure_directory(source, destination)
                copied.append({"path": relative, "type": "directory"})
                continue
            if stat.S_ISLNK(source_stat.st_mode):
                target = os.readlink(source)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    if destination.is_dir() and not destination.is_symlink():
                        shutil.rmtree(destination)
                    else:
                        destination.unlink()
                os.symlink(target, destination)
                copy_metadata(source, destination, symlink=True)
                copied.append(
                    {"path": relative, "type": "symlink", "target": target}
                )
                continue
            if not stat.S_ISREG(source_stat.st_mode):
                skipped.append({"path": relative, "reason": "non-regular-special-file"})
                continue

            machine = elf_machine(source)
            if machine in {3, 62}:
                blocked.append(
                    {
                        "path": relative,
                        "reason": "x86-elf-reference-asset",
                        "elf_machine": machine,
                        "size": source_stat.st_size,
                        "sha256": sha256_file(source),
                    }
                )
                continue
            if machine not in {None, 0, 183, 247}:
                blocked.append(
                    {
                        "path": relative,
                        "reason": "foreign-elf-reference-asset",
                        "elf_machine": machine,
                        "size": source_stat.st_size,
                        "sha256": sha256_file(source),
                    }
                )
                continue

            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and destination.is_dir():
                shutil.rmtree(destination)
            shutil.copyfile(source, destination)
            copy_metadata(source, destination)
            copied.append(
                {
                    "path": relative,
                    "type": "file",
                    "size": source_stat.st_size,
                    "sha256": sha256_file(source),
                    "elf_machine": machine,
                }
            )

    # x86 assets are deliberately omitted rather than copied. They are retained
    # in the evidence list so the port does not silently claim full functional
    # equivalence for an AMD64-only component.
    summary = {
        "schema": 1,
        "policy": "reference-config-and-visual-assets-without-x86-elf",
        "roots": list(roots),
        "copied_entry_count": len(copied),
        "copied_file_count": sum(row["type"] == "file" for row in copied),
        "copied_bytes": sum(row.get("size", 0) for row in copied),
        "skipped_entry_count": len(skipped),
        "blocked_architecture_asset_count": len(blocked),
        "overlay_applied": True,
    }
    result = {
        "summary": summary,
        "copied": copied,
        "skipped": skipped,
        "blocked_reference_architecture_assets": blocked,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
