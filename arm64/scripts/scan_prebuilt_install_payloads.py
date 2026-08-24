#!/usr/bin/env python3
"""Detect prebuilt non-ARM64 ELF files that Debian packaging installs directly.

The exact Git tree can still be unsuitable as ARM64 source when debian/*.install
copies an already-compiled x86 object into the package. This scanner evaluates
only existing source-tree files referenced by dh_install manifests; generated
build outputs that do not yet exist are recorded but never guessed.

Exit codes:
  0   no directly installed foreign ELF was found
  86  at least one directly installed foreign ELF requires source recovery
  2   malformed input or an internal audit error
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import shlex
import stat
import struct
from pathlib import Path
from typing import Any


TARGET_MACHINE = 183  # EM_AARCH64
IGNORED_ELF_MACHINES = {0, 247}  # EM_NONE and eBPF objects
MACHINE_NAMES = {
    0: "none",
    3: "i386",
    40: "arm32",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
    247: "bpf",
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
    byte_order = header[5]
    if byte_order == 1:
        return struct.unpack("<H", header[18:20])[0]
    if byte_order == 2:
        return struct.unpack(">H", header[18:20])[0]
    return -1


def install_manifests(source_root: Path) -> list[Path]:
    debian = source_root / "debian"
    if not debian.is_dir():
        return []
    manifests: set[Path] = set()
    for pattern in ("install", "*.install"):
        for path in debian.glob(pattern):
            if path.is_file():
                manifests.add(path)
    return sorted(manifests)


def parse_manifest(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("#!/usr/bin/dh-exec"):
            continue
        try:
            tokens = shlex.split(raw_line, comments=True, posix=True)
        except ValueError as error:
            rows.append(
                {
                    "line": line_number,
                    "raw": raw_line,
                    "status": "parse-error",
                    "error": str(error),
                }
            )
            continue
        if not tokens:
            continue
        # dh-exec supports `source => destination`; dh_install uses the first
        # token as the source pattern and an optional second token as directory.
        source_pattern = tokens[0]
        if source_pattern == "=>" or source_pattern.startswith("${"):
            rows.append(
                {
                    "line": line_number,
                    "raw": raw_line,
                    "status": "dynamic-pattern-not-expanded",
                    "source_pattern": source_pattern,
                }
            )
            continue
        rows.append(
            {
                "line": line_number,
                "raw": raw_line,
                "status": "parsed",
                "source_pattern": source_pattern,
                "destination": (
                    tokens[tokens.index("=>") + 1]
                    if "=>" in tokens and tokens.index("=>") + 1 < len(tokens)
                    else (tokens[1] if len(tokens) > 1 else "")
                ),
            }
        )
    return rows


def expand_pattern(source_root: Path, pattern: str) -> list[Path]:
    if pattern.startswith("/"):
        return []
    if any(token in pattern for token in ("${", "$(`", "$(", "`")):
        return []
    absolute_pattern = str(source_root / pattern)
    matches = [Path(value) for value in glob.glob(absolute_pattern, recursive=True)]
    return sorted(
        path
        for path in matches
        if path.exists() and not path.is_symlink() and path.is_file()
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", default="")
    parser.add_argument("--source-version", default="")
    parser.add_argument("--repository", default="")
    parser.add_argument("--commit-sha", default="")
    parser.add_argument("--tree-sha", default="")
    args = parser.parse_args()

    source_root = args.source_root.resolve()
    if not source_root.is_dir():
        raise SystemExit(f"source root is not a directory: {source_root}")

    manifest_rows: list[dict[str, Any]] = []
    inspected: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    parse_errors: list[dict[str, Any]] = []

    for manifest in install_manifests(source_root):
        relative_manifest = str(manifest.relative_to(source_root))
        for row in parse_manifest(manifest):
            record = {"manifest": relative_manifest, **row}
            manifest_rows.append(record)
            if row["status"] == "parse-error":
                parse_errors.append(record)
                continue
            if row["status"] != "parsed":
                continue
            pattern = str(row["source_pattern"])
            matches = expand_pattern(source_root, pattern)
            if not matches:
                record["matched_existing_file_count"] = 0
                continue
            record["matched_existing_file_count"] = len(matches)
            for path in matches:
                mode = path.lstat().st_mode
                if not stat.S_ISREG(mode):
                    continue
                machine = elf_machine(path)
                if machine is None:
                    continue
                relative_path = str(path.relative_to(source_root))
                evidence = {
                    "manifest": relative_manifest,
                    "manifest_line": row["line"],
                    "source_pattern": pattern,
                    "destination": row.get("destination", ""),
                    "path": relative_path,
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "elf_machine": machine,
                    "elf_machine_name": MACHINE_NAMES.get(
                        machine, f"machine-{machine}"
                    ),
                }
                inspected.append(evidence)
                if machine != TARGET_MACHINE and machine not in IGNORED_ELF_MACHINES:
                    blockers.append(evidence)

    summary = {
        "schema": 1,
        "policy": "block-directly-installed-prebuilt-foreign-elf",
        "target_architecture": "arm64",
        "target_elf_machine": TARGET_MACHINE,
        "source": args.source,
        "source_version": args.source_version,
        "repository": args.repository,
        "commit_sha": args.commit_sha,
        "tree_sha": args.tree_sha,
        "manifest_count": len({row["manifest"] for row in manifest_rows}),
        "manifest_entry_count": len(manifest_rows),
        "inspected_existing_elf_count": len(inspected),
        "foreign_elf_blocker_count": len(blockers),
        "parse_error_count": len(parse_errors),
        "source_recovery_required": bool(blockers),
        "passed": not blockers and not parse_errors,
    }
    result = {
        "summary": summary,
        "manifest_entries": manifest_rows,
        "inspected_elfs": inspected,
        "foreign_elf_blockers": blockers,
        "parse_errors": parse_errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))

    if parse_errors:
        return 2
    if blockers:
        return 86
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
