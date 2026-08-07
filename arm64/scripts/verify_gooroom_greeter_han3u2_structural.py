#!/usr/bin/env python3
"""Fail-closed structural equivalence gate for reconstructed greeter han3u2."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

ELF = b"\x7fELF"
VERSION = "0.3.1+grm3u1+han3u2"
CHANGELOG_SHA256 = "5a843cdc103427616c1b5f8e98f6259187941658d805b16e50b9cfafc170bb71"
EXACT_SECTIONS = {
    ".interp", ".note.ABI-tag", ".gnu.hash", ".gnu.version",
    ".gnu.version_r", ".rela.dyn", ".rela.plt", ".init", ".plt",
    ".plt.got", ".fini", ".rodata", ".gresource.greeter",
    ".init_array", ".fini_array", ".got", ".data", ".shstrtab",
}


def command(args: list[str]) -> str:
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed: {' '.join(args)}\n{result.stdout[-10000:]}")
    return result.stdout


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def payload(root: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        metadata = path.lstat()
        row: dict[str, Any] = {"mode": f"{stat.S_IMODE(metadata.st_mode):04o}"}
        if path.is_symlink():
            row.update(type="symlink", target=os.readlink(path))
        elif path.is_dir():
            row.update(type="directory")
        elif path.is_file():
            is_elf = path.read_bytes()[:4] == ELF
            row.update(type="file", size=metadata.st_size, sha256=digest(path), elf=is_elf)
            if path.name.endswith(".gz"):
                try:
                    clear = gzip.decompress(path.read_bytes())
                except OSError:
                    pass
                else:
                    row["decompressed_sha256"] = digest_bytes(clear)
        else:
            row.update(type="other")
        rows[rel] = row
    return rows


def sections(binary: Path) -> dict[str, dict[str, Any]]:
    raw = binary.read_bytes()
    rows: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\S+\s*(\S*)",
        re.MULTILINE,
    )
    for match in pattern.finditer(command(["readelf", "-SW", str(binary)])):
        name, kind, address, offset, size, flags = match.groups()
        start, length = int(offset, 16), int(size, 16)
        data = b"" if kind == "NOBITS" else raw[start:start + length]
        rows[name] = {
            "type": kind,
            "address": int(address, 16),
            "offset": start,
            "size": length,
            "flags": flags,
            "sha256": digest_bytes(data),
        }
    return rows


def header(binary: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in command(["readelf", "-hW", str(binary)]).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in {"Class", "Data", "Type", "Machine", "Entry point address"}:
            result[key] = value.strip()
    return result


def needed(binary: Path) -> list[str]:
    return re.findall(r"Shared library: \[([^]]+)\]",
                      command(["readelf", "-dW", str(binary)]))


def dynsym(binary: Path) -> list[tuple[str, ...]]:
    result: list[tuple[str, ...]] = []
    pattern = re.compile(
        r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s+(\S+)\s+"
        r"(\S+)\s+(\S+)\s*(.*)$"
    )
    for line in command(["readelf", "--dyn-syms", "-W", str(binary)]).splitlines():
        match = pattern.match(line)
        if match:
            result.append(tuple(value.strip() for value in match.groups()))
    return result


def clean_dwarf_value(value: str) -> str:
    value = value.strip()
    while value.startswith("(") and "):" in value:
        value = value.split("):", 1)[1].strip()
    return value


def debug_identity(root: Path) -> dict[str, Any]:
    files = [path for path in sorted(root.rglob("*"))
             if path.is_file() and path.read_bytes()[:4] == ELF]
    if len(files) != 1:
        raise RuntimeError(f"expected one debug ELF under {root}, found {len(files)}")
    info = command(["readelf", "--debug-dump=info", "--wide", str(files[0])])
    producers = []
    source_units = []
    for line in info.splitlines():
        if "DW_AT_producer" in line and ":" in line:
            producers.append(clean_dwarf_value(line.split("DW_AT_producer", 1)[1].split(":", 1)[1]))
        if "DW_AT_name" in line and line.rstrip().endswith(".c"):
            value = clean_dwarf_value(line.split("DW_AT_name", 1)[1].split(":", 1)[1])
            match = re.search(r"([A-Za-z0-9_.+\-]+\.c)$", value)
            if match:
                source_units.append(match.group(1))
    compiler_ids = sorted(set(
        match.group(1)
        for producer in producers
        for match in [re.search(r"(GNU C\d+ 10\.2\.1 20210110)", producer)]
        if match
    ))
    return {
        "path": files[0].relative_to(root).as_posix(),
        "sha256": digest(files[0]),
        "compiler_ids": compiler_ids,
        "producer_strings": sorted(set(producers)),
        "source_units": sorted(set(source_units)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--target-debug-root", type=Path, required=True)
    parser.add_argument("--candidate-debug-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    target_root, candidate_root = args.target_root.resolve(), args.candidate_root.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    target, candidate = payload(target_root), payload(candidate_root)
    write(output / "target-manifest.json", target)
    write(output / "candidate-manifest.json", candidate)
    target_debug, candidate_debug = debug_identity(args.target_debug_root.resolve()), debug_identity(args.candidate_debug_root.resolve())

    fatal: list[dict[str, Any]] = []
    elf_rows: list[dict[str, Any]] = []
    for rel in sorted(set(target) | set(candidate)):
        left, right = target.get(rel), candidate.get(rel)
        if left is None or right is None:
            fatal.append({"path": rel, "kind": "missing-path"})
            continue
        if left["type"] != right["type"] or left["mode"] != right["mode"]:
            fatal.append({"path": rel, "kind": "type-or-mode", "target": left, "candidate": right})
            continue
        if left["type"] == "symlink":
            if left["target"] != right["target"]:
                fatal.append({"path": rel, "kind": "symlink-target"})
            continue
        if left["type"] != "file":
            continue
        if bool(left.get("elf")) != bool(right.get("elf")):
            fatal.append({"path": rel, "kind": "elf-type"})
            continue
        target_path, candidate_path = target_root / rel, candidate_root / rel
        if not left.get("elf"):
            if left["sha256"] == right["sha256"]:
                continue
            if left.get("decompressed_sha256") and left.get("decompressed_sha256") == right.get("decompressed_sha256"):
                continue
            fatal.append({"path": rel, "kind": "non-elf-payload", "target": left, "candidate": right})
            continue

        target_sections, candidate_sections = sections(target_path), sections(candidate_path)
        exact = {
            name: target_sections.get(name, {}).get("sha256") == candidate_sections.get(name, {}).get("sha256")
            for name in sorted(EXACT_SECTIONS)
        }
        row = {
            "path": rel,
            "target_sha256": left["sha256"],
            "candidate_sha256": right["sha256"],
            "raw_identical": left["sha256"] == right["sha256"],
            "file_size_identical": left["size"] == right["size"],
            "header_identical": header(target_path) == header(candidate_path),
            "section_set_identical": set(target_sections) == set(candidate_sections),
            "required_section_identity": exact,
            "all_required_sections_exact": all(exact.values()),
            "needed_libraries_identical": needed(target_path) == needed(candidate_path),
            "dynamic_symbol_identity_identical": dynsym(target_path) == dynsym(candidate_path),
            "compiler_identity_identical": target_debug["compiler_ids"] == candidate_debug["compiler_ids"] and bool(target_debug["compiler_ids"]),
            "source_units_identical": target_debug["source_units"] == candidate_debug["source_units"] and bool(target_debug["source_units"]),
            "text_variance": {
                "target": target_sections.get(".text"),
                "candidate": candidate_sections.get(".text"),
            },
        }
        required = [
            "file_size_identical", "header_identical", "section_set_identical",
            "all_required_sections_exact", "needed_libraries_identical",
            "dynamic_symbol_identity_identical", "compiler_identity_identical",
            "source_units_identical",
        ]
        row["structurally_equivalent"] = all(row[key] for key in required)
        if not row["structurally_equivalent"]:
            fatal.append({"path": rel, "kind": "elf-structural-equivalence", "evidence": row})
        elf_rows.append(row)

    changelog_rel = "usr/share/doc/gooroom-greeter/changelog.gz"
    changelog_identical = False
    if (target_root / changelog_rel).is_file() and (candidate_root / changelog_rel).is_file():
        left = gzip.decompress((target_root / changelog_rel).read_bytes())
        right = gzip.decompress((candidate_root / changelog_rel).read_bytes())
        changelog_identical = left == right
        if digest_bytes(left) != CHANGELOG_SHA256 or not changelog_identical:
            fatal.append({"path": changelog_rel, "kind": "changelog-authority"})
    else:
        fatal.append({"path": changelog_rel, "kind": "changelog-missing"})

    structural = bool(elf_rows) and all(row["structurally_equivalent"] for row in elf_rows)
    summary = {
        "schema": 1,
        "source": "gooroom-greeter",
        "source_version": VERSION,
        "policy": "exact-non-elf-payload-and-elf-abi-resource-relocation-symbol-dwarf-equivalence",
        "target_path_count": len(target),
        "candidate_path_count": len(candidate),
        "same_path_set": set(target) == set(candidate),
        "changelog_text_identical": changelog_identical,
        "structural_elf_equivalence": structural,
        "raw_elf_identical": bool(elf_rows) and all(row["raw_identical"] for row in elf_rows),
        "fatal_difference_count": len(fatal),
        "verified": not fatal and structural and changelog_identical,
    }
    write(output / "target-debug-identity.json", target_debug)
    write(output / "candidate-debug-identity.json", candidate_debug)
    write(output / "elf-comparison.json", elf_rows)
    write(output / "differences.json", fatal)
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if fatal:
        print(json.dumps(fatal, indent=2, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
