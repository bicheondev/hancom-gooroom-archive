#!/usr/bin/env python3
"""Verify reconstructed han3u2 source against the locked AMD64 package.

The source authority is the target package changelog plus the surviving public
Gerrit change.  This verifier then checks that rebuilding that source produces
an identical package payload and an ELF with identical ABI, resources, static
data, relocation/call plumbing, dynamic symbol identity, source units, and GCC
producer.  Raw .text identity is recorded but is not required because the
vendor package was linked against the Gooroom build repository rather than the
plain Debian snapshot used by the independent reconstruction build.
"""

from __future__ import annotations

import argparse
import collections
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
EXPECTED_CHANGELOG_TEXT_SHA256 = "5a843cdc103427616c1b5f8e98f6259187941658d805b16e50b9cfafc170bb71"
EXACT_SECTIONS = {
    ".interp", ".note.ABI-tag", ".gnu.hash", ".gnu.version",
    ".gnu.version_r", ".rela.dyn", ".rela.plt", ".init", ".plt",
    ".plt.got", ".fini", ".rodata", ".gresource.greeter",
    ".init_array", ".fini_array", ".got", ".data", ".shstrtab",
}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def run(command: list[str]) -> str:
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, check=False)
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout[-10000:]}"
        )
    return completed.stdout


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def manifest(root: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        row: dict[str, Any] = {"mode": f"{stat.S_IMODE(metadata.st_mode):04o}"}
        if path.is_symlink():
            row.update(type="symlink", target=os.readlink(path))
        elif path.is_dir():
            row.update(type="directory")
        elif path.is_file():
            is_elf = path.read_bytes()[:4] == ELF
            row.update(type="file", size=metadata.st_size, sha256=sha(path), elf=is_elf)
            if path.name.endswith(".gz"):
                try:
                    decompressed = gzip.decompress(path.read_bytes())
                except OSError:
                    pass
                else:
                    row["decompressed_sha256"] = sha_bytes(decompressed)
                    row["decompressed_size"] = len(decompressed)
        else:
            row.update(type="other")
        rows[relative] = row
    return rows


def section_map(binary: Path) -> dict[str, dict[str, Any]]:
    data = binary.read_bytes()
    sections: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\S+\s+(\S*)",
        re.MULTILINE,
    )
    for match in pattern.finditer(run(["readelf", "-SW", str(binary)])):
        name, kind, address, offset, size, flags = match.groups()
        start = int(offset, 16)
        length = int(size, 16)
        payload = b"" if kind == "NOBITS" else data[start:start + length]
        sections[name] = {
            "type": kind,
            "address": int(address, 16),
            "offset": start,
            "size": length,
            "flags": flags,
            "sha256": sha_bytes(payload),
        }
    return sections


def elf_header(binary: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in run(["readelf", "-hW", str(binary)]).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in {"Class", "Data", "Type", "Machine", "Entry point address"}:
            fields[key] = value.strip()
    return fields


def needed_libraries(binary: Path) -> list[str]:
    return re.findall(r"Shared library: \[([^]]+)\]",
                      run(["readelf", "-dW", str(binary)]))


def dynamic_symbol_identity(binary: Path) -> list[tuple[str, ...]]:
    rows: list[tuple[str, ...]] = []
    pattern = re.compile(
        r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s+(\S+)\s+"
        r"(\S+)\s+(\S+)\s*(.*)$"
    )
    for line in run(["readelf", "--dyn-syms", "-W", str(binary)]).splitlines():
        match = pattern.match(line)
        if match:
            kind, binding, visibility, index, name = match.groups()
            rows.append((kind, binding, visibility, index, name.strip()))
    return rows


def string_multiset(binary: Path) -> collections.Counter[str]:
    return collections.Counter(run(["strings", "-a", str(binary)]).splitlines())


def debug_identity(root: Path) -> dict[str, Any]:
    debug_files = [
        path for path in sorted(root.rglob("*"))
        if path.is_file() and path.read_bytes()[:4] == ELF
    ]
    if len(debug_files) != 1:
        raise RuntimeError(f"expected one debug ELF under {root}, found {len(debug_files)}")
    text = run(["readelf", "--debug-dump=info", "--wide", str(debug_files[0])])
    producers = sorted(set(re.findall(
        r"DW_AT_producer\s*:\s*(?:\([^)]*\)\s*)?(.*)$", text, re.MULTILINE
    )))
    source_units = sorted(set(
        Path(value.strip()).name
        for value in re.findall(
            r"DW_AT_name\s*:\s*(?:\([^)]*\)\s*)?([^\n]+\.c)\s*$",
            text,
            re.MULTILINE,
        )
    ))
    return {
        "path": debug_files[0].relative_to(root).as_posix(),
        "sha256": sha(debug_files[0]),
        "producer_strings": producers,
        "source_units": source_units,
    }


def compare_elf(target_path: Path, candidate_path: Path,
                target_debug: dict[str, Any], candidate_debug: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fatal: list[dict[str, Any]] = []
    target_sections = section_map(target_path)
    candidate_sections = section_map(candidate_path)
    target_header = elf_header(target_path)
    candidate_header = elf_header(candidate_path)

    if target_path.stat().st_size != candidate_path.stat().st_size:
        fatal.append({"kind": "elf-file-size", "target": target_path.stat().st_size,
                      "candidate": candidate_path.stat().st_size})
    if target_header != candidate_header:
        fatal.append({"kind": "elf-header", "target": target_header,
                      "candidate": candidate_header})
    if set(target_sections) != set(candidate_sections):
        fatal.append({"kind": "elf-section-set"})

    section_rows: dict[str, Any] = {}
    for name in sorted(set(target_sections) | set(candidate_sections)):
        left = target_sections.get(name)
        right = candidate_sections.get(name)
        exact = left is not None and right is not None and left["sha256"] == right["sha256"]
        section_rows[name] = {"target": left, "candidate": right, "exact": exact}
        if name in EXACT_SECTIONS and not exact:
            fatal.append({"kind": "required-exact-section", "section": name,
                          "target": left, "candidate": right})

    target_needed = needed_libraries(target_path)
    candidate_needed = needed_libraries(candidate_path)
    if target_needed != candidate_needed:
        fatal.append({"kind": "needed-libraries", "target": target_needed,
                      "candidate": candidate_needed})
    target_symbols = dynamic_symbol_identity(target_path)
    candidate_symbols = dynamic_symbol_identity(candidate_path)
    if target_symbols != candidate_symbols:
        fatal.append({"kind": "dynamic-symbol-identity",
                      "target_count": len(target_symbols),
                      "candidate_count": len(candidate_symbols)})
    strings_equal = string_multiset(target_path) == string_multiset(candidate_path)
    if not strings_equal:
        fatal.append({"kind": "string-multiset"})
    producers_equal = target_debug["producer_strings"] == candidate_debug["producer_strings"]
    units_equal = target_debug["source_units"] == candidate_debug["source_units"]
    if not producers_equal:
        fatal.append({"kind": "dwarf-producer", "target": target_debug["producer_strings"],
                      "candidate": candidate_debug["producer_strings"]})
    if not units_equal:
        fatal.append({"kind": "dwarf-source-units", "target": target_debug["source_units"],
                      "candidate": candidate_debug["source_units"]})

    text_left = target_sections.get(".text", {})
    text_right = candidate_sections.get(".text", {})
    row = {
        "target_raw_sha256": sha(target_path),
        "candidate_raw_sha256": sha(candidate_path),
        "raw_identical": sha(target_path) == sha(candidate_path),
        "target_size": target_path.stat().st_size,
        "candidate_size": candidate_path.stat().st_size,
        "elf_header_identical": target_header == candidate_header,
        "needed_libraries_identical": target_needed == candidate_needed,
        "dynamic_symbol_identity_identical": target_symbols == candidate_symbols,
        "string_multiset_identical": strings_equal,
        "dwarf_producer_identical": producers_equal,
        "dwarf_source_units_identical": units_equal,
        "required_exact_sections": sorted(EXACT_SECTIONS),
        "all_required_sections_exact": all(
            section_rows.get(name, {}).get("exact") for name in EXACT_SECTIONS
        ),
        "text_variance": {
            "target_size": text_left.get("size"),
            "candidate_size": text_right.get("size"),
            "target_sha256": text_left.get("sha256"),
            "candidate_sha256": text_right.get("sha256"),
            "exact": text_left.get("sha256") == text_right.get("sha256"),
        },
        "sections": section_rows,
        "target_debug": target_debug,
        "candidate_debug": candidate_debug,
        "structurally_equivalent": not fatal,
    }
    return row, fatal


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--target-debug-root", type=Path, required=True)
    parser.add_argument("--candidate-debug-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    target_root = args.target_root.resolve()
    candidate_root = args.candidate_root.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    target = manifest(target_root)
    candidate = manifest(candidate_root)
    write_json(output / "target-manifest.json", target)
    write_json(output / "candidate-manifest.json", candidate)

    fatal: list[dict[str, Any]] = []
    target_paths = set(target)
    candidate_paths = set(candidate)
    target_debug = debug_identity(args.target_debug_root.resolve())
    candidate_debug = debug_identity(args.candidate_debug_root.resolve())
    elf_rows: list[dict[str, Any]] = []

    for relative in sorted(target_paths | candidate_paths):
        left = target.get(relative)
        right = candidate.get(relative)
        if left is None or right is None:
            fatal.append({"path": relative, "kind": "missing-path",
                          "target": left, "candidate": right})
            continue
        if left["type"] != right["type"] or left["mode"] != right["mode"]:
            fatal.append({"path": relative, "kind": "type-or-mode",
                          "target": left, "candidate": right})
            continue
        if left["type"] == "symlink":
            if left["target"] != right["target"]:
                fatal.append({"path": relative, "kind": "symlink-target"})
            continue
        if left["type"] != "file":
            continue
        if bool(left.get("elf")) != bool(right.get("elf")):
            fatal.append({"path": relative, "kind": "elf-type"})
            continue
        target_path = target_root / relative
        candidate_path = candidate_root / relative
        if left.get("elf"):
            row, elf_fatal = compare_elf(target_path, candidate_path,
                                         target_debug, candidate_debug)
            row["path"] = relative
            elf_rows.append(row)
            fatal.extend({"path": relative, **item} for item in elf_fatal)
            continue
        if left["sha256"] == right["sha256"]:
            continue
        if left.get("decompressed_sha256") == right.get("decompressed_sha256") and left.get("decompressed_sha256"):
            continue
        fatal.append({"path": relative, "kind": "non-elf-payload",
                      "target": left, "candidate": right})

    changelog = "usr/share/doc/gooroom-greeter/changelog.gz"
    target_changelog = target_root / changelog
    candidate_changelog = candidate_root / changelog
    changelog_identical = False
    if target_changelog.is_file() and candidate_changelog.is_file():
        target_text = gzip.decompress(target_changelog.read_bytes())
        candidate_text = gzip.decompress(candidate_changelog.read_bytes())
        changelog_identical = target_text == candidate_text
        if sha_bytes(target_text) != EXPECTED_CHANGELOG_TEXT_SHA256:
            fatal.append({"path": changelog, "kind": "target-changelog-authority-drift"})
        if not changelog_identical:
            fatal.append({"path": changelog, "kind": "changelog-text"})
    else:
        fatal.append({"path": changelog, "kind": "required-changelog-missing"})

    structural = bool(elf_rows) and all(row["structurally_equivalent"] for row in elf_rows)
    summary = {
        "schema": 2,
        "source": "gooroom-greeter",
        "source_version": "0.3.1+grm3u1+han3u2",
        "policy": "exact-non-elf-payload-plus-elf-abi-resource-relocation-symbol-and-dwarf-equivalence",
        "target_path_count": len(target_paths),
        "candidate_path_count": len(candidate_paths),
        "same_path_set": target_paths == candidate_paths,
        "changelog_text_identical": changelog_identical,
        "elf_comparison_count": len(elf_rows),
        "structural_elf_equivalence": structural,
        "raw_elf_identical": bool(elf_rows) and all(row["raw_identical"] for row in elf_rows),
        "fatal_difference_count": len(fatal),
        "verified": not fatal and structural and changelog_identical,
    }
    write_json(output / "elf-comparison.json", elf_rows)
    write_json(output / "differences.json", fatal)
    write_json(output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if fatal:
        print(json.dumps(fatal, indent=2, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
