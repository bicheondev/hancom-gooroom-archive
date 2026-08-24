#!/usr/bin/env python3
"""Fail-closed reproducibility gate for the reconstructed Hancom applauncher ELF.

Raw ELF and DEB identity remain separate claims.  Runtime ELF identity is
accepted only when every differing byte is confined to the 20-byte GNU Build
ID descriptor or to the .gnu_debuglink payload mechanically derived from that
Build ID, and the complete package payload outside that ELF is byte-identical.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ELF_PATH = Path(
    "usr/lib/x86_64-linux-gnu/gnome-panel/modules/"
    "libgooroom-applauncher-applet.so"
)
ALLOWED_SECTIONS = (".gnu_debuglink", ".note.gnu.build-id")


def run(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={"LC_ALL": "C.UTF-8"},
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout[-4000:]}\n"
            f"stderr:\n{completed.stderr[-4000:]}"
        )
    return completed.stdout


def sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def align4(value: int) -> int:
    return (value + 3) & ~3


def section_table(path: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    sections: list[dict[str, Any]] = []
    by_name: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        r"^\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
    )
    for line in run(["readelf", "-SW", str(path)]).splitlines():
        match = pattern.match(line)
        if not match:
            continue
        index, name, section_type, address, offset, size = match.groups()
        record = {
            "index": int(index),
            "name": name,
            "type": section_type,
            "address": int(address, 16),
            "offset": int(offset, 16),
            "size": int(size, 16),
        }
        sections.append(record)
        if name in by_name:
            raise RuntimeError(f"duplicate ELF section name: {name}")
        by_name[name] = record
    if not sections:
        raise RuntimeError(f"could not parse ELF section table: {path}")
    return sections, by_name


def normalize(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    data = bytearray(raw)
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise RuntimeError(f"not an ELF file: {path}")
    if data[4] != 2 or data[5] != 1:
        raise RuntimeError(
            f"expected ELF64 little-endian input, got class={data[4]} data={data[5]}"
        )

    sections, by_name = section_table(path)
    missing = sorted(set(ALLOWED_SECTIONS) - set(by_name))
    if missing:
        raise RuntimeError(f"required reproducibility sections are missing: {missing}")

    build = by_name[".note.gnu.build-id"]
    build_start = build["offset"]
    build_end = build_start + build["size"]
    if build["type"] != "NOTE" or build_end > len(data) or build["size"] < 16:
        raise RuntimeError("invalid .note.gnu.build-id section")
    namesz, descsz, note_type = struct.unpack_from("<III", data, build_start)
    name_start = build_start + 12
    name_end = name_start + namesz
    descriptor_start = build_start + 12 + align4(namesz)
    descriptor_end = descriptor_start + descsz
    if name_end > build_end or descriptor_end > build_end:
        raise RuntimeError("GNU Build ID note extends beyond its section")
    if namesz != 4 or bytes(data[name_start:name_end]) != b"GNU\x00":
        raise RuntimeError("unexpected GNU Build ID note owner")
    if note_type != 3 or descsz != 20:
        raise RuntimeError(
            f"unexpected GNU Build ID note shape: type={note_type}, descsz={descsz}"
        )
    build_id = bytes(data[descriptor_start:descriptor_end]).hex()

    debug = by_name[".gnu_debuglink"]
    debug_start = debug["offset"]
    debug_end = debug_start + debug["size"]
    if debug["type"] != "PROGBITS" or debug_end > len(data):
        raise RuntimeError("invalid .gnu_debuglink section")
    debug_payload = bytes(data[debug_start:debug_end])
    terminator = debug_payload.find(b"\x00")
    if terminator <= 0:
        raise RuntimeError("invalid .gnu_debuglink filename")
    try:
        debug_filename = debug_payload[:terminator].decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError("non-ASCII .gnu_debuglink filename") from exc
    padding_end = align4(terminator + 1)
    if padding_end + 4 != len(debug_payload):
        raise RuntimeError("unexpected .gnu_debuglink padding or CRC layout")
    if any(debug_payload[terminator + 1 : padding_end]):
        raise RuntimeError("non-zero .gnu_debuglink alignment padding")
    if not re.fullmatch(r"[0-9a-f]{38}\.debug", debug_filename):
        raise RuntimeError(f"unexpected build-id debug filename: {debug_filename}")
    expected_debug_filename = build_id[2:] + ".debug"
    if debug_filename != expected_debug_filename:
        raise RuntimeError(
            ".gnu_debuglink filename is not derived from GNU Build ID: "
            f"{debug_filename} != {expected_debug_filename}"
        )

    debug_crc32_le = int.from_bytes(debug_payload[padding_end:], "little")
    data[descriptor_start:descriptor_end] = b"\x00" * descsz
    data[debug_start:debug_end] = b"\x00" * debug["size"]

    return bytes(data), {
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "normalized_sha256": sha256_bytes(data),
        "build_id": build_id,
        "build_id_descriptor_range": [descriptor_start, descriptor_end],
        "debuglink_filename": debug_filename,
        "debuglink_crc32_le": f"0x{debug_crc32_le:08x}",
        "debuglink_range": [debug_start, debug_end],
        "debuglink_derived_from_build_id": True,
        "sections": sections,
    }


def offset_section(offset: int, sections: list[dict[str, Any]]) -> str:
    for section in sections:
        if section["type"] == "NOBITS":
            continue
        start = section["offset"]
        end = start + section["size"]
        if section["size"] and start <= offset < end:
            return section["name"]
    return "<outside-section>"


def difference_ranges(offsets: list[int], sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not offsets:
        return []
    result: list[dict[str, Any]] = []
    start = previous = offsets[0]
    section_name = offset_section(start, sections)
    for offset in offsets[1:]:
        current_section = offset_section(offset, sections)
        if offset != previous + 1 or current_section != section_name:
            result.append(
                {
                    "start": start,
                    "end_exclusive": previous + 1,
                    "bytes": previous + 1 - start,
                    "section": section_name,
                }
            )
            start = offset
            section_name = current_section
        previous = offset
    result.append(
        {
            "start": start,
            "end_exclusive": previous + 1,
            "bytes": previous + 1 - start,
            "section": section_name,
        }
    )
    return result


def compare(target: Path, rebuilt: Path) -> dict[str, Any]:
    target_raw = target.read_bytes()
    rebuilt_raw = rebuilt.read_bytes()
    target_normalized, target_metadata = normalize(target)
    rebuilt_normalized, rebuilt_metadata = normalize(rebuilt)

    same_size = len(target_raw) == len(rebuilt_raw)
    if same_size:
        offsets = [
            index
            for index, (left, right) in enumerate(zip(target_raw, rebuilt_raw))
            if left != right
        ]
    else:
        common = min(len(target_raw), len(rebuilt_raw))
        offsets = [
            index
            for index, (left, right) in enumerate(
                zip(target_raw[:common], rebuilt_raw[:common])
            )
            if left != right
        ]
        offsets.extend(range(common, max(len(target_raw), len(rebuilt_raw))))

    target_allowed = [
        tuple(target_metadata["build_id_descriptor_range"]),
        tuple(target_metadata["debuglink_range"]),
    ]
    rebuilt_allowed = [
        tuple(rebuilt_metadata["build_id_descriptor_range"]),
        tuple(rebuilt_metadata["debuglink_range"]),
    ]
    allowed_ranges_match = target_allowed == rebuilt_allowed

    def allowed(offset: int) -> bool:
        return any(start <= offset < end for start, end in target_allowed)

    unexpected = [offset for offset in offsets if not allowed(offset)]
    differing_sections = sorted(
        {offset_section(offset, target_metadata["sections"]) for offset in offsets}
    )
    section_layout_match = (
        target_metadata["sections"] == rebuilt_metadata["sections"]
    )
    normalized_identity = target_normalized == rebuilt_normalized
    metadata_only = all(
        [
            same_size,
            section_layout_match,
            allowed_ranges_match,
            not unexpected,
            normalized_identity,
            set(differing_sections).issubset(set(ALLOWED_SECTIONS)),
            target_metadata["debuglink_derived_from_build_id"],
            rebuilt_metadata["debuglink_derived_from_build_id"],
        ]
    )
    return {
        "raw_byte_identity": target_raw == rebuilt_raw,
        "normalized_elf_identity": normalized_identity,
        "nondeterministic_metadata_only": metadata_only,
        "same_size": same_size,
        "section_layout_match": section_layout_match,
        "allowed_ranges_match": allowed_ranges_match,
        "allowed_nondeterministic_sections": list(ALLOWED_SECTIONS),
        "raw_differing_byte_count": len(offsets),
        "differing_sections": differing_sections,
        "differing_ranges": difference_ranges(offsets, target_metadata["sections"]),
        "unexpected_differing_byte_count": len(unexpected),
        "unexpected_differing_offsets": unexpected[:256],
        "target": target_metadata,
        "rebuilt": rebuilt_metadata,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-deb", type=Path, required=True)
    parser.add_argument("--rebuilt-deb", type=Path, required=True)
    parser.add_argument("--verification-json", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()

    verification = json.loads(args.verification_json.read_text(encoding="utf-8"))
    if not verification.get("verification_complete"):
        raise RuntimeError("base source-lineage verification is incomplete")
    for field in (
        "source_relationship_valid",
        "source_lineage_validated",
        "elf_semantic_match",
    ):
        if verification.get(field) is not True:
            raise RuntimeError(f"base source-lineage verification failed: {field}")

    if verification["target_package"]["sha256"] != sha256_file(args.target_deb):
        raise RuntimeError("target DEB differs from base verification authority")
    if verification["rebuilt_package"]["sha256"] != sha256_file(args.rebuilt_deb):
        raise RuntimeError("rebuilt DEB differs from base verification authority")

    with tempfile.TemporaryDirectory(prefix="applauncher-reproducible-") as temporary:
        temporary_path = Path(temporary)
        target_root = temporary_path / "target"
        rebuilt_root = temporary_path / "rebuilt"
        target_root.mkdir()
        rebuilt_root.mkdir()
        run(["dpkg-deb", "-x", str(args.target_deb), str(target_root)])
        run(["dpkg-deb", "-x", str(args.rebuilt_deb), str(rebuilt_root)])
        target_elf = target_root / ELF_PATH
        rebuilt_elf = rebuilt_root / ELF_PATH
        if not target_elf.is_file() or not rebuilt_elf.is_file():
            raise RuntimeError(f"required ELF is missing: {ELF_PATH}")
        reproducibility = compare(target_elf, rebuilt_elf)

    if verification["target_elf"]["sha256"] != reproducibility["target"]["sha256"]:
        raise RuntimeError("target ELF differs from base verification record")
    if verification["rebuilt_elf"]["sha256"] != reproducibility["rebuilt"]["sha256"]:
        raise RuntimeError("rebuilt ELF differs from base verification record")

    expected_payload_change = [
        {
            "path": ELF_PATH.as_posix(),
            "fields": ["sha256"],
        }
    ]
    payload = verification["payload_comparison"]
    payload_non_elf_exact = all(
        [
            payload.get("target_only") == [],
            payload.get("rebuilt_only") == [],
            payload.get("changed_common") == expected_payload_change,
        ]
    )
    package_byte_identity = (
        verification["target_package"]["sha256"]
        == verification["rebuilt_package"]["sha256"]
    )
    raw_elf_identity = reproducibility["raw_byte_identity"]
    normalized_identity = reproducibility["normalized_elf_identity"]
    metadata_only = reproducibility["nondeterministic_metadata_only"]
    payload_reproducible_identity = payload_non_elf_exact and metadata_only
    strict_validated = all(
        [
            verification["source_relationship_valid"],
            verification["source_lineage_validated"],
            verification["elf_semantic_match"],
            normalized_identity,
            metadata_only,
            payload_reproducible_identity,
        ]
    )

    verification.update(
        {
            "source_lineage_validated": strict_validated,
            "normalized_elf_identity": normalized_identity,
            "elf_nondeterministic_metadata_only": metadata_only,
            "elf_byte_identity": raw_elf_identity,
            "package_byte_identity": package_byte_identity,
            "payload_reproducible_identity": payload_reproducible_identity,
            "elf_reproducibility": reproducibility,
            "payload_reproducibility": {
                "non_elf_payload_byte_identity": payload_non_elf_exact,
                "expected_raw_change": expected_payload_change,
                "exact_after_elf_metadata_normalization": payload_reproducible_identity,
            },
        }
    )
    verification["claims"] = {
        "source_status": (
            "public-direct-parent-lineage-validated"
            if strict_validated
            else "public-lineage-candidate"
        ),
        "reconstruction_status": (
            "built-and-reproducibly-validated"
            if strict_validated
            else "built-comparison-incomplete"
        ),
        "functional_elf_identity_claimed": normalized_identity and metadata_only,
        "byte_identity_claimed": package_byte_identity,
    }
    args.verification_json.write_text(
        json.dumps(verification, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary = [
        "# Gooroom applauncher Hancom source-lineage verification",
        "",
        f"- Source relationship valid: `{str(verification['source_relationship_valid']).lower()}`",
        f"- Source lineage strictly validated: `{str(strict_validated).lower()}`",
        f"- ELF semantic match: `{str(verification['elf_semantic_match']).lower()}`",
        f"- Normalized runtime ELF identity: `{str(normalized_identity).lower()}`",
        f"- ELF differences limited to Build ID/debug-link metadata: `{str(metadata_only).lower()}`",
        f"- Non-ELF payload byte identity: `{str(payload_non_elf_exact).lower()}`",
        f"- Raw ELF byte identity: `{str(raw_elf_identity).lower()}`",
        f"- Full DEB byte identity: `{str(package_byte_identity).lower()}`",
        f"- Raw differing ELF bytes: `{reproducibility['raw_differing_byte_count']}`",
        f"- Differing ELF sections: `{', '.join(reproducibility['differing_sections'])}`",
        "",
        "## Hashes",
        "",
        f"- Target DEB SHA-256: `{verification['target_package']['sha256']}`",
        f"- Rebuilt DEB SHA-256: `{verification['rebuilt_package']['sha256']}`",
        f"- Target ELF SHA-256: `{reproducibility['target']['sha256']}`",
        f"- Rebuilt ELF SHA-256: `{reproducibility['rebuilt']['sha256']}`",
        f"- Normalized ELF SHA-256: `{reproducibility['target']['normalized_sha256']}`",
        "",
        "Full byte identity is claimed only when the full DEB hashes are equal. ",
        "The normalized ELF claim permits only the validated 20-byte GNU Build ",
        "ID descriptor and its mechanically derived .gnu_debuglink payload.",
    ]
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text("\n".join(summary) + "\n", encoding="utf-8")
    return 0 if strict_validated else 1


if __name__ == "__main__":
    raise SystemExit(main())
