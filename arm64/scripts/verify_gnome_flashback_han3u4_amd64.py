#!/usr/bin/env python3
"""Strictly verify a reconstructed gnome-flashback AMD64 build.

The immutable Hancom Gooroom 3.3 vendor packages are the target authority.
Every binary package must preserve its complete semantic control paragraph,
installed path/type/mode/symlink set, all architecture-neutral payload bytes
(or the decompressed bytes of gzip members), and every ELF after removing
locked build metadata sections plus canonicalizing only dynamic string-table
storage proven semantically identical by complete symbol, dynamic-tag, and
string-multiset checks.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable

SOURCE = "gnome-flashback"
VERSION = "3.38.0-2+grm3u2+han3u4"
ELF_MAGIC = b"\x7fELF"
EXPECTED_PACKAGES = {
    "gnome-flashback": {
        "architecture": "amd64",
        "filename": "gnome-flashback_3.38.0-2+grm3u2+han3u4_amd64.deb",
        "size": 436564,
        "sha256": "6c62fea3341f7c208448250d9eaa2b467df99abdbad53bc236f089fad9741408",
    },
    "gnome-flashback-common": {
        "architecture": "all",
        "filename": "gnome-flashback-common_3.38.0-2+grm3u2+han3u4_all.deb",
        "size": 99916,
        "sha256": "5770961e60c68b25ea7a84ab14871635b450b79f25f9596c79edad67a34e4543",
    },
    "gnome-session-flashback": {
        "architecture": "all",
        "filename": "gnome-session-flashback_3.38.0-2+grm3u2+han3u4_all.deb",
        "size": 14508,
        "sha256": "3968b152293606e4626fbe3317913d6f57add08001c3a5a66abd71a8576abcf6",
    },
}
NONDETERMINISTIC_ELF_SECTIONS = (
    ".note.gnu.build-id",
    ".gnu_debuglink",
    ".gnu_debugaltlink",
    ".comment",
)


def run(arguments: list[str], *, binary: bool = False) -> str | bytes:
    completed = subprocess.run(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not binary,
        check=False,
    )
    if completed.returncode:
        stdout = completed.stdout
        stderr = completed.stderr
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    return completed.stdout


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_control_paragraph(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        if not raw_line:
            continue
        if raw_line[0].isspace():
            if current is None:
                raise ValueError("control continuation without a field")
            fields[current] += "\n" + raw_line[1:]
            continue
        if ":" not in raw_line:
            raise ValueError(f"malformed control line: {raw_line!r}")
        current, value = raw_line.split(":", 1)
        current = current.strip()
        fields[current] = value.lstrip()
    return fields


def deb_control(path: Path) -> dict[str, str]:
    return parse_control_paragraph(str(run(["dpkg-deb", "-f", str(path)])))


def declared_source(control: dict[str, str]) -> str:
    value = control.get("Source", "")
    if value:
        return value.split(" ", 1)[0]
    return control.get("Package", "").removesuffix("-dbgsym")


def extract_payload(path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    run(["dpkg-deb", "-x", str(path), str(destination)])


def extract_control(path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    run(["dpkg-deb", "-e", str(path), str(destination)])


def payload_manifest(root: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        row: dict[str, Any] = {
            "path": relative,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
        if path.is_symlink():
            row.update(type="symlink", target=os.readlink(path))
        elif path.is_dir():
            row.update(type="directory")
        elif path.is_file():
            payload = path.read_bytes()
            row.update(
                type="file",
                size=len(payload),
                sha256=sha256_bytes(payload),
                elf=payload.startswith(ELF_MAGIC),
            )
            if path.name.endswith(".gz"):
                try:
                    clear = gzip.decompress(payload)
                except OSError:
                    pass
                else:
                    row["decompressed_size"] = len(clear)
                    row["decompressed_sha256"] = sha256_bytes(clear)
        else:
            row.update(type="other")
        rows[relative] = row
    return rows


def auxiliary_control_manifest(root: Path) -> dict[str, dict[str, Any]]:
    """Return exact non-generated control members.

    `control` is compared semantically and `md5sums` follows the payload. All
    maintainer scripts, triggers, conffiles, and other members remain exact.
    """

    rows: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in {"control", "md5sums"}:
            continue
        payload = path.read_bytes()
        rows[relative] = {
            "path": relative,
            "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
            "size": len(payload),
            "sha256": sha256_bytes(payload),
        }
    return rows


def elf_header(path: Path) -> dict[str, str]:
    selected = {
        "Class",
        "Data",
        "Version",
        "OS/ABI",
        "ABI Version",
        "Type",
        "Machine",
        "Entry point address",
        "Flags",
    }
    result: dict[str, str] = {}
    for line in str(run(["readelf", "-hW", str(path)])).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in selected:
            result[key] = value.strip()
    return result


def elf_interpreter(path: Path) -> str | None:
    output = str(run(["readelf", "-lW", str(path)]))
    match = re.search(r"Requesting program interpreter:\s*([^]]+)\]", output)
    return match.group(1).strip() if match else None


def dynamic_identity(path: Path) -> dict[str, list[str]]:
    output = str(run(["readelf", "-dW", str(path)]))
    return {
        "needed": re.findall(r"Shared library: \[([^]]+)\]", output),
        "soname": re.findall(r"Library soname: \[([^]]+)\]", output),
        "rpath": re.findall(r"Library rpath: \[([^]]+)\]", output),
        "runpath": re.findall(r"Library runpath: \[([^]]+)\]", output),
    }


def exported_symbols(path: Path) -> list[tuple[str, ...]]:
    rows: list[tuple[str, ...]] = []
    pattern = re.compile(
        r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s+(\S+)\s+"
        r"(\S+)\s+(\S+)\s*(.*)$"
    )
    for line in str(run(["readelf", "--dyn-syms", "-W", str(path)])).splitlines():
        match = pattern.match(line)
        if not match:
            continue
        kind, binding, visibility, index, name = (
            value.strip() for value in match.groups()
        )
        if index == "UND" or binding not in {"GLOBAL", "WEAK", "GNU_UNIQUE"}:
            continue
        rows.append((kind, binding, visibility, index, name))
    return sorted(rows)



def complete_dynamic_symbols(path: Path) -> list[tuple[str, ...]]:
    rows: list[tuple[str, ...]] = []
    pattern = re.compile(
        r"^\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+"
        r"(\S+)\s+(\S+)\s*(.*)$"
    )
    for line in str(run(["readelf", "--dyn-syms", "-W", str(path)])).splitlines():
        match = pattern.match(line)
        if match:
            rows.append(tuple(value.strip() for value in match.groups()))
    return rows


def complete_dynamic_table(path: Path) -> list[tuple[str, ...]]:
    return [
        tuple(line.split())
        for line in str(run(["readelf", "-dW", str(path)])).splitlines()
        if line.lstrip().startswith("0x")
    ]


def semantic_sequence_summary(rows: list[tuple[str, ...]]) -> dict[str, Any]:
    payload = json.dumps(
        rows, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return {"count": len(rows), "canonical_sha256": sha256_bytes(payload)}


def elf_section_layout(path: Path) -> dict[str, dict[str, int]]:
    rows: dict[str, dict[str, int]] = {}
    pattern = re.compile(
        r"^\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9a-fA-F]+\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
    )
    for line in str(run(["readelf", "-SW", str(path)])).splitlines():
        match = pattern.match(line)
        if not match:
            continue
        name, offset, size, entry_size = match.groups()
        rows[name] = {
            "offset": int(offset, 16),
            "size": int(size, 16),
            "entry_size": int(entry_size, 16),
        }
    return rows


def dynamic_strings(path: Path) -> tuple[bytes, ...]:
    section = elf_section_layout(path).get(".dynstr")
    if section is None:
        return ()
    payload = path.read_bytes()
    start = section["offset"]
    end = start + section["size"]
    if end > len(payload):
        raise RuntimeError(f"{path}: .dynstr escapes the ELF file")
    return tuple(sorted(payload[start:end].split(b"\0")))


def dynamic_string_multiset_summary(strings: tuple[bytes, ...]) -> dict[str, Any]:
    digest = hashlib.sha256()
    for value in strings:
        digest.update(len(value).to_bytes(8, "little"))
        digest.update(value)
    return {
        "string_count": len(strings),
        "canonical_multiset_sha256": digest.hexdigest(),
    }


def canonicalize_dynamic_string_storage(path: Path) -> dict[str, Any]:
    payload = bytearray(path.read_bytes())
    if not payload.startswith(ELF_MAGIC):
        raise RuntimeError(f"{path}: not an ELF file")
    if len(payload) < 6 or payload[4] != 2 or payload[5] != 1:
        raise RuntimeError(f"{path}: expected ELF64 little-endian storage")
    sections = elf_section_layout(path)
    dynstr = sections.get(".dynstr")
    dynsym = sections.get(".dynsym")
    if dynstr is None and dynsym is None:
        return {"applied": False, "dynstr_size": 0, "dynsym_entry_count": 0}
    if dynstr is None or dynsym is None:
        raise RuntimeError(f"{path}: incomplete dynamic string/symbol section pair")
    if dynsym["entry_size"] != 24 or dynsym["size"] % dynsym["entry_size"]:
        raise RuntimeError(f"{path}: unexpected ELF64 .dynsym geometry")
    dynstr_start = dynstr["offset"]
    dynstr_end = dynstr_start + dynstr["size"]
    dynsym_start = dynsym["offset"]
    dynsym_end = dynsym_start + dynsym["size"]
    if max(dynstr_end, dynsym_end) > len(payload):
        raise RuntimeError(f"{path}: dynamic section escapes the ELF file")
    payload[dynstr_start:dynstr_end] = b"\0" * dynstr["size"]
    for offset in range(dynsym_start, dynsym_end, dynsym["entry_size"]):
        payload[offset:offset + 4] = b"\0" * 4
    path.write_bytes(payload)
    return {
        "applied": True,
        "dynstr_size": dynstr["size"],
        "dynsym_entry_count": dynsym["size"] // dynsym["entry_size"],
    }


def normalized_elf(path: Path, destination: Path) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, destination)
    temporary = destination.with_suffix(destination.suffix + ".new")
    command = ["objcopy"]
    for section in NONDETERMINISTIC_ELF_SECTIONS:
        command.append(f"--remove-section={section}")
    command.extend([str(destination), str(temporary)])
    run(command)
    temporary.replace(destination)
    dynamic_storage = canonicalize_dynamic_string_storage(destination)
    return {
        "size": destination.stat().st_size,
        "sha256": sha256_file(destination),
        "dynamic_string_storage": dynamic_storage,
    }


def find_debs(directory: Path) -> tuple[dict[str, Path], list[dict[str, Any]]]:
    selected: dict[str, Path] = {}
    extras: list[dict[str, Any]] = []
    for deb in sorted(directory.glob("*.deb")):
        control = deb_control(deb)
        package = control.get("Package", "")
        row = {
            "package": package,
            "version": control.get("Version", ""),
            "architecture": control.get("Architecture", ""),
            "source": declared_source(control),
            "filename": deb.name,
            "size": deb.stat().st_size,
            "sha256": sha256_file(deb),
        }
        if package in EXPECTED_PACKAGES:
            if package in selected:
                raise SystemExit(f"duplicate DEB for {package} in {directory}")
            selected[package] = deb
        else:
            extras.append(row)
    return selected, extras


def compare_mapping(
    target: dict[str, dict[str, Any]],
    candidate: dict[str, dict[str, Any]],
    *,
    kind: str,
) -> tuple[bool, list[dict[str, Any]]]:
    differences: list[dict[str, Any]] = []
    for path in sorted(set(target) | set(candidate)):
        left = target.get(path)
        right = candidate.get(path)
        if left != right:
            differences.append(
                {"kind": kind, "path": path, "target": left, "candidate": right}
            )
    return not differences, differences


def compare_package(
    package: str,
    target_deb: Path,
    candidate_deb: Path,
    temporary: Path,
    output: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fatal: list[dict[str, Any]] = []
    target_control = deb_control(target_deb)
    candidate_control = deb_control(candidate_deb)
    control_identical = target_control == candidate_control
    if not control_identical:
        fatal.append(
            {
                "kind": "control-fields",
                "package": package,
                "target": target_control,
                "candidate": candidate_control,
            }
        )

    target_root = temporary / "target" / package
    candidate_root = temporary / "candidate" / package
    target_control_root = temporary / "target-control" / package
    candidate_control_root = temporary / "candidate-control" / package
    extract_payload(target_deb, target_root)
    extract_payload(candidate_deb, candidate_root)
    extract_control(target_deb, target_control_root)
    extract_control(candidate_deb, candidate_control_root)

    target_manifest = payload_manifest(target_root)
    candidate_manifest = payload_manifest(candidate_root)
    write_json(output / "manifests" / f"{package}-target.json", target_manifest)
    write_json(output / "manifests" / f"{package}-candidate.json", candidate_manifest)

    target_aux = auxiliary_control_manifest(target_control_root)
    candidate_aux = auxiliary_control_manifest(candidate_control_root)
    aux_identical, aux_differences = compare_mapping(
        target_aux, candidate_aux, kind="auxiliary-control-member"
    )
    for row in aux_differences:
        row["package"] = package
    fatal.extend(aux_differences)

    same_path_set = set(target_manifest) == set(candidate_manifest)
    if not same_path_set:
        fatal.append(
            {
                "kind": "payload-path-set",
                "package": package,
                "target_only": sorted(set(target_manifest) - set(candidate_manifest)),
                "candidate_only": sorted(set(candidate_manifest) - set(target_manifest)),
            }
        )

    non_elf_rows: list[dict[str, Any]] = []
    elf_rows: list[dict[str, Any]] = []
    for relative in sorted(set(target_manifest) | set(candidate_manifest)):
        left = target_manifest.get(relative)
        right = candidate_manifest.get(relative)
        if left is None or right is None:
            continue
        if left["type"] != right["type"] or left["mode"] != right["mode"]:
            fatal.append(
                {
                    "kind": "payload-type-or-mode",
                    "package": package,
                    "path": relative,
                    "target": left,
                    "candidate": right,
                }
            )
            continue
        if left["type"] == "symlink":
            identical = left.get("target") == right.get("target")
            if not identical:
                fatal.append(
                    {
                        "kind": "symlink-target",
                        "package": package,
                        "path": relative,
                        "target": left.get("target"),
                        "candidate": right.get("target"),
                    }
                )
            continue
        if left["type"] != "file":
            continue
        if bool(left.get("elf")) != bool(right.get("elf")):
            fatal.append(
                {
                    "kind": "elf-classification",
                    "package": package,
                    "path": relative,
                }
            )
            continue

        target_path = target_root / relative
        candidate_path = candidate_root / relative
        if not left.get("elf"):
            raw_identical = left.get("sha256") == right.get("sha256")
            decompressed_identical = (
                left.get("decompressed_sha256") is not None
                and left.get("decompressed_sha256")
                == right.get("decompressed_sha256")
            )
            accepted = raw_identical or decompressed_identical
            row = {
                "package": package,
                "path": relative,
                "target_sha256": left.get("sha256"),
                "candidate_sha256": right.get("sha256"),
                "raw_identical": raw_identical,
                "target_decompressed_sha256": left.get("decompressed_sha256"),
                "candidate_decompressed_sha256": right.get("decompressed_sha256"),
                "decompressed_identical": decompressed_identical,
                "verified": accepted,
            }
            non_elf_rows.append(row)
            if not accepted:
                fatal.append(
                    {
                        "kind": "non-elf-payload",
                        "package": package,
                        "path": relative,
                        "target": left,
                        "candidate": right,
                    }
                )
            continue

        key = hashlib.sha256(f"{package}:{relative}".encode()).hexdigest()
        normalized_target = normalized_elf(
            target_path, temporary / "normalized" / f"{key}-target"
        )
        normalized_candidate = normalized_elf(
            candidate_path, temporary / "normalized" / f"{key}-candidate"
        )
        target_header = elf_header(target_path)
        candidate_header = elf_header(candidate_path)
        target_dynamic = dynamic_identity(target_path)
        candidate_dynamic = dynamic_identity(candidate_path)
        target_exports = exported_symbols(target_path)
        candidate_exports = exported_symbols(candidate_path)
        target_complete_symbols = complete_dynamic_symbols(target_path)
        candidate_complete_symbols = complete_dynamic_symbols(candidate_path)
        target_complete_dynamic = complete_dynamic_table(target_path)
        candidate_complete_dynamic = complete_dynamic_table(candidate_path)
        target_dynamic_strings = dynamic_strings(target_path)
        candidate_dynamic_strings = dynamic_strings(candidate_path)
        row = {
            "package": package,
            "path": relative,
            "target_sha256": left.get("sha256"),
            "candidate_sha256": right.get("sha256"),
            "raw_identical": left.get("sha256") == right.get("sha256"),
            "target_header": target_header,
            "candidate_header": candidate_header,
            "header_identical": target_header == candidate_header,
            "target_interpreter": elf_interpreter(target_path),
            "candidate_interpreter": elf_interpreter(candidate_path),
            "interpreter_identical": elf_interpreter(target_path)
            == elf_interpreter(candidate_path),
            "target_dynamic": target_dynamic,
            "candidate_dynamic": candidate_dynamic,
            "dynamic_identity_identical": target_dynamic == candidate_dynamic,
            "target_exported_symbols": target_exports,
            "candidate_exported_symbols": candidate_exports,
            "exported_symbols_identical": target_exports == candidate_exports,
            "target_complete_dynamic_symbols": semantic_sequence_summary(
                target_complete_symbols
            ),
            "candidate_complete_dynamic_symbols": semantic_sequence_summary(
                candidate_complete_symbols
            ),
            "complete_dynamic_symbols_identical": (
                target_complete_symbols == candidate_complete_symbols
            ),
            "target_complete_dynamic_table": semantic_sequence_summary(
                target_complete_dynamic
            ),
            "candidate_complete_dynamic_table": semantic_sequence_summary(
                candidate_complete_dynamic
            ),
            "complete_dynamic_table_identical": (
                target_complete_dynamic == candidate_complete_dynamic
            ),
            "target_dynamic_string_multiset": (
                dynamic_string_multiset_summary(target_dynamic_strings)
            ),
            "candidate_dynamic_string_multiset": (
                dynamic_string_multiset_summary(candidate_dynamic_strings)
            ),
            "dynamic_string_multiset_identical": (
                target_dynamic_strings == candidate_dynamic_strings
            ),
            "normalized_target": normalized_target,
            "normalized_candidate": normalized_candidate,
            "normalized_byte_identity": normalized_target == normalized_candidate,
            "removed_sections": list(NONDETERMINISTIC_ELF_SECTIONS),
            "canonicalized_storage": [".dynstr", ".dynsym.st_name"],
        }
        row["verified"] = all(
            row[field]
            for field in (
                "header_identical",
                "interpreter_identical",
                "dynamic_identity_identical",
                "exported_symbols_identical",
                "complete_dynamic_symbols_identical",
                "complete_dynamic_table_identical",
                "dynamic_string_multiset_identical",
                "normalized_byte_identity",
            )
        )
        elf_rows.append(row)
        if not row["verified"]:
            fatal.append(
                {
                    "kind": "normalized-elf-identity",
                    "package": package,
                    "path": relative,
                    "evidence": row,
                }
            )

    write_json(output / "comparisons" / f"{package}-non-elf.json", non_elf_rows)
    write_json(output / "comparisons" / f"{package}-elf.json", elf_rows)
    result = {
        "package": package,
        "target_deb": {
            "filename": target_deb.name,
            "size": target_deb.stat().st_size,
            "sha256": sha256_file(target_deb),
        },
        "candidate_deb": {
            "filename": candidate_deb.name,
            "size": candidate_deb.stat().st_size,
            "sha256": sha256_file(candidate_deb),
        },
        "control_fields_identical": control_identical,
        "auxiliary_control_members_identical": aux_identical,
        "same_payload_path_set": same_path_set,
        "non_elf_file_count": len(non_elf_rows),
        "non_elf_payload_identity": all(row["verified"] for row in non_elf_rows),
        "elf_file_count": len(elf_rows),
        "normalized_elf_identity": all(row["verified"] for row in elf_rows),
        "raw_elf_identity": all(row["raw_identical"] for row in elf_rows),
        "fatal_difference_count": len(fatal),
        "verified": not fatal,
    }
    return result, fatal


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-deb-dir", type=Path, required=True)
    parser.add_argument("--candidate-deb-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    target_dir = args.target_deb_dir.resolve()
    candidate_dir = args.candidate_deb_dir.resolve()
    output = args.output_dir.resolve()
    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)

    fatal: list[dict[str, Any]] = []
    target_debs, target_extras = find_debs(target_dir)
    candidate_debs, candidate_extras = find_debs(candidate_dir)

    if set(target_debs) != set(EXPECTED_PACKAGES):
        fatal.append(
            {
                "kind": "target-package-set",
                "expected": sorted(EXPECTED_PACKAGES),
                "actual": sorted(target_debs),
            }
        )
    if set(candidate_debs) != set(EXPECTED_PACKAGES):
        fatal.append(
            {
                "kind": "candidate-package-set",
                "expected": sorted(EXPECTED_PACKAGES),
                "actual": sorted(candidate_debs),
            }
        )

    for package, authority in EXPECTED_PACKAGES.items():
        path = target_debs.get(package)
        if path is None:
            continue
        control = deb_control(path)
        if path.name != authority["filename"]:
            fatal.append(
                {
                    "kind": "target-filename-authority",
                    "package": package,
                    "actual": path.name,
                    "expected": authority["filename"],
                }
            )
        if path.stat().st_size != authority["size"]:
            fatal.append({"kind": "target-size-authority", "package": package})
        if sha256_file(path) != authority["sha256"]:
            fatal.append({"kind": "target-sha256-authority", "package": package})
        if control.get("Package") != package:
            fatal.append({"kind": "target-package-identity", "package": package})
        if control.get("Version") != VERSION:
            fatal.append({"kind": "target-version-identity", "package": package})
        if control.get("Architecture") != authority["architecture"]:
            fatal.append(
                {"kind": "target-architecture-identity", "package": package}
            )
        if declared_source(control) != SOURCE:
            fatal.append({"kind": "target-source-identity", "package": package})

    for package, path in candidate_debs.items():
        authority = EXPECTED_PACKAGES[package]
        control = deb_control(path)
        if control.get("Version") != VERSION:
            fatal.append({"kind": "candidate-version-identity", "package": package})
        if control.get("Architecture") != authority["architecture"]:
            fatal.append(
                {"kind": "candidate-architecture-identity", "package": package}
            )
        if declared_source(control) != SOURCE:
            fatal.append({"kind": "candidate-source-identity", "package": package})

    invalid_extras = [
        row
        for row in candidate_extras
        if not (
            row["package"].endswith("-dbgsym")
            and row["version"] == VERSION
            and row["architecture"] == "amd64"
            and row["source"] == SOURCE
        )
    ]
    if invalid_extras:
        fatal.append({"kind": "unexpected-candidate-debs", "debs": invalid_extras})
    if target_extras:
        fatal.append({"kind": "unexpected-target-debs", "debs": target_extras})

    package_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="gnome-flashback-amd64-") as temp:
        temporary = Path(temp)
        for package in sorted(set(target_debs) & set(candidate_debs)):
            result, differences = compare_package(
                package,
                target_debs[package],
                candidate_debs[package],
                temporary,
                output,
            )
            package_results.append(result)
            fatal.extend(differences)

    write_json(output / "target-extra-debs.json", target_extras)
    write_json(output / "candidate-extra-debs.json", candidate_extras)
    write_json(output / "package-comparisons.json", package_results)
    write_json(output / "differences.json", fatal)

    all_controls = bool(package_results) and all(
        row["control_fields_identical"] for row in package_results
    )
    all_aux = bool(package_results) and all(
        row["auxiliary_control_members_identical"] for row in package_results
    )
    all_paths = bool(package_results) and all(
        row["same_payload_path_set"] for row in package_results
    )
    all_non_elf = bool(package_results) and all(
        row["non_elf_payload_identity"] for row in package_results
    )
    elf_count = sum(row["elf_file_count"] for row in package_results)
    all_elf = elf_count > 0 and all(
        row["normalized_elf_identity"] for row in package_results
    )
    all_raw_elf = elf_count > 0 and all(
        row["raw_elf_identity"] for row in package_results
    )
    summary = {
        "schema": 1,
        "source": SOURCE,
        "source_version": VERSION,
        "target_architecture": "amd64",
        "policy": (
            "exact-semantic-control-plus-exact-auxiliary-control-plus-"
            "exact-path-type-mode-symlink-plus-non-elf-byte-or-decompressed-"
            "identity-plus-elf-byte-identity-after-build-metadata-removal-and-"
            "semantically-proven-dynamic-string-storage-canonicalization"
        ),
        "expected_binary_package_count": len(EXPECTED_PACKAGES),
        "compared_binary_package_count": len(package_results),
        "candidate_debug_package_count": len(candidate_extras),
        "control_fields_identical": all_controls,
        "auxiliary_control_members_identical": all_aux,
        "same_payload_path_sets": all_paths,
        "non_elf_payload_identity": all_non_elf,
        "elf_file_count": elf_count,
        "normalized_elf_identity": all_elf,
        "raw_elf_identity": all_raw_elf,
        "fatal_difference_count": len(fatal),
        "package_results": package_results,
        "verified": (
            len(package_results) == len(EXPECTED_PACKAGES)
            and all_controls
            and all_aux
            and all_paths
            and all_non_elf
            and all_elf
            and not fatal
        ),
    }
    write_json(output / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    if fatal:
        print(json.dumps(fatal, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
