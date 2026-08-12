#!/usr/bin/env python3
"""Verify reconstructed dockbarx han3u1 against the exact shipped AMD64 DEB."""

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
from typing import Any

SOURCE = "gooroom-dockbarx-applet"
VERSION = "0.3.1+grm3u1+han3u1"
TARGET_SHA256 = "9d810f3185babcd24e0d7c868586c930a8d39bcb7b0a01dee4d8cee02f440b0d"
TARGET_SIZE = 14096
ELF_MAGIC = b"\x7fELF"
NONDETERMINISTIC_SECTIONS = (
    ".note.gnu.build-id",
    ".gnu_debuglink",
    ".gnu_debugaltlink",
    ".comment",
)
CONTROL_FIELDS = (
    "Package",
    "Version",
    "Architecture",
    "Maintainer",
    "Depends",
    "Section",
    "Priority",
    "Description",
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
        stderr = completed.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n{stderr}"
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
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def deb_field(path: Path, field: str) -> str:
    return str(run(["dpkg-deb", "-f", str(path), field])).strip()


def control_identity(path: Path) -> dict[str, str]:
    return {field: deb_field(path, field) for field in CONTROL_FIELDS}


def extract_deb(path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    run(["dpkg-deb", "-x", str(path), str(destination)])


def manifest(root: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        row: dict[str, Any] = {
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


def elf_header(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    wanted = {
        "Class",
        "Data",
        "Type",
        "Machine",
        "Entry point address",
    }
    for line in str(run(["readelf", "-hW", str(path)])).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in wanted:
            result[key] = value.strip()
    return result


def dynamic_identity(path: Path) -> dict[str, Any]:
    output = str(run(["readelf", "-dW", str(path)]))
    return {
        "needed": re.findall(r"Shared library: \[([^]]+)\]", output),
        "soname": re.findall(r"Library soname: \[([^]]+)\]", output),
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


def normalized_elf(path: Path, destination: Path) -> dict[str, Any]:
    shutil.copyfile(path, destination)
    command = ["objcopy"]
    for section in NONDETERMINISTIC_SECTIONS:
        command.append(f"--remove-section={section}")
    command.extend([str(destination), str(destination) + ".new"])
    run(command)
    normalized = Path(str(destination) + ".new")
    normalized.replace(destination)
    return {
        "size": destination.stat().st_size,
        "sha256": sha256_file(destination),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-deb", type=Path, required=True)
    parser.add_argument("--candidate-deb", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    target_deb = args.target_deb.resolve()
    candidate_deb = args.candidate_deb.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    fatal: list[dict[str, Any]] = []
    if target_deb.stat().st_size != TARGET_SIZE:
        fatal.append({"kind": "target-size-authority"})
    if sha256_file(target_deb) != TARGET_SHA256:
        fatal.append({"kind": "target-sha256-authority"})

    target_control = control_identity(target_deb)
    candidate_control = control_identity(candidate_deb)
    for control in (target_control, candidate_control):
        if control["Package"] != SOURCE:
            fatal.append({"kind": "package-identity", "control": control})
        if control["Version"] != VERSION:
            fatal.append({"kind": "version-identity", "control": control})
        if control["Architecture"] != "amd64":
            fatal.append({"kind": "architecture-identity", "control": control})
    control_identical = target_control == candidate_control
    if not control_identical:
        fatal.append(
            {
                "kind": "control-fields",
                "target": target_control,
                "candidate": candidate_control,
            }
        )

    with tempfile.TemporaryDirectory(prefix="dockbarx-amd64-equivalence-") as temp:
        temporary = Path(temp)
        target_root = temporary / "target"
        candidate_root = temporary / "candidate"
        extract_deb(target_deb, target_root)
        extract_deb(candidate_deb, candidate_root)
        target_manifest = manifest(target_root)
        candidate_manifest = manifest(candidate_root)
        write_json(output / "target-manifest.json", target_manifest)
        write_json(output / "candidate-manifest.json", candidate_manifest)

        same_path_set = set(target_manifest) == set(candidate_manifest)
        if not same_path_set:
            fatal.append(
                {
                    "kind": "path-set",
                    "target_only": sorted(set(target_manifest) - set(candidate_manifest)),
                    "candidate_only": sorted(set(candidate_manifest) - set(target_manifest)),
                }
            )

        elf_rows: list[dict[str, Any]] = []
        non_elf_rows: list[dict[str, Any]] = []
        for relative in sorted(set(target_manifest) | set(candidate_manifest)):
            left = target_manifest.get(relative)
            right = candidate_manifest.get(relative)
            if left is None or right is None:
                continue
            if left["type"] != right["type"] or left["mode"] != right["mode"]:
                fatal.append(
                    {
                        "kind": "type-or-mode",
                        "path": relative,
                        "target": left,
                        "candidate": right,
                    }
                )
                continue
            if left["type"] == "symlink":
                if left["target"] != right["target"]:
                    fatal.append({"kind": "symlink-target", "path": relative})
                continue
            if left["type"] != "file":
                continue
            if bool(left.get("elf")) != bool(right.get("elf")):
                fatal.append({"kind": "elf-classification", "path": relative})
                continue

            target_path = target_root / relative
            candidate_path = candidate_root / relative
            if not left.get("elf"):
                raw_identical = left["sha256"] == right["sha256"]
                decompressed_identical = (
                    left.get("decompressed_sha256") is not None
                    and left.get("decompressed_sha256")
                    == right.get("decompressed_sha256")
                )
                accepted = raw_identical or decompressed_identical
                row = {
                    "path": relative,
                    "raw_identical": raw_identical,
                    "decompressed_identical": decompressed_identical,
                    "accepted": accepted,
                }
                non_elf_rows.append(row)
                if not accepted:
                    fatal.append(
                        {
                            "kind": "non-elf-payload",
                            "path": relative,
                            "target": left,
                            "candidate": right,
                        }
                    )
                continue

            normalized_target_path = temporary / (
                "normalized-target-" + hashlib.sha256(relative.encode()).hexdigest()
            )
            normalized_candidate_path = temporary / (
                "normalized-candidate-" + hashlib.sha256(relative.encode()).hexdigest()
            )
            normalized_target = normalized_elf(
                target_path, normalized_target_path
            )
            normalized_candidate = normalized_elf(
                candidate_path, normalized_candidate_path
            )
            row = {
                "path": relative,
                "target_sha256": left["sha256"],
                "candidate_sha256": right["sha256"],
                "raw_identical": left["sha256"] == right["sha256"],
                "header_identical": elf_header(target_path)
                == elf_header(candidate_path),
                "dynamic_identity_identical": dynamic_identity(target_path)
                == dynamic_identity(candidate_path),
                "exported_symbols_identical": exported_symbols(target_path)
                == exported_symbols(candidate_path),
                "normalized_target": normalized_target,
                "normalized_candidate": normalized_candidate,
                "normalized_byte_identity": normalized_target
                == normalized_candidate,
                "removed_sections": list(NONDETERMINISTIC_SECTIONS),
            }
            row["verified"] = all(
                row[field]
                for field in (
                    "header_identical",
                    "dynamic_identity_identical",
                    "exported_symbols_identical",
                    "normalized_byte_identity",
                )
            )
            elf_rows.append(row)
            if not row["verified"]:
                fatal.append(
                    {
                        "kind": "normalized-elf-identity",
                        "path": relative,
                        "evidence": row,
                    }
                )

    write_json(output / "elf-comparison.json", elf_rows)
    write_json(output / "non-elf-comparison.json", non_elf_rows)
    write_json(output / "differences.json", fatal)
    summary = {
        "schema": 1,
        "source": SOURCE,
        "source_version": VERSION,
        "policy": (
            "exact-control-and-non-elf-payload-plus-normalized-elf-byte-identity"
        ),
        "target_deb_sha256": TARGET_SHA256,
        "candidate_deb_sha256": sha256_file(candidate_deb),
        "control_fields_identical": control_identical,
        "same_path_set": same_path_set,
        "non_elf_file_count": len(non_elf_rows),
        "non_elf_payload_identity": bool(non_elf_rows)
        and all(row["accepted"] for row in non_elf_rows),
        "elf_file_count": len(elf_rows),
        "normalized_elf_identity": bool(elf_rows)
        and all(row["verified"] for row in elf_rows),
        "raw_elf_identity": bool(elf_rows)
        and all(row["raw_identical"] for row in elf_rows),
        "fatal_difference_count": len(fatal),
        "verified": not fatal and bool(elf_rows),
    }
    write_json(output / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    if fatal:
        print(json.dumps(fatal, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
