#!/usr/bin/env python3
"""Verify a native ARM64 integration-applet candidate against the locked AMD64 target.

Byte-identical ELF comparison is impossible across architectures. This verifier
therefore requires exact normalized non-ELF payloads, identical ELF path sets,
identical embedded GResources, identical defined dynamic-symbol sets, identical
DT_NEEDED sets, and AArch64 machine type for every candidate ELF.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

MULTIARCH_RE = re.compile(
    r"^usr/lib/(?:x86_64-linux-gnu|aarch64-linux-gnu)/"
)
EXPECTED_PACKAGE = "gooroom-integration-applet"
EXPECTED_VERSION = "0.3.1+grm3u1+han3u3"


def run(command: list[str], *, check: bool = True, text: bool = True) -> subprocess.CompletedProcess:
    process = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        check=False,
    )
    if check and process.returncode:
        stdout = process.stdout if text else process.stdout.decode("utf-8", errors="replace")
        stderr = process.stderr if text else process.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(command)}\n{stdout}\n{stderr}"
        )
    return process


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def control(deb: Path, field: str) -> str:
    return run(["dpkg-deb", "-f", str(deb), field]).stdout.strip()


def normalize_path(relative: str) -> str:
    return MULTIARCH_RE.sub("usr/lib/@MULTIARCH@/", relative)


def is_elf(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    with path.open("rb") as stream:
        return stream.read(4) == b"\x7fELF"


def machine(path: Path) -> dict[str, str]:
    output = run(["readelf", "-h", str(path)]).stdout
    result: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in {"Class", "Data", "Type", "Machine"}:
            result[key.lower()] = value.strip()
    return result


def defined_dynamic_symbols(path: Path) -> list[str]:
    output = run(["readelf", "--dyn-syms", "-W", str(path)]).stdout
    names: set[str] = set()
    pattern = re.compile(
        r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(.+?)\s*$"
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        section, name = match.groups()
        if section == "UND":
            continue
        clean = name.split("@", 1)[0]
        if clean:
            names.add(clean)
    return sorted(names)


def needed_libraries(path: Path) -> list[str]:
    output = run(["readelf", "-d", "-W", str(path)]).stdout
    names = re.findall(r"\(NEEDED\).*?\[(.+?)\]", output)
    return sorted(set(names))


def resources(path: Path) -> dict[str, dict[str, Any]]:
    listing = run(["gresource", "list", str(path)], check=False)
    if listing.returncode != 0:
        return {}
    result: dict[str, dict[str, Any]] = {}
    for resource_path in sorted(
        line.strip() for line in listing.stdout.splitlines() if line.strip()
    ):
        extracted = run(
            ["gresource", "extract", str(path), resource_path],
            check=False,
            text=False,
        )
        if extracted.returncode != 0:
            raise RuntimeError(f"failed to extract GResource {resource_path} from {path}")
        data = extracted.stdout
        result[resource_path] = {
            "size": len(data),
            "sha256": sha256_bytes(data),
        }
    return result


def inventory(root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Path]]:
    non_elf: dict[str, dict[str, Any]] = {}
    elfs: dict[str, Path] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        normalized = normalize_path(relative)
        if path.is_symlink():
            non_elf[normalized] = {
                "kind": "symlink",
                "target": normalize_path(os.readlink(path)),
            }
        elif path.is_file():
            if is_elf(path):
                if normalized in elfs:
                    raise RuntimeError(f"normalized ELF collision: {normalized}")
                elfs[normalized] = path
            else:
                non_elf[normalized] = {
                    "kind": "file",
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
    return non_elf, elfs


def compare_maps(target: dict[str, Any], candidate: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(set(target) | set(candidate)):
        left = target.get(path)
        right = candidate.get(path)
        if left == right:
            continue
        rows.append({
            "path": path,
            "target": left,
            "candidate": right,
            "status": (
                "candidate-only" if left is None
                else "target-only" if right is None
                else "different"
            ),
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-deb", type=Path, required=True)
    parser.add_argument("--candidate-deb", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    target_deb = args.target_deb.resolve()
    candidate_deb = args.candidate_deb.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    target_control = {
        field: control(target_deb, field)
        for field in ("Package", "Version", "Architecture")
    }
    candidate_control = {
        field: control(candidate_deb, field)
        for field in ("Package", "Version", "Architecture")
    }

    with tempfile.TemporaryDirectory(prefix="integration-applet-arm64-v1-") as temporary:
        temporary_path = Path(temporary)
        target_root = temporary_path / "target"
        candidate_root = temporary_path / "candidate"
        target_root.mkdir()
        candidate_root.mkdir()
        run(["dpkg-deb", "-x", str(target_deb), str(target_root)])
        run(["dpkg-deb", "-x", str(candidate_deb), str(candidate_root)])

        target_non_elf, target_elfs = inventory(target_root)
        candidate_non_elf, candidate_elfs = inventory(candidate_root)
        non_elf_differences = compare_maps(target_non_elf, candidate_non_elf)

        target_paths = set(target_elfs)
        candidate_paths = set(candidate_elfs)
        all_candidate_aarch64 = True
        x86_candidate_elfs: list[str] = []
        elf_rows: list[dict[str, Any]] = []

        for path in sorted(target_paths | candidate_paths):
            target_path = target_elfs.get(path)
            candidate_path = candidate_elfs.get(path)
            row: dict[str, Any] = {
                "path": path,
                "target_present": target_path is not None,
                "candidate_present": candidate_path is not None,
            }
            if target_path is not None:
                row["target_machine"] = machine(target_path)
                row["target_sha256"] = sha256_file(target_path)
            if candidate_path is not None:
                candidate_machine = machine(candidate_path)
                row["candidate_machine"] = candidate_machine
                row["candidate_sha256"] = sha256_file(candidate_path)
                is_aarch64 = (
                    candidate_machine.get("machine") == "AArch64"
                    and candidate_machine.get("class") == "ELF64"
                )
                row["candidate_is_aarch64"] = is_aarch64
                if not is_aarch64:
                    all_candidate_aarch64 = False
                    x86_candidate_elfs.append(path)
            if target_path is not None and candidate_path is not None:
                target_symbols = defined_dynamic_symbols(target_path)
                candidate_symbols = defined_dynamic_symbols(candidate_path)
                target_needed = needed_libraries(target_path)
                candidate_needed = needed_libraries(candidate_path)
                target_resources = resources(target_path)
                candidate_resources = resources(candidate_path)
                row.update({
                    "defined_dynamic_symbols_equal": target_symbols == candidate_symbols,
                    "target_defined_dynamic_symbols": target_symbols,
                    "candidate_defined_dynamic_symbols": candidate_symbols,
                    "target_only_defined_dynamic_symbols": sorted(set(target_symbols) - set(candidate_symbols)),
                    "candidate_only_defined_dynamic_symbols": sorted(set(candidate_symbols) - set(target_symbols)),
                    "needed_libraries_equal": target_needed == candidate_needed,
                    "target_needed_libraries": target_needed,
                    "candidate_needed_libraries": candidate_needed,
                    "resources_equal": target_resources == candidate_resources,
                    "target_resources": target_resources,
                    "candidate_resources": candidate_resources,
                })
            else:
                row.update({
                    "defined_dynamic_symbols_equal": False,
                    "needed_libraries_equal": False,
                    "resources_equal": False,
                })
            elf_rows.append(row)

    control_valid = (
        target_control == {
            "Package": EXPECTED_PACKAGE,
            "Version": EXPECTED_VERSION,
            "Architecture": "amd64",
        }
        and candidate_control == {
            "Package": EXPECTED_PACKAGE,
            "Version": EXPECTED_VERSION,
            "Architecture": "arm64",
        }
    )
    elf_path_set_equal = target_paths == candidate_paths and bool(target_paths)
    resources_equal = elf_path_set_equal and all(row["resources_equal"] for row in elf_rows)
    symbols_equal = elf_path_set_equal and all(
        row["defined_dynamic_symbols_equal"] for row in elf_rows
    )
    needed_equal = elf_path_set_equal and all(
        row["needed_libraries_equal"] for row in elf_rows
    )
    normalized_non_elf_equal = not non_elf_differences and bool(target_non_elf)

    verified = all((
        control_valid,
        normalized_non_elf_equal,
        elf_path_set_equal,
        all_candidate_aarch64,
        resources_equal,
        symbols_equal,
        needed_equal,
    ))

    document = {
        "schema": 1,
        "source": EXPECTED_PACKAGE,
        "version": EXPECTED_VERSION,
        "target_deb_sha256": sha256_file(target_deb),
        "candidate_deb_sha256": sha256_file(candidate_deb),
        "target_control": target_control,
        "candidate_control": candidate_control,
        "control_valid": control_valid,
        "normalized_non_elf_payload_equal": normalized_non_elf_equal,
        "non_elf_difference_count": len(non_elf_differences),
        "elf_path_set_equal": elf_path_set_equal,
        "target_elf_paths": sorted(target_paths),
        "candidate_elf_paths": sorted(candidate_paths),
        "candidate_elf_count": len(candidate_paths),
        "all_candidate_elfs_aarch64": all_candidate_aarch64,
        "foreign_candidate_elfs": x86_candidate_elfs,
        "embedded_resources_equal": resources_equal,
        "defined_dynamic_symbol_sets_equal": symbols_equal,
        "needed_library_sets_equal": needed_equal,
        "elf_rows": elf_rows,
        "native_arm64_candidate_verified": verified,
        "package_layer_promotion_allowed": False,
        "iso_assembly_allowed": False,
        "fail_closed": True,
        "next_action": (
            "integrate the verified candidate into a disposable ARM64 rootfs and run desktop smoke tests"
            if verified
            else "repair the native candidate mismatch before rootfs integration"
        ),
    }
    (output / "summary.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "non-elf-differences.json").write_text(
        json.dumps(non_elf_differences, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "elf-comparison.json").write_text(
        json.dumps(elf_rows, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
