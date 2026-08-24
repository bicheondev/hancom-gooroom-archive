#!/usr/bin/env python3
"""Compare two same-architecture DEBs and preserve actionable binary evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def run(arguments: list[str], *, check: bool = True) -> str:
    result = subprocess.run(
        arguments,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(arguments)}\n{result.stdout}")
    return result.stdout


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def deb_field(path: Path, field: str) -> str:
    return run(["dpkg-deb", "-f", str(path), field]).strip()


def file_type(path: Path) -> str:
    return run(["file", "-b", str(path)]).strip()


def extract(deb: Path, destination: Path) -> tuple[Path, Path]:
    root = destination / "root"
    control = destination / "control"
    root.mkdir(parents=True, exist_ok=True)
    control.mkdir(parents=True, exist_ok=True)
    run(["dpkg-deb", "-x", str(deb), str(root)])
    run(["dpkg-deb", "-e", str(deb), str(control)])
    return root, control


def inventory(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        row: dict[str, Any] = {
            "path": relative,
            "mode": oct(stat.S_IMODE(metadata.st_mode)),
        }
        if path.is_symlink():
            row.update({"kind": "symlink", "link_target": os.readlink(path)})
        elif path.is_file():
            description = file_type(path)
            row.update(
                {
                    "kind": "file",
                    "size": metadata.st_size,
                    "sha256": sha256_file(path),
                    "file_type": description,
                    "elf": description.startswith("ELF "),
                }
            )
        elif path.is_dir():
            row["kind"] = "directory"
        else:
            row["kind"] = "other"
        result[relative] = row
    return result


def normalize_readelf(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        if "Build ID:" in line:
            continue
        if line.strip().startswith("Entry point address:"):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip() + "\n"


def extract_gresources(binary: Path, destination: Path) -> list[dict[str, Any]]:
    listing = run(["gresource", "list", str(binary)], check=False)
    if not listing.strip() or "The resource at" in listing or "not found" in listing.lower():
        return []
    rows: list[dict[str, Any]] = []
    for resource in sorted({line.strip() for line in listing.splitlines() if line.strip().startswith("/")}):
        relative = resource.lstrip("/")
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["gresource", "extract", str(binary), resource],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode:
            rows.append(
                {
                    "resource": resource,
                    "status": "extract-failed",
                    "error": result.stderr.decode("utf-8", "replace"),
                }
            )
            continue
        output.write_bytes(result.stdout)
        rows.append(
            {
                "resource": resource,
                "status": "extracted",
                "size": output.stat().st_size,
                "sha256": sha256_file(output),
            }
        )
    return rows


def analyze_elf(path: Path, destination: Path) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True)
    commands = {
        "readelf-header-program-dynamic-symbols-relocs-notes.txt": [
            "readelf", "-h", "-l", "-d", "-s", "-r", "-n", "--wide", str(path)
        ],
        "dynamic-symbols.txt": ["nm", "-D", "-anC", str(path)],
        "all-strings.txt": ["strings", "-a", "-n", "4", str(path)],
        "disassembly.txt": ["objdump", "-drwC", str(path)],
    }
    hashes: dict[str, str] = {}
    for filename, command in commands.items():
        text = run(command, check=False)
        if filename.startswith("readelf-"):
            text = normalize_readelf(text)
        output = destination / filename
        output.write_text(text, encoding="utf-8", errors="replace")
        hashes[filename] = sha256_file(output)
    resources = extract_gresources(path, destination / "gresources")
    return {
        "file_type": file_type(path),
        "sha256": sha256_file(path),
        "analysis_hashes": hashes,
        "resources": resources,
    }


def compare_rows(target: dict[str, Any] | None, candidate: dict[str, Any] | None, path: str) -> dict[str, Any]:
    if target is None:
        return {"path": path, "status": "candidate-only", "candidate": candidate}
    if candidate is None:
        return {"path": path, "status": "target-only", "target": target}
    if target == candidate:
        return {"path": path, "status": "identical", "kind": target.get("kind")}
    return {
        "path": path,
        "status": "different",
        "kind": "elf" if target.get("elf") or candidate.get("elf") else target.get("kind"),
        "target": target,
        "candidate": candidate,
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-deb", required=True, type=Path)
    parser.add_argument("--candidate-deb", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    output = arguments.output_directory
    output.mkdir(parents=True, exist_ok=True)

    target_meta = {
        "package": deb_field(arguments.target_deb, "Package"),
        "version": deb_field(arguments.target_deb, "Version"),
        "architecture": deb_field(arguments.target_deb, "Architecture"),
        "size": arguments.target_deb.stat().st_size,
        "sha256": sha256_file(arguments.target_deb),
    }
    candidate_meta = {
        "package": deb_field(arguments.candidate_deb, "Package"),
        "version": deb_field(arguments.candidate_deb, "Version"),
        "architecture": deb_field(arguments.candidate_deb, "Architecture"),
        "size": arguments.candidate_deb.stat().st_size,
        "sha256": sha256_file(arguments.candidate_deb),
    }
    for field in ("package", "version", "architecture"):
        if target_meta[field] != candidate_meta[field]:
            raise RuntimeError(
                f"target/candidate {field} mismatch: {target_meta[field]!r} != {candidate_meta[field]!r}"
            )

    with tempfile.TemporaryDirectory(prefix="deb-payload-compare-") as temporary_directory:
        temporary = Path(temporary_directory)
        target_root, target_control = extract(arguments.target_deb, temporary / "target")
        candidate_root, candidate_control = extract(arguments.candidate_deb, temporary / "candidate")
        target_inventory = inventory(target_root)
        candidate_inventory = inventory(candidate_root)
        rows = [
            compare_rows(target_inventory.get(path), candidate_inventory.get(path), path)
            for path in sorted(set(target_inventory) | set(candidate_inventory))
        ]

        elf_paths = sorted(
            {
                row["path"]
                for row in rows
                if row.get("kind") == "elf"
                or target_inventory.get(row["path"], {}).get("elf")
                or candidate_inventory.get(row["path"], {}).get("elf")
            }
        )
        elf_analysis: dict[str, Any] = {}
        for relative in elf_paths:
            target_path = target_root / relative
            candidate_path = candidate_root / relative
            safe = relative.replace("/", "__")
            record: dict[str, Any] = {}
            if target_path.is_file():
                record["target"] = analyze_elf(target_path, output / "elf" / safe / "target")
            if candidate_path.is_file():
                record["candidate"] = analyze_elf(candidate_path, output / "elf" / safe / "candidate")
            if "target" in record and "candidate" in record:
                target_strings = set(
                    (output / "elf" / safe / "target" / "all-strings.txt")
                    .read_text(encoding="utf-8", errors="replace")
                    .splitlines()
                )
                candidate_strings = set(
                    (output / "elf" / safe / "candidate" / "all-strings.txt")
                    .read_text(encoding="utf-8", errors="replace")
                    .splitlines()
                )
                target_only = sorted(target_strings - candidate_strings)
                candidate_only = sorted(candidate_strings - target_strings)
                (output / "elf" / safe / "target-only-strings.txt").write_text(
                    "\n".join(target_only) + ("\n" if target_only else ""), encoding="utf-8"
                )
                (output / "elf" / safe / "candidate-only-strings.txt").write_text(
                    "\n".join(candidate_only) + ("\n" if candidate_only else ""), encoding="utf-8"
                )
                record["target_only_string_count"] = len(target_only)
                record["candidate_only_string_count"] = len(candidate_only)
                target_resources = {
                    item["resource"]: item
                    for item in record["target"].get("resources", [])
                    if item.get("status") == "extracted"
                }
                candidate_resources = {
                    item["resource"]: item
                    for item in record["candidate"].get("resources", [])
                    if item.get("status") == "extracted"
                }
                resource_differences: list[dict[str, Any]] = []
                for resource in sorted(set(target_resources) | set(candidate_resources)):
                    left = target_resources.get(resource)
                    right = candidate_resources.get(resource)
                    if left == right:
                        continue
                    resource_differences.append(
                        {"resource": resource, "target": left, "candidate": right}
                    )
                record["resource_differences"] = resource_differences
            elf_analysis[relative] = record

        control_rows: dict[str, Any] = {}
        for filename in sorted(
            {path.name for path in target_control.iterdir() if path.is_file()}
            | {path.name for path in candidate_control.iterdir() if path.is_file()}
        ):
            left = target_control / filename
            right = candidate_control / filename
            control_rows[filename] = {
                "target_sha256": sha256_file(left) if left.is_file() else None,
                "candidate_sha256": sha256_file(right) if right.is_file() else None,
                "identical": left.is_file() and right.is_file() and sha256_file(left) == sha256_file(right),
            }

    different = [row for row in rows if row["status"] != "identical"]
    different_non_elf = [row for row in different if row.get("kind") != "elf"]
    different_elf = [row for row in different if row.get("kind") == "elf"]
    summary = {
        "schema": 2,
        "target": target_meta,
        "candidate": candidate_meta,
        "path_set_identical": set(target_inventory) == set(candidate_inventory),
        "payload_path_count": len(rows),
        "identical_path_count": len(rows) - len(different),
        "different_path_count": len(different),
        "different_non_elf_path_count": len(different_non_elf),
        "different_non_elf_paths": [row["path"] for row in different_non_elf],
        "different_elf_path_count": len(different_elf),
        "different_elf_paths": [row["path"] for row in different_elf],
        "target_only_paths": [row["path"] for row in rows if row["status"] == "target-only"],
        "candidate_only_paths": [row["path"] for row in rows if row["status"] == "candidate-only"],
        "control": control_rows,
        "elf_analysis": elf_analysis,
    }
    (output / "payload-comparison.json").write_text(
        json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise
    except BaseException as error:
        print(f"fatal: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
