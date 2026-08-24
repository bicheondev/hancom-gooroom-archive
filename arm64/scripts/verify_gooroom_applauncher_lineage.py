#!/usr/bin/env python3
"""Verify a reconstructed Gooroom applauncher build against the exact Hancom DEB."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ELF_PATH = Path(
    "usr/lib/x86_64-linux-gnu/gnome-panel/modules/"
    "libgooroom-applauncher-applet.so"
)


def run(command: list[str], *, check: bool = True) -> str:
    env = os.environ.copy()
    env["LC_ALL"] = "C.UTF-8"
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout[-4000:]}\n"
            f"stderr:\n{completed.stderr[-4000:]}"
        )
    return completed.stdout


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def control_fields(deb: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    current = ""
    for line in run(["dpkg-deb", "-f", str(deb)]).splitlines():
        if line[:1].isspace() and current:
            fields[current] += "\n" + line[1:]
        elif ":" in line:
            current, value = line.split(":", 1)
            current = current.strip()
            fields[current] = value.lstrip()
    return fields


def package_record(deb: Path) -> dict[str, Any]:
    return {
        "bytes": deb.stat().st_size,
        "sha256": sha256_file(deb),
        "control": control_fields(deb),
    }


def extract(deb: Path, root: Path, control: Path) -> None:
    root.mkdir(parents=True)
    control.mkdir(parents=True)
    run(["dpkg-deb", "-x", str(deb), str(root)])
    run(["dpkg-deb", "-e", str(deb), str(control)])


def is_elf(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        with path.open("rb") as stream:
            return stream.read(4) == b"\x7fELF"
    except OSError:
        return False


def inventory(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            result[relative] = {
                "type": "symlink",
                "mode": f"{mode:04o}",
                "target": os.readlink(path),
            }
        elif path.is_dir():
            result[relative] = {
                "type": "directory",
                "mode": f"{mode:04o}",
            }
        elif path.is_file():
            item: dict[str, Any] = {
                "type": "file",
                "mode": f"{mode:04o}",
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "elf": is_elf(path),
            }
            if path.suffix == ".gz":
                completed = subprocess.run(
                    ["gzip", "-dc", str(path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if completed.returncode == 0:
                    item["decompressed_sha256"] = hashlib.sha256(
                        completed.stdout
                    ).hexdigest()
            result[relative] = item
        else:
            result[relative] = {
                "type": "other",
                "mode": f"{mode:04o}",
            }
    return result


def parse_symbols(path: Path) -> tuple[list[str], list[str], dict[str, int]]:
    imports: set[str] = set()
    exports: set[str] = set()
    function_sizes: dict[str, int] = {}
    for line in run(["readelf", "-WsW", str(path)]).splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8 or not parts[0].rstrip(":").isdigit():
            continue
        _, _, size, symbol_type, bind, visibility, index, name = parts
        if index == "UND":
            imports.add(name)
        elif bind in {"GLOBAL", "WEAK", "GNU_UNIQUE"} and visibility in {
            "DEFAULT",
            "PROTECTED",
        }:
            exports.add(name)
            if symbol_type == "FUNC" and size.isdigit():
                function_sizes[name] = int(size)
    return sorted(imports), sorted(exports), function_sizes


def normalized_disassembly(path: Path, symbol: str) -> list[str]:
    text = run(
        [
            "objdump",
            "-drwC",
            "-Mintel",
            "--no-show-raw-insn",
            f"--disassemble={symbol}",
            str(path),
        ]
    )
    normalized: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("Disassembly of section"):
            continue
        if line.endswith(":") and re.match(r"^[0-9a-f]+ <.*>:$", line):
            match = re.match(r"^[0-9a-f]+ <(.*)>:$", line)
            if match:
                normalized.append(f"<{match.group(1)}>")
            continue
        match = re.match(r"^[0-9a-f]+:\s*(.*)$", line)
        if not match:
            continue
        instruction = match.group(1)
        instruction = re.sub(
            r"\b[0-9a-f]+\s+<([^>]+)>",
            r"<\1>",
            instruction,
        )
        instruction = re.sub(r"\s+", " ", instruction).strip()
        normalized.append(instruction)
    return normalized


def elf_record(path: Path, required_functions: list[str]) -> dict[str, Any]:
    header: dict[str, str] = {}
    for line in run(["readelf", "-hW", str(path)]).splitlines():
        match = re.match(r"\s*([^:]+):\s*(.*)$", line)
        if match:
            header[match.group(1).strip()] = match.group(2).strip()

    needed: list[str] = []
    for line in run(["readelf", "-dW", str(path)]).splitlines():
        match = re.search(r"\(NEEDED\).*?\[(.*?)\]", line)
        if match:
            needed.append(match.group(1))

    imports, exports, function_sizes = parse_symbols(path)
    build_ids = sorted(
        set(
            value.lower()
            for value in re.findall(
                r"Build ID:\s*([0-9a-f]+)",
                run(["readelf", "-nW", str(path)]),
                re.I,
            )
        )
    )
    section_names: list[str] = []
    section_shape: list[dict[str, Any]] = []
    for line in run(["readelf", "-SW", str(path)]).splitlines():
        match = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+\S+\s+"
            r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",
            line,
        )
        if match:
            name, offset, size = match.groups()
            section_names.append(name)
            section_shape.append(
                {
                    "name": name,
                    "offset": int(offset, 16),
                    "size": int(size, 16),
                }
            )

    disassembly = {
        symbol: normalized_disassembly(path, symbol)
        for symbol in required_functions
    }
    semantic = {
        "class": header.get("Class"),
        "data": header.get("Data"),
        "type": header.get("Type"),
        "machine": header.get("Machine"),
        "os_abi": header.get("OS/ABI"),
        "needed": sorted(set(needed)),
        "imports": imports,
        "exports": exports,
        "function_sizes": {
            symbol: function_sizes.get(symbol) for symbol in required_functions
        },
        "section_names": section_names,
        "section_shape": section_shape,
        "normalized_disassembly": disassembly,
    }
    return {
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "build_ids": build_ids,
        "semantic": semantic,
        "semantic_sha256": sha256_json(semantic),
    }


def compare_inventory(
    target: dict[str, dict[str, Any]],
    rebuilt: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    target_paths = set(target)
    rebuilt_paths = set(rebuilt)
    changes: list[dict[str, Any]] = []
    for path in sorted(target_paths & rebuilt_paths):
        left = target[path]
        right = rebuilt[path]
        if left == right:
            continue
        changed_fields = sorted(
            key
            for key in set(left) | set(right)
            if left.get(key) != right.get(key)
        )
        changes.append({"path": path, "fields": changed_fields})
    return {
        "target_only": sorted(target_paths - rebuilt_paths),
        "rebuilt_only": sorted(rebuilt_paths - target_paths),
        "changed_common": changes,
        "exact": not (target_paths - rebuilt_paths)
        and not (rebuilt_paths - target_paths)
        and not changes,
    }


def compare_dict(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return {
        key: {"target": left.get(key), "rebuilt": right.get(key)}
        for key in sorted(set(left) | set(right))
        if left.get(key) != right.get(key)
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-deb", type=Path, required=True)
    parser.add_argument("--rebuilt-deb", type=Path, required=True)
    parser.add_argument("--lineage-lock", type=Path, required=True)
    parser.add_argument("--source-evidence", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    lock = load_json(args.lineage_lock)
    source_evidence = load_json(args.source_evidence)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    target_package = package_record(args.target_deb)
    rebuilt_package = package_record(args.rebuilt_deb)
    expected = lock["target"]
    expected_pairs = {
        "Package": expected["package"],
        "Version": expected["version"],
        "Architecture": expected["architecture"],
    }
    target_identity_mismatch = {
        key: {
            "actual": target_package["control"].get(key),
            "expected": value,
        }
        for key, value in expected_pairs.items()
        if target_package["control"].get(key) != value
    }
    rebuilt_identity_mismatch = {
        key: {
            "actual": rebuilt_package["control"].get(key),
            "expected": value,
        }
        for key, value in expected_pairs.items()
        if rebuilt_package["control"].get(key) != value
    }
    if target_package["sha256"] != expected["sha256"]:
        target_identity_mismatch["SHA256"] = {
            "actual": target_package["sha256"],
            "expected": expected["sha256"],
        }
    if target_identity_mismatch or rebuilt_identity_mismatch:
        raise RuntimeError(
            "package identity mismatch: "
            f"target={target_identity_mismatch}, rebuilt={rebuilt_identity_mismatch}"
        )

    required_functions = lock["public_candidate"]["expected_new_dynamic_exports"]
    with tempfile.TemporaryDirectory(prefix="applauncher-lineage-") as temporary:
        temp = Path(temporary)
        target_root = temp / "target-root"
        rebuilt_root = temp / "rebuilt-root"
        target_control = temp / "target-control"
        rebuilt_control = temp / "rebuilt-control"
        extract(args.target_deb, target_root, target_control)
        extract(args.rebuilt_deb, rebuilt_root, rebuilt_control)

        target_inventory = inventory(target_root)
        rebuilt_inventory = inventory(rebuilt_root)
        payload_comparison = compare_inventory(target_inventory, rebuilt_inventory)
        control_comparison = compare_inventory(
            inventory(target_control), inventory(rebuilt_control)
        )

        target_elf_path = target_root / ELF_PATH
        rebuilt_elf_path = rebuilt_root / ELF_PATH
        if not target_elf_path.is_file() or not rebuilt_elf_path.is_file():
            raise RuntimeError(f"required ELF is missing: {ELF_PATH}")
        target_elf = elf_record(target_elf_path, required_functions)
        rebuilt_elf = elf_record(rebuilt_elf_path, required_functions)

    target_exports = set(target_elf["semantic"]["exports"])
    rebuilt_exports = set(rebuilt_elf["semantic"]["exports"])
    missing_target_exports = sorted(set(required_functions) - target_exports)
    missing_rebuilt_exports = sorted(set(required_functions) - rebuilt_exports)
    if missing_target_exports or missing_rebuilt_exports:
        raise RuntimeError(
            "required exports missing: "
            f"target={missing_target_exports}, rebuilt={missing_rebuilt_exports}"
        )

    semantic_mismatch = compare_dict(
        target_elf["semantic"], rebuilt_elf["semantic"]
    )
    package_control_mismatch = compare_dict(
        target_package["control"], rebuilt_package["control"]
    )
    source_relationship_valid = all(
        [
            source_evidence.get("repository")
            == lock["public_candidate"]["repository"],
            source_evidence.get("candidate_commit")
            == lock["public_candidate"]["commit"],
            source_evidence.get("candidate_tree")
            == lock["public_candidate"]["tree"],
            source_evidence.get("candidate_parent")
            == lock["public_candidate"]["parent"],
            source_evidence.get("changed_paths")
            == sorted(lock["public_candidate"]["changed_paths"]),
            source_evidence.get("overlay", {}).get("changelog_sha256")
            == lock["target"]["changelog_sha256"],
            source_evidence.get("overlay", {}).get("icon_sha256")
            == lock["target"]["icon_sha256"],
        ]
    )

    elf_byte_identity = target_elf["sha256"] == rebuilt_elf["sha256"]
    package_byte_identity = (
        target_package["sha256"] == rebuilt_package["sha256"]
    )
    elf_semantic_match = not semantic_mismatch
    source_lineage_validated = source_relationship_valid and elf_semantic_match

    result = {
        "schema": 1,
        "verification_complete": True,
        "source_relationship_valid": source_relationship_valid,
        "source_lineage_validated": source_lineage_validated,
        "elf_semantic_match": elf_semantic_match,
        "elf_byte_identity": elf_byte_identity,
        "package_byte_identity": package_byte_identity,
        "payload_byte_identity": payload_comparison["exact"],
        "control_archive_byte_identity": control_comparison["exact"],
        "claims": {
            "source_status": (
                "public-direct-parent-lineage-validated"
                if source_lineage_validated
                else "public-lineage-candidate"
            ),
            "reconstruction_status": (
                "built-and-validated"
                if source_lineage_validated
                else "built-comparison-incomplete"
            ),
            "byte_identity_claimed": package_byte_identity,
        },
        "target_package": target_package,
        "rebuilt_package": rebuilt_package,
        "package_control_mismatch": package_control_mismatch,
        "payload_comparison": payload_comparison,
        "control_comparison": control_comparison,
        "target_elf": target_elf,
        "rebuilt_elf": rebuilt_elf,
        "elf_semantic_mismatch": semantic_mismatch,
        "source_evidence": source_evidence,
        "lineage_lock_sha256": sha256_file(args.lineage_lock),
    }
    output_json = args.output_dir / "verification.json"
    output_json.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary = [
        "# Gooroom applauncher Hancom source-lineage verification",
        "",
        f"- Source relationship valid: `{str(source_relationship_valid).lower()}`",
        f"- Source lineage validated: `{str(source_lineage_validated).lower()}`",
        f"- ELF semantic match: `{str(elf_semantic_match).lower()}`",
        f"- ELF byte identity: `{str(elf_byte_identity).lower()}`",
        f"- Payload byte identity: `{str(payload_comparison['exact']).lower()}`",
        f"- Control archive byte identity: `{str(control_comparison['exact']).lower()}`",
        f"- Full DEB byte identity: `{str(package_byte_identity).lower()}`",
        "",
        "## Authority",
        "",
        f"- Candidate commit: `{lock['public_candidate']['commit']}`",
        f"- Candidate tree: `{lock['public_candidate']['tree']}`",
        f"- Direct parent: `{lock['public_candidate']['parent']}`",
        f"- Target SHA-256: `{target_package['sha256']}`",
        f"- Rebuilt SHA-256: `{rebuilt_package['sha256']}`",
        f"- Target ELF SHA-256: `{target_elf['sha256']}`",
        f"- Rebuilt ELF SHA-256: `{rebuilt_elf['sha256']}`",
        "",
        "Byte identity is claimed only when the full DEB hashes are equal.",
    ]
    (args.output_dir / "verification-summary.md").write_text(
        "\n".join(summary) + "\n", encoding="utf-8"
    )

    return 0 if source_lineage_validated else 1


if __name__ == "__main__":
    raise SystemExit(main())
