#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def run(
    command: list[str],
    *,
    check: bool = True,
    text: bool = False,
    cwd: Path | None = None,
    input_data: bytes | str | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        check=check,
        cwd=cwd,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_elf(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open("rb") as stream:
        return stream.read(4) == b"\x7fELF"


def extract_deb(deb: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    run(["dpkg-deb", "-x", str(deb), str(destination)])


def find_unique(root: Path, name: str) -> Path:
    matches = sorted(path for path in root.rglob(name) if path.is_file())
    if len(matches) != 1:
        raise RuntimeError(f"expected one {name} below {root}, found {len(matches)}")
    return matches[0]


def target_changelog(target_root: Path) -> Path:
    matches = sorted(
        target_root.glob("usr/share/doc/gooroom-integration-applet/changelog*")
    )
    if not matches:
        raise RuntimeError("target changelog not found")
    return matches[0]


def read_maybe_gzip(path: Path) -> bytes:
    if path.suffix == ".gz":
        with gzip.open(path, "rb") as stream:
            return stream.read()
    return path.read_bytes()


def resource_mapping(source: Path) -> list[tuple[str, Path, Path]]:
    rows: list[tuple[str, Path, Path]] = []
    for manifest in sorted(source.rglob("gresource.xml")):
        tree = ET.parse(manifest)
        for group in tree.getroot().findall(".//gresource"):
            prefix = (group.attrib.get("prefix") or "").rstrip("/")
            for file_element in group.findall("file"):
                relative_text = (file_element.text or "").strip()
                if not relative_text:
                    continue
                alias = file_element.attrib.get("alias") or relative_text
                resource_path = f"{prefix}/{alias.lstrip('/')}"
                source_path = manifest.parent / relative_text
                rows.append((resource_path, source_path, manifest))
    return rows


def gresource_list(binary: Path) -> list[str]:
    process = run(["gresource", "list", str(binary)], check=False, text=True)
    if process.returncode != 0:
        return []
    return sorted(line.strip() for line in process.stdout.splitlines() if line.strip())


def gresource_extract(binary: Path, resource_path: str) -> bytes | None:
    process = run(
        ["gresource", "extract", str(binary), resource_path],
        check=False,
        text=False,
    )
    if process.returncode != 0:
        return None
    return process.stdout


def reconstruct(args: argparse.Namespace) -> int:
    source = Path(args.source).resolve()
    target_root = Path(args.target_root).resolve()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    target_main = find_unique(target_root, "libgooroom-integration-applet.so")
    target_resources = set(gresource_list(target_main))

    changelog_destination = source / "debian/changelog"
    changelog_data = read_maybe_gzip(target_changelog(target_root))
    changelog_destination.write_bytes(changelog_data)

    resource_rows: list[dict[str, Any]] = []
    for resource_path, source_path, manifest in resource_mapping(source):
        data = gresource_extract(target_main, resource_path)
        row: dict[str, Any] = {
            "resource_path": resource_path,
            "source_path": source_path.relative_to(source).as_posix(),
            "manifest": manifest.relative_to(source).as_posix(),
            "target_present": resource_path in target_resources,
            "replaced": False,
        }
        if data is not None:
            source_path.parent.mkdir(parents=True, exist_ok=True)
            old = source_path.read_bytes() if source_path.exists() else None
            source_path.write_bytes(data)
            row.update(
                {
                    "replaced": True,
                    "target_sha256": sha256_bytes(data),
                    "previous_sha256": sha256_bytes(old) if old is not None else None,
                    "changed": old != data,
                    "size": len(data),
                }
            )
        resource_rows.append(row)

    source_resource_paths = {row["resource_path"] for row in resource_rows}
    unmapped_target_resources = sorted(target_resources - source_resource_paths)

    target_icon_root = target_root / "usr/share/icons/hicolor/scalable"
    source_icon_root = source / "icons"
    source_icon_root.mkdir(parents=True, exist_ok=True)
    icon_rows: list[dict[str, Any]] = []
    target_icon_basenames: set[str] = set()
    if target_icon_root.exists():
        for target_icon in sorted(target_icon_root.rglob("*.svg")):
            target_icon_basenames.add(target_icon.name)
            source_icon = source_icon_root / target_icon.name
            old = source_icon.read_bytes() if source_icon.exists() else None
            data = target_icon.read_bytes()
            source_icon.write_bytes(data)
            icon_rows.append(
                {
                    "target_path": target_icon.relative_to(target_root).as_posix(),
                    "source_path": source_icon.relative_to(source).as_posix(),
                    "previous_sha256": sha256_bytes(old) if old is not None else None,
                    "target_sha256": sha256_bytes(data),
                    "changed": old != data,
                }
            )
    source_only_icons = sorted(
        path.name
        for path in source_icon_root.glob("*.svg")
        if path.name not in target_icon_basenames
    )

    locale_rows: list[dict[str, Any]] = []
    target_locale_root = target_root / "usr/share/locale"
    if target_locale_root.exists():
        for mo in sorted(
            target_locale_root.glob(
                "*/LC_MESSAGES/gooroom-integration-applet.mo"
            )
        ):
            locale = mo.parents[1].name
            po = source / "po" / f"{locale}.po"
            process = run(
                ["msgunfmt", str(mo)],
                check=False,
                text=False,
            )
            row = {
                "locale": locale,
                "mo_path": mo.relative_to(target_root).as_posix(),
                "po_path": po.relative_to(source).as_posix(),
                "recovered": process.returncode == 0,
            }
            if process.returncode == 0:
                old = po.read_bytes() if po.exists() else None
                po.write_bytes(process.stdout)
                row.update(
                    {
                        "changed": old != process.stdout,
                        "target_mo_sha256": sha256_file(mo),
                        "recovered_po_sha256": sha256_bytes(process.stdout),
                    }
                )
            else:
                row["stderr"] = process.stderr.decode(
                    "utf-8", errors="replace"
                )[-2000:]
            locale_rows.append(row)

    report = {
        "schema": 1,
        "source": "gooroom-integration-applet",
        "target_version": args.version,
        "target_main_elf": target_main.relative_to(target_root).as_posix(),
        "target_resource_count": len(target_resources),
        "source_resource_mapping_count": len(resource_rows),
        "replaced_resource_count": sum(
            bool(row["replaced"]) for row in resource_rows
        ),
        "changed_resource_count": sum(
            bool(row.get("changed")) for row in resource_rows
        ),
        "unmapped_target_resources": unmapped_target_resources,
        "resource_rows": resource_rows,
        "icon_rows": icon_rows,
        "source_only_icons": source_only_icons,
        "locale_rows": locale_rows,
        "changelog_sha256": sha256_bytes(changelog_data),
    }
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


def allocated_sections(path: Path) -> dict[str, dict[str, Any]]:
    process = run(["readelf", "-SW", str(path)], text=True)
    names: list[str] = []
    for line in process.stdout.splitlines():
        match = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)",
            line,
        )
        if not match:
            continue
        name, flags = match.groups()
        if "A" in flags and name != ".note.gnu.build-id":
            names.append(name)
    result: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory() as temporary:
        temporary_path = Path(temporary)
        for index, name in enumerate(names):
            output = temporary_path / str(index)
            process = run(
                ["objcopy", "--dump-section", f"{name}={output}", str(path)],
                check=False,
                text=True,
            )
            if process.returncode == 0 and output.exists():
                result[name] = {
                    "size": output.stat().st_size,
                    "sha256": sha256_file(output),
                }
            else:
                result[name] = {
                    "error": process.stderr[-1000:],
                }
    return result


def dynamic_functions(path: Path) -> dict[str, tuple[int, int]]:
    process = run(["readelf", "--dyn-syms", "-W", str(path)], text=True)
    result: dict[str, tuple[int, int]] = {}
    pattern = re.compile(
        r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+(\S+)\s+(.+?)\s*$"
    )
    for line in process.stdout.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        value_text, size_text, section, name = match.groups()
        name = name.split("@", 1)[0]
        if section == "UND":
            continue
        value = int(value_text, 16)
        size = int(size_text)
        if value and size and name:
            result[name] = (value, size)
    return result


def normalized_disassembly(path: Path, value: int, size: int) -> str:
    process = run(
        [
            "objdump",
            "-d",
            "--no-show-raw-insn",
            f"--start-address={value}",
            f"--stop-address={value + size}",
            str(path),
        ],
        check=False,
        text=True,
    )
    rows: list[str] = []
    for line in process.stdout.splitlines():
        if not re.match(r"^\s*[0-9a-fA-F]+:", line):
            continue
        line = re.sub(r"^\s*[0-9a-fA-F]+:\s*", "", line)
        line = re.sub(r"\b[0-9a-fA-F]+\s+(<[^>]+>)", r"ADDR \1", line)
        line = re.sub(r"\s+#\s+[0-9a-fA-Fx]+\s*(<[^>]+>)?", r" # ADDR \1", line)
        line = re.sub(r"\s+", " ", line).strip()
        rows.append(line)
    return "\n".join(rows)


def resource_inventory(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for resource_path in gresource_list(path):
        data = gresource_extract(path, resource_path)
        if data is not None:
            result[resource_path] = {
                "size": len(data),
                "sha256": sha256_bytes(data),
            }
    return result


def elf_comparison(target: Path, candidate: Path) -> dict[str, Any]:
    target_sections = allocated_sections(target)
    candidate_sections = allocated_sections(candidate)
    different_sections = [
        name
        for name in sorted(set(target_sections) | set(candidate_sections))
        if target_sections.get(name) != candidate_sections.get(name)
    ]

    target_functions = dynamic_functions(target)
    candidate_functions = dynamic_functions(candidate)
    function_rows: list[dict[str, Any]] = []
    for name in sorted(set(target_functions) | set(candidate_functions)):
        target_spec = target_functions.get(name)
        candidate_spec = candidate_functions.get(name)
        row: dict[str, Any] = {
            "name": name,
            "target_present": target_spec is not None,
            "candidate_present": candidate_spec is not None,
        }
        if target_spec and candidate_spec:
            target_disassembly = normalized_disassembly(
                target, target_spec[0], target_spec[1]
            )
            candidate_disassembly = normalized_disassembly(
                candidate, candidate_spec[0], candidate_spec[1]
            )
            row.update(
                {
                    "target_size": target_spec[1],
                    "candidate_size": candidate_spec[1],
                    "target_disassembly_sha256": sha256_bytes(
                        target_disassembly.encode()
                    ),
                    "candidate_disassembly_sha256": sha256_bytes(
                        candidate_disassembly.encode()
                    ),
                    "normalized_disassembly_equal": (
                        target_disassembly == candidate_disassembly
                    ),
                }
            )
        else:
            row["normalized_disassembly_equal"] = False
        function_rows.append(row)

    target_resources = resource_inventory(target)
    candidate_resources = resource_inventory(candidate)
    different_resources = [
        name
        for name in sorted(set(target_resources) | set(candidate_resources))
        if target_resources.get(name) != candidate_resources.get(name)
    ]

    target_strings = set(
        run(["strings", "-a", "-n", "4", str(target)], text=True).stdout.splitlines()
    )
    candidate_strings = set(
        run(["strings", "-a", "-n", "4", str(candidate)], text=True).stdout.splitlines()
    )
    target_only_strings = sorted(target_strings - candidate_strings)
    candidate_only_strings = sorted(candidate_strings - target_strings)

    return {
        "target_path": str(target),
        "candidate_path": str(candidate),
        "target_sha256": sha256_file(target),
        "candidate_sha256": sha256_file(candidate),
        "target_size": target.stat().st_size,
        "candidate_size": candidate.stat().st_size,
        "different_allocated_sections": different_sections,
        "different_allocated_section_count": len(different_sections),
        "target_dynamic_function_count": len(target_functions),
        "candidate_dynamic_function_count": len(candidate_functions),
        "different_dynamic_functions": [
            row for row in function_rows
            if not row["normalized_disassembly_equal"]
        ],
        "different_dynamic_function_count": sum(
            not row["normalized_disassembly_equal"] for row in function_rows
        ),
        "function_rows": function_rows,
        "different_resources": different_resources,
        "different_resource_count": len(different_resources),
        "target_resources": target_resources,
        "candidate_resources": candidate_resources,
        "target_only_strings": target_only_strings[:500],
        "candidate_only_strings": candidate_only_strings[:500],
        "target_only_string_count": len(target_only_strings),
        "candidate_only_string_count": len(candidate_only_strings),
    }


def non_elf_inventory(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            result[path.relative_to(root).as_posix()] = {
                "kind": "symlink",
                "target": os.readlink(path),
            }
        elif path.is_file() and not is_elf(path):
            result[path.relative_to(root).as_posix()] = {
                "kind": "file",
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
    return result


def compare(args: argparse.Namespace) -> int:
    target_deb = Path(args.target_deb).resolve()
    candidate_deb = Path(args.candidate_deb).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as temporary:
        temporary_path = Path(temporary)
        target_root = temporary_path / "target"
        candidate_root = temporary_path / "candidate"
        extract_deb(target_deb, target_root)
        extract_deb(candidate_deb, candidate_root)

        target_main = find_unique(target_root, "libgooroom-integration-applet.so")
        candidate_main = find_unique(candidate_root, "libgooroom-integration-applet.so")
        target_nimf = find_unique(target_root, "libnimf-gooroom.so")
        candidate_nimf = find_unique(candidate_root, "libnimf-gooroom.so")

        target_non_elf = non_elf_inventory(target_root)
        candidate_non_elf = non_elf_inventory(candidate_root)
        non_elf_rows = []
        for path in sorted(set(target_non_elf) | set(candidate_non_elf)):
            left = target_non_elf.get(path)
            right = candidate_non_elf.get(path)
            non_elf_rows.append(
                {
                    "path": path,
                    "target": left,
                    "candidate": right,
                    "equal": left == right,
                }
            )

        target_main = find_unique(target_root, "libgooroom-integration-applet.so")
        candidate_main = find_unique(candidate_root, "libgooroom-integration-applet.so")
        target_nimf = find_unique(target_root, "libnimf-gooroom.so")
        candidate_nimf = find_unique(candidate_root, "libnimf-gooroom.so")
        main = elf_comparison(target_main, candidate_main)
        nimf = elf_comparison(target_nimf, candidate_nimf)
        summary = {
            "schema": 1,
            "source": "gooroom-integration-applet",
            "target_version": args.version,
            "candidate_label": args.candidate_label,
            "candidate_commit_sha": args.candidate_commit,
            "target_deb_sha256": sha256_file(target_deb),
            "candidate_deb_sha256": sha256_file(candidate_deb),
            "non_elf_difference_count": sum(
                not row["equal"] for row in non_elf_rows
            ),
            "different_dynamic_function_count": (
                main["different_dynamic_function_count"]
                + nimf["different_dynamic_function_count"]
            ),
            "different_resource_count": (
                main["different_resource_count"]
                + nimf["different_resource_count"]
            ),
            "different_allocated_section_count": (
                main["different_allocated_section_count"]
                + nimf["different_allocated_section_count"]
            ),
            "main_elf": main,
            "nimf_elf": nimf,
            "comparison_rank": [
                main["different_resource_count"] + nimf["different_resource_count"],
                main["different_dynamic_function_count"] + nimf["different_dynamic_function_count"],
                main["different_allocated_section_count"] + nimf["different_allocated_section_count"],
                sum(not row["equal"] for row in non_elf_rows),
                abs(main["target_size"] - main["candidate_size"])
                + abs(nimf["target_size"] - nimf["candidate_size"]),
            ],
        }
        (output / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (output / "non-elf-comparison.json").write_text(
            json.dumps(non_elf_rows, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        function_rows = []
        for elf_name, result in (("main", main), ("nimf", nimf)):
            for row in result["different_dynamic_functions"]:
                function_rows.append(
                    {
                        "elf": elf_name,
                        "name": row["name"],
                        "target_size": row.get("target_size"),
                        "candidate_size": row.get("candidate_size"),
                        "target_present": row["target_present"],
                        "candidate_present": row["candidate_present"],
                    }
                )
        with (output / "different-functions.tsv").open("w", encoding="utf-8") as stream:
            stream.write(
                "elf\tname\ttarget_size\tcandidate_size\ttarget_present\tcandidate_present\n"
            )
            for row in function_rows:
                stream.write(
                    f"{row['elf']}\t{row['name']}\t{row['target_size'] or ''}\t"
                    f"{row['candidate_size'] or ''}\t"
                    f"{str(row['target_present']).lower()}\t"
                    f"{str(row['candidate_present']).lower()}\n"
                )
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    reconstruct_parser = commands.add_parser("reconstruct")
    reconstruct_parser.add_argument("--source", required=True)
    reconstruct_parser.add_argument("--target-root", required=True)
    reconstruct_parser.add_argument("--output", required=True)
    reconstruct_parser.add_argument("--version", required=True)
    reconstruct_parser.set_defaults(function=reconstruct)

    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("--target-deb", required=True)
    compare_parser.add_argument("--candidate-deb", required=True)
    compare_parser.add_argument("--output", required=True)
    compare_parser.add_argument("--version", required=True)
    compare_parser.add_argument("--candidate-label", required=True)
    compare_parser.add_argument("--candidate-commit", required=True)
    compare_parser.set_defaults(function=compare)
    return root


def main() -> int:
    args = parser().parse_args()
    return int(args.function(args))


if __name__ == "__main__":
    raise SystemExit(main())
