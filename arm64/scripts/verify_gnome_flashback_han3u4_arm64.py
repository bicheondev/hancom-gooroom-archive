#!/usr/bin/env python3
"""Verify native ARM64 packages built from reconstructed gnome-flashback han3u4.

The immutable Hancom Gooroom 3.3 AMD64 packages remain the shipped target
authority. Cross-architecture verification preserves package/source identity,
all architecture-neutral payload bytes, canonical installed paths and modes,
GResource bytes, dynamic library identity, and exported ABI while requiring
that every candidate ELF is AArch64.
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
from typing import Any

SOURCE = "gnome-flashback"
VERSION = "3.38.0-2+grm3u2+han3u4"
ELF_MAGIC = b"\x7fELF"
AARCH64_LOADER = "ld-linux-aarch64.so.1"

EXPECTED_PACKAGES: dict[str, dict[str, Any]] = {
    "gnome-flashback": {
        "target_architecture": "amd64",
        "candidate_architecture": "arm64",
        "target_filename": "gnome-flashback_3.38.0-2+grm3u2+han3u4_amd64.deb",
        "target_size": 436564,
        "target_sha256": "6c62fea3341f7c208448250d9eaa2b467df99abdbad53bc236f089fad9741408",
    },
    "gnome-flashback-common": {
        "target_architecture": "all",
        "candidate_architecture": "all",
        "target_filename": "gnome-flashback-common_3.38.0-2+grm3u2+han3u4_all.deb",
        "target_size": 99916,
        "target_sha256": "5770961e60c68b25ea7a84ab14871635b450b79f25f9596c79edad67a34e4543",
    },
    "gnome-session-flashback": {
        "target_architecture": "all",
        "candidate_architecture": "all",
        "target_filename": "gnome-session-flashback_3.38.0-2+grm3u2+han3u4_all.deb",
        "target_size": 14508,
        "target_sha256": "3968b152293606e4626fbe3317913d6f57add08001c3a5a66abd71a8576abcf6",
    },
}

MULTIARCH_SEGMENTS = {
    "x86_64-linux-gnu": "@MULTIARCH@",
    "aarch64-linux-gnu": "@MULTIARCH@",
}
ARCH_RUNTIME_DEB_EXTRAS = {"libgcc-s1", "libatomic1", "gcc-10-base"}
ARCH_RUNTIME_ELF_EXTRAS = {"libgcc_s.so.1", "libatomic.so.1"}
CONTROL_ARCH_VARIANT_FIELDS = {"Architecture", "Installed-Size", "Depends", "Built-Using"}


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
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    return completed.stdout


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_control_paragraph(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for raw in text.splitlines():
        if not raw:
            continue
        if raw[0].isspace():
            if current is None:
                raise ValueError("control continuation without a field")
            fields[current] += "\n" + raw[1:]
            continue
        if ":" not in raw:
            raise ValueError(f"malformed control line: {raw!r}")
        current, value = raw.split(":", 1)
        current = current.strip()
        fields[current] = value.lstrip()
    return fields


def deb_control(path: Path) -> dict[str, str]:
    return parse_control_paragraph(str(run(["dpkg-deb", "-f", str(path)])))


def declared_source(control: dict[str, str]) -> str:
    source = control.get("Source", "")
    if source:
        return source.split(" ", 1)[0]
    return control.get("Package", "").removesuffix("-dbgsym")


def canonical_path(relative: str) -> str:
    parts = relative.split("/")
    parts = [MULTIARCH_SEGMENTS.get(part, part) for part in parts]
    return "/".join(parts)


def canonical_symlink_target(target: str) -> str:
    value = target
    for segment, replacement in MULTIARCH_SEGMENTS.items():
        value = value.replace(segment, replacement)
    return value


def is_elf(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    with path.open("rb") as stream:
        return stream.read(4) == ELF_MAGIC


def payload_manifest(root: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        canonical = canonical_path(relative)
        if canonical in rows:
            raise SystemExit(f"canonical payload path collision: {relative} -> {canonical}")
        metadata = path.lstat()
        row: dict[str, Any] = {
            "path": canonical,
            "actual_path": relative,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
        if path.is_symlink():
            row.update(
                type="symlink",
                target=canonical_symlink_target(os.readlink(path)),
                actual_target=os.readlink(path),
            )
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
        rows[canonical] = row
    return rows


def auxiliary_control_manifest(root: Path) -> dict[str, dict[str, Any]]:
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
    selected = {"Class", "Data", "Version", "OS/ABI", "ABI Version", "Type", "Machine"}
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


def exported_symbols(path: Path) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    pattern = re.compile(
        r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s+(\S+)\s+"
        r"(\S+)\s+(\S+)\s*(.*)$"
    )
    for line in str(run(["readelf", "--dyn-syms", "-W", str(path)])).splitlines():
        match = pattern.match(line)
        if not match:
            continue
        kind, binding, visibility, index, name = (value.strip() for value in match.groups())
        if index == "UND" or binding not in {"GLOBAL", "WEAK", "GNU_UNIQUE"}:
            continue
        rows.append((kind, binding, visibility, name))
    return sorted(rows)


def section_bytes(path: Path, section: str, temporary: Path) -> bytes | None:
    sections = str(run(["readelf", "-SW", str(path)]))
    if not re.search(rf"\]\s+{re.escape(section)}\s", sections):
        return None
    temporary.parent.mkdir(parents=True, exist_ok=True)
    if temporary.exists():
        temporary.unlink()
    run(["objcopy", f"--dump-section={section}={temporary}", str(path)])
    return temporary.read_bytes()


def dependency_groups(value: str) -> list[list[str]]:
    if not value:
        return []
    groups: list[list[str]] = []
    for raw_group in value.replace("\n", " ").split(","):
        alternatives: list[str] = []
        for raw_alt in raw_group.split("|"):
            token = raw_alt.strip()
            token = re.sub(r"\s*\([^)]*\)", "", token)
            token = re.sub(r"\s*\[[^]]*\]", "", token)
            token = token.split(":", 1)[0].strip()
            if token:
                alternatives.append(token)
        if alternatives:
            groups.append(alternatives)
    return groups


def dependency_names(value: str) -> set[str]:
    return {name for group in dependency_groups(value) for name in group}


def locate_debs(directory: Path, expected: set[str]) -> tuple[dict[str, Path], list[dict[str, Any]]]:
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
        if package in expected:
            if package in selected:
                raise SystemExit(f"duplicate package {package} in {directory}")
            selected[package] = deb
        else:
            extras.append(row)
    return selected, extras


def compare_control(
    package: str,
    target: dict[str, str],
    candidate: dict[str, str],
) -> tuple[bool, dict[str, Any]]:
    if package != SOURCE:
        return target == candidate, {
            "mode": "exact",
            "target": target,
            "candidate": candidate,
            "identical": target == candidate,
        }

    target_static = {k: v for k, v in target.items() if k not in CONTROL_ARCH_VARIANT_FIELDS}
    candidate_static = {k: v for k, v in candidate.items() if k not in CONTROL_ARCH_VARIANT_FIELDS}
    static_identical = target_static == candidate_static
    target_dep_names = dependency_names(target.get("Depends", ""))
    candidate_dep_names = dependency_names(candidate.get("Depends", ""))
    missing = sorted(target_dep_names - candidate_dep_names)
    extras = sorted(candidate_dep_names - target_dep_names)
    unexpected_extras = sorted(set(extras) - ARCH_RUNTIME_DEB_EXTRAS)
    dependencies_compatible = not missing and not unexpected_extras
    return static_identical and dependencies_compatible, {
        "mode": "cross-architecture",
        "ignored_fields": sorted(CONTROL_ARCH_VARIANT_FIELDS),
        "target_static": target_static,
        "candidate_static": candidate_static,
        "static_identical": static_identical,
        "target_dependency_names": sorted(target_dep_names),
        "candidate_dependency_names": sorted(candidate_dep_names),
        "missing_dependencies": missing,
        "extra_dependencies": extras,
        "allowed_architecture_runtime_extras": sorted(ARCH_RUNTIME_DEB_EXTRAS),
        "dependencies_compatible": dependencies_compatible,
    }


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

    errors: list[dict[str, Any]] = []
    warnings: list[str] = []
    expected_names = set(EXPECTED_PACKAGES)
    target_debs, target_extras = locate_debs(target_dir, expected_names)
    candidate_debs, candidate_extras = locate_debs(candidate_dir, expected_names)

    if target_extras:
        errors.append({"kind": "unexpected-target-debs", "debs": target_extras})
    if set(target_debs) != expected_names:
        errors.append({
            "kind": "target-package-set",
            "expected": sorted(expected_names),
            "actual": sorted(target_debs),
        })
    if set(candidate_debs) != expected_names:
        errors.append({
            "kind": "candidate-package-set",
            "expected": sorted(expected_names),
            "actual": sorted(candidate_debs),
        })

    invalid_candidate_extras = [
        row for row in candidate_extras
        if not (
            row["package"].endswith("-dbgsym")
            and row["version"] == VERSION
            and row["architecture"] == "arm64"
            and row["source"] == SOURCE
        )
    ]
    if invalid_candidate_extras:
        errors.append({"kind": "unexpected-candidate-debs", "debs": invalid_candidate_extras})

    for package, authority in EXPECTED_PACKAGES.items():
        target = target_debs.get(package)
        if target is not None:
            control = deb_control(target)
            if target.name != authority["target_filename"]:
                errors.append({"kind": "target-filename", "package": package})
            if target.stat().st_size != authority["target_size"]:
                errors.append({"kind": "target-size", "package": package})
            if sha256_file(target) != authority["target_sha256"]:
                errors.append({"kind": "target-sha256", "package": package})
            if control.get("Package") != package:
                errors.append({"kind": "target-package", "package": package})
            if control.get("Version") != VERSION:
                errors.append({"kind": "target-version", "package": package})
            if control.get("Architecture") != authority["target_architecture"]:
                errors.append({"kind": "target-architecture", "package": package})
            if declared_source(control) != SOURCE:
                errors.append({"kind": "target-source", "package": package})

        candidate = candidate_debs.get(package)
        if candidate is not None:
            control = deb_control(candidate)
            if control.get("Package") != package:
                errors.append({"kind": "candidate-package", "package": package})
            if control.get("Version") != VERSION:
                errors.append({"kind": "candidate-version", "package": package})
            if control.get("Architecture") != authority["candidate_architecture"]:
                errors.append({"kind": "candidate-architecture", "package": package})
            if declared_source(control) != SOURCE:
                errors.append({"kind": "candidate-source", "package": package})

    package_rows: list[dict[str, Any]] = []
    non_elf_rows: list[dict[str, Any]] = []
    elf_rows: list[dict[str, Any]] = []
    all_candidate_elf_rows: list[dict[str, Any]] = []
    foreign_elfs: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="gnome-flashback-arm64-") as temp_raw:
        temp = Path(temp_raw)
        for package in sorted(expected_names & set(target_debs) & set(candidate_debs)):
            target_deb = target_debs[package]
            candidate_deb = candidate_debs[package]
            target_root = temp / "target" / package
            candidate_root = temp / "candidate" / package
            target_control_root = temp / "target-control" / package
            candidate_control_root = temp / "candidate-control" / package
            for path in (target_root, candidate_root, target_control_root, candidate_control_root):
                path.mkdir(parents=True, exist_ok=True)
            run(["dpkg-deb", "-x", str(target_deb), str(target_root)])
            run(["dpkg-deb", "-x", str(candidate_deb), str(candidate_root)])
            run(["dpkg-deb", "-e", str(target_deb), str(target_control_root)])
            run(["dpkg-deb", "-e", str(candidate_deb), str(candidate_control_root)])

            target_control = deb_control(target_deb)
            candidate_control = deb_control(candidate_deb)
            control_ok, control_evidence = compare_control(package, target_control, candidate_control)
            target_aux = auxiliary_control_manifest(target_control_root)
            candidate_aux = auxiliary_control_manifest(candidate_control_root)
            aux_ok = target_aux == candidate_aux

            target_manifest = payload_manifest(target_root)
            candidate_manifest = payload_manifest(candidate_root)
            write_json(output / "manifests" / f"{package}-target.json", target_manifest)
            write_json(output / "manifests" / f"{package}-candidate.json", candidate_manifest)
            path_set_ok = set(target_manifest) == set(candidate_manifest)
            if not path_set_ok:
                errors.append({
                    "kind": "payload-path-set",
                    "package": package,
                    "target_only": sorted(set(target_manifest) - set(candidate_manifest)),
                    "candidate_only": sorted(set(candidate_manifest) - set(target_manifest)),
                })

            package_non_elf_ok = True
            package_elf_ok = True
            for canonical in sorted(set(target_manifest) & set(candidate_manifest)):
                left = target_manifest[canonical]
                right = candidate_manifest[canonical]
                if left["type"] != right["type"] or left["mode"] != right["mode"]:
                    errors.append({
                        "kind": "payload-type-or-mode",
                        "package": package,
                        "path": canonical,
                        "target": left,
                        "candidate": right,
                    })
                    package_non_elf_ok = False
                    package_elf_ok = False
                    continue
                if left["type"] == "symlink":
                    if left.get("target") != right.get("target"):
                        errors.append({
                            "kind": "symlink-target",
                            "package": package,
                            "path": canonical,
                            "target": left.get("target"),
                            "candidate": right.get("target"),
                        })
                        package_non_elf_ok = False
                    continue
                if left["type"] != "file":
                    continue
                if bool(left.get("elf")) != bool(right.get("elf")):
                    errors.append({"kind": "elf-classification", "package": package, "path": canonical})
                    package_non_elf_ok = False
                    package_elf_ok = False
                    continue

                target_path = target_root / left["actual_path"]
                candidate_path = candidate_root / right["actual_path"]
                if not left.get("elf"):
                    raw_identical = left.get("sha256") == right.get("sha256")
                    decompressed_identical = (
                        left.get("decompressed_sha256") is not None
                        and left.get("decompressed_sha256") == right.get("decompressed_sha256")
                    )
                    verified = raw_identical or decompressed_identical
                    row = {
                        "package": package,
                        "path": canonical,
                        "target_actual_path": left["actual_path"],
                        "candidate_actual_path": right["actual_path"],
                        "target_sha256": left.get("sha256"),
                        "candidate_sha256": right.get("sha256"),
                        "raw_identical": raw_identical,
                        "target_decompressed_sha256": left.get("decompressed_sha256"),
                        "candidate_decompressed_sha256": right.get("decompressed_sha256"),
                        "decompressed_identical": decompressed_identical,
                        "verified": verified,
                    }
                    non_elf_rows.append(row)
                    if not verified:
                        errors.append({"kind": "non-elf-payload", "evidence": row})
                        package_non_elf_ok = False
                    continue

                target_header = elf_header(target_path)
                candidate_header = elf_header(candidate_path)
                target_dynamic = dynamic_identity(target_path)
                candidate_dynamic = dynamic_identity(candidate_path)
                target_needed = set(target_dynamic["needed"])
                candidate_needed = set(candidate_dynamic["needed"])
                missing_needed = sorted(target_needed - candidate_needed)
                extra_needed = sorted(candidate_needed - target_needed)
                unexpected_needed = sorted(set(extra_needed) - ARCH_RUNTIME_ELF_EXTRAS)
                target_interpreter = elf_interpreter(target_path)
                candidate_interpreter = elf_interpreter(candidate_path)
                target_exports = exported_symbols(target_path)
                candidate_exports = exported_symbols(candidate_path)
                resource_target = section_bytes(
                    target_path,
                    ".gresource.gf",
                    temp / "sections" / f"{package}-{hashlib.sha256(canonical.encode()).hexdigest()}-target",
                )
                resource_candidate = section_bytes(
                    candidate_path,
                    ".gresource.gf",
                    temp / "sections" / f"{package}-{hashlib.sha256(canonical.encode()).hexdigest()}-candidate",
                )
                resource_identity = (
                    (resource_target is None and resource_candidate is None)
                    or (
                        resource_target is not None
                        and resource_candidate is not None
                        and resource_target == resource_candidate
                    )
                )
                interpreter_ok = (
                    (target_interpreter is None and candidate_interpreter is None)
                    or (
                        target_interpreter is not None
                        and candidate_interpreter is not None
                        and os.path.basename(candidate_interpreter) == AARCH64_LOADER
                    )
                )
                verified = (
                    candidate_header.get("Machine") == "AArch64"
                    and target_header.get("Class") == candidate_header.get("Class") == "ELF64"
                    and target_header.get("Data") == candidate_header.get("Data")
                    and target_header.get("Type") == candidate_header.get("Type")
                    and interpreter_ok
                    and not missing_needed
                    and not unexpected_needed
                    and target_dynamic["soname"] == candidate_dynamic["soname"]
                    and target_dynamic["rpath"] == candidate_dynamic["rpath"]
                    and target_dynamic["runpath"] == candidate_dynamic["runpath"]
                    and target_exports == candidate_exports
                    and resource_identity
                )
                row = {
                    "package": package,
                    "path": canonical,
                    "target_actual_path": left["actual_path"],
                    "candidate_actual_path": right["actual_path"],
                    "target_header": target_header,
                    "candidate_header": candidate_header,
                    "target_interpreter": target_interpreter,
                    "candidate_interpreter": candidate_interpreter,
                    "interpreter_verified": interpreter_ok,
                    "target_dynamic": target_dynamic,
                    "candidate_dynamic": candidate_dynamic,
                    "missing_needed": missing_needed,
                    "extra_needed": extra_needed,
                    "allowed_architecture_runtime_extras": sorted(ARCH_RUNTIME_ELF_EXTRAS),
                    "unexpected_needed": unexpected_needed,
                    "target_exported_symbols": target_exports,
                    "candidate_exported_symbols": candidate_exports,
                    "exported_symbols_identical": target_exports == candidate_exports,
                    "target_gresource_sha256": sha256_bytes(resource_target) if resource_target is not None else None,
                    "candidate_gresource_sha256": sha256_bytes(resource_candidate) if resource_candidate is not None else None,
                    "gresource_identity": resource_identity,
                    "verified": verified,
                }
                elf_rows.append(row)
                if not verified:
                    errors.append({"kind": "cross-architecture-elf", "evidence": row})
                    package_elf_ok = False

            if not control_ok:
                errors.append({"kind": "control-fields", "package": package, "evidence": control_evidence})
            if not aux_ok:
                errors.append({
                    "kind": "auxiliary-control-members",
                    "package": package,
                    "target": target_aux,
                    "candidate": candidate_aux,
                })

            package_rows.append({
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
                "control_verified": control_ok,
                "control_evidence": control_evidence,
                "auxiliary_control_members_verified": aux_ok,
                "payload_path_set_verified": path_set_ok,
                "non_elf_payload_verified": package_non_elf_ok,
                "elf_payload_verified": package_elf_ok,
                "verified": control_ok and aux_ok and path_set_ok and package_non_elf_ok and package_elf_ok,
            })

        # Scan every candidate package, including dbgsym packages, for foreign ELFs.
        for deb in sorted(candidate_dir.glob("*.deb")):
            control = deb_control(deb)
            package = control.get("Package", "")
            root = temp / "scan" / package
            root.mkdir(parents=True, exist_ok=True)
            run(["dpkg-deb", "-x", str(deb), str(root)])
            for path in sorted(root.rglob("*")):
                if not is_elf(path):
                    continue
                header = elf_header(path)
                description = str(run(["file", "-b", str(path)])).strip()
                row = {
                    "package": package,
                    "path": path.relative_to(root).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "file": description,
                    "machine": header.get("Machine", ""),
                    "elf_type": header.get("Type", ""),
                }
                all_candidate_elf_rows.append(row)
                if header.get("Machine") != "AArch64" or "x86-64" in description or "Intel 80386" in description:
                    foreign_elfs.append(row)

    if foreign_elfs:
        errors.append({"kind": "foreign-elfs", "elfs": foreign_elfs})
    if not elf_rows:
        errors.append({"kind": "no-runtime-elfs-compared"})

    deb_artifacts: list[dict[str, Any]] = []
    for deb in sorted(candidate_dir.glob("*.deb")):
        control = deb_control(deb)
        deb_artifacts.append({
            "package": control.get("Package", ""),
            "version": control.get("Version", ""),
            "architecture": control.get("Architecture", ""),
            "source": declared_source(control),
            "source_version": VERSION,
            "filename": deb.name,
            "size": deb.stat().st_size,
            "sha256": sha256_file(deb),
        })

    verified = (
        set(target_debs) == expected_names
        and set(candidate_debs) == expected_names
        and not invalid_candidate_extras
        and not foreign_elfs
        and len(package_rows) == len(expected_names)
        and all(row["verified"] for row in package_rows)
        and bool(elf_rows)
        and not errors
    )
    summary = {
        "schema": 1,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": "verified-reconstructed-git-tree",
        "target_architecture": "arm64",
        "policy": (
            "immutable-amd64-authority-plus-canonical-cross-arch-paths-plus-"
            "exact-non-elf-payload-plus-aarch64-elf-dynamic-export-and-gresource-identity"
        ),
        "expected_package_count": len(expected_names),
        "compared_package_count": len(package_rows),
        "candidate_debug_package_count": len([
            row for row in candidate_extras if row["package"].endswith("-dbgsym")
        ]),
        "candidate_extra_debs": candidate_extras,
        "deb_artifacts": deb_artifacts,
        "package_results": package_rows,
        "non_elf_checks": non_elf_rows,
        "runtime_elf_checks": elf_rows,
        "all_candidate_elf_payloads": all_candidate_elf_rows,
        "wrong_architecture_executables": foreign_elfs,
        "verification_errors": errors,
        "verification_warnings": warnings,
        "verified": verified,
    }
    write_json(output / "deb-artifacts.json", deb_artifacts)
    write_json(output / "package-comparisons.json", package_rows)
    write_json(output / "non-elf-comparisons.json", non_elf_rows)
    write_json(output / "elf-comparisons.json", elf_rows)
    write_json(output / "elf-payloads.json", all_candidate_elf_rows)
    write_json(output / "wrong-architecture-elfs.json", foreign_elfs)
    write_json(output / "verification-summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
