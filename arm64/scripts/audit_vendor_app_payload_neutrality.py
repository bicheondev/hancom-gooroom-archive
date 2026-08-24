#!/usr/bin/env python3
"""Audit exact AMD64 vendor DEBs for architecture-neutral ARM64 repacking.

This is a conservative, fail-closed audit. A package becomes a repack candidate
only when its complete data payload has no ELF, PE, Mach-O, WebAssembly, native
Python extension, architecture-specific library path, or architecture-specific
maintainer-script reference. Candidate DEBs are rebuilt with only the Debian
Architecture field changed to arm64, then their data payload is proved
byte-identical to the locked AMD64 package.

The audit does not claim recovered original source and does not promote any
package by itself. It emits evidence for a later explicit architecture-replace
authority decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

HEX64 = re.compile(r"^[0-9a-f]{64}$")
ARCH_PATH_RE = re.compile(
    r"(?:^|/)(?:x86_64-linux-gnu|i386-linux-gnu|i686-linux-gnu|amd64|x86_64|lib64)(?:/|$)",
    re.IGNORECASE,
)
SCRIPT_ARCH_RE = re.compile(
    r"(?:x86_64|amd64|i[3-6]86|x86_64-linux-gnu|i386-linux-gnu|/lib64(?:/|\b))",
    re.IGNORECASE,
)
NATIVE_SUFFIX_RE = re.compile(r"(?:\.so(?:\.[0-9.]+)?|\.node|\.dll|\.dylib|\.exe)$", re.IGNORECASE)


@dataclass(frozen=True)
class Target:
    package: str
    version: str
    source: str


TARGETS: tuple[Target, ...] = (
    Target("gooroom-dockbarx-applet", "0.3.1+grm3u1+han3u1", "gooroom-dockbarx-applet"),
    Target("gooroom-guide", "0.5.3+grm3u1+han3u1", "gooroom-guide"),
    Target("gooroom-integration-applet", "0.3.1+grm3u1+han3u3", "gooroom-integration-applet"),
    Target("gooroom-session-manager", "0.3.9+grm3u1+han3u2", "gooroom-session-manager"),
)

MACHINES = {
    0: "none",
    3: "i386",
    8: "mips",
    20: "powerpc",
    21: "powerpc64",
    40: "arm",
    50: "ia64",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}


def run(args: list[str], *, check: bool = False, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def parse_control_text(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line.strip()
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields


def deb_fields(path: Path) -> dict[str, str]:
    process = run(["dpkg-deb", "-f", str(path)])
    if process.returncode:
        raise RuntimeError(f"dpkg-deb -f failed for {path}: {process.stderr[-2000:]}")
    return parse_control_text(process.stdout)


def exact_source_identity(fields: dict[str, str]) -> tuple[str, str]:
    package_version = fields.get("Version", "")
    raw = fields.get("Source", "").strip()
    if not raw:
        return fields.get("Package", ""), package_version
    match = re.fullmatch(r"([^\s(]+)(?:\s*\(([^)]+)\))?", raw)
    if match:
        return match.group(1), match.group(2) or package_version
    return raw, package_version


def select_debs(root: Path) -> dict[Target, Path]:
    matches: dict[Target, list[Path]] = {target: [] for target in TARGETS}
    for path in sorted(root.rglob("*.deb")):
        try:
            fields = deb_fields(path)
        except RuntimeError:
            continue
        source, source_version = exact_source_identity(fields)
        for target in TARGETS:
            if (
                fields.get("Package") == target.package
                and fields.get("Version") == target.version
                and fields.get("Architecture") == "amd64"
                and source == target.source
                and source_version == target.version
            ):
                matches[target].append(path)
    selected: dict[Target, Path] = {}
    for target, paths in matches.items():
        if len(paths) != 1:
            raise RuntimeError(
                f"exact DEB selection for {target.package} {target.version} is not unique: "
                f"{[str(path) for path in paths]}"
            )
        selected[target] = paths[0]
    return selected


def elf_machine(path: Path) -> str | None:
    with path.open("rb") as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    byteorder = {1: "little", 2: "big"}.get(header[5])
    if byteorder is None:
        return "invalid-endian"
    machine = int.from_bytes(header[18:20], byteorder)
    return MACHINES.get(machine, f"machine-{machine}")


def binary_magic(path: Path) -> str | None:
    with path.open("rb") as stream:
        head = stream.read(16)
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x00asm"):
        return "wasm"
    if head[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    }:
        return "mach-o"
    return None


def file_manifest(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = "/" + path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            rows.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "mode": stat.S_IMODE(mode),
                    "size": len(os.fsencode(target)),
                    "sha256": hashlib.sha256(os.fsencode(target)).hexdigest(),
                    "target": target,
                }
            )
        elif stat.S_ISREG(mode):
            rows.append(
                {
                    "path": relative,
                    "type": "file",
                    "mode": stat.S_IMODE(mode),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "target": "",
                }
            )
        elif stat.S_ISDIR(mode):
            rows.append(
                {
                    "path": relative,
                    "type": "directory",
                    "mode": stat.S_IMODE(mode),
                    "size": 0,
                    "sha256": "",
                    "target": "",
                }
            )
    return rows


def scan_payload(root: Path) -> dict[str, Any]:
    native: list[dict[str, Any]] = []
    suspicious_suffixes: list[dict[str, str]] = []
    architecture_paths: list[str] = []
    executable_scripts: list[dict[str, str]] = []
    python_files: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = "/" + path.relative_to(root).as_posix()
        if ARCH_PATH_RE.search(relative):
            architecture_paths.append(relative)
        if path.is_symlink() or not path.is_file():
            continue
        machine = elf_machine(path)
        magic = binary_magic(path)
        if machine is not None or magic is not None:
            native.append(
                {
                    "path": relative,
                    "kind": "elf" if machine is not None else magic,
                    "machine": machine,
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
        elif NATIVE_SUFFIX_RE.search(path.name):
            suspicious_suffixes.append({"path": relative, "reason": "native-looking suffix without recognized magic"})
        if path.suffix == ".py":
            python_files.append(relative)
        if path.stat().st_mode & 0o111:
            with path.open("rb") as stream:
                first = stream.readline(4096)
            if first.startswith(b"#!"):
                executable_scripts.append(
                    {"path": relative, "shebang": first.decode("utf-8", errors="replace").strip()}
                )
    return {
        "native_payloads": native,
        "native_looking_suffixes": suspicious_suffixes,
        "architecture_specific_paths": sorted(set(architecture_paths)),
        "executable_scripts": executable_scripts,
        "python_files": python_files,
    }


def maintainer_script_audit(control_dir: Path) -> dict[str, Any]:
    scripts: list[dict[str, Any]] = []
    architecture_references: list[dict[str, Any]] = []
    for name in ("preinst", "postinst", "prerm", "postrm", "config", "triggers"):
        path = control_dir / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        record = {
            "name": name,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
            "shebang": text.splitlines()[0] if text.splitlines() else "",
        }
        scripts.append(record)
        for line_number, line in enumerate(text.splitlines(), start=1):
            if SCRIPT_ARCH_RE.search(line):
                architecture_references.append(
                    {"script": name, "line": line_number, "text": line[:500]}
                )
    return {
        "scripts": scripts,
        "architecture_references": architecture_references,
    }


def replace_architecture(control_path: Path, architecture: str) -> None:
    lines = control_path.read_text(encoding="utf-8", errors="strict").splitlines()
    replaced = 0
    output: list[str] = []
    for line in lines:
        if line.startswith("Architecture:"):
            output.append(f"Architecture: {architecture}")
            replaced += 1
        else:
            output.append(line)
    if replaced != 1:
        raise RuntimeError(f"expected exactly one Architecture field in {control_path}, found {replaced}")
    control_path.write_text("\n".join(output) + "\n", encoding="utf-8")


def verify_python(root: Path) -> dict[str, Any]:
    files = sorted(root.rglob("*.py"))
    failures: list[dict[str, str]] = []
    compiled = 0
    for path in files:
        process = run(
            [
                "python3",
                "-c",
                "import py_compile,sys; py_compile.compile(sys.argv[1], doraise=True, cfile='/tmp/hancom-gooroom-pycheck.pyc')",
                str(path),
            ]
        )
        if process.returncode:
            failures.append({"path": "/" + path.relative_to(root).as_posix(), "error": process.stderr[-2000:]})
        else:
            compiled += 1
    return {"python_file_count": len(files), "compiled_count": compiled, "failures": failures}


def audit_one(target: Target, deb: Path, output: Path) -> dict[str, Any]:
    package_dir = output / target.package
    package_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"{target.package}-neutrality-") as temp_name:
        temp = Path(temp_name)
        original_root = temp / "original-root"
        original_control = temp / "original-control"
        repack_tree = temp / "repack"
        repack_control = repack_tree / "DEBIAN"
        original_root.mkdir()
        original_control.mkdir()
        process = run(["dpkg-deb", "-x", str(deb), str(original_root)])
        if process.returncode:
            raise RuntimeError(process.stderr[-2000:])
        process = run(["dpkg-deb", "-e", str(deb), str(original_control)])
        if process.returncode:
            raise RuntimeError(process.stderr[-2000:])

        fields = deb_fields(deb)
        source, source_version = exact_source_identity(fields)
        scan = scan_payload(original_root)
        scripts = maintainer_script_audit(original_control)
        original_manifest = file_manifest(original_root)
        pycheck = verify_python(original_root)
        blocker_reasons: list[str] = []
        if scan["native_payloads"]:
            blocker_reasons.append("native-payload-present")
        if scan["native_looking_suffixes"]:
            blocker_reasons.append("native-looking-suffix-present")
        if scan["architecture_specific_paths"]:
            blocker_reasons.append("architecture-specific-path-present")
        if scripts["architecture_references"]:
            blocker_reasons.append("maintainer-script-architecture-reference")
        if pycheck["failures"]:
            blocker_reasons.append("python-bytecode-check-failed")
        if fields.get("Architecture") != "amd64":
            blocker_reasons.append("unexpected-original-architecture")
        candidate = not blocker_reasons

        result: dict[str, Any] = {
            "schema": 1,
            "policy": "conservative-byte-identical-data-payload-arm64-metadata-repack-audit",
            "package": target.package,
            "version": target.version,
            "source": target.source,
            "source_version": target.version,
            "selected_deb": deb.name,
            "selected_deb_size": deb.stat().st_size,
            "selected_deb_sha256": sha256_file(deb),
            "control_fields": fields,
            "parsed_source": source,
            "parsed_source_version": source_version,
            "payload_scan": scan,
            "maintainer_script_audit": scripts,
            "python_verification": pycheck,
            "original_payload_manifest_sha256": hashlib.sha256(
                (json.dumps(original_manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
            ).hexdigest(),
            "original_payload_entry_count": len(original_manifest),
            "repack_candidate": candidate,
            "blocker_reasons": blocker_reasons,
            "repacked": False,
            "promotion_allowed": False,
            "byte_identity_claimed_for_data_payload_only": candidate,
            "original_source_recovered": False,
        }
        write_json(package_dir / "original-payload-manifest.json", original_manifest)

        if candidate:
            shutil.copytree(original_root, repack_tree, symlinks=True)
            shutil.copytree(original_control, repack_control, symlinks=True)
            replace_architecture(repack_control / "control", "arm64")
            repacked_deb = package_dir / f"{target.package}_{target.version}_arm64.repacked.deb"
            process = run(
                ["dpkg-deb", "--root-owner-group", "--build", str(repack_tree), str(repacked_deb)]
            )
            if process.returncode:
                raise RuntimeError(f"repack failed: {process.stderr[-4000:]}")
            verify_root = temp / "verify-root"
            verify_control = temp / "verify-control"
            verify_root.mkdir()
            verify_control.mkdir()
            run(["dpkg-deb", "-x", str(repacked_deb), str(verify_root)], check=True)
            run(["dpkg-deb", "-e", str(repacked_deb), str(verify_control)], check=True)
            repacked_manifest = file_manifest(verify_root)
            repacked_fields = deb_fields(repacked_deb)
            identical = original_manifest == repacked_manifest
            verify_scan = scan_payload(verify_root)
            if not identical:
                raise RuntimeError(f"{target.package}: repacked data payload differs from exact AMD64 package")
            if repacked_fields.get("Architecture") != "arm64":
                raise RuntimeError(f"{target.package}: repacked Architecture is not arm64")
            if verify_scan["native_payloads"] or verify_scan["architecture_specific_paths"]:
                raise RuntimeError(f"{target.package}: repacked payload gained architecture-specific content")
            write_json(package_dir / "repacked-payload-manifest.json", repacked_manifest)
            result.update(
                {
                    "repacked": True,
                    "repacked_deb": repacked_deb.name,
                    "repacked_deb_size": repacked_deb.stat().st_size,
                    "repacked_deb_sha256": sha256_file(repacked_deb),
                    "repacked_control_fields": repacked_fields,
                    "data_payload_byte_identical": identical,
                    "repacked_payload_scan": verify_scan,
                    "recommended_authority": "verified-architecture-neutral-data-payload-repack",
                }
            )

        write_json(package_dir / "result.json", result)
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deb-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.deb_root.is_dir():
        raise SystemExit(f"DEB root is missing: {args.deb_root}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    selected = select_debs(args.deb_root)
    results = [audit_one(target, selected[target], args.output_dir) for target in TARGETS]
    candidates = [row for row in results if row["repack_candidate"] and row["repacked"]]
    summary = {
        "schema": 1,
        "policy": "conservative-byte-identical-data-payload-arm64-metadata-repack-audit",
        "target_count": len(TARGETS),
        "exact_deb_selected_count": len(selected),
        "repack_candidate_count": len(candidates),
        "native_source_required_count": len(TARGETS) - len(candidates),
        "candidate_packages": [row["package"] for row in candidates],
        "native_source_required_packages": [
            row["package"] for row in results if not row["repack_candidate"]
        ],
        "results": results,
        "promotion_allowed": False,
        "next_gate": "explicit-architecture-replace-authority-and-native-arm64-install-smoke-test",
    }
    write_json(args.output_dir / "summary.json", summary)
    (args.output_dir / "summary.tsv").write_text(
        "package\tversion\trepack_candidate\trepacked\tnative_payloads\tarch_paths\tblocker_reasons\n"
        + "".join(
            "\t".join(
                [
                    row["package"],
                    row["version"],
                    str(row["repack_candidate"]).lower(),
                    str(row["repacked"]).lower(),
                    str(len(row["payload_scan"]["native_payloads"])),
                    str(len(row["payload_scan"]["architecture_specific_paths"])),
                    ",".join(row["blocker_reasons"]),
                ]
            )
            + "\n"
            for row in results
        ),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
