#!/usr/bin/env python3
"""Fail closed when a DEB contains foreign machine code.

Every ELF file and every ELF member of a static archive must report AArch64.
PE/COFF and Mach-O payloads are rejected.  Scripts, bytecode, firmware-like
data, icons, translations and other architecture-neutral files are left
untouched.  The audit is content based and does not trust the DEB Architecture
field alone.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
AR_MAGIC = b"!<arch>\n"


def run(*args: str) -> str:
    completed = subprocess.run(
        args,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    return completed.stdout


def elf_machine(path: Path) -> str:
    output = run("readelf", "-h", str(path))
    for line in output.splitlines():
        if "Machine:" in line:
            return line.split("Machine:", 1)[1].strip()
    raise RuntimeError(f"readelf did not report a machine for {path}")


def check_elf(path: Path, display: str, records: list[dict[str, Any]], failures: list[dict[str, Any]]) -> None:
    machine = elf_machine(path)
    record = {"path": display, "format": "ELF", "machine": machine}
    records.append(record)
    normalized = machine.lower()
    if "aarch64" not in normalized and "arm64" not in normalized:
        failures.append(record)


def archive_members(path: Path, work: Path) -> list[Path]:
    member_names = [line for line in run("ar", "t", str(path)).splitlines() if line]
    destination = work / (path.name + ".members")
    destination.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["ar", "x", str(path)],
        cwd=destination,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return [destination / name for name in member_names if (destination / name).is_file()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("deb", type=Path, nargs="+")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    for command in ("dpkg-deb", "readelf", "ar"):
        if shutil.which(command) is None:
            raise SystemExit(f"required command is missing: {command}")

    all_reports: list[dict[str, Any]] = []
    failed = False
    for deb in args.deb:
        if not deb.is_file():
            raise SystemExit(f"DEB is absent: {deb}")
        with tempfile.TemporaryDirectory(prefix="deb-machine-") as temporary:
            work = Path(temporary)
            root = work / "root"
            root.mkdir()
            subprocess.run(
                ["dpkg-deb", "-x", str(deb), str(root)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            records: list[dict[str, Any]] = []
            failures: list[dict[str, Any]] = []
            rejected_formats: list[dict[str, str]] = []
            for path in sorted(item for item in root.rglob("*") if item.is_file()):
                relative = "/" + str(path.relative_to(root))
                try:
                    head = path.read_bytes()[:8]
                except OSError as error:
                    failures.append({"path": relative, "error": repr(error)})
                    continue
                if head.startswith(ELF_MAGIC):
                    check_elf(path, relative, records, failures)
                elif head.startswith(AR_MAGIC):
                    archive_work = work / "archives"
                    archive_work.mkdir(exist_ok=True)
                    try:
                        for member in archive_members(path, archive_work):
                            member_head = member.read_bytes()[:8]
                            display = f"{relative}({member.name})"
                            if member_head.startswith(ELF_MAGIC):
                                check_elf(member, display, records, failures)
                            elif member_head[:4] in MACHO_MAGICS or member_head.startswith(b"MZ"):
                                rejected_formats.append(
                                    {"path": display, "format": "foreign object"}
                                )
                    except Exception as error:
                        failures.append(
                            {"path": relative, "format": "ar", "error": repr(error)}
                        )
                elif head[:4] in MACHO_MAGICS:
                    rejected_formats.append({"path": relative, "format": "Mach-O"})
                elif head.startswith(b"MZ"):
                    rejected_formats.append({"path": relative, "format": "PE/COFF"})

            failures.extend(rejected_formats)
            package = run("dpkg-deb", "-f", str(deb), "Package").strip()
            version = run("dpkg-deb", "-f", str(deb), "Version").strip()
            architecture = run("dpkg-deb", "-f", str(deb), "Architecture").strip()
            report = {
                "deb": str(deb),
                "package": package,
                "version": version,
                "declared_architecture": architecture,
                "machine_code_records": records,
                "failure_count": len(failures),
                "failures": failures,
            }
            all_reports.append(report)
            if failures:
                failed = True

    document = {
        "status": "failed" if failed else "passed",
        "deb_count": len(all_reports),
        "packages": all_reports,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(document, ensure_ascii=False, indent=2))
    return 5 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
