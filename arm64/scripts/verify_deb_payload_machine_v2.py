#!/usr/bin/env python3
"""Memory-bounded machine-code audit for Debian packages.

The audit reads only file headers, checks every ELF with ``readelf``, and streams
static-archive members to temporary files before checking them.  A valid native
ARM64 package may contain scripts and architecture-neutral data, but every ELF
object must be AArch64 and PE/COFF or Mach-O payloads are rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, BinaryIO

ELF_MAGIC = b"\x7fELF"
AR_MAGIC = b"!<arch>\n"
THIN_AR_MAGIC = b"!<thin>\n"
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


def command_text(*args: str) -> str:
    return subprocess.run(
        args,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    ).stdout


def head(path: Path, size: int = 8) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def machine(path: Path) -> str:
    output = command_text("readelf", "-h", str(path))
    for line in output.splitlines():
        if "Machine:" in line:
            return line.split("Machine:", 1)[1].strip()
    raise RuntimeError(f"readelf did not report a machine for {path}")


def inspect_object(
    path: Path,
    display: str,
    records: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> None:
    signature = head(path)
    if signature.startswith(ELF_MAGIC):
        value = machine(path)
        record = {"path": display, "format": "ELF", "machine": value}
        records.append(record)
        normalized = value.casefold()
        if "aarch64" not in normalized and "arm64" not in normalized:
            failures.append(record)
    elif signature[:4] in MACHO_MAGICS:
        failures.append({"path": display, "format": "Mach-O"})
    elif signature.startswith(b"MZ"):
        failures.append({"path": display, "format": "PE/COFF"})


def stream_archive_member(archive: Path, member: str, destination: Path) -> None:
    with destination.open("wb") as handle:
        subprocess.run(
            ["ar", "p", str(archive), member],
            check=True,
            stdout=handle,
            stderr=subprocess.PIPE,
        )


def inspect_archive(
    archive: Path,
    display: str,
    work: Path,
    records: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> None:
    members = [line for line in command_text("ar", "t", str(archive)).splitlines() if line]
    archive_id = hashlib.sha256(str(archive).encode()).hexdigest()[:16]
    archive_work = work / archive_id
    archive_work.mkdir(parents=True, exist_ok=True)
    for index, member in enumerate(members):
        destination = archive_work / f"{index:06d}.member"
        try:
            stream_archive_member(archive, member, destination)
            inspect_object(
                destination,
                f"{display}({member})",
                records,
                failures,
            )
        except Exception as error:
            failures.append(
                {
                    "path": f"{display}({member})",
                    "format": "ar-member",
                    "error": repr(error),
                }
            )


def field(deb: Path, name: str) -> str:
    return command_text("dpkg-deb", "-f", str(deb), name).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("deb", type=Path, nargs="+")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    for command in ("dpkg-deb", "readelf", "ar"):
        if shutil.which(command) is None:
            raise SystemExit(f"required command is missing: {command}")

    reports: list[dict[str, Any]] = []
    failed = False
    for deb in args.deb:
        if not deb.is_file():
            raise SystemExit(f"DEB is absent: {deb}")
        with tempfile.TemporaryDirectory(prefix="deb-machine-v2-") as temporary:
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
            for path in sorted(item for item in root.rglob("*") if item.is_file()):
                relative = "/" + str(path.relative_to(root))
                try:
                    signature = head(path)
                    if signature.startswith((AR_MAGIC, THIN_AR_MAGIC)):
                        inspect_archive(path, relative, work / "archives", records, failures)
                    else:
                        inspect_object(path, relative, records, failures)
                except Exception as error:
                    failures.append({"path": relative, "error": repr(error)})

            report = {
                "deb": str(deb),
                "package": field(deb, "Package"),
                "version": field(deb, "Version"),
                "declared_architecture": field(deb, "Architecture"),
                "machine_code_records": records,
                "failure_count": len(failures),
                "failures": failures,
            }
            reports.append(report)
            failed = failed or bool(failures)

    document = {
        "status": "failed" if failed else "passed",
        "deb_count": len(reports),
        "packages": reports,
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
