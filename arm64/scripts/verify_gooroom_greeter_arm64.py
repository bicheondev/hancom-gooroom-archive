#!/usr/bin/env python3
"""Verify gooroom-greeter han3u2 native ARM64 DEBs and all ELF payloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

VERSION = "0.3.1+grm3u1+han3u2"


def command(arguments: list[str]) -> str:
    result = subprocess.run(arguments, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed: {' '.join(arguments)}\n{result.stdout}")
    return result.stdout.strip()


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deb-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    deb_dir = args.deb_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    debs: list[dict[str, Any]] = []
    elves: list[dict[str, Any]] = []
    wrong: list[dict[str, Any]] = []
    for deb in sorted(deb_dir.glob("*.deb")):
        package = command(["dpkg-deb", "-f", str(deb), "Package"])
        version = command(["dpkg-deb", "-f", str(deb), "Version"])
        architecture = command(["dpkg-deb", "-f", str(deb), "Architecture"])
        if version != VERSION or architecture != "arm64":
            raise RuntimeError(f"wrong package identity: {package} {version} {architecture}")
        root = output / "extracted" / package
        root.mkdir(parents=True, exist_ok=True)
        command(["dpkg-deb", "-x", str(deb), str(root)])
        row = {
            "filename": deb.name,
            "package": package,
            "version": version,
            "architecture": architecture,
            "size": deb.stat().st_size,
            "sha256": sha(deb),
        }
        debs.append(row)
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.read_bytes()[:4] != b"\x7fELF":
                continue
            header = command(["readelf", "-hW", str(path)])
            description = command(["file", "-b", str(path)])
            elf = {
                "package": package,
                "path": path.relative_to(root).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha(path),
                "file": description,
                "machine_header": header,
            }
            elves.append(elf)
            if "AArch64" not in header or "x86-64" in description or "Intel 80386" in description:
                wrong.append(elf)

    mains = [row for row in debs if row["package"] == "gooroom-greeter"]
    verified = len(mains) == 1 and bool(elves) and not wrong
    summary = {
        "schema": 1,
        "source": "gooroom-greeter",
        "source_version": VERSION,
        "target_architecture": "arm64",
        "deb_artifacts": debs,
        "elf_payloads": elves,
        "wrong_architecture_executables": wrong,
        "main_package_count": len(mains),
        "verified": verified,
    }
    (output / "verification-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    (output / "deb-artifacts.json").write_text(
        json.dumps(debs, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
