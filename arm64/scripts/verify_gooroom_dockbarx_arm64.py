#!/usr/bin/env python3
"""Verify reconstructed gooroom-dockbarx-applet native ARM64 packages."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

SOURCE = "gooroom-dockbarx-applet"
VERSION = "0.3.1+grm3u1+han3u1"
MULTIARCH = "aarch64-linux-gnu"
ELF_MAGIC = b"\x7fELF"
EXPECTED_MAIN_FILES = {
    f"usr/lib/{MULTIARCH}/gnome-panel/modules/gooroom-update-launchers-helper",
    f"usr/lib/{MULTIARCH}/gnome-panel/modules/libgooroom-dockbarx-applet.so",
    f"usr/lib/{MULTIARCH}/gnome-panel/modules/xfce4-dockbarx-plug.py",
    "usr/share/doc/gooroom-dockbarx-applet/changelog.gz",
    "usr/share/doc/gooroom-dockbarx-applet/copyright",
    "usr/share/locale/en_GB/LC_MESSAGES/gooroom-dockbarx-applet.mo",
    "usr/share/locale/ko/LC_MESSAGES/gooroom-dockbarx-applet.mo",
}
EXACT_FILE_HASHES = {
    f"usr/lib/{MULTIARCH}/gnome-panel/modules/xfce4-dockbarx-plug.py": (
        "46dffbcb5d62f1499c1b5e89646234b4c9fa7716680a5c90cb1c0bb3955a6895"
    ),
    "usr/share/doc/gooroom-dockbarx-applet/copyright": (
        "454e47751383f4ecdaf3346c01041bba926f1ee5d2f2581cc528b0a1eacae940"
    ),
    "usr/share/locale/en_GB/LC_MESSAGES/gooroom-dockbarx-applet.mo": (
        "b3d50c58e4bde65eba5bb2e5f0fb2faeb26df4aea99c04f10155c338c78e8299"
    ),
    "usr/share/locale/ko/LC_MESSAGES/gooroom-dockbarx-applet.mo": (
        "ae52d79be69b0f8d9865120f51940d5bbf229af33c37fbf686952f0c08180730"
    ),
}
CHANGELOG_DECOMPRESSED_SHA256 = (
    "586ab9025d7e46d667889d616ce2d9fe48256e82f8d7ae442dffd350a94e83c0"
)
EXPECTED_ELF_RUNTIME = {
    f"usr/lib/{MULTIARCH}/gnome-panel/modules/gooroom-update-launchers-helper": {
        "type_contains": "Position-Independent Executable",
        "needed": [
            "libjson-c.so.5",
            "libgio-2.0.so.0",
            "libgobject-2.0.so.0",
            "libglib-2.0.so.0",
            "libc.so.6",
        ],
        "soname": [],
        "required_exports": [],
    },
    f"usr/lib/{MULTIARCH}/gnome-panel/modules/libgooroom-dockbarx-applet.so": {
        "type_contains": "shared object",
        "needed": [
            "libgnome-panel.so.0",
            "libgtk-3.so.0",
            "libgdk-3.so.0",
            "libgio-2.0.so.0",
            "libgobject-2.0.so.0",
            "libglib-2.0.so.0",
            "libc.so.6",
        ],
        "soname": ["libgooroom-dockbarx-applet.so"],
        "required_exports": [
            "gooroom_dockbarx_applet_get_type",
            "gp_module_load",
            "panel_g_utf8_strstrcase",
        ],
    },
}


def run(arguments: list[str]) -> str:
    completed = subprocess.run(
        arguments,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"{completed.stdout}"
        )
    return completed.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def deb_field(deb: Path, field: str) -> str:
    completed = subprocess.run(
        ["dpkg-deb", "-f", str(deb), field],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def parse_source(value: str, package: str) -> str:
    if value:
        return value.split(" ", 1)[0]
    return package.removesuffix("-dbgsym")


def elf_machine(path: Path) -> str:
    for line in run(["readelf", "-hW", str(path)]).splitlines():
        match = re.match(r"\s*Machine:\s*(.*)$", line)
        if match:
            return match.group(1).strip()
    return ""


def dynamic_identity(path: Path) -> dict[str, list[str]]:
    output = run(["readelf", "-dW", str(path)])
    return {
        "needed": re.findall(r"Shared library: \[([^]]+)\]", output),
        "soname": re.findall(r"Library soname: \[([^]]+)\]", output),
    }


def exported_symbols(path: Path) -> set[str]:
    result: set[str] = set()
    for line in run(["readelf", "--dyn-syms", "-W", str(path)]).splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8 or not parts[0].rstrip(":").isdigit():
            continue
        _, _, _, _, binding, visibility, index, name = parts
        if (
            index != "UND"
            and binding in {"GLOBAL", "WEAK", "GNU_UNIQUE"}
            and visibility in {"DEFAULT", "PROTECTED"}
        ):
            result.add(name)
    return result


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deb-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    deb_dir = args.deb_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    errors: list[str] = []
    debs: list[dict[str, Any]] = []
    elf_rows: list[dict[str, Any]] = []
    wrong_architecture: list[dict[str, Any]] = []
    main_roots: list[Path] = []
    debug_roots: list[Path] = []

    for deb in sorted(deb_dir.glob("*.deb")):
        package = deb_field(deb, "Package")
        version = deb_field(deb, "Version")
        architecture = deb_field(deb, "Architecture")
        source = parse_source(deb_field(deb, "Source"), package)
        if version != VERSION:
            errors.append(f"wrong version in {deb.name}: {version}")
        if architecture != "arm64":
            errors.append(f"wrong architecture in {deb.name}: {architecture}")
        if source != SOURCE:
            errors.append(f"wrong source in {deb.name}: {source}")

        root = output / "extracted" / package
        root.mkdir(parents=True, exist_ok=True)
        run(["dpkg-deb", "-x", str(deb), str(root)])
        if package == SOURCE:
            main_roots.append(root)
        if package == SOURCE + "-dbgsym":
            debug_roots.append(root)

        debs.append(
            {
                "filename": deb.name,
                "package": package,
                "source": source,
                "source_version": VERSION,
                "version": version,
                "architecture": architecture,
                "size": deb.stat().st_size,
                "sha256": sha256_file(deb),
            }
        )

        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.read_bytes()[:4] != ELF_MAGIC:
                continue
            relative = path.relative_to(root).as_posix()
            description = run(["file", "-b", str(path)])
            machine = elf_machine(path)
            row = {
                "package": package,
                "path": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "file": description,
                "machine": machine,
            }
            elf_rows.append(row)
            if (
                "AArch64" not in machine
                or "x86-64" in description
                or "Intel 80386" in description
            ):
                wrong_architecture.append(row)

    if len(main_roots) != 1:
        errors.append(f"expected one main package, found {len(main_roots)}")
    if len(debug_roots) != 1:
        errors.append(f"expected one dbgsym package, found {len(debug_roots)}")

    payload_checks: dict[str, Any] = {}
    runtime_checks: list[dict[str, Any]] = []
    if len(main_roots) == 1:
        root = main_roots[0]
        files = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        if files != EXPECTED_MAIN_FILES:
            errors.append(
                "main package file set mismatch: "
                f"missing={sorted(EXPECTED_MAIN_FILES - files)} "
                f"extra={sorted(files - EXPECTED_MAIN_FILES)}"
            )
        if any("x86_64-linux-gnu" in path for path in files):
            errors.append("x86_64 multiarch path survived in the main package")

        for relative, expected in EXACT_FILE_HASHES.items():
            path = root / relative
            actual = sha256_file(path) if path.is_file() else None
            payload_checks[relative] = {
                "expected_sha256": expected,
                "actual_sha256": actual,
                "identical": actual == expected,
            }
            if actual != expected:
                errors.append(f"exact payload mismatch: {relative}")

        changelog = root / "usr/share/doc/gooroom-dockbarx-applet/changelog.gz"
        if not changelog.is_file():
            errors.append("compressed changelog is missing")
        else:
            actual = sha256_bytes(gzip.decompress(changelog.read_bytes()))
            payload_checks["changelog_decompressed_sha256"] = actual
            if actual != CHANGELOG_DECOMPRESSED_SHA256:
                errors.append("decompressed changelog authority mismatch")

        for relative, expectation in EXPECTED_ELF_RUNTIME.items():
            path = root / relative
            if not path.is_file():
                errors.append(f"required runtime ELF is missing: {relative}")
                continue
            description = run(["file", "-b", str(path)])
            dynamic = dynamic_identity(path)
            exports = exported_symbols(path)
            missing_exports = sorted(set(expectation["required_exports"]) - exports)
            row = {
                "path": relative,
                "description": description,
                "machine": elf_machine(path),
                "needed": dynamic["needed"],
                "expected_needed": expectation["needed"],
                "needed_identical": dynamic["needed"] == expectation["needed"],
                "soname": dynamic["soname"],
                "expected_soname": expectation["soname"],
                "soname_identical": dynamic["soname"] == expectation["soname"],
                "required_exports": expectation["required_exports"],
                "missing_exports": missing_exports,
                "type_match": expectation["type_contains"].lower()
                in description.lower(),
            }
            row["verified"] = (
                row["machine"] == "AArch64"
                and row["needed_identical"]
                and row["soname_identical"]
                and not missing_exports
                and row["type_match"]
            )
            runtime_checks.append(row)
            if not row["verified"]:
                errors.append(f"runtime ELF identity mismatch: {relative}")

    verified = (
        len(main_roots) == 1
        and len(debug_roots) == 1
        and len(elf_rows) >= 3
        and not wrong_architecture
        and not errors
        and len(runtime_checks) == len(EXPECTED_ELF_RUNTIME)
        and all(row["verified"] for row in runtime_checks)
    )
    summary = {
        "schema": 2,
        "source": SOURCE,
        "source_version": VERSION,
        "source_type": "verified-reconstructed-git-tree",
        "target_architecture": "arm64",
        "deb_artifacts": debs,
        "elf_payloads": elf_rows,
        "wrong_architecture_executables": wrong_architecture,
        "main_package_count": len(main_roots),
        "debug_package_count": len(debug_roots),
        "payload_checks": payload_checks,
        "runtime_checks": runtime_checks,
        "verification_errors": errors,
        "verified": verified,
    }
    write_json(output / "verification-summary.json", summary)
    write_json(output / "deb-artifacts.json", debs)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
