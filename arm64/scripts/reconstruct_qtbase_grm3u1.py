#!/usr/bin/env python3
"""Reconstruct QtBase 5.15.2+dfsg-9+grm3u1 without claiming original bytes.

Authority chain:
  * the exact AMD64 vendor package supplies the complete downstream changelog;
  * Debian snapshot supplies the signed 5.15.2+dfsg-9 base source archive;
  * a signed Debian security source archive supplies CVE-2022-25255.diff;
  * the downstream changelog identifies that CVE patch as the only code change.

The result is a reproducible, evidence-locked source reconstruction.  It is not
labelled as the lost original source archive and cannot be promoted by version
text alone.
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
from pathlib import Path
from typing import Any, Iterable

SOURCE = "qtbase-opensource-src"
BASE_VERSION = "5.15.2+dfsg-9"
SECURITY_VERSION = "5.15.2+dfsg-9+deb11u1"
TARGET_VERSION = "5.15.2+dfsg-9+grm3u1"
VENDOR_PACKAGE = "libqt5core5a"
PATCH_NAME = "CVE-2022-25255.diff"
CHANGELOG_COMMIT = "b90b36aa"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CHANGELOG_HEADER = re.compile(r"^(\S+) \(([^)]+)\) ([^;]+);(.*)$")


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and process.returncode:
        raise SystemExit(
            f"command failed ({process.returncode}): {' '.join(args)}\n"
            f"stdout:\n{process.stdout[-8000:]}\n"
            f"stderr:\n{process.stderr[-8000:]}"
        )
    return process


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def dpkg_deb_field(path: Path, field: str) -> str:
    process = run(["dpkg-deb", "-f", str(path), field], check=True)
    return process.stdout.strip()


def parse_changelog(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if CHANGELOG_HEADER.match(line)]
    entries: list[dict[str, Any]] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        block = lines[start:end]
        match = CHANGELOG_HEADER.match(block[0])
        if match is None:
            continue
        entries.append(
            {
                "source": match.group(1),
                "version": match.group(2),
                "suite": match.group(3),
                "body": block[1:],
                "text": "\n".join(block).rstrip() + "\n",
            }
        )
    return entries


def parse_deb822(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="strict")
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        separator = text.find("\n\n")
        require(separator >= 0, f"malformed clearsigned file: {path}")
        text = text[separator + 2 :]
        signature = text.find("\n-----BEGIN PGP SIGNATURE-----")
        if signature >= 0:
            text = text[:signature]
    fields: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields


def checksum_rows(fields: dict[str, str]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for field, algorithm in (
        ("Files", "md5"),
        ("Checksums-Sha1", "sha1"),
        ("Checksums-Sha256", "sha256"),
    ):
        for line in fields.get(field, "").splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            checksum, size, filename = parts
            row = rows.setdefault(filename, {"filename": filename})
            row["size"] = int(size)
            row[algorithm] = checksum
    return rows


def verify_dsc_members(dsc: Path, root: Path) -> list[dict[str, Any]]:
    fields = parse_deb822(dsc)
    rows = checksum_rows(fields)
    require(rows, f"no source members in {dsc}")
    verified: list[dict[str, Any]] = []
    for filename, expected in sorted(rows.items()):
        path = root / filename
        require(path.is_file(), f"source member missing: {path}")
        actual_size = path.stat().st_size
        actual_sha256 = sha256(path)
        require(actual_size == int(expected["size"]), f"size mismatch: {path}")
        if "sha256" in expected:
            require(actual_sha256 == expected["sha256"], f"SHA-256 mismatch: {path}")
        verified.append(
            {
                "filename": filename,
                "size": actual_size,
                "sha256": actual_sha256,
                "expected": expected,
            }
        )
    return verified


def vendor_changelog(vendor_deb: Path) -> tuple[str, list[dict[str, Any]]]:
    require(dpkg_deb_field(vendor_deb, "Package") == VENDOR_PACKAGE, "vendor package mismatch")
    require(dpkg_deb_field(vendor_deb, "Version") == TARGET_VERSION, "vendor version mismatch")
    require(dpkg_deb_field(vendor_deb, "Architecture") == "amd64", "vendor architecture mismatch")
    require(dpkg_deb_field(vendor_deb, "Source").split()[0] == SOURCE, "vendor source mismatch")
    with tempfile.TemporaryDirectory(prefix="qtbase-vendor-changelog-") as temporary:
        root = Path(temporary)
        run(["dpkg-deb", "-x", str(vendor_deb), str(root)], check=True)
        changelog = root / "usr/share/doc" / VENDOR_PACKAGE / "changelog.Debian.gz"
        require(changelog.is_file(), f"vendor changelog missing: {changelog}")
        process = run(["gzip", "-cd", str(changelog)], check=True)
        text = process.stdout
    entries = parse_changelog(text)
    require(len(entries) >= 3, "vendor changelog is too short")
    require(entries[0]["source"] == SOURCE, "vendor changelog source mismatch")
    require(entries[0]["version"] == TARGET_VERSION, "vendor changelog top version mismatch")
    require(entries[1]["version"] == TARGET_VERSION, "vendor changelog second version mismatch")
    require(entries[2]["version"] == BASE_VERSION, "vendor changelog base version mismatch")
    first_body = "\n".join(entries[0]["body"])
    second_body = "\n".join(entries[1]["body"])
    require("UNRELEASED" in first_body, "vendor top changelog entry is not the recorded UNRELEASED entry")
    require(f"[{CHANGELOG_COMMIT}]" in second_body, "expected private changelog commit is missing")
    require("CVE-2022-25255 patch" in second_body, "expected CVE patch changelog text is missing")
    return text, entries[:3]


def patch_paths(text: str) -> list[str]:
    paths: set[str] = set()
    for line in text.splitlines():
        if not line.startswith("+++ "):
            continue
        value = line[4:].split("\t", 1)[0]
        value = re.sub(r"^[ab]/", "", value)
        match = re.search(r"(?:^|/)(src/.*|tests/.*)$", value)
        if match:
            paths.add(match.group(1))
    return sorted(paths)


def validate_cve_patch(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="strict")
    required = (
        "CVE-2022-25255",
        "QStandardPaths::findExecutable(program)",
        "argv[0] = ::strdup(tmp.constData());",
        'testProcess.start("./desktopsettingsaware_helper")',
        'testProcess.start("./modal_helper", arguments)',
    )
    for value in required:
        require(value in text, f"canonical patch is missing expected content: {value}")
    paths = patch_paths(text)
    expected_paths = [
        "src/corelib/io/qprocess_unix.cpp",
        "tests/auto/widgets/kernel/qapplication/tst_qapplication.cpp",
    ]
    require(paths == expected_paths, f"unexpected CVE patch paths: {paths}")
    return {
        "filename": path.name,
        "size": path.stat().st_size,
        "sha256": sha256(path),
        "paths": paths,
        "required_semantics_verified": True,
    }


def manifest_rows(root: Path, excluded_prefixes: tuple[str, ...] = (".pc/",)) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if any(relative == prefix.rstrip("/") or relative.startswith(prefix) for prefix in excluded_prefixes):
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            rows.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "target": target,
                    "sha256": hashlib.sha256(os.fsencode(target)).hexdigest(),
                    "size": len(os.fsencode(target)),
                }
            )
        elif stat.S_ISREG(mode):
            rows.append(
                {
                    "path": relative,
                    "type": "file",
                    "size": path.stat().st_size,
                    "sha256": sha256(path),
                }
            )
    return rows


def write_tsv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        stream.write("type\tsize\tsha256\tpath\ttarget\n")
        for row in rows:
            stream.write(
                "\t".join(
                    [
                        str(row.get("type", "")),
                        str(row.get("size", "")),
                        str(row.get("sha256", "")),
                        str(row.get("path", "")),
                        str(row.get("target", "")),
                    ]
                )
                + "\n"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-tree", type=Path, required=True)
    parser.add_argument("--base-source-dir", type=Path, required=True)
    parser.add_argument("--base-dsc", type=Path, required=True)
    parser.add_argument("--security-dsc", type=Path, required=True)
    parser.add_argument("--vendor-deb", type=Path, required=True)
    parser.add_argument("--cve-patch", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--archive-output-dir", type=Path, required=True)
    args = parser.parse_args()

    for path, label in (
        (args.source_tree, "source tree"),
        (args.base_source_dir, "base source directory"),
        (args.base_dsc, "base DSC"),
        (args.security_dsc, "security DSC"),
        (args.vendor_deb, "vendor DEB"),
        (args.cve_patch, "CVE patch"),
    ):
        require(path.exists(), f"{label} is missing: {path}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.archive_output_dir.mkdir(parents=True, exist_ok=True)

    base_fields = parse_deb822(args.base_dsc)
    security_fields = parse_deb822(args.security_dsc)
    require(base_fields.get("Source") == SOURCE, "base DSC source mismatch")
    require(base_fields.get("Version") == BASE_VERSION, "base DSC version mismatch")
    require(security_fields.get("Source") == SOURCE, "security DSC source mismatch")
    require(security_fields.get("Version") == SECURITY_VERSION, "security DSC version mismatch")
    base_members = verify_dsc_members(args.base_dsc, args.base_source_dir)

    process = run(
        ["dpkg-parsechangelog", f"-l{args.source_tree / 'debian/changelog'}", "-S", "Version"],
        check=True,
    )
    require(process.stdout.strip() == BASE_VERSION, "extracted base source version mismatch")

    changelog_text, changelog_entries = vendor_changelog(args.vendor_deb)
    patch_record = validate_cve_patch(args.cve_patch)

    patches_dir = args.source_tree / "debian/patches"
    series_path = patches_dir / "series"
    require(series_path.is_file(), "base source patch series is missing")
    series_before = series_path.read_text(encoding="utf-8")
    require(PATCH_NAME not in [line.split()[0] for line in series_before.splitlines() if line.strip() and not line.lstrip().startswith("#")], "CVE patch already exists in base patch series")

    target_patch = patches_dir / PATCH_NAME
    shutil.copy2(args.cve_patch, target_patch)
    with series_path.open("a", encoding="utf-8") as stream:
        if series_before and not series_before.endswith("\n"):
            stream.write("\n")
        stream.write(PATCH_NAME + "\n")
    (args.source_tree / "debian/changelog").write_text(changelog_text, encoding="utf-8")

    quilt_env = dict(os.environ)
    quilt_env.update({"QUILT_PATCHES": "debian/patches", "QUILT_REFRESH_ARGS": "-p ab --no-timestamps --no-index"})
    quilt = run(["quilt", "push", "-a"], cwd=args.source_tree, env=quilt_env, check=True)
    applied = run(["quilt", "applied"], cwd=args.source_tree, env=quilt_env, check=True)
    applied_names = [Path(line.strip()).name for line in applied.stdout.splitlines() if line.strip()]
    require(applied_names and applied_names[-1] == PATCH_NAME, "CVE patch was not the final applied patch")

    qprocess = (args.source_tree / "src/corelib/io/qprocess_unix.cpp").read_text(encoding="utf-8", errors="strict")
    qapplication = (args.source_tree / "tests/auto/widgets/kernel/qapplication/tst_qapplication.cpp").read_text(encoding="utf-8", errors="strict")
    require("argv[0] = ::strdup(tmp.constData());" in qprocess, "patched QProcess implementation is absent")
    require('testProcess.start("./desktopsettingsaware_helper")' in qapplication, "patched desktop helper test is absent")
    require('testProcess.start("./modal_helper", arguments)' in qapplication, "patched modal helper test is absent")

    target_source = run(
        ["dpkg-parsechangelog", f"-l{args.source_tree / 'debian/changelog'}", "-S", "Source"],
        check=True,
    ).stdout.strip()
    target_version = run(
        ["dpkg-parsechangelog", f"-l{args.source_tree / 'debian/changelog'}", "-S", "Version"],
        check=True,
    ).stdout.strip()
    require(target_source == SOURCE, "reconstructed source name mismatch")
    require(target_version == TARGET_VERSION, "reconstructed source version mismatch")

    build = run(["dpkg-source", "-b", str(args.source_tree)], cwd=args.source_tree.parent, check=True)
    parent = args.source_tree.parent
    dsc_candidates = sorted(parent.glob(f"{SOURCE}_{TARGET_VERSION}.dsc"))
    require(len(dsc_candidates) == 1, f"reconstructed DSC is not unique: {dsc_candidates}")
    reconstructed_dsc = dsc_candidates[0]
    reconstructed_fields = parse_deb822(reconstructed_dsc)
    require(reconstructed_fields.get("Source") == SOURCE, "reconstructed DSC source mismatch")
    require(reconstructed_fields.get("Version") == TARGET_VERSION, "reconstructed DSC version mismatch")
    reconstructed_member_records = verify_dsc_members(reconstructed_dsc, parent)

    source_files = [reconstructed_dsc]
    source_files.extend(parent / row["filename"] for row in reconstructed_member_records)
    unique_source_files: dict[str, Path] = {path.name: path for path in source_files}
    for name, path in sorted(unique_source_files.items()):
        shutil.copy2(path, args.archive_output_dir / name)

    with tempfile.TemporaryDirectory(prefix="verify-reconstructed-qtbase-") as temporary:
        verify_tree = Path(temporary) / "source"
        run(["dpkg-source", "-x", str(args.archive_output_dir / reconstructed_dsc.name), str(verify_tree)], check=True)
        verify_source = run(
            ["dpkg-parsechangelog", f"-l{verify_tree / 'debian/changelog'}", "-S", "Source"],
            check=True,
        ).stdout.strip()
        verify_version = run(
            ["dpkg-parsechangelog", f"-l{verify_tree / 'debian/changelog'}", "-S", "Version"],
            check=True,
        ).stdout.strip()
        require(verify_source == SOURCE and verify_version == TARGET_VERSION, "round-trip source identity failed")
        verify_patch = verify_tree / "debian/patches" / PATCH_NAME
        require(verify_patch.is_file(), "round-trip CVE patch is missing")
        require(sha256(verify_patch) == patch_record["sha256"], "round-trip CVE patch SHA-256 changed")

    manifest = manifest_rows(args.source_tree)
    write_tsv(args.output_dir / "source-tree-manifest.tsv", manifest)
    (args.output_dir / "vendor-changelog.txt").write_text(changelog_text, encoding="utf-8")
    shutil.copy2(args.cve_patch, args.output_dir / PATCH_NAME)
    (args.output_dir / "quilt-push.stdout.txt").write_text(quilt.stdout, encoding="utf-8")
    (args.output_dir / "quilt-push.stderr.txt").write_text(quilt.stderr, encoding="utf-8")
    (args.output_dir / "dpkg-source-build.stdout.txt").write_text(build.stdout, encoding="utf-8")
    (args.output_dir / "dpkg-source-build.stderr.txt").write_text(build.stderr, encoding="utf-8")

    archive_rows = []
    for path in sorted(args.archive_output_dir.iterdir()):
        if path.is_file():
            archive_rows.append({"filename": path.name, "size": path.stat().st_size, "sha256": sha256(path)})
    write_json(args.output_dir / "source-archive-members.json", archive_rows)

    authority = {
        "schema": 1,
        "policy": "exact-vendor-changelog-plus-signed-debian-base-plus-single-official-cve-patch",
        "source": SOURCE,
        "source_version": TARGET_VERSION,
        "source_status": "reconstructed-not-recovered-original-source",
        "build_mode": "signed-debian-base-with-vendor-declared-single-patch-reconstruction",
        "byte_identity_claimed": False,
        "promotion_allowed": False,
        "base_authority": {
            "source": SOURCE,
            "version": BASE_VERSION,
            "dsc": args.base_dsc.name,
            "dsc_sha256": sha256(args.base_dsc),
            "members": base_members,
        },
        "security_patch_authority": {
            "source": SOURCE,
            "version": SECURITY_VERSION,
            "dsc": args.security_dsc.name,
            "dsc_sha256": sha256(args.security_dsc),
            "patch": patch_record,
        },
        "vendor_binary_authority": {
            "package": VENDOR_PACKAGE,
            "version": TARGET_VERSION,
            "architecture": "amd64",
            "filename": args.vendor_deb.name,
            "size": args.vendor_deb.stat().st_size,
            "sha256": sha256(args.vendor_deb),
            "changelog_top_entries": changelog_entries,
            "declared_code_change_commit": CHANGELOG_COMMIT,
            "declared_code_change": "CVE-2022-25255 patch",
        },
        "reconstruction": {
            "patch_series_base_sha256": hashlib.sha256(series_before.encode()).hexdigest(),
            "patch_series_final_sha256": sha256(series_path),
            "final_applied_patch": PATCH_NAME,
            "applied_patch_count": len(applied_names),
            "source_tree_manifest_sha256": sha256(args.output_dir / "source-tree-manifest.tsv"),
            "source_tree_manifest_entry_count": len(manifest),
            "reconstructed_dsc": reconstructed_dsc.name,
            "reconstructed_dsc_sha256": sha256(args.archive_output_dir / reconstructed_dsc.name),
            "archive_members": archive_rows,
            "round_trip_verified": True,
        },
        "claims": {
            "exact_package_name_and_version": True,
            "exact_vendor_changelog_preserved": True,
            "base_source_is_signed_debian_5_15_2_dfsg_9": True,
            "only_vendor_declared_code_patch_added": True,
            "cve_patch_semantics_verified": True,
            "lost_original_source_archive_recovered": False,
            "binary_equivalence_verified": False,
            "native_arm64_build_verified": False,
        },
    }
    write_json(args.output_dir / "authority.json", authority)
    print(json.dumps(authority, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
