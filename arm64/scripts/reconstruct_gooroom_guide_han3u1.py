#!/usr/bin/env python3
"""Reconstruct Hancom Gooroom 3.3 gooroom-guide from the public 0.5.1 tree.

The lost 0.5.3 source archive is not claimed as recovered.  The exact shipped
AMD64 DEB is the immutable target authority.  Reconstruction is bounded to the
changes described by its packaged changelog: source cleanup, removal of the
duplicate GtkOverlay insertion, and the Hancom Gooroom 3.3 guide contents.
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
from pathlib import Path
from typing import Any

SOURCE = "gooroom-guide"
BASE_VERSION = "0.5.1+grm3u1+han3u1"
TARGET_VERSION = "0.5.3+grm3u1+han3u1"
BASE_REPOSITORY = "hancomgooroom/gooroom-guide"
BASE_COMMIT = "c788c29119d43bb97c554973f6dabbc41a9abe79"
BASE_TREE = "0d4bb01b49c69e33208a47c0aff47545291ee646"
TARGET_DEB_SIZE = 3620004
TARGET_DEB_SHA256 = "80b2fa518e934f79c624a9aafdd44add1524389b2b3b899f1a4ffcb7fdf99142"
TARGET_GUIDE_ROOT = "usr/share/gooroom-guide/guide"
TARGET_CHANGELOG = "usr/share/doc/gooroom-guide/changelog.gz"
SOURCE_GUIDE_ROOT = "data/guide"
DIMENSION_BLOCK = """#define MINIMUM_WIDTH 600
#define MINIMUM_HEIGHT 330

#define MINIMUM_WIDTH 600
#define MINIMUM_HEIGHT 330
"""
CLEAN_DIMENSION_BLOCK = """#define MINIMUM_WIDTH 600
#define MINIMUM_HEIGHT 330
"""
OVERLAY_BLOCK = """

  gtk_overlay_add_overlay (GTK_OVERLAY(self->guide_overlay), self->bar_stack);
"""
EXPECTED_IMAGE_NAMES = {
    f"{language}/{name}"
    for language in ("en", "ko")
    for name in (
        "1_intro.jpg",
        "2_information.jpg",
        "3_desktop.jpg",
        "4_systemtray.jpg",
        "5_window.jpg",
        "6_notification.jpg",
        "7_browser.jpg",
        "8_basicapps.jpg",
        "9_security.jpg",
        "10_finish.jpg",
    )
}
EXPECTED_CHANGED_PATHS = {
    "debian/changelog",
    "src/guide-window.c",
    "data/guide/toc.json",
    *(f"data/guide/{name}" for name in EXPECTED_IMAGE_NAMES),
}
ELF_MAGIC = b"\x7fELF"


def run(arguments: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
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
    return run(["dpkg-deb", "-f", str(deb), field])


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def elf_header(path: Path) -> dict[str, str]:
    result = {"machine": "", "type": ""}
    for line in run(["readelf", "-hW", str(path)]).splitlines():
        if line.lstrip().startswith("Machine:"):
            result["machine"] = line.split(":", 1)[1].strip()
        elif line.lstrip().startswith("Type:"):
            result["type"] = line.split(":", 1)[1].strip().split()[0]
    return result


def elf_interpreter(path: Path) -> str | None:
    output = run(["readelf", "-lW", str(path)])
    match = re.search(r"Requesting program interpreter:\s*([^]]+)\]", output)
    return match.group(1).strip() if match else None


def dynamic_identity(path: Path) -> dict[str, list[str]]:
    output = run(["readelf", "-dW", str(path)])
    return {
        "needed": re.findall(r"Shared library: \[([^]]+)\]", output),
        "soname": re.findall(r"Library soname: \[([^]]+)\]", output),
    }


def payload_manifest(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        row: dict[str, Any] = {
            "path": relative,
            "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
            "size": len(payload),
            "sha256": sha256_bytes(payload),
            "elf": payload.startswith(ELF_MAGIC),
        }
        if path.name.endswith(".gz"):
            try:
                clear = gzip.decompress(payload)
            except OSError:
                pass
            else:
                row["decompressed_size"] = len(clear)
                row["decompressed_sha256"] = sha256_bytes(clear)
        if row["elf"]:
            row["elf_header"] = elf_header(path)
            row["interpreter"] = elf_interpreter(path)
            row["dynamic"] = dynamic_identity(path)
        rows.append(row)
    return rows


def require_equal_bytes(left: Path, right: Path, label: str) -> None:
    if not left.is_file() or not right.is_file():
        raise SystemExit(f"{label}: required file is missing")
    if left.read_bytes() != right.read_bytes():
        raise SystemExit(f"{label}: public base and target payload differ unexpectedly")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--target-deb", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    repository = args.repository.resolve()
    target_deb = args.target_deb.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    if not (repository / ".git").exists():
        raise SystemExit(f"not a Git working tree: {repository}")
    if not target_deb.is_file():
        raise SystemExit(f"target DEB is missing: {target_deb}")
    if target_deb.stat().st_size != TARGET_DEB_SIZE:
        raise SystemExit(
            f"target DEB size mismatch: {target_deb.stat().st_size} != {TARGET_DEB_SIZE}"
        )
    if sha256_file(target_deb) != TARGET_DEB_SHA256:
        raise SystemExit("target DEB SHA-256 does not match the locked authority")
    if deb_field(target_deb, "Package") != SOURCE:
        raise SystemExit("target package identity mismatch")
    if deb_field(target_deb, "Version") != TARGET_VERSION:
        raise SystemExit("target version identity mismatch")
    if deb_field(target_deb, "Architecture") != "amd64":
        raise SystemExit("target architecture identity mismatch")

    actual_commit = run(["git", "rev-parse", "HEAD"], cwd=repository)
    actual_tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=repository)
    if actual_commit != BASE_COMMIT:
        raise SystemExit(f"public base commit mismatch: {actual_commit}")
    if actual_tree != BASE_TREE:
        raise SystemExit(f"public base tree mismatch: {actual_tree}")
    if run(["git", "status", "--porcelain=v1"], cwd=repository):
        raise SystemExit("public base checkout is not clean")
    base_version = run(
        ["dpkg-parsechangelog", "-l", "debian/changelog", "-SVersion"],
        cwd=repository,
    )
    if base_version != BASE_VERSION:
        raise SystemExit(f"public base changelog mismatch: {base_version}")

    target_root = output / "target-root"
    shutil.rmtree(target_root, ignore_errors=True)
    target_root.mkdir(parents=True)
    run(["dpkg-deb", "-x", str(target_deb), str(target_root)])
    target_guide = target_root / TARGET_GUIDE_ROOT
    target_changelog_path = target_root / TARGET_CHANGELOG
    if not target_guide.is_dir() or not target_changelog_path.is_file():
        raise SystemExit("target payload lacks the expected guide or changelog")

    target_images = {
        path.relative_to(target_guide).as_posix()
        for path in target_guide.rglob("*.jpg")
    }
    if target_images != EXPECTED_IMAGE_NAMES:
        raise SystemExit(
            "target image set mismatch: "
            f"missing={sorted(EXPECTED_IMAGE_NAMES - target_images)} "
            f"extra={sorted(target_images - EXPECTED_IMAGE_NAMES)}"
        )

    source_guide = repository / SOURCE_GUIDE_ROOT
    require_equal_bytes(source_guide / "order", target_guide / "order", "guide order")
    require_equal_bytes(
        source_guide / "en/common.css",
        target_guide / "en/common.css",
        "English guide CSS",
    )
    require_equal_bytes(
        source_guide / "ko/common.css",
        target_guide / "ko/common.css",
        "Korean guide CSS",
    )
    require_equal_bytes(
        repository / "app-icons/scalable/apps/gooroom-guide.svg",
        target_root / "usr/share/icons/hicolor/scalable/apps/gooroom-guide.svg",
        "application icon",
    )
    require_equal_bytes(
        repository / "debian/copyright",
        target_root / "usr/share/doc/gooroom-guide/copyright",
        "copyright payload",
    )

    source_c = repository / "src/guide-window.c"
    source_text = source_c.read_text(encoding="utf-8")
    if source_text.count(DIMENSION_BLOCK) != 1:
        raise SystemExit("duplicate dimension-block anchor was not found exactly once")
    if source_text.count(OVERLAY_BLOCK) != 1:
        raise SystemExit("GtkOverlay insertion anchor was not found exactly once")
    source_text = source_text.replace(DIMENSION_BLOCK, CLEAN_DIMENSION_BLOCK)
    source_text = source_text.replace(OVERLAY_BLOCK, "")
    source_c.write_text(source_text, encoding="utf-8")

    shutil.rmtree(source_guide)
    shutil.copytree(target_guide, source_guide)
    changelog_bytes = gzip.decompress(target_changelog_path.read_bytes())
    (repository / "debian/changelog").write_bytes(changelog_bytes)

    target_version = run(
        ["dpkg-parsechangelog", "-l", "debian/changelog", "-SVersion"],
        cwd=repository,
    )
    if target_version != TARGET_VERSION:
        raise SystemExit(f"reconstructed source version mismatch: {target_version}")

    run(["git", "diff", "--check"], cwd=repository)
    changed = set(
        filter(
            None,
            run(["git", "diff", "--name-only", "--relative"], cwd=repository)
            .splitlines(),
        )
    )
    if changed != EXPECTED_CHANGED_PATHS:
        raise SystemExit(
            "reconstruction escaped its bounded path set: "
            f"expected={sorted(EXPECTED_CHANGED_PATHS)} actual={sorted(changed)}"
        )

    patch = run(
        ["git", "diff", "--binary", "--full-index", "--no-ext-diff"],
        cwd=repository,
    ) + "\n"
    patch_path = output / "reconstruction.patch"
    patch_path.write_text(patch, encoding="utf-8")

    run(["git", "add", "--all"], cwd=repository)
    reconstructed_tree = run(["git", "write-tree"], cwd=repository)

    archive = output / "reconstructed-source.tar.gz"
    if archive.exists():
        archive.unlink()
    run(
        [
            "tar",
            "--sort=name",
            "--mtime=@0",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--exclude=.git",
            "-czf",
            str(archive),
            "-C",
            str(repository),
            ".",
        ]
    )

    manifest = payload_manifest(target_root)
    changelog_row = next(row for row in manifest if row["path"] == TARGET_CHANGELOG)
    image_rows = [
        row for row in manifest if row["path"].startswith(TARGET_GUIDE_ROOT + "/")
        and row["path"].endswith(".jpg")
    ]
    lock = {
        "schema": 2,
        "source": SOURCE,
        "source_version": TARGET_VERSION,
        "source_status": "verified-reconstructed-git-tree",
        "base_source": {
            "repository_full_name": BASE_REPOSITORY,
            "commit_sha": BASE_COMMIT,
            "tree_sha": BASE_TREE,
            "source_version": BASE_VERSION,
        },
        "target_binary_authority": {
            "filename": target_deb.name,
            "size": TARGET_DEB_SIZE,
            "sha256": TARGET_DEB_SHA256,
            "architecture": "amd64",
        },
        "reconstruction": {
            "policy": "minimal-source-cleanup-plus-exact-shipped-static-guide-assets",
            "changed_paths": sorted(EXPECTED_CHANGED_PATHS),
            "tree_sha": reconstructed_tree,
            "patch_filename": patch_path.name,
            "patch_sha256": sha256_file(patch_path),
            "archive_filename": archive.name,
            "archive_size": archive.stat().st_size,
            "archive_sha256": sha256_file(archive),
        },
        "packaged_changelog_evidence": [
            {
                "version": "0.5.2+grm3u1+han3u1",
                "commit_prefix": "8dd75aa0",
                "description": "Clean up sources",
            },
            {
                "version": "0.5.2+grm3u1+han3u1",
                "commit_prefix": "7f8fabb0",
                "description": "Removed duplicate used gtk_overlay",
            },
            {
                "version": TARGET_VERSION,
                "commit_prefix": "8f97ebbb",
                "description": "Modify contents for Hancom Gooroom 3.3",
            },
        ],
        "exact_payload_relationship": {
            "guide_image_count": len(image_rows),
            "guide_images": image_rows,
            "unchanged_public_base_payloads": [
                "data/guide/order",
                "data/guide/en/common.css",
                "data/guide/ko/common.css",
                "app-icons/scalable/apps/gooroom-guide.svg",
                "debian/copyright",
            ],
            "changelog_decompressed_sha256": changelog_row[
                "decompressed_sha256"
            ],
            "changelog_byte_identity_verified": True,
            "source_cleanup_anchors_verified": True,
            "removed_obsolete_path": "data/guide/toc.json",
        },
        "target_payload_manifest": manifest,
        "claims": {
            "lost_original_source_archive_recovered": False,
            "reconstructed_source_claimed": True,
            "exact_shipped_static_assets_used_as_source_inputs": True,
            "amd64_equivalence_verified": False,
            "native_arm64_build_verified": False,
            "promotion_allowed": False,
        },
    }
    write_json(output / "reconstruction-lock.json", lock)

    shutil.rmtree(target_root)
    rows = []
    for path in sorted(output.iterdir()):
        if path.is_file() and path.name != "LOCKSUMS.sha256":
            rows.append(f"{sha256_file(path)}  {path.name}\n")
    (output / "LOCKSUMS.sha256").write_text("".join(rows), encoding="utf-8")
    print(json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
