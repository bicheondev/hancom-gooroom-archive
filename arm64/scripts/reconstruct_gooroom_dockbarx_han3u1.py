#!/usr/bin/env python3
"""Reconstruct the Hancom Gooroom 3.3 dockbarx source from its public base.

The exact AMD64 vendor DEB is the target authority.  The public Gooroom
0.3.1+grm3u1 commit is accepted only when both its commit and tree identities
match the immutable constants below.  Reconstruction is deliberately bounded
to the two files described by the packaged changelog: the Debian version entry
and the Python panel background/theme branch.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

SOURCE = "gooroom-dockbarx-applet"
BASE_VERSION = "0.3.1+grm3u1"
TARGET_VERSION = "0.3.1+grm3u1+han3u1"
BASE_REPOSITORY = "gooroom/gooroom-dockbarx-applet"
BASE_COMMIT = "9485507dcb027b1d146c5d3edf7a0f15fa13e558"
BASE_TREE = "3c3fac8ab436e75fca8d366c85a20f1592a1a5ad"
TARGET_DEB_SIZE = 14096
TARGET_DEB_SHA256 = (
    "9d810f3185babcd24e0d7c868586c930a8d39bcb7b0a01dee4d8cee02f440b0d"
)
TARGET_PYTHON_PATH = (
    "usr/lib/x86_64-linux-gnu/gnome-panel/modules/xfce4-dockbarx-plug.py"
)
TARGET_PYTHON_SHA256 = (
    "46dffbcb5d62f1499c1b5e89646234b4c9fa7716680a5c90cb1c0bb3955a6895"
)
TARGET_CHANGELOG_DECOMPRESSED_SHA256 = (
    "586ab9025d7e46d667889d616ce2d9fe48256e82f8d7ae442dffd350a94e83c0"
)
CHANGED_PATHS = {
    "debian/changelog",
    "src/xfce4-dockbarx-plug.py",
}

CHANGELOG_ENTRY = """gooroom-dockbarx-applet (0.3.1+grm3u1+han3u1) unstable; urgency=medium

  [ boyeon.choi ]
  * [95268201] Add a new icon theme for Hancom Gooroom 3.3

 -- Gooroom Autobuilder <jenkins@gooroom.kr>  Fri, 30 Jun 2023 19:21:30 +0900

"""

OLD_DRAW_BLOCK = """        ctx.clip()
        ctx.set_source_rgba(0.0,0.0,0.0,0.7)
        ctx.paint()
"""

NEW_DRAW_BLOCK = """        ctx.clip()
        if GSETTINGS_DT_IFACE_CLIENT.get_string(\"gtk-theme\") == \"Arc-Darker\":
            ctx.set_source_rgba(0.169,0.184,0.251,0.95)
        elif GSETTINGS_DT_IFACE_CLIENT.get_string(\"gtk-theme\") ==  \"Arc-Lighter\":
            ctx.set_source_rgba(0.941,0.953,0.976,0.96)
        else:
            ctx.set_source_rgba(0.0,0.0,0.0,0.7)

        ctx.paint()
"""


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
        raise SystemExit("target DEB size does not match the locked authority")
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
    target_python = target_root / TARGET_PYTHON_PATH
    target_changelog = (
        target_root / "usr/share/doc/gooroom-dockbarx-applet/changelog.gz"
    )
    if not target_python.is_file() or not target_changelog.is_file():
        raise SystemExit("target payload lacks the expected Python or changelog file")
    if sha256_file(target_python) != TARGET_PYTHON_SHA256:
        raise SystemExit("target Python payload lock mismatch")
    target_changelog_bytes = gzip.decompress(target_changelog.read_bytes())
    if (
        sha256_bytes(target_changelog_bytes)
        != TARGET_CHANGELOG_DECOMPRESSED_SHA256
    ):
        raise SystemExit("target changelog payload lock mismatch")

    python_path = repository / "src/xfce4-dockbarx-plug.py"
    python_text = python_path.read_text(encoding="utf-8")
    if python_text.count(OLD_DRAW_BLOCK) != 1:
        raise SystemExit("the exact public draw-block anchor was not found once")
    if "Arc-Darker" in python_text or "Arc-Lighter" in python_text:
        raise SystemExit("public base unexpectedly already contains the Hancom theme")
    python_path.write_text(
        python_text.replace(OLD_DRAW_BLOCK, NEW_DRAW_BLOCK),
        encoding="utf-8",
    )

    changelog_path = repository / "debian/changelog"
    base_changelog = changelog_path.read_text(encoding="utf-8")
    if base_changelog.startswith(CHANGELOG_ENTRY):
        raise SystemExit("public base unexpectedly already contains the Hancom entry")
    changelog_path.write_text(
        CHANGELOG_ENTRY + base_changelog,
        encoding="utf-8",
    )

    if sha256_file(python_path) != TARGET_PYTHON_SHA256:
        raise SystemExit(
            "reconstructed Python source is not byte-identical to the shipped payload"
        )
    if changelog_path.read_bytes() != target_changelog_bytes:
        raise SystemExit(
            "reconstructed Debian changelog is not byte-identical to the shipped payload"
        )
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
    if changed != CHANGED_PATHS:
        raise SystemExit(
            f"reconstruction escaped its two-file boundary: {sorted(changed)}"
        )

    patch = run(
        ["git", "diff", "--binary", "--full-index", "--no-ext-diff"],
        cwd=repository,
    ) + "\n"
    patch_path = output / "reconstruction.patch"
    patch_path.write_text(patch, encoding="utf-8")

    run(["git", "add", "--", *sorted(CHANGED_PATHS)], cwd=repository)
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

    payload_manifest = []
    for path in sorted(target_root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            payload_manifest.append(
                {
                    "path": path.relative_to(target_root).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "elf": path.read_bytes()[:4] == b"\x7fELF",
                }
            )

    lock = {
        "schema": 1,
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
            "changed_paths": sorted(CHANGED_PATHS),
            "tree_sha": reconstructed_tree,
            "patch_filename": patch_path.name,
            "patch_sha256": sha256_file(patch_path),
            "archive_filename": archive.name,
            "archive_size": archive.stat().st_size,
            "archive_sha256": sha256_file(archive),
        },
        "exact_payload_relationship": {
            "python_path": TARGET_PYTHON_PATH,
            "python_sha256": TARGET_PYTHON_SHA256,
            "python_byte_identity_verified": True,
            "changelog_decompressed_sha256": (
                TARGET_CHANGELOG_DECOMPRESSED_SHA256
            ),
            "changelog_byte_identity_verified": True,
            "packaged_change_id": "95268201",
            "packaged_change_description": (
                "Add a new icon theme for Hancom Gooroom 3.3"
            ),
        },
        "target_payload_manifest": payload_manifest,
        "claims": {
            "lost_original_source_archive_recovered": False,
            "reconstructed_source_claimed": True,
            "byte_identity_claimed_for_changed_script_and_changelog": True,
            "native_elf_identity_claimed": False,
            "native_arm64_build_verified": False,
            "promotion_allowed": False,
        },
    }
    write_json(output / "reconstruction-lock.json", lock)

    shutil.rmtree(target_root)
    checksums = []
    for path in sorted(output.iterdir()):
        if path.is_file() and path.name != "LOCKSUMS.sha256":
            checksums.append(f"{sha256_file(path)}  {path.name}\n")
    (output / "LOCKSUMS.sha256").write_text(
        "".join(checksums), encoding="utf-8"
    )
    print(json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
