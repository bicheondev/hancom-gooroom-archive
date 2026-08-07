#!/usr/bin/env python3
"""Reconstruct the unpublished gooroom-greeter han3u2 source revision.

The Hancom package's shipped changelog identifies an unpublished vendor commit
(`daff60c9`) and its subject.  The same Gerrit Change-Id and one-line change
survive publicly as hancomgooroom/gooroom-greeter commit 053a6835.  This script
applies that exact asserted delta to the exact public han3u1 tree and prepends
the exact changelog stanza extracted from the locked han3u2 AMD64 package.

It does not claim source equivalence by itself.  The resulting tree must still
pass the independent AMD64 package/payload/ELF reproduction gate before it is
accepted for an ARM64 build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

BASE_REPOSITORY = "hancom-io/gooroom-greeter"
BASE_COMMIT = "886f8b6c5cd35117fd5a2d31896e4f9818400960"
BASE_TREE = "ef841874d45b7f44f08c4d337d49802b28d35b5e"
BASE_VERSION = "0.3.1+grm3u1+han3u1"
TARGET_VERSION = "0.3.1+grm3u1+han3u2"

PATCH_AUTHORITY_REPOSITORY = "hancomgooroom/gooroom-greeter"
PATCH_AUTHORITY_COMMIT = "053a6835c1b24866876c1bd082ee923d3f5a30c7"
PATCH_AUTHORITY_PARENT = "a4ff3ff58418c1e03d9707ac9a95ade7c291e480"
PATCH_AUTHORITY_TREE = "5d05541bcc8d3160fb92bb1d3a5032a222f2b547"
PATCH_MERGE_COMMIT = "d6076ffe9ffa2203567d60f06339fe4bf5fd3091"
PATCH_CHANGE_ID = "I0fe62f0bed88fcb1ca9760d210335fc774263e65"
PATCH_SUBJECT = (
    "Fixed Laterbutton actable when the message a password change for security pop up"
)
TARGET_VENDOR_COMMIT_SHORT = "daff60c9"

TARGET_PACKAGE_URL = (
    "https://update.hancomgooroom.com/hancom/pool/main/g/gooroom-greeter/"
    "gooroom-greeter_0.3.1+grm3u1+han3u2_amd64.deb"
)
TARGET_PACKAGE_SHA256 = (
    "61189d72a44e030a7e5658dc9d470a6c52579ab7994deef2f705c34cd0084836"
)
TARGET_PACKAGE_SIZE = 282940
TARGET_CHANGELOG_GZIP_SHA256 = (
    "67c5c5ff7dd0a77442744b2bdb76d6d03ae2432a223db7c6d937a6f3bff0d737"
)
TARGET_CHANGELOG_TEXT_SHA256 = (
    "5a843cdc103427616c1b5f8e98f6259187941658d805b16e50b9cfafc170bb71"
)

CHANGELOG_PREFIX = """gooroom-greeter (0.3.1+grm3u1+han3u2) unstable; urgency=medium

  [ boyeon.choi ]
  * [daff60c9] [HGOOROOM-171]Fixed Laterbutton actable when the message a password change for security pop up

 -- Gooroom Autobuilder <jenkins@gooroom.kr>  Fri, 30 Jun 2023 19:02:02 +0900

"""


def run(command: list[str], *, cwd: Path | None = None, check: bool = True) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout[-12000:]}"
        )
    return completed.stdout


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def assert_source_identity(source_dir: Path) -> None:
    head = run(["git", "rev-parse", "HEAD"], cwd=source_dir).strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=source_dir).strip()
    status = run(["git", "status", "--porcelain=v1"], cwd=source_dir).strip()
    if head != BASE_COMMIT:
        raise RuntimeError(f"base commit mismatch: {head} != {BASE_COMMIT}")
    if tree != BASE_TREE:
        raise RuntimeError(f"base tree mismatch: {tree} != {BASE_TREE}")
    if status:
        raise RuntimeError(f"source tree is not clean before reconstruction:\n{status}")
    version = run(
        ["dpkg-parsechangelog", "-ldebian/changelog", "-SVersion"], cwd=source_dir
    ).strip()
    source = run(
        ["dpkg-parsechangelog", "-ldebian/changelog", "-SSource"], cwd=source_dir
    ).strip()
    if source != "gooroom-greeter":
        raise RuntimeError(f"unexpected source name: {source}")
    if version != BASE_VERSION:
        raise RuntimeError(f"base version mismatch: {version} != {BASE_VERSION}")


def apply_code_delta(source_dir: Path) -> dict[str, Any]:
    path = source_dir / "src/greeter-window.c"
    original = path.read_bytes()
    newline = b"\r\n" if b"\r\n" in original else b"\n"
    marker = newline.join(
        [
            b'\t\t\tlightdm_greeter_respond (priv->lightdm, "chpasswd_no");',
            b"#endif",
            b"\t\t}",
            b"\t}",
            b"",
            b"out:",
        ]
    )
    replacement = newline.join(
        [
            b'\t\t\tlightdm_greeter_respond (priv->lightdm, "chpasswd_no");',
            b"#endif",
            b"\t\t}",
            b"\t\treturn;",
            b"\t}",
            b"",
            b"out:",
        ]
    )
    count = original.count(marker)
    if count != 1:
        raise RuntimeError(
            f"expected exactly one asserted Later-button patch context, found {count}"
        )
    modified = original.replace(marker, replacement, 1)
    if modified.count(b"\t\treturn;" + newline + b"\t}" + newline + newline + b"out:") != 1:
        raise RuntimeError("post-patch control-flow assertion failed")
    path.write_bytes(modified)
    return {
        "path": "src/greeter-window.c",
        "newline": "crlf" if newline == b"\r\n" else "lf",
        "base_blob_sha256": sha256_bytes(original),
        "reconstructed_blob_sha256": sha256_bytes(modified),
        "change": "insert one return statement after sending chpasswd_no",
    }


def apply_changelog_delta(source_dir: Path) -> dict[str, Any]:
    path = source_dir / "debian/changelog"
    original = path.read_bytes()
    expected_prefix = f"gooroom-greeter ({BASE_VERSION})".encode()
    if not original.startswith(expected_prefix):
        raise RuntimeError("base changelog does not start with the exact han3u1 stanza")
    prefix = CHANGELOG_PREFIX.encode("utf-8")
    modified = prefix + original
    path.write_bytes(modified)
    version = run(
        ["dpkg-parsechangelog", "-ldebian/changelog", "-SVersion"], cwd=source_dir
    ).strip()
    if version != TARGET_VERSION:
        raise RuntimeError(f"reconstructed version mismatch: {version} != {TARGET_VERSION}")
    if sha256_bytes(prefix) != "51ab38387687cef1864af23bc9abb0874ea5b1d7fbff3ca4e659cd51fd3c1f56":
        raise RuntimeError("canonical changelog-prefix digest changed unexpectedly")
    return {
        "path": "debian/changelog",
        "base_blob_sha256": sha256_bytes(original),
        "reconstructed_blob_sha256": sha256_bytes(modified),
        "prefix_sha256": sha256_bytes(prefix),
        "prefix_text": CHANGELOG_PREFIX,
    }


def build_reconstruction_lock(source_dir: Path, output_lock: Path) -> dict[str, Any]:
    assert_source_identity(source_dir)
    code_delta = apply_code_delta(source_dir)
    changelog_delta = apply_changelog_delta(source_dir)

    changed_paths = run(["git", "diff", "--name-only"], cwd=source_dir).splitlines()
    if changed_paths != ["debian/changelog", "src/greeter-window.c"]:
        raise RuntimeError(f"unexpected reconstructed path set: {changed_paths}")

    diff_bytes = subprocess.run(
        ["git", "diff", "--binary", "--full-index", "--no-ext-diff"],
        cwd=source_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout
    diff_path = output_lock.with_name("reconstruction.patch")
    diff_path.parent.mkdir(parents=True, exist_ok=True)
    diff_path.write_bytes(diff_bytes)

    run(["git", "add", "debian/changelog", "src/greeter-window.c"], cwd=source_dir)
    reconstructed_tree = run(["git", "write-tree"], cwd=source_dir).strip()

    archive_path = output_lock.with_name("reconstructed-source.tar")
    with archive_path.open("wb") as stream:
        completed = subprocess.run(
            ["git", "archive", "--format=tar", reconstructed_tree],
            cwd=source_dir,
            stdout=stream,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode:
        raise RuntimeError(completed.stderr.decode(errors="replace"))

    lock: dict[str, Any] = {
        "schema": 1,
        "source": "gooroom-greeter",
        "source_version": TARGET_VERSION,
        "status": "binary-equivalence-verification-required",
        "base_source": {
            "repository_full_name": BASE_REPOSITORY,
            "commit_sha": BASE_COMMIT,
            "tree_sha": BASE_TREE,
            "version": BASE_VERSION,
        },
        "target_binary_authority": {
            "url": TARGET_PACKAGE_URL,
            "size": TARGET_PACKAGE_SIZE,
            "sha256": TARGET_PACKAGE_SHA256,
            "shipped_changelog": {
                "path": "usr/share/doc/gooroom-greeter/changelog.gz",
                "gzip_sha256": TARGET_CHANGELOG_GZIP_SHA256,
                "text_sha256": TARGET_CHANGELOG_TEXT_SHA256,
                "vendor_commit_short": TARGET_VENDOR_COMMIT_SHORT,
                "issue": "HGOOROOM-171",
                "subject": PATCH_SUBJECT,
            },
        },
        "patch_authority": {
            "repository_full_name": PATCH_AUTHORITY_REPOSITORY,
            "commit_sha": PATCH_AUTHORITY_COMMIT,
            "parent_sha": PATCH_AUTHORITY_PARENT,
            "tree_sha": PATCH_AUTHORITY_TREE,
            "merge_commit_sha": PATCH_MERGE_COMMIT,
            "change_id": PATCH_CHANGE_ID,
            "subject": PATCH_SUBJECT,
            "changed_paths": ["src/greeter-window.c"],
            "additions": 1,
            "deletions": 0,
            "relationship_to_target": (
                "same subject and one-line behavioral delta as the unpublished "
                "vendor commit named by the target package changelog"
            ),
        },
        "reconstruction": {
            "changed_paths": changed_paths,
            "code_delta": code_delta,
            "changelog_delta": changelog_delta,
            "tree_sha": reconstructed_tree,
            "patch_filename": diff_path.name,
            "patch_size": len(diff_bytes),
            "patch_sha256": sha256_bytes(diff_bytes),
            "archive_filename": archive_path.name,
            "archive_size": archive_path.stat().st_size,
            "archive_sha256": sha256_file(archive_path),
        },
        "acceptance_gate": {
            "plain_version_relabel_allowed": False,
            "required": [
                "Build this exact reconstructed tree for AMD64 in a locked Bullseye environment.",
                "Compare package path set, non-ELF payloads, normalized ELF semantics, and shipped changelog against the exact target AMD64 package.",
                "Only after equivalence passes may the same tree be built for ARM64.",
            ],
        },
    }
    write_json(output_lock, lock)
    return lock


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--output-lock", required=True, type=Path)
    arguments = parser.parse_args()
    source_dir = arguments.source_dir.resolve()
    if not (source_dir / ".git").exists():
        raise RuntimeError(f"not a Git work tree: {source_dir}")
    lock = build_reconstruction_lock(source_dir, arguments.output_lock.resolve())
    print(json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # fail closed with a concise CI diagnostic
        print(f"reconstruction failed: {error}", file=sys.stderr)
        raise
