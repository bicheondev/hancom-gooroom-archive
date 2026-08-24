#!/usr/bin/env python3
"""Reconstruct the unpublished gooroom-greeter han3u2 source revision.

The locked AMD64 package names vendor commit ``daff60c9`` and HGOOROOM-171.
The same subject, Gerrit Change-Id, and one-line behavioral delta survive in
public commit 053a6835.  This script applies that asserted delta to the exact
public han3u1 tree and prepends the exact changelog stanza shipped by han3u2.
An independent AMD64 reproduction gate must still pass before ARM64 promotion.
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

PATCH_REPOSITORY = "hancomgooroom/gooroom-greeter"
PATCH_COMMIT = "053a6835c1b24866876c1bd082ee923d3f5a30c7"
PATCH_PARENT = "a4ff3ff58418c1e03d9707ac9a95ade7c291e480"
PATCH_TREE = "5d05541bcc8d3160fb92bb1d3a5032a222f2b547"
PATCH_MERGE_COMMIT = "d6076ffe9ffa2203567d60f06339fe4bf5fd3091"
PATCH_CHANGE_ID = "I0fe62f0bed88fcb1ca9760d210335fc774263e65"
PATCH_SUBJECT = (
    "Fixed Laterbutton actable when the message a password change for security pop up"
)

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
CHANGELOG_PREFIX_SHA256 = (
    "ee7f5aa853da77444fb7bbc1886cdeeb3e047f0072ae1f4a3f0db3293ae462f3"
)


def run(command: list[str], cwd: Path, *, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=text,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode:
        tail = completed.stdout[-12000:]
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{tail}"
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


def exact_git_value(source_dir: Path, expression: str) -> str:
    return str(run(["git", "rev-parse", expression], source_dir)).strip()


def assert_base(source_dir: Path) -> None:
    if exact_git_value(source_dir, "HEAD") != BASE_COMMIT:
        raise RuntimeError("base commit does not match the locked han3u1 commit")
    if exact_git_value(source_dir, "HEAD^{tree}") != BASE_TREE:
        raise RuntimeError("base tree does not match the locked han3u1 tree")
    if str(run(["git", "status", "--porcelain=v1"], source_dir)).strip():
        raise RuntimeError("base source work tree is not clean")
    source = str(
        run(["dpkg-parsechangelog", "-ldebian/changelog", "-SSource"], source_dir)
    ).strip()
    version = str(
        run(["dpkg-parsechangelog", "-ldebian/changelog", "-SVersion"], source_dir)
    ).strip()
    if source != "gooroom-greeter" or version != BASE_VERSION:
        raise RuntimeError(f"base package identity mismatch: {source} {version}")


def apply_code_delta(source_dir: Path) -> dict[str, Any]:
    path = source_dir / "src/greeter-window.c"
    before = path.read_bytes()
    newline = b"\r\n" if b"\r\n" in before else b"\n"
    old = newline.join(
        [
            b'\t\t\tlightdm_greeter_respond (priv->lightdm, "chpasswd_no");',
            b"#endif",
            b"\t\t}",
            b"\t}",
            b"",
            b"out:",
        ]
    )
    new = newline.join(
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
    if before.count(old) != 1:
        raise RuntimeError("the exact Later-button control-flow context was not unique")
    after = before.replace(old, new, 1)
    if after.count(new) != 1:
        raise RuntimeError("the asserted one-line code delta was not applied exactly once")
    path.write_bytes(after)
    return {
        "path": "src/greeter-window.c",
        "newline": "crlf" if newline == b"\r\n" else "lf",
        "base_sha256": sha256_bytes(before),
        "reconstructed_sha256": sha256_bytes(after),
        "inserted_statement": "return;",
    }


def apply_changelog_delta(source_dir: Path) -> dict[str, Any]:
    path = source_dir / "debian/changelog"
    before = path.read_bytes()
    if not before.startswith(f"gooroom-greeter ({BASE_VERSION})".encode()):
        raise RuntimeError("the base changelog does not begin with han3u1")
    prefix = CHANGELOG_PREFIX.encode("utf-8")
    if sha256_bytes(prefix) != CHANGELOG_PREFIX_SHA256:
        raise RuntimeError("the canonical han3u2 changelog prefix digest changed")
    after = prefix + before
    path.write_bytes(after)
    version = str(
        run(["dpkg-parsechangelog", "-ldebian/changelog", "-SVersion"], source_dir)
    ).strip()
    if version != TARGET_VERSION:
        raise RuntimeError(f"reconstructed version mismatch: {version}")
    return {
        "path": "debian/changelog",
        "base_sha256": sha256_bytes(before),
        "reconstructed_sha256": sha256_bytes(after),
        "prefix_sha256": CHANGELOG_PREFIX_SHA256,
        "prefix_text": CHANGELOG_PREFIX,
    }


def reconstruct(source_dir: Path, output_lock: Path) -> dict[str, Any]:
    assert_base(source_dir)
    code_delta = apply_code_delta(source_dir)
    changelog_delta = apply_changelog_delta(source_dir)

    changed = str(run(["git", "diff", "--name-only"], source_dir)).splitlines()
    if changed != ["debian/changelog", "src/greeter-window.c"]:
        raise RuntimeError(f"unexpected reconstructed path set: {changed}")

    patch = bytes(
        run(
            ["git", "diff", "--binary", "--full-index", "--no-ext-diff"],
            source_dir,
            text=False,
        )
    )
    output_lock.parent.mkdir(parents=True, exist_ok=True)
    patch_path = output_lock.with_name("reconstruction.patch")
    patch_path.write_bytes(patch)

    run(["git", "add", *changed], source_dir)
    tree = exact_git_value(source_dir, "$(git write-tree)") if False else str(
        run(["git", "write-tree"], source_dir)
    ).strip()

    archive_path = output_lock.with_name("reconstructed-source.tar")
    with archive_path.open("wb") as output:
        completed = subprocess.run(
            ["git", "archive", "--format=tar", tree],
            cwd=source_dir,
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode:
        raise RuntimeError(completed.stderr.decode(errors="replace"))

    lock: dict[str, Any] = {
        "schema": 2,
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
                "vendor_commit_short": "daff60c9",
                "issue": "HGOOROOM-171",
                "subject": PATCH_SUBJECT,
            },
        },
        "patch_authority": {
            "repository_full_name": PATCH_REPOSITORY,
            "commit_sha": PATCH_COMMIT,
            "parent_sha": PATCH_PARENT,
            "tree_sha": PATCH_TREE,
            "merge_commit_sha": PATCH_MERGE_COMMIT,
            "change_id": PATCH_CHANGE_ID,
            "subject": PATCH_SUBJECT,
            "changed_paths": ["src/greeter-window.c"],
            "additions": 1,
            "deletions": 0,
        },
        "reconstruction": {
            "changed_paths": changed,
            "code_delta": code_delta,
            "changelog_delta": changelog_delta,
            "tree_sha": tree,
            "patch_filename": patch_path.name,
            "patch_size": len(patch),
            "patch_sha256": sha256_bytes(patch),
            "archive_filename": archive_path.name,
            "archive_size": archive_path.stat().st_size,
            "archive_sha256": sha256_file(archive_path),
        },
        "acceptance_gate": {
            "plain_version_relabel_allowed": False,
            "required": [
                "Rebuild this exact tree for AMD64 in a locked Bullseye environment.",
                "Compare its path set, non-ELF payload, normalized ELF behavior, and shipped changelog with the exact target AMD64 package.",
                "Build ARM64 only after that equivalence gate passes.",
            ],
        },
    }
    output_lock.write_text(
        json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return lock


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-lock", type=Path, required=True)
    arguments = parser.parse_args()
    source_dir = arguments.source_dir.resolve()
    if not (source_dir / ".git").is_dir():
        raise RuntimeError(f"not a Git work tree: {source_dir}")
    lock = reconstruct(source_dir, arguments.output_lock.resolve())
    print(json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"reconstruction failed: {error}", file=sys.stderr)
        raise
