#!/usr/bin/env python3
"""Verify a reconstructed gooroom-greeter han3u2 package against the locked AMD64 package."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

ELF = b"\x7fELF"
EXPECTED_CHANGELOG_TEXT_SHA256 = "5a843cdc103427616c1b5f8e98f6259187941658d805b16e50b9cfafc170bb71"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def run(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout[-8000:]}"
        )
    return completed.stdout


def manifest(root: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        meta = path.lstat()
        row: dict[str, Any] = {"mode": f"{stat.S_IMODE(meta.st_mode):04o}"}
        if path.is_symlink():
            row.update(type="symlink", target=os.readlink(path))
        elif path.is_dir():
            row.update(type="directory")
        elif path.is_file():
            is_elf = path.read_bytes()[:4] == ELF
            row.update(type="file", size=meta.st_size, sha256=sha(path), elf=is_elf)
            if path.name.endswith(".gz"):
                try:
                    decompressed = gzip.decompress(path.read_bytes())
                except OSError:
                    pass
                else:
                    row["decompressed_sha256"] = sha_bytes(decompressed)
                    row["decompressed_size"] = len(decompressed)
        else:
            row.update(type="other")
        rows[rel] = row
    return rows


def normalize_elf(source: Path, destination: Path) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "objcopy",
            "--remove-section=.note.gnu.build-id",
            "--remove-section=.comment",
            "--strip-debug",
            str(source),
            str(destination),
        ]
    )
    return sha(destination)


def semantic_digest(binary: Path, command: list[str]) -> str:
    text = run(command + [str(binary)])
    lines = [line for line in text.splitlines() if "Build ID:" not in line]
    return sha_bytes(("\n".join(lines) + "\n").encode())


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    target_root = args.target_root.resolve()
    candidate_root = args.candidate_root.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    target = manifest(target_root)
    candidate = manifest(candidate_root)
    write_json(output / "target-manifest.json", target)
    write_json(output / "candidate-manifest.json", candidate)

    differences: list[dict[str, Any]] = []
    elf_rows: list[dict[str, Any]] = []
    target_paths = set(target)
    candidate_paths = set(candidate)

    for rel in sorted(target_paths | candidate_paths):
        left = target.get(rel)
        right = candidate.get(rel)
        if left is None or right is None:
            differences.append({"path": rel, "kind": "missing-path", "target": left, "candidate": right})
            continue
        if left["type"] != right["type"]:
            differences.append({"path": rel, "kind": "type", "target": left, "candidate": right})
            continue
        if left["mode"] != right["mode"]:
            differences.append({"path": rel, "kind": "mode", "target": left, "candidate": right})
        if left["type"] == "symlink":
            if left["target"] != right["target"]:
                differences.append({"path": rel, "kind": "symlink-target", "target": left, "candidate": right})
            continue
        if left["type"] != "file":
            continue
        if bool(left.get("elf")) != bool(right.get("elf")):
            differences.append({"path": rel, "kind": "elf-type", "target": left, "candidate": right})
            continue
        target_path = target_root / rel
        candidate_path = candidate_root / rel
        if left.get("elf"):
            key = hashlib.sha256(rel.encode()).hexdigest()[:16]
            target_normalized = output / "normalized" / f"{key}.target"
            candidate_normalized = output / "normalized" / f"{key}.candidate"
            target_normalized_sha = normalize_elf(target_path, target_normalized)
            candidate_normalized_sha = normalize_elf(candidate_path, candidate_normalized)
            row = {
                "path": rel,
                "target_raw_sha256": left["sha256"],
                "candidate_raw_sha256": right["sha256"],
                "target_normalized_sha256": target_normalized_sha,
                "candidate_normalized_sha256": candidate_normalized_sha,
                "normalized_identical": target_normalized_sha == candidate_normalized_sha,
                "dynamic_identical": semantic_digest(target_path, ["readelf", "-dW"]) == semantic_digest(candidate_path, ["readelf", "-dW"]),
                "symbols_identical": semantic_digest(target_path, ["readelf", "-WsW"]) == semantic_digest(candidate_path, ["readelf", "-WsW"]),
                "strings_identical": semantic_digest(target_path, ["strings", "-a"]) == semantic_digest(candidate_path, ["strings", "-a"]),
            }
            elf_rows.append(row)
            if not row["normalized_identical"]:
                differences.append({"path": rel, "kind": "normalized-elf", "evidence": row})
            continue
        if left["sha256"] == right["sha256"]:
            continue
        if (
            left.get("decompressed_sha256")
            and left.get("decompressed_sha256") == right.get("decompressed_sha256")
        ):
            continue
        differences.append({"path": rel, "kind": "file-bytes", "target": left, "candidate": right})

    target_changelog = target_root / "usr/share/doc/gooroom-greeter/changelog.gz"
    candidate_changelog = candidate_root / "usr/share/doc/gooroom-greeter/changelog.gz"
    if not target_changelog.is_file() or not candidate_changelog.is_file():
        differences.append(
            {
                "path": "usr/share/doc/gooroom-greeter/changelog.gz",
                "kind": "required-changelog-missing",
            }
        )
        changelog_identical = False
    else:
        target_text = gzip.decompress(target_changelog.read_bytes())
        candidate_text = gzip.decompress(candidate_changelog.read_bytes())
        target_text_sha = sha_bytes(target_text)
        candidate_text_sha = sha_bytes(candidate_text)
        changelog_identical = target_text == candidate_text
        if target_text_sha != EXPECTED_CHANGELOG_TEXT_SHA256:
            differences.append({"path": str(target_changelog), "kind": "target-changelog-authority-drift", "sha256": target_text_sha})
        if not changelog_identical:
            differences.append(
                {
                    "path": "usr/share/doc/gooroom-greeter/changelog.gz",
                    "kind": "changelog-text",
                    "target_sha256": target_text_sha,
                    "candidate_sha256": candidate_text_sha,
                }
            )

    summary = {
        "schema": 1,
        "source": "gooroom-greeter",
        "source_version": "0.3.1+grm3u1+han3u2",
        "policy": "exact-payload-and-normalized-elf-equivalence",
        "target_path_count": len(target_paths),
        "candidate_path_count": len(candidate_paths),
        "same_path_set": target_paths == candidate_paths,
        "changelog_text_identical": changelog_identical,
        "elf_comparison_count": len(elf_rows),
        "all_elf_normalized_identical": bool(elf_rows) and all(row["normalized_identical"] for row in elf_rows),
        "difference_count": len(differences),
        "verified": not differences,
    }
    write_json(output / "elf-comparison.json", elf_rows)
    write_json(output / "differences.json", differences)
    write_json(output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if differences:
        print(json.dumps(differences, indent=2, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
