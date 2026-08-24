#!/usr/bin/env python3
"""Compare the exact Hancom Gooroom greeter han3u2 binary with a han3u1 baseline.

This auditor is deliberately fail-closed.  It never declares the unpublished
han3u2 source exact merely because the package names are close.  It records the
whole payload delta, normalizes ELF build-only sections, and reports the
strongest conclusion actually supported by the evidence.
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

ELF_MAGIC = b"\x7fELF"
DOC_PREFIX = "usr/share/doc/gooroom-greeter/"
BUILD_ONLY_DOC_NAMES = {
    "changelog",
    "changelog.gz",
    "changelog.Debian.gz",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout[-8000:]}"
        )
    return completed


def maybe_decompressed_sha(path: Path) -> str | None:
    if not path.name.endswith(".gz"):
        return None
    try:
        payload = gzip.decompress(path.read_bytes())
    except (OSError, EOFError):
        return None
    return hashlib.sha256(payload).hexdigest()


def manifest(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        entry: dict[str, Any] = {"mode": f"{stat.S_IMODE(metadata.st_mode):04o}"}
        if path.is_symlink():
            entry.update({"type": "symlink", "target": os.readlink(path)})
        elif path.is_dir():
            entry.update({"type": "directory"})
        elif path.is_file():
            header = path.read_bytes()[:4]
            entry.update(
                {
                    "type": "file",
                    "size": metadata.st_size,
                    "sha256": sha256_file(path),
                    "elf": header == ELF_MAGIC,
                }
            )
            decompressed = maybe_decompressed_sha(path)
            if decompressed:
                entry["decompressed_sha256"] = decompressed
        else:
            entry.update({"type": "other"})
        result[relative] = entry
    return result


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def normalize_text(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        if "Build ID:" in line:
            continue
        line = re.sub(r"/[^\s:]+/gooroom-greeter[^\s:]*", "/BUILD/gooroom-greeter", line)
        line = re.sub(r"\b[0-9a-f]{8,16}\b", "HEX", line)
        lines.append(line.rstrip())
    return "\n".join(lines).strip() + "\n"


def command_evidence(binary: Path) -> dict[str, Any]:
    commands = {
        "file": ["file", "-b", str(binary)],
        "dynamic": ["readelf", "-dW", str(binary)],
        "symbols": ["readelf", "-WsW", str(binary)],
        "notes": ["readelf", "-nW", str(binary)],
        "strings": ["strings", "-a", str(binary)],
        "disassembly": ["objdump", "-d", "--no-show-raw-insn", str(binary)],
    }
    result: dict[str, Any] = {}
    for name, command in commands.items():
        completed = run(command)
        normalized = normalize_text(completed.stdout)
        result[name] = {
            "exit_code": completed.returncode,
            "sha256": hashlib.sha256(normalized.encode()).hexdigest(),
            "text": normalized,
        }
    return result


def normalize_elf(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    completed = run(
        [
            "objcopy",
            "--remove-section=.note.gnu.build-id",
            "--remove-section=.comment",
            "--strip-debug",
            str(source),
            str(destination),
        ]
    )
    if completed.returncode:
        shutil.copy2(source, destination)


def metadata_only_path(path: str) -> bool:
    if not path.startswith(DOC_PREFIX):
        return False
    return Path(path).name in BUILD_ONLY_DOC_NAMES


def extract_changelog_candidates(root: Path) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    doc_root = root / DOC_PREFIX
    if not doc_root.exists():
        return candidates
    for path in sorted(doc_root.rglob("*changelog*")):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        try:
            text = gzip.decompress(raw).decode("utf-8", errors="replace") if path.name.endswith(".gz") else raw.decode("utf-8", errors="replace")
        except (OSError, EOFError):
            text = raw.decode("utf-8", errors="replace")
        candidates.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "contains_target_version": "0.3.1+grm3u1+han3u2" in text,
                "head": text[:4000],
            }
        )
    return candidates


def debug_evidence(debug_root: Path, source_root: Path) -> dict[str, Any]:
    debug_files: list[dict[str, Any]] = []
    source_basenames = {
        path.name for path in source_root.rglob("*") if path.is_file()
    }
    for path in sorted(debug_root.rglob("*")):
        if not path.is_file() or path.read_bytes()[:4] != ELF_MAGIC:
            continue
        info = run(["readelf", "--debug-dump=info", "--wide", str(path)])
        decoded = run(["readelf", "--debug-dump=decodedline", "--wide", str(path)])
        text = info.stdout + "\n" + decoded.stdout
        names = sorted(
            {
                match.group(1).strip()
                for match in re.finditer(r"DW_AT_name\s*:\s*(?:\([^)]*\):\s*)?([^\n]+)", text)
            }
        )
        matched = sorted(
            name for name in names if Path(name).name in source_basenames
        )
        producers = sorted(
            {
                match.group(1).strip()
                for match in re.finditer(r"DW_AT_producer\s*:\s*(?:\([^)]*\):\s*)?([^\n]+)", text)
            }
        )
        debug_files.append(
            {
                "path": path.relative_to(debug_root).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "producer_strings": producers[:50],
                "declared_source_name_count": len(names),
                "source_name_matches_public_tree_count": len(matched),
                "source_name_matches_public_tree": matched[:500],
            }
        )
    return {
        "debug_file_count": len(debug_files),
        "debug_files": debug_files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--target-debug-root", type=Path)
    parser.add_argument("--baseline-origin", required=True)
    arguments = parser.parse_args()

    output = arguments.output
    output.mkdir(parents=True, exist_ok=True)
    target = manifest(arguments.target_root)
    baseline = manifest(arguments.baseline_root)
    write_json(output / "target-payload-manifest.json", target)
    write_json(output / "baseline-payload-manifest.json", baseline)

    delta: list[dict[str, Any]] = []
    for relative in sorted(set(target) | set(baseline)):
        left = baseline.get(relative)
        right = target.get(relative)
        if left == right:
            continue
        delta.append({"path": relative, "baseline": left, "target": right})
    write_json(output / "payload-delta.json", delta)

    with (output / "payload-delta.tsv").open("w", encoding="utf-8") as stream:
        stream.write(
            "path\tbaseline_type\ttarget_type\tbaseline_sha256\t"
            "target_sha256\tbaseline_decompressed_sha256\t"
            "target_decompressed_sha256\telf\n"
        )
        for item in delta:
            left = item["baseline"] or {}
            right = item["target"] or {}
            stream.write(
                "\t".join(
                    [
                        item["path"],
                        str(left.get("type", "missing")),
                        str(right.get("type", "missing")),
                        str(left.get("sha256", "")),
                        str(right.get("sha256", "")),
                        str(left.get("decompressed_sha256", "")),
                        str(right.get("decompressed_sha256", "")),
                        str(bool(left.get("elf") or right.get("elf"))).lower(),
                    ]
                )
                + "\n"
            )

    elf_evidence: list[dict[str, Any]] = []
    normalized_root = output / "normalized-elf"
    for item in delta:
        relative = item["path"]
        left = item["baseline"] or {}
        right = item["target"] or {}
        if not (left.get("elf") and right.get("elf")):
            continue
        baseline_binary = arguments.baseline_root / relative
        target_binary = arguments.target_root / relative
        key = hashlib.sha256(relative.encode()).hexdigest()[:16]
        baseline_normalized = normalized_root / f"{key}.baseline"
        target_normalized = normalized_root / f"{key}.target"
        normalize_elf(baseline_binary, baseline_normalized)
        normalize_elf(target_binary, target_normalized)
        baseline_commands = command_evidence(baseline_binary)
        target_commands = command_evidence(target_binary)
        semantic_keys = ["dynamic", "symbols", "strings"]
        elf_evidence.append(
            {
                "path": relative,
                "baseline_raw_sha256": left["sha256"],
                "target_raw_sha256": right["sha256"],
                "baseline_normalized_sha256": sha256_file(baseline_normalized),
                "target_normalized_sha256": sha256_file(target_normalized),
                "normalized_identical": sha256_file(baseline_normalized)
                == sha256_file(target_normalized),
                "semantic_evidence_identical": all(
                    baseline_commands[key_name]["sha256"]
                    == target_commands[key_name]["sha256"]
                    for key_name in semantic_keys
                ),
                "baseline_evidence": baseline_commands,
                "target_evidence": target_commands,
            }
        )
    write_json(output / "elf-comparison.json", elf_evidence)
    with (output / "elf-comparison.tsv").open("w", encoding="utf-8") as stream:
        stream.write(
            "path\tbaseline_raw_sha256\ttarget_raw_sha256\t"
            "baseline_normalized_sha256\ttarget_normalized_sha256\t"
            "normalized_identical\tsemantic_evidence_identical\n"
        )
        for row in elf_evidence:
            stream.write(
                "\t".join(
                    [
                        row["path"],
                        row["baseline_raw_sha256"],
                        row["target_raw_sha256"],
                        row["baseline_normalized_sha256"],
                        row["target_normalized_sha256"],
                        str(row["normalized_identical"]).lower(),
                        str(row["semantic_evidence_identical"]).lower(),
                    ]
                )
                + "\n"
            )

    changed_paths = [item["path"] for item in delta]
    changed_elf_paths = [row["path"] for row in elf_evidence]
    non_elf_changes = [path for path in changed_paths if path not in changed_elf_paths]
    substantive_non_elf_changes = [
        path for path in non_elf_changes if not metadata_only_path(path)
    ]
    same_path_set = set(target) == set(baseline)
    all_elf_normalized_identical = bool(elf_evidence) and all(
        row["normalized_identical"] for row in elf_evidence
    )
    all_elf_semantically_identical = bool(elf_evidence) and all(
        row["semantic_evidence_identical"] for row in elf_evidence
    )

    if (
        same_path_set
        and not substantive_non_elf_changes
        and all_elf_normalized_identical
    ):
        classification = "public-han3u1-source-payload-equivalent-to-han3u2"
        confidence = "strong"
    elif (
        same_path_set
        and not substantive_non_elf_changes
        and all_elf_semantically_identical
    ):
        classification = "public-han3u1-source-semantically-matches-han3u2-build"
        confidence = "moderate"
    elif all_elf_normalized_identical and substantive_non_elf_changes:
        classification = "code-equivalent-with-vendor-resource-or-packaging-delta"
        confidence = "strong-for-code-only"
    else:
        classification = "han3u2-source-reconstruction-still-required"
        confidence = "fail-closed"

    target_changelogs = extract_changelog_candidates(arguments.target_root)
    baseline_changelogs = extract_changelog_candidates(arguments.baseline_root)
    source_changelog = arguments.source_root / "debian/changelog"
    source_identity = {
        "repository_full_name": "hancom-io/gooroom-greeter",
        "commit_sha": run(
            ["git", "-C", str(arguments.source_root), "rev-parse", "HEAD"], check=True
        ).stdout.strip(),
        "tree_sha": run(
            ["git", "-C", str(arguments.source_root), "rev-parse", "HEAD^{tree}"],
            check=True,
        ).stdout.strip(),
        "declared_version": run(
            ["dpkg-parsechangelog", f"-l{source_changelog}", "-SVersion"], check=True
        ).stdout.strip(),
        "changelog_sha256": sha256_file(source_changelog),
    }

    debug = (
        debug_evidence(arguments.target_debug_root, arguments.source_root)
        if arguments.target_debug_root and arguments.target_debug_root.exists()
        else {"debug_file_count": 0, "debug_files": []}
    )

    summary = {
        "schema": 3,
        "source": "gooroom-greeter",
        "target_version": "0.3.1+grm3u1+han3u2",
        "baseline_version": "0.3.1+grm3u1+han3u1",
        "baseline_origin": arguments.baseline_origin,
        "classification": classification,
        "confidence": confidence,
        "public_source": source_identity,
        "payload": {
            "target_entry_count": len(target),
            "baseline_entry_count": len(baseline),
            "same_path_set": same_path_set,
            "changed_path_count": len(changed_paths),
            "changed_paths": changed_paths,
            "changed_elf_paths": changed_elf_paths,
            "changed_non_elf_paths": non_elf_changes,
            "substantive_non_elf_changes": substantive_non_elf_changes,
            "all_changed_elf_normalized_identical": all_elf_normalized_identical,
            "all_changed_elf_semantically_identical": all_elf_semantically_identical,
        },
        "changelog_evidence": {
            "target_candidates": target_changelogs,
            "baseline_candidates": baseline_changelogs,
            "target_package_contains_exact_version_in_changelog": any(
                item["contains_target_version"] for item in target_changelogs
            ),
        },
        "debug_evidence": debug,
        "acceptance": {
            "exact_han3u2_git_commit_found": False,
            "public_han3u1_tree_locked": True,
            "target_binary_locked": True,
            "automatic_source_equivalence_promotion_allowed": classification
            == "public-han3u1-source-payload-equivalent-to-han3u2",
            "resource_overlay_reconstruction_allowed": classification
            == "code-equivalent-with-vendor-resource-or-packaging-delta",
            "plain_version_relabel_allowed": False,
        },
    }
    write_json(output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
