#!/usr/bin/env python3
"""Audit an exact Debian package payload against complete public Git histories.

The audit is deliberately evidentiary: it does not assert that a public commit
is the missing exact source merely because some installed files match.  It
records package metadata, Debian changelog entries and embedded change IDs,
Git refs, exact-version history searches, per-payload Git blob matches, native
payloads, and unresolved files.  Later reconstruction workflows can consume
this immutable evidence without weakening the exact-version policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

CHANGE_ID_RE = re.compile(r"\[([0-9a-fA-F]{7,40})\]")
CHANGELOG_HEAD_RE = re.compile(
    r"^(?P<source>\S+) \((?P<version>[^)]+)\) (?P<suite>[^;]+);(?P<rest>.*)$"
)


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha_bytes(chunks: Iterable[bytes], size: int) -> str:
    digest = hashlib.sha1()
    digest.update(f"blob {size}\0".encode("ascii"))
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha_file(path: Path) -> str:
    def chunks() -> Iterable[bytes]:
        with path.open("rb") as stream:
            yield from iter(lambda: stream.read(1024 * 1024), b"")

    return git_blob_sha_bytes(chunks(), path.stat().st_size)


def git_blob_sha_literal(value: bytes) -> str:
    return git_blob_sha_bytes((value,), len(value))


def parse_control(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line.strip()
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields


def parse_changelog_entries(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    starts: list[int] = []
    for index, line in enumerate(lines):
        if CHANGELOG_HEAD_RE.match(line):
            starts.append(index)
    entries: list[dict[str, Any]] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        block = lines[start:end]
        match = CHANGELOG_HEAD_RE.match(block[0])
        if match is None:
            continue
        trailer = ""
        for line in reversed(block):
            if line.startswith(" -- "):
                trailer = line
                break
        change_ids = sorted(
            {value.lower() for value in CHANGE_ID_RE.findall("\n".join(block))}
        )
        entries.append(
            {
                "source": match.group("source"),
                "version": match.group("version"),
                "suite": match.group("suite").strip(),
                "header": block[0],
                "trailer": trailer,
                "change_ids": change_ids,
                "body": block[1:],
            }
        )
    return entries


def peel_ref(repo: Path, ref: str) -> str | None:
    result = run(["git", f"--git-dir={repo}", "rev-parse", "--verify", f"{ref}^{{commit}}"])
    if result.returncode != 0:
        return None
    commit = result.stdout.strip()
    return commit if re.fullmatch(r"[0-9a-f]{40}", commit) else None


def changelog_head(repo: Path, commit: str) -> str:
    result = run(["git", f"--git-dir={repo}", "show", f"{commit}:debian/changelog"])
    if result.returncode != 0 or not result.stdout:
        return ""
    return result.stdout.splitlines()[0]


def resolve_change_id(repo: Path, change_id: str) -> dict[str, Any] | None:
    result = run(
        [
            "git",
            f"--git-dir={repo}",
            "rev-parse",
            "--verify",
            f"{change_id}^{{commit}}",
        ]
    )
    if result.returncode != 0:
        return None
    commit = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        return None
    tree_result = run(["git", f"--git-dir={repo}", "rev-parse", f"{commit}^{{tree}}"])
    show = run(
        [
            "git",
            f"--git-dir={repo}",
            "show",
            "-s",
            "--format=%H%x09%T%x09%ct%x09%an%x09%s",
            commit,
        ]
    )
    values = show.stdout.rstrip("\n").split("\t", 4) if show.returncode == 0 else []
    return {
        "change_id": change_id,
        "commit_sha": commit,
        "tree_sha": tree_result.stdout.strip() if tree_result.returncode == 0 else "",
        "commit_time": values[2] if len(values) > 2 else "",
        "author": values[3] if len(values) > 3 else "",
        "subject": values[4] if len(values) > 4 else "",
        "changelog_head": changelog_head(repo, commit),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--git-root", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    if not args.rootfs.is_dir():
        raise SystemExit(f"package rootfs is missing: {args.rootfs}")
    control_path = args.control / "control"
    if not control_path.is_file():
        raise SystemExit(f"package control file is missing: {control_path}")
    args.evidence.mkdir(parents=True, exist_ok=True)

    fields = parse_control(control_path)
    if fields.get("Version") != args.version:
        raise SystemExit(
            f"package version mismatch: {fields.get('Version')!r} != {args.version!r}"
        )

    packaged_changelogs: dict[str, dict[str, Any]] = {}
    all_change_ids: set[str] = set()
    target_changelog_entry_count = 0
    for path in sorted(args.evidence.glob("packaged-changelog*.txt")):
        text = path.read_text(encoding="utf-8", errors="replace")
        entries = parse_changelog_entries(text)
        packaged_changelogs[path.name] = {"entries": entries}
        for entry in entries:
            all_change_ids.update(entry["change_ids"])
            if entry["source"] == args.source and entry["version"] == args.version:
                target_changelog_entry_count += 1

    repositories: dict[str, Path] = {}
    object_paths: dict[str, dict[str, list[str]]] = {}
    refs: dict[str, list[dict[str, str]]] = {}
    version_searches: dict[str, dict[str, Any]] = {}
    change_id_resolutions: dict[str, list[dict[str, Any]]] = {
        change_id: [] for change_id in sorted(all_change_ids)
    }

    for repo in sorted(args.git_root.glob("*.git")):
        key = repo.name.removesuffix(".git")
        repositories[key] = repo
        mapping: dict[str, list[str]] = defaultdict(list)
        objects = run(["git", f"--git-dir={repo}", "rev-list", "--objects", "--all"])
        if objects.returncode != 0:
            raise SystemExit(f"unable to enumerate Git objects in {repo}: {objects.stderr}")
        for line in objects.stdout.splitlines():
            object_sha, separator, object_path = line.partition(" ")
            if separator and object_path:
                mapping[object_sha].append(object_path)
        object_paths[key] = dict(mapping)

        ref_result = run(
            [
                "git",
                f"--git-dir={repo}",
                "for-each-ref",
                "--format=%(refname)",
                "refs/heads",
                "refs/tags",
            ]
        )
        repo_refs: list[dict[str, str]] = []
        for ref in ref_result.stdout.splitlines():
            commit = peel_ref(repo, ref)
            if commit is None:
                continue
            tree = run(["git", f"--git-dir={repo}", "rev-parse", f"{commit}^{{tree}}"])
            repo_refs.append(
                {
                    "ref": ref,
                    "commit": commit,
                    "tree": tree.stdout.strip() if tree.returncode == 0 else "",
                    "changelog_head": changelog_head(repo, commit),
                }
            )
        refs[key] = repo_refs

        search = run(
            [
                "git",
                f"--git-dir={repo}",
                "log",
                "--all",
                "--format=%H%x09%T%x09%ct%x09%s",
                "-S",
                args.version,
                "--",
                "debian/changelog",
            ]
        )
        version_searches[key] = {
            "exit_code": search.returncode,
            "hits": search.stdout.splitlines(),
            "stderr": search.stderr[-4000:],
        }

        for change_id in sorted(all_change_ids):
            resolved = resolve_change_id(repo, change_id)
            if resolved is not None:
                resolved["repository"] = key
                change_id_resolutions[change_id].append(resolved)

    if not repositories:
        raise SystemExit("no public Git repository was cloned successfully")

    rows: list[dict[str, Any]] = []
    regular_file_count = 0
    symlink_count = 0
    matched_any_count = 0
    matched_all_count = 0
    unmatched_paths: list[str] = []
    native_payloads: list[dict[str, Any]] = []

    for path in sorted(args.rootfs.rglob("*")):
        relative = "/" + path.relative_to(args.rootfs).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            symlink_count += 1
            target = os.readlink(path)
            blob = git_blob_sha_literal(os.fsencode(target))
            matches = {
                key: object_paths.get(key, {}).get(blob, [])
                for key in sorted(repositories)
            }
            matched_repositories = [key for key, paths in matches.items() if paths]
            if matched_repositories:
                matched_any_count += 1
            else:
                unmatched_paths.append(relative)
            if len(matched_repositories) == len(repositories):
                matched_all_count += 1
            rows.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "size": len(os.fsencode(target)),
                    "sha256": hashlib.sha256(os.fsencode(target)).hexdigest(),
                    "git_blob_sha1": blob,
                    "symlink_target": target,
                    "matches": matches,
                }
            )
            continue
        if not stat.S_ISREG(mode):
            continue

        regular_file_count += 1
        digest = sha256(path)
        blob = git_blob_sha_file(path)
        matches = {
            key: object_paths.get(key, {}).get(blob, [])
            for key in sorted(repositories)
        }
        matched_repositories = [key for key, paths in matches.items() if paths]
        if matched_repositories:
            matched_any_count += 1
        else:
            unmatched_paths.append(relative)
        if len(matched_repositories) == len(repositories):
            matched_all_count += 1

        with path.open("rb") as stream:
            magic = stream.read(64)
        if magic.startswith(b"\x7fELF") or magic.startswith(b"MZ"):
            info = run(["file", "-b", str(path)]).stdout.strip()
            native_payloads.append(
                {"path": relative, "file": info, "sha256": digest, "size": path.stat().st_size}
            )

        rows.append(
            {
                "path": relative,
                "type": "file",
                "size": path.stat().st_size,
                "sha256": digest,
                "git_blob_sha1": blob,
                "symlink_target": "",
                "matches": matches,
            }
        )

    clone_failures = sorted(
        path.name.removesuffix(".clone.exit-code")
        for path in args.git_root.glob("*.clone.exit-code")
        if path.read_text(encoding="utf-8", errors="replace").strip() != "0"
    )
    resolved_change_ids = {
        change_id: matches
        for change_id, matches in change_id_resolutions.items()
        if matches
    }

    summary = {
        "schema": 2,
        "policy": "exact-amd64-package-payload-versus-complete-public-git-histories",
        "source": args.source,
        "source_version": args.version,
        "package": fields.get("Package"),
        "package_version": fields.get("Version"),
        "architecture": fields.get("Architecture"),
        "source_field": fields.get("Source"),
        "regular_file_count": regular_file_count,
        "symlink_count": symlink_count,
        "matched_in_any_repository_count": matched_any_count,
        "matched_in_all_repositories_count": matched_all_count,
        "unmatched_file_count": len(unmatched_paths),
        "native_payload_count": len(native_payloads),
        "repositories_cloned": sorted(repositories),
        "repository_clone_failures": clone_failures,
        "exact_version_history_hit_count": sum(
            len(value["hits"]) for value in version_searches.values()
        ),
        "packaged_changelog_files": sorted(packaged_changelogs),
        "packaged_changelog_target_entry_count": target_changelog_entry_count,
        "packaged_change_id_count": len(all_change_ids),
        "resolved_packaged_change_id_count": len(resolved_change_ids),
    }

    write_json(args.evidence / "summary.json", summary)
    write_json(args.evidence / "payload-manifest.json", rows)
    write_json(args.evidence / "unmatched-paths.json", unmatched_paths)
    write_json(args.evidence / "native-payloads.json", native_payloads)
    write_json(args.evidence / "repository-refs.json", refs)
    write_json(args.evidence / "exact-version-history-search.json", version_searches)
    write_json(args.evidence / "packaged-changelog.json", packaged_changelogs)
    write_json(args.evidence / "packaged-change-id-resolutions.json", change_id_resolutions)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
