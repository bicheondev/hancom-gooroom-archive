#!/usr/bin/env python3
"""Resolve exact Gooroom/Hancom source versions to Git commits, fail closed.

Repository names and branch names are discovery hints only. A source is locked
only after `debian/changelog` at the selected commit declares the exact Source
and Version extracted from the AMD64 reference image.
"""

from __future__ import annotations

import argparse
import csv
import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


API = "https://api.github.com"
OWNERS = ("hancomgooroom", "hancom-io", "gooroom")
ALIASES = {
    "gtk+2.0": ["gtk2", "gtk-2.0"],
    "gtk+3.0": ["gtk3", "gtk-3.0"],
    "pam-gooroom": ["libpam-gooroom-authenticator"],
    "qtbase-opensource-src": ["qtbase5", "qtbase"],
    "linux": ["linux", "linux-kernel"],
}
ARCH_SOURCE_EXCEPTIONS = {
    "linux-signed-amd64": {
        "status": "arch-replace",
        "reason": "AMD64 signed-kernel metapackage is replaced by linux-image-arm64 after rebuilding the exact linux source",
    }
}
HEADER_RE = re.compile(r"^([^\s]+)\s+\(([^)]+)\)\s+", re.MULTILINE)
SERIES3_RE = re.compile(r"(?:^|[-_/])(?:hancom|gooroom)?-?3(?:[._/-]|$)", re.I)
VENDOR_PREFIX_RE = re.compile(r"^(?:gooroom|hancom|hancomgrm)+")


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        command,
        cwd=cwd,
        text=text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and process.returncode:
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(command)}\n"
            f"stdout:\n{process.stdout[-4000:]}\n"
            f"stderr:\n{process.stderr[-4000:]}"
        )
    return process


class GitHub:
    def __init__(self, token: str | None) -> None:
        self.token = token
        self.cache: dict[str, Any] = {}
        self.request_count = 0

    def get(self, path: str, *, missing_ok: bool = False) -> Any:
        url = path if path.startswith("http") else API + path
        if url in self.cache:
            return self.cache[url]
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "hancom-gooroom-arm64-source-lock",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        for attempt in range(5):
            try:
                with urlopen(Request(url, headers=headers), timeout=90) as response:
                    result = json.load(response)
                self.request_count += 1
                self.cache[url] = result
                return result
            except HTTPError as error:
                if missing_ok and error.code == 404:
                    return None
                if error.code in {403, 429, 502, 503, 504} and attempt < 4:
                    retry_after = int(error.headers.get("Retry-After", "0") or 0)
                    time.sleep(max(retry_after, 2**attempt))
                    continue
                payload = error.read()[:500]
                raise RuntimeError(f"GitHub API {error.code}: {url}: {payload!r}") from error
        raise AssertionError("unreachable")

    def pages(self, path: str, *, max_pages: int = 20) -> list[Any]:
        separator = "&" if "?" in path else "?"
        rows: list[Any] = []
        for page in range(1, max_pages + 1):
            chunk = self.get(f"{path}{separator}per_page=100&page={page}")
            rows.extend(chunk)
            if len(chunk) < 100:
                break
        return rows

    def repositories(self, owner: str) -> list[dict[str, Any]]:
        if self.get(f"/orgs/{owner}", missing_ok=True):
            return self.pages(f"/orgs/{owner}/repos?type=public")
        return self.pages(f"/users/{owner}/repos?type=public")


def normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def core_normalize(name: str) -> str:
    return VENDOR_PREFIX_RE.sub("", normalize(name))


def parse_head(text: str | None) -> tuple[str, str] | None:
    if not text:
        return None
    match = HEADER_RE.search(text)
    return match.groups() if match else None


def contains_header(text: str | None, source: str, version: str) -> bool:
    if not text:
        return False
    pattern = re.compile(
        rf"^{re.escape(source)}\s+\({re.escape(version)}\)\s+", re.MULTILINE
    )
    return pattern.search(text) is not None


def target_rows(reference: Path) -> list[dict[str, Any]]:
    document = json.loads(reference.read_text(encoding="utf-8"))
    packages: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for package in document["packages"]:
        packages[(package["source"], package["source_version"])].append(package)

    rows: list[dict[str, Any]] = []
    for source in document["sources"]:
        if not source.get("custom_candidate"):
            continue
        members = packages[(source["source"], source["source_version"])]
        architectures = sorted({member["architecture"] for member in members})
        role = "reuse-all" if architectures == ["all"] else "rebuild-arm64"
        if source["source"] in ARCH_SOURCE_EXCEPTIONS:
            role = "arch-replace"
        rows.append(
            {
                "source": source["source"],
                "source_version": source["source_version"],
                "binary_packages": sorted(member["package"] for member in members),
                "binary_architectures": architectures,
                "role": role,
            }
        )
    return sorted(rows, key=lambda row: row["source"])


def owner_order(target: dict[str, Any]) -> tuple[str, ...]:
    version = target["source_version"].lower()
    source = target["source"].lower()
    if "han" in version or source.startswith("hancom"):
        return ("hancom-io", "hancomgooroom", "gooroom")
    return ("gooroom", "hancom-io", "hancomgooroom")


def candidate_repositories(
    target: dict[str, Any], indexes: dict[str, dict[str, dict[str, Any]]]
) -> list[dict[str, Any]]:
    names = {target["source"].lower()}
    names.update(alias.lower() for alias in ALIASES.get(target["source"], []))
    normalized = {normalize(name) for name in names}
    core = {core_normalize(name) for name in names}

    found: dict[str, dict[str, Any]] = {}
    for owner in OWNERS:
        for repository in indexes[owner].values():
            repository_name = repository["name"].lower()
            if (
                repository_name in names
                or normalize(repository_name) in normalized
                or core_normalize(repository_name) in core
            ):
                found[repository["full_name"]] = repository
    return list(found.values())


class RepositoryProbe:
    def __init__(
        self,
        root: Path,
        repository: dict[str, Any],
        token: str | None,
    ) -> None:
        self.repository = repository
        self.owner = repository["owner"]["login"]
        self.name = repository["name"]
        self.full_name = repository["full_name"]
        self.default_branch = repository.get("default_branch") or "master"
        self.url = f"https://github.com/{self.full_name}.git"
        self.path = root / (self.full_name.replace("/", "__") + ".git")
        self.token = token
        self._refs: tuple[dict[str, str], dict[str, str]] | None = None
        self._raw_cache: dict[str, str | None] = {}
        self._fetched: set[str] = set()

    def git_environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        if self.token:
            environment.update(
                {
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "http.extraHeader",
                    "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {self.token}",
                }
            )
        return environment

    def git(self, arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = ["git", f"--git-dir={self.path}", *arguments]
        process = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.git_environment(),
            check=False,
        )
        if check and process.returncode:
            raise RuntimeError(
                f"git failed ({self.full_name}): {' '.join(arguments)}\n"
                f"stdout:\n{process.stdout[-4000:]}\n"
                f"stderr:\n{process.stderr[-4000:]}"
            )
        return process

    def ensure_repository(self) -> None:
        if self.path.exists():
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "init", "--bare", str(self.path)])
        self.git(["remote", "add", "origin", self.url])
        self.git(["config", "remote.origin.promisor", "true"])
        self.git(["config", "remote.origin.partialclonefilter", "blob:none"])

    def refs(self) -> tuple[dict[str, str], dict[str, str]]:
        if self._refs is not None:
            return self._refs
        process = subprocess.run(
            ["git", "ls-remote", "--heads", "--tags", self.url],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.git_environment(),
            check=False,
        )
        if process.returncode:
            raise RuntimeError(
                f"git ls-remote failed for {self.full_name}: {process.stderr[-4000:]}"
            )
        branches: dict[str, str] = {}
        tag_objects: dict[str, str] = {}
        peeled_tags: dict[str, str] = {}
        for line in process.stdout.splitlines():
            if not line.strip():
                continue
            sha, ref = line.split("\t", 1)
            if ref.startswith("refs/heads/"):
                branches[ref.removeprefix("refs/heads/")] = sha
            elif ref.startswith("refs/tags/"):
                name = ref.removeprefix("refs/tags/")
                if name.endswith("^{}"):
                    peeled_tags[name[:-3]] = sha
                else:
                    tag_objects[name] = sha
        tags = {name: peeled_tags.get(name, sha) for name, sha in tag_objects.items()}
        self._refs = branches, tags
        return self._refs

    def raw_changelog(self, sha: str) -> str | None:
        if sha in self._raw_cache:
            return self._raw_cache[sha]
        url = f"https://raw.githubusercontent.com/{self.full_name}/{sha}/debian/changelog"
        headers = {"User-Agent": "hancom-gooroom-arm64-source-lock"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            with urlopen(Request(url, headers=headers), timeout=90) as response:
                text = response.read().decode("utf-8", "replace")
        except HTTPError as error:
            if error.code == 404:
                text = None
            else:
                raise
        self._raw_cache[sha] = text
        return text

    def branch_priority(self, branch: str, target: dict[str, Any]) -> tuple[int, str]:
        version = target["source_version"].lower()
        wants_hancom = "han" in version
        lowered = branch.lower()
        if wants_hancom and "hancom-3" in lowered:
            return (0, lowered)
        if not wants_hancom and "gooroom-3" in lowered:
            return (0, lowered)
        if SERIES3_RE.search(branch):
            return (1, lowered)
        if branch == self.default_branch:
            return (2, lowered)
        if branch in {"master", "main"}:
            return (3, lowered)
        if "3" in lowered:
            return (4, lowered)
        return (5, lowered)

    def fetch_branch(self, branch: str, depth: int) -> str:
        self.ensure_repository()
        digest = hashlib.sha1(branch.encode()).hexdigest()[:16]
        local_ref = f"refs/arm64-lock/{digest}"
        key = f"{branch}:{depth}"
        if key not in self._fetched:
            self.git(
                [
                    "fetch",
                    "--force",
                    "--no-tags",
                    "--filter=blob:none",
                    f"--depth={depth}",
                    "origin",
                    f"refs/heads/{branch}:{local_ref}",
                ]
            )
            self._fetched.add(key)
        return local_ref

    def fetch_commit(self, sha: str) -> str:
        self.ensure_repository()
        local_ref = f"refs/arm64-lock/commit-{sha}"
        if local_ref not in self._fetched:
            self.git(
                [
                    "fetch",
                    "--force",
                    "--no-tags",
                    "--filter=blob:none",
                    "--depth=1",
                    "origin",
                    f"{sha}:{local_ref}",
                ]
            )
            self._fetched.add(local_ref)
        return local_ref

    def commit_record(
        self,
        sha: str,
        *,
        ref_kind: str,
        ref_name: str,
        match_scope: str,
        target: dict[str, Any],
    ) -> dict[str, Any] | None:
        self.fetch_commit(sha)
        changelog = self.git(["show", f"{sha}:debian/changelog"], check=False)
        if changelog.returncode or parse_head(changelog.stdout) != (
            target["source"],
            target["source_version"],
        ):
            return None
        tree = self.git(["rev-parse", f"{sha}^{{tree}}"], check=True).stdout.strip()
        date = self.git(["show", "-s", "--format=%cI", sha], check=True).stdout.strip()
        return {
            "owner": self.owner,
            "repository": self.name,
            "repository_full_name": self.full_name,
            "ref_kind": ref_kind,
            "ref_name": ref_name,
            "commit_sha": sha,
            "tree_sha": tree,
            "committer_date": date,
            "match_scope": match_scope,
            "declared_source": target["source"],
            "declared_version": target["source_version"],
            "changelog_path": "debian/changelog",
            "source_archive": f"https://github.com/{self.full_name}/archive/{sha}.tar.gz",
        }

    def find_exact(self, target: dict[str, Any], max_depth: int) -> list[dict[str, Any]]:
        branches, tags = self.refs()
        header = f"{target['source']} ({target['source_version']})"
        matches: list[dict[str, Any]] = []

        ordered_branches = sorted(
            branches, key=lambda branch: self.branch_priority(branch, target)
        )
        promising: list[tuple[str, str]] = []
        for branch in ordered_branches:
            sha = branches[branch]
            changelog = self.raw_changelog(sha)
            if not contains_header(
                changelog, target["source"], target["source_version"]
            ):
                continue
            promising.append((branch, sha))
            if parse_head(changelog) == (target["source"], target["source_version"]):
                record = self.commit_record(
                    sha,
                    ref_kind="branch",
                    ref_name=branch,
                    match_scope="ref-tip",
                    target=target,
                )
                if record:
                    matches.append(record)

        if matches:
            return matches

        for branch, _ in promising:
            for depth in (300, max_depth):
                reference = self.fetch_branch(branch, depth)
                process = self.git(
                    [
                        "log",
                        "--format=%H",
                        "--fixed-strings",
                        f"-S{header}",
                        reference,
                        "--",
                        "debian/changelog",
                    ],
                    check=False,
                )
                for sha in process.stdout.splitlines():
                    record = self.commit_record(
                        sha.strip(),
                        ref_kind="branch-history",
                        ref_name=branch,
                        match_scope=f"pickaxe-depth-{depth}",
                        target=target,
                    )
                    if record:
                        matches.append(record)
                if matches:
                    break
            if matches:
                break

        if matches:
            return matches

        ordered_tags = sorted(
            tags,
            key=lambda tag: (
                0 if SERIES3_RE.search(tag) else 1,
                0 if target["source_version"] in tag else 1,
                tag,
            ),
        )
        for tag in ordered_tags:
            sha = tags[tag]
            changelog = self.raw_changelog(sha)
            if parse_head(changelog) != (target["source"], target["source_version"]):
                continue
            record = self.commit_record(
                sha,
                ref_kind="tag",
                ref_name=tag,
                match_scope="ref-tip",
                target=target,
            )
            if record:
                matches.append(record)
        return matches


def resolve_target(
    target: dict[str, Any],
    indexes: dict[str, dict[str, dict[str, Any]]],
    probes_root: Path,
    token: str | None,
    max_depth: int,
) -> dict[str, Any]:
    if target["source"] in ARCH_SOURCE_EXCEPTIONS:
        exception = ARCH_SOURCE_EXCEPTIONS[target["source"]]
        return {
            **target,
            "status": exception["status"],
            "reason": exception["reason"],
            "repositories_found": [],
            "exact_matches": [],
            "selected": None,
        }

    repositories = candidate_repositories(target, indexes)
    result: dict[str, Any] = {
        **target,
        "status": "unresolved-repository" if not repositories else "unresolved-version",
        "reason": "",
        "repositories_found": sorted(repository["full_name"] for repository in repositories),
        "exact_matches": [],
        "selected": None,
    }
    if not repositories:
        return result

    ranking = {owner: index for index, owner in enumerate(owner_order(target))}
    matches: list[dict[str, Any]] = []
    for repository in sorted(
        repositories,
        key=lambda item: (ranking[item["owner"]["login"]], item["full_name"]),
    ):
        probe = RepositoryProbe(probes_root, repository, token)
        try:
            repository_matches = probe.find_exact(target, max_depth)
        except Exception as error:  # preserve evidence rather than hiding a probe failure
            result.setdefault("probe_errors", []).append(
                {"repository": repository["full_name"], "error": str(error)}
            )
            continue
        matches.extend(repository_matches)
        if repository_matches and ranking[repository["owner"]["login"]] == 0:
            break

    unique = {
        (match["repository_full_name"], match["commit_sha"]): match for match in matches
    }
    matches = list(unique.values())
    result["exact_matches"] = sorted(
        matches,
        key=lambda match: (
            ranking[match["owner"]],
            match["ref_kind"],
            match["ref_name"],
            match["commit_sha"],
        ),
    )
    if not matches:
        return result

    best_owner_rank = min(ranking[match["owner"]] for match in matches)
    authoritative = [
        match for match in matches if ranking[match["owner"]] == best_owner_rank
    ]

    def match_priority(match: dict[str, Any]) -> tuple[int, int, str]:
        ref_name = match["ref_name"]
        return (
            0 if SERIES3_RE.search(ref_name) else 1,
            0 if match["ref_kind"] == "tag" else 1,
            ref_name,
        )

    best_priority = min(match_priority(match)[:2] for match in authoritative)
    finalists = [
        match
        for match in authoritative
        if match_priority(match)[:2] == best_priority
    ]
    tree_hashes = {match["tree_sha"] for match in finalists}
    if len(tree_hashes) != 1:
        result["status"] = "ambiguous-exact-version"
        result["reason"] = "multiple authoritative commits declare the exact version with different trees"
        return result

    finalists.sort(
        key=lambda match: (match.get("committer_date") or "", match["commit_sha"]),
        reverse=True,
    )
    result["selected"] = finalists[0]
    result["status"] = "resolved"
    return result


def write_outputs(output_dir: Path, rows: list[dict[str, Any]], api_requests: int) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    blocking = [
        row
        for row in rows
        if row["role"] == "rebuild-arm64" and row["status"] != "resolved"
    ]
    unresolved = [
        row
        for row in rows
        if row["status"] not in {"resolved", "arch-replace"}
    ]
    summary = {
        "schema": 2,
        "policy": "exact-debian-changelog-version",
        "source_target_count": len(rows),
        "resolved_count": sum(row["status"] == "resolved" for row in rows),
        "arch_replace_count": sum(row["status"] == "arch-replace" for row in rows),
        "unresolved_count": len(unresolved),
        "rebuild_target_count": sum(row["role"] == "rebuild-arm64" for row in rows),
        "rebuild_unresolved_count": len(blocking),
        "reuse_all_target_count": sum(row["role"] == "reuse-all" for row in rows),
        "github_api_request_count": api_requests,
    }
    (output_dir / "source-lock.json").write_text(
        json.dumps({"summary": summary, "sources": rows}, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    (output_dir / "source-lock-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "unresolved-sources.json").write_text(
        json.dumps(unresolved, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output_dir / "blocking-rebuild-sources.json").write_text(
        json.dumps(blocking, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    fields = [
        "source",
        "source_version",
        "role",
        "status",
        "binary_architectures",
        "repository_full_name",
        "ref_kind",
        "ref_name",
        "commit_sha",
        "tree_sha",
        "match_scope",
    ]
    with (output_dir / "source-lock.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in rows:
            selected = row.get("selected") or {}
            writer.writerow(
                {
                    "source": row["source"],
                    "source_version": row["source_version"],
                    "role": row["role"],
                    "status": row["status"],
                    "binary_architectures": ",".join(row["binary_architectures"]),
                    **{field: selected.get(field, "") for field in fields[5:]},
                }
            )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--max-depth", type=int, default=2000)
    args = parser.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    github = GitHub(token)
    indexes: dict[str, dict[str, dict[str, Any]]] = {}
    for owner in OWNERS:
        repositories = github.repositories(owner)
        indexes[owner] = {repository["name"].lower(): repository for repository in repositories}
        print(f"indexed {owner}: {len(repositories)} repositories", file=sys.stderr)

    targets = target_rows(args.reference)
    rows: list[dict[str, Any]] = []
    args.work_dir.mkdir(parents=True, exist_ok=True)
    for index, target in enumerate(targets, 1):
        print(
            f"[{index}/{len(targets)}] {target['source']} "
            f"{target['source_version']} ({target['role']})",
            file=sys.stderr,
            flush=True,
        )
        row = resolve_target(
            target, indexes, args.work_dir, token, args.max_depth
        )
        rows.append(row)
        print(
            f"  -> {row['status']}"
            + (
                f" {row['selected']['repository_full_name']}@{row['selected']['commit_sha'][:12]}"
                if row.get("selected")
                else ""
            ),
            file=sys.stderr,
            flush=True,
        )

    summary = write_outputs(args.output_dir, rows, github.request_count)
    print(json.dumps(summary, indent=2))
    return 2 if summary["rebuild_unresolved_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
