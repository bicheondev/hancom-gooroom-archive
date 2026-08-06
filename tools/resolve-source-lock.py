#!/usr/bin/env python3
"""Resolve exact GitHub source commits for the AMD64 Hancom Gooroom package set.

The installed AMD64 dpkg database is authoritative. A repository is accepted
only when a commit's top debian/changelog entry has the same source package name
and the exact same version string. Branch names, tags, and newer source trees do
not count as a match.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

CHANGELOG_RE = re.compile(r"^([a-z0-9][a-z0-9+.-]*)\s+\(([^)]+)\)\s+[^;]+;", re.I)
VENDOR_VERSION_RE = re.compile(r"(?:\+|~)(?:grm|han)\d", re.I)
VENDOR_SOURCE_RE = re.compile(r"^(?:gooroom|hancom|hancomgrm|pam-gooroom|gooroomsystem)(?:$|-)", re.I)
FIELD_RE = re.compile(r"^([A-Za-z0-9-]+):\s*(.*)$")

REPO_ALIASES: dict[str, list[str]] = {
    "gtk+2.0": ["gtk2"],
    "gtk+3.0": ["gtk3"],
    "pam-gooroom": ["pam-gooroom", "libpam-gooroom-authenticator"],
    "celluloid": ["celluloid", "gnome-mpv"],
    "gooroom-dockbarx": ["gooroom-dockbarx", "dockbarx"],
    "linux-signed-amd64": ["linux-signed-amd64", "linux-signed", "linux-latest"],
    "qtbase-opensource-src": ["qtbase-opensource-src", "qtbase5"],
}


@dataclass(frozen=True)
class RequiredSource:
    source: str
    source_version: str
    binary_packages: str
    binary_architectures: str
    custom_hint: str


@dataclass
class Repository:
    full_name: str
    owner: str
    name: str
    default_branch: str
    archived: bool
    fork: bool
    clone_url: str


class GitHubAPI:
    def __init__(self, token: str | None) -> None:
        self.token = token
        self.api_calls = 0
        self.raw_calls = 0

    def _headers(self, *, raw: bool = False, byte_range: str | None = None) -> dict[str, str]:
        headers = {
            "User-Agent": "hancom-gooroom-arm64-source-lock/1",
            "Accept": "application/vnd.github.raw+json" if raw else "application/vnd.github+json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if not raw:
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        if byte_range:
            headers["Range"] = byte_range
        return headers

    def _request(self, url: str, *, raw: bool = False, byte_range: str | None = None) -> bytes:
        request = urllib.request.Request(url, headers=self._headers(raw=raw, byte_range=byte_range))
        for attempt in range(5):
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    if raw:
                        self.raw_calls += 1
                    else:
                        self.api_calls += 1
                    return response.read()
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raise FileNotFoundError(url) from exc
                if exc.code in {403, 429, 500, 502, 503, 504} and attempt < 4:
                    retry_after = exc.headers.get("Retry-After")
                    delay = float(retry_after) if retry_after else 2.0**attempt
                    time.sleep(min(delay, 30.0))
                    continue
                body = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"GitHub request failed ({exc.code}) {url}: {body[:1000]}") from exc
            except (TimeoutError, urllib.error.URLError) as exc:
                if attempt < 4:
                    time.sleep(2.0**attempt)
                    continue
                raise RuntimeError(f"GitHub request failed {url}: {exc}") from exc
        raise AssertionError("unreachable")

    def json(self, path_or_url: str) -> Any:
        url = path_or_url if path_or_url.startswith("https://") else f"https://api.github.com{path_or_url}"
        return json.loads(self._request(url).decode("utf-8"))

    def raw_file(self, repo: str, commit: str, path: str, *, max_bytes: int = 524288) -> str:
        quoted_path = "/".join(urllib.parse.quote(segment, safe="") for segment in path.split("/"))
        url = f"https://raw.githubusercontent.com/{repo}/{commit}/{quoted_path}"
        payload = self._request(url, raw=True, byte_range=f"bytes=0-{max_bytes - 1}")
        return payload.decode("utf-8", errors="replace")

    def public_repositories(self, owner: str) -> list[Repository]:
        repos: list[Repository] = []
        owner_key = urllib.parse.quote(owner, safe="")
        owner_metadata = self.json(f"/users/{owner_key}")
        endpoint = "orgs" if owner_metadata.get("type") == "Organization" else "users"
        page = 1
        while True:
            payload = self.json(
                f"/{endpoint}/{owner_key}/repos?per_page=100&page={page}&sort=full_name&direction=asc&type=all"
            )
            if not isinstance(payload, list):
                raise TypeError(f"Unexpected repository response for {owner}: {payload!r}")
            for item in payload:
                repos.append(
                    Repository(
                        full_name=item["full_name"],
                        owner=item["owner"]["login"],
                        name=item["name"],
                        default_branch=item.get("default_branch") or "",
                        archived=bool(item.get("archived")),
                        fork=bool(item.get("fork")),
                        clone_url=item.get("clone_url") or f"https://github.com/{item['full_name']}.git",
                    )
                )
            if len(payload) < 100:
                break
            page += 1
        return repos

    def branches(self, repo: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        page = 1
        while True:
            payload = self.json(f"/repos/{repo}/branches?per_page=100&page={page}")
            result.extend(payload)
            if len(payload) < 100:
                return result
            page += 1

    def tags(self, repo: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        page = 1
        while page <= 3:
            payload = self.json(f"/repos/{repo}/tags?per_page=100&page={page}")
            result.extend(payload)
            if len(payload) < 100:
                break
            page += 1
        return result

    def changelog_commits(self, repo: str, sha: str | None = None, max_pages: int = 5) -> Iterator[dict[str, Any]]:
        for page in range(1, max_pages + 1):
            query = {"path": "debian/changelog", "per_page": "100", "page": str(page)}
            if sha:
                query["sha"] = sha
            payload = self.json(f"/repos/{repo}/commits?{urllib.parse.urlencode(query)}")
            for item in payload:
                yield item
            if len(payload) < 100:
                return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--strict", action="store_true", help="exit non-zero when the lock is incomplete")
    parser.add_argument("--max-history-pages", type=int, default=5)
    return parser.parse_args()


def read_required_sources(path: Path) -> list[RequiredSource]:
    required: list[RequiredSource] = []
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            source = row["source"]
            version = row["source_version"]
            if not (VENDOR_VERSION_RE.search(version) or VENDOR_SOURCE_RE.search(source)):
                continue
            required.append(
                RequiredSource(
                    source=source,
                    source_version=version,
                    binary_packages=row.get("binary_packages", ""),
                    binary_architectures=row.get("binary_architectures", ""),
                    custom_hint=row.get("custom_hint", ""),
                )
            )
    required.sort(key=lambda item: (item.source, item.source_version))
    return required


def parse_changelog_head(text: str) -> tuple[str, str] | None:
    for line in text.splitlines()[:20]:
        match = CHANGELOG_RE.match(line.strip())
        if match:
            return match.group(1), match.group(2)
    return None


def parse_control(text: str) -> list[dict[str, str]]:
    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key: str | None = None
    for raw in text.splitlines():
        if not raw.strip():
            if current:
                paragraphs.append(current)
                current = {}
                last_key = None
            continue
        if raw[0].isspace():
            if last_key:
                current[last_key] = current[last_key] + " " + raw.strip()
            continue
        match = FIELD_RE.match(raw)
        if match:
            last_key = match.group(1)
            current[last_key] = match.group(2)
    if current:
        paragraphs.append(current)
    return paragraphs


def arm64_classification(control: str | None) -> dict[str, Any]:
    if not control:
        return {
            "control_source": None,
            "binary_architectures": [],
            "arm64_build_class": "unknown-no-control",
        }
    paragraphs = parse_control(control)
    source_name = paragraphs[0].get("Source") if paragraphs else None
    architectures: list[str] = []
    for paragraph in paragraphs[1:]:
        if "Package" in paragraph and "Architecture" in paragraph:
            architectures.extend(paragraph["Architecture"].split())
    architectures = sorted(set(architectures))
    arm64_capable = {"all", "any", "linux-any", "arm64"}
    explicitly_x86 = {"amd64", "i386", "x32", "any-amd64", "any-i386"}
    if architectures and set(architectures).issubset({"all"}):
        build_class = "architecture-all"
    elif any(token in arm64_capable for token in architectures):
        build_class = "arm64-allowed"
    elif architectures and set(architectures).issubset(explicitly_x86):
        build_class = "x86-only"
    elif architectures:
        build_class = "needs-architecture-review"
    else:
        build_class = "unknown-no-binary-architecture"
    return {
        "control_source": source_name,
        "binary_architectures": architectures,
        "arm64_build_class": build_class,
    }


def candidate_names(source: str) -> list[str]:
    names = [source]
    names.extend(REPO_ALIASES.get(source, []))
    if source.endswith("-opensource-src"):
        names.append(source.removesuffix("-opensource-src"))
    names.extend(
        [
            source.replace("+", ""),
            source.replace("+", "-"),
            source.replace(".", ""),
        ]
    )
    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        lowered = name.lower()
        if name and lowered not in seen:
            seen.add(lowered)
            result.append(name)
    return result


def repo_candidates(required: RequiredSource, catalog: list[Repository], owner_priority: dict[str, int]) -> list[Repository]:
    names = candidate_names(required.source)
    name_priority = {name.lower(): index for index, name in enumerate(names)}
    candidates = [repo for repo in catalog if repo.name.lower() in name_priority]
    candidates.sort(
        key=lambda repo: (
            name_priority[repo.name.lower()],
            owner_priority.get(repo.owner.lower(), 999),
            repo.archived,
            repo.fork,
            repo.full_name.lower(),
        )
    )
    return candidates


def inspect_commit(
    api: GitHubAPI,
    repo: Repository,
    commit: str,
    required: RequiredSource,
    cache: dict[tuple[str, str], tuple[str, str] | None],
) -> tuple[bool, tuple[str, str] | None]:
    key = (repo.full_name, commit)
    if key not in cache:
        try:
            cache[key] = parse_changelog_head(api.raw_file(repo.full_name, commit, "debian/changelog", max_bytes=131072))
        except FileNotFoundError:
            cache[key] = None
    identity = cache[key]
    exact = bool(identity and identity[0] == required.source and identity[1] == required.source_version)
    return exact, identity


def resolve_one(
    api: GitHubAPI,
    required: RequiredSource,
    candidates: list[Repository],
    max_history_pages: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    observed: list[dict[str, Any]] = []
    changelog_cache: dict[tuple[str, str], tuple[str, str] | None] = {}

    for repo in candidates:
        ref_commits: dict[str, set[str]] = defaultdict(set)
        try:
            for branch in api.branches(repo.full_name):
                sha = branch.get("commit", {}).get("sha")
                if sha:
                    ref_commits[sha].add(f"refs/heads/{branch['name']}")
            for tag in api.tags(repo.full_name):
                sha = tag.get("commit", {}).get("sha")
                if sha:
                    ref_commits[sha].add(f"refs/tags/{tag['name']}")
        except FileNotFoundError:
            observed.append({"repository": repo.full_name, "status": "repository-not-found"})
            continue

        for sha, refs in ref_commits.items():
            exact, identity = inspect_commit(api, repo, sha, required, changelog_cache)
            if identity:
                observed.append(
                    {
                        "repository": repo.full_name,
                        "commit": sha,
                        "refs": sorted(refs),
                        "source": identity[0],
                        "version": identity[1],
                        "location": "ref-tip",
                    }
                )
            if exact:
                matches.append(
                    {
                        "repository": repo.full_name,
                        "commit": sha,
                        "refs": sorted(refs),
                        "match_location": "ref-tip",
                    }
                )

        if matches:
            continue

        seen_history: set[str] = set()
        history_roots: list[str | None] = [repo.default_branch or None]
        likely_v3_heads = sorted(
            {
                ref.removeprefix("refs/heads/")
                for refs in ref_commits.values()
                for ref in refs
                if ref.startswith("refs/heads/")
                and re.search(r"(?:gooroom|hancom)[-_]?3(?:\.0)?|bullseye", ref, re.I)
            }
        )
        history_roots.extend(likely_v3_heads)
        for history_root in history_roots:
            try:
                for commit_item in api.changelog_commits(
                    repo.full_name, sha=history_root, max_pages=max_history_pages
                ):
                    sha = commit_item.get("sha")
                    if not sha or sha in seen_history:
                        continue
                    seen_history.add(sha)
                    exact, identity = inspect_commit(api, repo, sha, required, changelog_cache)
                    if identity:
                        observed.append(
                            {
                                "repository": repo.full_name,
                                "commit": sha,
                                "refs": sorted(ref_commits.get(sha, set())),
                                "source": identity[0],
                                "version": identity[1],
                                "location": "changelog-history",
                                "history_root": history_root,
                            }
                        )
                    if exact:
                        matches.append(
                            {
                                "repository": repo.full_name,
                                "commit": sha,
                                "refs": sorted(ref_commits.get(sha, set())),
                                "match_location": "changelog-history",
                                "history_root": history_root,
                            }
                        )
                        break
                if any(match["repository"] == repo.full_name for match in matches):
                    break
            except FileNotFoundError:
                continue

    return matches, {"candidates": [repo.full_name for repo in candidates], "observed": observed}


def write_tsv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            normalized = {}
            for field in fields:
                value = row.get(field, "")
                if isinstance(value, list):
                    value = ",".join(str(item) for item in value)
                normalized[field] = value
            writer.writerow(normalized)


def main() -> int:
    args = parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    owners = [str(owner) for owner in config["source_organizations"]]
    owner_priority = {owner.lower(): index for index, owner in enumerate(owners)}
    required_sources = read_required_sources(args.sources)
    args.output.mkdir(parents=True, exist_ok=True)

    api = GitHubAPI(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    catalog: list[Repository] = []
    for owner in owners:
        catalog.extend(api.public_repositories(owner))
    catalog = list({repo.full_name.lower(): repo for repo in catalog}.values())
    catalog.sort(key=lambda repo: repo.full_name.lower())
    (args.output / "repository-catalog.json").write_text(
        json.dumps([asdict(repo) for repo in catalog], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    selected: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {}

    for index, required in enumerate(required_sources, start=1):
        print(
            f"[{index:02d}/{len(required_sources):02d}] {required.source}={required.source_version}",
            flush=True,
        )
        candidates = repo_candidates(required, catalog, owner_priority)
        if not candidates:
            unresolved.append(
                {
                    **asdict(required),
                    "reason": "no-repository-name-match",
                    "candidate_repositories": [],
                }
            )
            diagnostics[required.source] = {"candidates": [], "observed": []}
            continue

        matches, diagnostic = resolve_one(api, required, candidates, args.max_history_pages)
        diagnostics[required.source] = diagnostic
        if not matches:
            observed_versions = sorted(
                {
                    str(item.get("version"))
                    for item in diagnostic["observed"]
                    if item.get("source") == required.source and item.get("version")
                }
            )
            unresolved.append(
                {
                    **asdict(required),
                    "reason": "exact-version-not-found",
                    "candidate_repositories": [repo.full_name for repo in candidates],
                    "observed_versions": observed_versions,
                }
            )
            continue

        matches.sort(
            key=lambda match: (
                owner_priority.get(match["repository"].split("/", 1)[0].lower(), 999),
                match["repository"].split("/", 1)[1].lower() != required.source.lower(),
                match["repository"].lower(),
                match["commit"],
            )
        )
        chosen = matches[0]
        repo = next(repo for repo in candidates if repo.full_name == chosen["repository"])
        try:
            control = api.raw_file(repo.full_name, chosen["commit"], "debian/control", max_bytes=1048576)
        except FileNotFoundError:
            control = None
        architecture = arm64_classification(control)
        if architecture["control_source"] and architecture["control_source"] != required.source:
            unresolved.append(
                {
                    **asdict(required),
                    "reason": "debian-control-source-mismatch",
                    "candidate_repositories": [repo.full_name for repo in candidates],
                    "observed_versions": [required.source_version],
                }
            )
            continue
        selected.append(
            {
                **asdict(required),
                "repository": repo.full_name,
                "commit": chosen["commit"],
                "refs": chosen.get("refs", []),
                "match_location": chosen["match_location"],
                "default_branch": repo.default_branch,
                "archived_repository": repo.archived,
                "fork_repository": repo.fork,
                "clone_url": repo.clone_url,
                "version_match": "exact",
                **architecture,
                "alternative_exact_matches": [
                    match
                    for match in matches[1:]
                    if (match["repository"], match["commit"])
                    != (chosen["repository"], chosen["commit"])
                ],
            }
        )

    selected.sort(key=lambda item: (item["source"], item["source_version"]))
    unresolved.sort(key=lambda item: (item["source"], item["source_version"]))
    lock = {
        "schema": 1,
        "product": config["product"],
        "version": config["version"],
        "reference_architecture": config["base_architecture"],
        "target_architecture": config["target_architecture"],
        "comparison": "exact Debian source package name and version from debian/changelog",
        "source_organizations": owners,
        "required_source_count": len(required_sources),
        "resolved_source_count": len(selected),
        "unresolved_source_count": len(unresolved),
        "complete": not unresolved,
        "sources": selected,
        "unresolved": unresolved,
    }
    (args.output / "source-lock.json").write_text(
        json.dumps(lock, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output / "source-audit-diagnostics.json").write_text(
        json.dumps(diagnostics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    write_tsv(
        args.output / "source-lock.tsv",
        selected,
        [
            "source",
            "source_version",
            "repository",
            "commit",
            "refs",
            "match_location",
            "version_match",
            "binary_packages",
            "binary_architectures",
            "arm64_build_class",
            "control_source",
            "default_branch",
            "archived_repository",
            "fork_repository",
        ],
    )
    write_tsv(
        args.output / "unresolved-sources.tsv",
        unresolved,
        [
            "source",
            "source_version",
            "reason",
            "candidate_repositories",
            "observed_versions",
            "binary_packages",
            "binary_architectures",
        ],
    )
    summary = {
        "required": len(required_sources),
        "resolved": len(selected),
        "unresolved": len(unresolved),
        "complete": not unresolved,
        "arm64_build_classes": {
            build_class: sum(1 for item in selected if item["arm64_build_class"] == build_class)
            for build_class in sorted({item["arm64_build_class"] for item in selected})
        },
        "github_api_calls": api.api_calls,
        "github_raw_file_calls": api.raw_calls,
    }
    (args.output / "source-audit-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    if args.strict and unresolved:
        print(
            f"fatal: {len(unresolved)} of {len(required_sources)} source versions are not exactly locked",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
