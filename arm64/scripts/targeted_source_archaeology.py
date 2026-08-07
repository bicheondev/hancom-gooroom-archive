#!/usr/bin/env python3
"""Find one exact historical Debian packaging commit across GitHub mirrors."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHANGELOG_HEAD_RE = re.compile(r"^([^\s]+)\s+\(([^)]+)\)\s+([^;]+);")
OWNER_PRIORITY = {"hancomgooroom": 0, "hancom-io": 1, "gooroom": 2}


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def api(path: str, token: str | None) -> tuple[Any | None, dict[str, Any]]:
    url = path if path.startswith("http") else f"https://api.github.com/{path.lstrip('/')}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "hancom-gooroom-arm64-source-archaeology/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            body = response.read().decode("utf-8")
            return json.loads(body), {
                "url": url,
                "status": response.status,
                "rate_limit_remaining": response.headers.get(
                    "X-RateLimit-Remaining"
                ),
            }
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        return None, {
            "url": url,
            "status": error.code,
            "error": body[:4000],
        }
    except Exception as error:
        return None, {"url": url, "status": None, "error": repr(error)}


def paginate_repositories(owner: str, token: str | None) -> tuple[list[str], list[dict[str, Any]]]:
    """List repositories for either an organization or a user account.

    hancomgooroom is a GitHub user account, while hancom-io and gooroom are
    organizations. The old organization-only request silently omitted every
    hancomgooroom mirror after receiving 404.
    """

    repositories: list[str] = []
    requests: list[dict[str, Any]] = []
    for account_kind, endpoint in (
        ("organization", "orgs"),
        ("user", "users"),
    ):
        endpoint_resolved = False
        page = 1
        while page <= 10:
            value, evidence = api(
                f"{endpoint}/{owner}/repos?type=all&per_page=100&page={page}",
                token,
            )
            evidence["account_kind"] = account_kind
            requests.append(evidence)
            if not isinstance(value, list):
                break
            endpoint_resolved = True
            repositories.extend(
                item["full_name"]
                for item in value
                if isinstance(item, dict) and item.get("full_name")
            )
            if len(value) < 100:
                break
            page += 1
        if endpoint_resolved:
            break
    return repositories, requests


def search_code(query: str, token: str | None) -> tuple[list[str], dict[str, Any]]:
    encoded = urllib.parse.urlencode({"q": query, "per_page": 100})
    value, evidence = api(f"search/code?{encoded}", token)
    repositories: list[str] = []
    if isinstance(value, dict):
        for item in value.get("items", []):
            repository = item.get("repository") if isinstance(item, dict) else None
            if isinstance(repository, dict) and repository.get("full_name"):
                repositories.append(repository["full_name"])
        evidence["total_count"] = value.get("total_count")
    evidence["query"] = query
    return repositories, evidence


def search_repositories(query: str, token: str | None) -> tuple[list[str], dict[str, Any]]:
    encoded = urllib.parse.urlencode(
        {"q": query, "sort": "updated", "order": "desc", "per_page": 100}
    )
    value, evidence = api(f"search/repositories?{encoded}", token)
    repositories: list[str] = []
    if isinstance(value, dict):
        repositories = [
            item["full_name"]
            for item in value.get("items", [])
            if isinstance(item, dict) and item.get("full_name")
        ]
        evidence["total_count"] = value.get("total_count")
    evidence["query"] = query
    return repositories, evidence


def run(
    command: list[str],
    cwd: Path | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def parse_head(text: str) -> tuple[str | None, str | None, str | None]:
    line = text.splitlines()[0].strip() if text.splitlines() else ""
    match = CHANGELOG_HEAD_RE.match(line)
    if not match:
        return None, None, line
    return match.group(1), match.group(2), line


def repository_score(full_name: str, source: str) -> tuple[int, int, str]:
    owner, name = full_name.split("/", 1)
    normalized_source = re.sub(r"[^a-z0-9]", "", source.lower())
    normalized_name = re.sub(r"[^a-z0-9]", "", name.lower())
    exact_name = 0 if normalized_source == normalized_name else 1
    return OWNER_PRIORITY.get(owner, 50), exact_name, full_name.lower()


def inspect_repository(
    full_name: str,
    source: str,
    version: str,
    work_root: Path,
    token: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    directory = work_root / re.sub(r"[^A-Za-z0-9_.-]+", "_", full_name)
    clone_url = f"https://github.com/{full_name}.git"
    if token:
        clone_url = f"https://x-access-token:{token}@github.com/{full_name}.git"
    attempt: dict[str, Any] = {
        "repository_full_name": full_name,
        "clone_status": None,
        "history_search_status": None,
        "candidate_commit_count": 0,
        "stderr_tail": None,
    }
    matches: list[dict[str, Any]] = []
    try:
        process = run(
            [
                "git",
                "clone",
                "--bare",
                "--filter=blob:none",
                "--no-tags",
                clone_url,
                str(directory),
            ],
            timeout=240,
        )
        attempt["clone_status"] = process.returncode
        attempt["stderr_tail"] = process.stderr[-4000:]
        if process.returncode:
            return matches, attempt
        fetch = run(
            [
                "git",
                "fetch",
                "--force",
                "--prune",
                "--tags",
                "origin",
                "+refs/heads/*:refs/remotes/origin/*",
                "+refs/tags/*:refs/tags/*",
            ],
            cwd=directory,
            timeout=300,
        )
        attempt["fetch_status"] = fetch.returncode
        if fetch.returncode:
            attempt["stderr_tail"] = fetch.stderr[-4000:]

        history = run(
            [
                "git",
                "log",
                "--all",
                f"-S{version}",
                "--format=%H",
                "--",
                "debian/changelog",
            ],
            cwd=directory,
            timeout=300,
        )
        attempt["history_search_status"] = history.returncode
        commits = [line.strip() for line in history.stdout.splitlines() if line.strip()]
        if not commits:
            refs = run(
                ["git", "for-each-ref", "--format=%(objectname)"],
                cwd=directory,
                timeout=60,
            )
            commits = [
                line.strip() for line in refs.stdout.splitlines() if line.strip()
            ]
        commits = list(dict.fromkeys(commits))[:1000]
        attempt["candidate_commit_count"] = len(commits)

        for commit in commits:
            changelog = run(
                ["git", "show", f"{commit}:debian/changelog"],
                cwd=directory,
                timeout=90,
            )
            if changelog.returncode:
                continue
            declared_source, declared_version, head = parse_head(changelog.stdout)
            if declared_source != source or declared_version != version:
                continue
            tree = run(
                ["git", "show", "-s", "--format=%T", commit],
                cwd=directory,
                timeout=30,
            ).stdout.strip()
            date = run(
                ["git", "show", "-s", "--format=%cI", commit],
                cwd=directory,
                timeout=30,
            ).stdout.strip()
            refs = run(
                ["git", "for-each-ref", "--contains", commit, "--format=%(refname)"],
                cwd=directory,
                timeout=60,
            ).stdout.splitlines()
            matches.append(
                {
                    "type": "git",
                    "repository_full_name": full_name,
                    "repository_url": f"https://github.com/{full_name}",
                    "commit_sha": commit,
                    "tree_sha": tree,
                    "committer_date": date,
                    "declared_source": declared_source,
                    "declared_version": declared_version,
                    "changelog_head": head,
                    "containing_refs": sorted(refs)[:200],
                    "source_archive": (
                        f"https://github.com/{full_name}/archive/{commit}.tar.gz"
                    ),
                    "match_scope": "complete-debian-changelog-history",
                }
            )
        return matches, attempt
    except subprocess.TimeoutExpired as error:
        attempt["timeout"] = str(error)
        return matches, attempt
    except Exception as error:
        attempt["exception"] = repr(error)
        return matches, attempt
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--owner", action="append", default=["hancomgooroom", "hancom-io", "gooroom"]
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--maximum-repositories", type=int, default=30)
    parser.add_argument(
        "--enable-code-search",
        action="store_true",
        help=(
            "Use GitHub code search as a secondary discovery path. Disabled by "
            "default because its installation rate limit is shared and very low."
        ),
    )
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    api_evidence: list[dict[str, Any]] = []
    repositories: set[str] = set()

    for owner in args.owner:
        values, evidence = paginate_repositories(owner, token)
        repositories.update(values)
        api_evidence.extend(evidence)

    if args.enable_code_search:
        code_queries = [
            f'"{args.version}" org:{owner}' for owner in args.owner
        ] + [
            f'"{args.version}" "{args.source}"',
            f'"{args.version}" path:debian/changelog',
        ]
        for query in code_queries:
            values, evidence = search_code(query, token)
            repositories.update(values)
            api_evidence.append(evidence)
            time.sleep(1.2)

    repository_queries = list(
        dict.fromkeys(
            (
                f"{args.source} in:name",
                f"{args.source.replace('-opensource-src', '')} in:name",
            )
        )
    )
    for query in repository_queries:
        values, evidence = search_repositories(query, token)
        repositories.update(values)
        api_evidence.append(evidence)

    source_terms = {
        re.sub(r"[^a-z0-9]", "", args.source.lower()),
        re.sub(
            r"[^a-z0-9]", "", args.source.lower().replace("-opensource-src", "")
        ),
    }
    ranked = sorted(
        repositories,
        key=lambda full_name: repository_score(full_name, args.source),
    )
    strongly_named = [
        full_name
        for full_name in ranked
        if any(
            term and term in re.sub(r"[^a-z0-9]", "", full_name.lower())
            for term in source_terms
        )
    ]
    search_discovered = [
        full_name
        for full_name in ranked
        if full_name not in strongly_named
    ]
    candidates = (strongly_named + search_discovered)[: args.maximum_repositories]

    work_root = Path(tempfile.mkdtemp(prefix="source-archaeology-"))
    all_matches: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    try:
        for full_name in candidates:
            matches, attempt = inspect_repository(
                full_name,
                args.source,
                args.version,
                work_root,
                token,
            )
            all_matches.extend(matches)
            attempts.append(attempt)
    finally:
        shutil.rmtree(work_root, ignore_errors=True)

    trees = {match.get("tree_sha") for match in all_matches if match.get("tree_sha")}
    status = "unresolved"
    selected: dict[str, Any] | None = None
    reason = "no exact changelog commit was found"
    if all_matches and len(trees) == 1:
        all_matches.sort(
            key=lambda match: (
                repository_score(match["repository_full_name"], args.source),
                match.get("committer_date") or "",
                match.get("commit_sha") or "",
            )
        )
        selected = all_matches[0]
        status = "resolved"
        reason = "all exact changelog matches identify one immutable Git tree"
    elif all_matches:
        status = "ambiguous"
        reason = "exact changelog matches identify multiple Git trees"

    result = {
        "schema": "hancom-gooroom-targeted-source-archaeology-v1",
        "generated_at": now(),
        "status": status,
        "reason": reason,
        "source": args.source,
        "version": args.version,
        "owners": args.owner,
        "repository_candidate_count": len(candidates),
        "repository_candidates": candidates,
        "exact_match_count": len(all_matches),
        "exact_tree_count": len(trees),
        "selected": selected,
        "exact_matches": all_matches,
        "repository_attempts": attempts,
        "api_evidence": api_evidence,
    }
    filename = (
        "targeted-source-lock.json"
        if status == "resolved"
        else "targeted-source-archaeology.json"
    )
    (args.output_dir / filename).write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if status == "resolved" else 11


if __name__ == "__main__":
    raise SystemExit(main())
