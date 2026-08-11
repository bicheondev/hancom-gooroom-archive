#!/usr/bin/env python3
"""Trace short commit IDs embedded in the exact AMD64 package changelogs.

The audit searches current repository refs, pull-request refs, GitHub's global
commit index, and public forks.  Finding a short object ID is not sufficient to
promote source: the resolved commit must also expose a Debian changelog whose
head is the exact locked source/version.  All other results remain evidence
only and preserve the project's fail-closed source policy.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

API = "https://api.github.com"
PREFERRED_OWNERS = {"gooroom", "hancom-io", "hancomgooroom"}
HEX_SHORT = re.compile(r"^[0-9a-f]{7,40}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
CHANGELOG_HEAD = re.compile(r"^(?P<source>\S+) \((?P<version>[^)]+)\)")
MAX_REPOSITORIES_PER_TARGET = 20
MAX_FORKS_PER_TARGET = 40
MAX_CLONES_PER_TARGET = 3
MAX_CLONE_REPOSITORY_KB = 350_000


@dataclass(frozen=True)
class Target:
    source: str
    version: str
    final_change_id: str
    change_ids: tuple[str, ...]


class GitHubAPI:
    def __init__(self, token: str, evidence: list[dict[str, Any]]) -> None:
        self.token = token
        self.evidence = evidence

    def get(
        self,
        path: str,
        *,
        params: dict[str, str | int] | None = None,
        accept: str = "application/vnd.github+json",
        retries: int = 3,
    ) -> Any | None:
        if not path.startswith("http"):
            url = API + path
        else:
            url = path
        if params:
            separator = "&" if "?" in url else "?"
            url += separator + urllib.parse.urlencode(params)
        headers = {
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hancom-gooroom-arm64-changelog-object-audit/1",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        for attempt in range(1, retries + 1):
            request = urllib.request.Request(url, headers=headers)
            started = time.monotonic()
            try:
                with urllib.request.urlopen(request, timeout=45) as response:
                    body = response.read()
                    record = {
                        "url": url,
                        "status": int(getattr(response, "status", 200)),
                        "size": len(body),
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "rate_limit_remaining": response.headers.get("X-RateLimit-Remaining"),
                    }
                    self.evidence.append(record)
                    if not body:
                        return None
                    return json.loads(body.decode("utf-8"))
            except urllib.error.HTTPError as error:
                body = error.read(4096).decode("utf-8", errors="replace")
                record = {
                    "url": url,
                    "status": int(error.code),
                    "error": body,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "rate_limit_remaining": error.headers.get("X-RateLimit-Remaining"),
                }
                self.evidence.append(record)
                if error.code in {403, 429, 502, 503, 504} and attempt < retries:
                    retry_after = error.headers.get("Retry-After")
                    delay = int(retry_after) if retry_after and retry_after.isdigit() else attempt * 3
                    time.sleep(min(delay, 15))
                    continue
                return None
            except Exception as error:
                self.evidence.append(
                    {
                        "url": url,
                        "status": None,
                        "error": repr(error),
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                    }
                )
                if attempt < retries:
                    time.sleep(attempt * 2)
                    continue
                return None
        return None


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def load_targets(path: Path) -> list[Target]:
    document = json.loads(path.read_text(encoding="utf-8"))
    rows = document.get("targets")
    if not isinstance(rows, list):
        raise SystemExit("targets document lacks a targets array")
    targets: list[Target] = []
    for row in rows:
        source = str(row.get("source", ""))
        version = str(row.get("source_version", ""))
        final_change_id = str(row.get("final_change_id", "")).lower()
        ids = tuple(str(value).lower() for value in row.get("change_ids", []))
        if not source or not version or not ids:
            raise SystemExit(f"malformed target row: {row!r}")
        if final_change_id not in ids:
            raise SystemExit(f"final change ID is not listed for {source}")
        if any(HEX_SHORT.fullmatch(value) is None for value in ids):
            raise SystemExit(f"invalid change ID for {source}: {ids!r}")
        targets.append(Target(source, version, final_change_id, ids))
    return targets


def archaeology_candidates(root: Path, target: Target) -> tuple[list[str], list[str]]:
    repositories: set[str] = set()
    evidence_paths: list[str] = []
    for path in sorted(root.rglob("targeted-source-archaeology.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if document.get("source") != target.source:
            continue
        version = document.get("version") or document.get("source_version")
        if version != target.version:
            continue
        evidence_paths.append(path.as_posix())
        for value in document.get("repository_candidates", []):
            if isinstance(value, str) and value.count("/") == 1:
                repositories.add(value)
        for attempt in document.get("repository_attempts", []):
            value = attempt.get("repository_full_name") if isinstance(attempt, dict) else None
            if isinstance(value, str) and value.count("/") == 1:
                repositories.add(value)

    for owner in sorted(PREFERRED_OWNERS):
        repositories.add(f"{owner}/{target.source}")
    return sorted(repositories), evidence_paths


def repository_score(repository: str, source: str) -> tuple[int, str]:
    owner, name = repository.lower().split("/", 1)
    score = 0
    if owner in PREFERRED_OWNERS:
        score += 50
    if name == source.lower():
        score += 100
    elif source.lower() in name:
        score += 30
    if owner == "gooroom":
        score += 10
    return (-score, repository)


def compact_repository_metadata(document: dict[str, Any]) -> dict[str, Any]:
    owner = document.get("owner") if isinstance(document.get("owner"), dict) else {}
    return {
        "full_name": document.get("full_name"),
        "default_branch": document.get("default_branch"),
        "fork": document.get("fork"),
        "archived": document.get("archived"),
        "disabled": document.get("disabled"),
        "size_kb": document.get("size"),
        "forks_count": document.get("forks_count"),
        "owner": owner.get("login"),
        "html_url": document.get("html_url"),
        "updated_at": document.get("updated_at"),
    }


def resolve_commit_api(api: GitHubAPI, repository: str, change_id: str) -> dict[str, Any] | None:
    document = api.get(f"/repos/{repository}/commits/{change_id}")
    if not isinstance(document, dict):
        return None
    sha = str(document.get("sha", ""))
    if HEX40.fullmatch(sha) is None or not sha.startswith(change_id):
        return None
    commit = document.get("commit") if isinstance(document.get("commit"), dict) else {}
    tree = commit.get("tree") if isinstance(commit.get("tree"), dict) else {}
    return {
        "repository": repository,
        "change_id": change_id,
        "full_sha": sha,
        "tree_sha": tree.get("sha"),
        "message": commit.get("message"),
        "html_url": document.get("html_url"),
        "discovery": "repository-commit-api",
    }


def global_commit_search(api: GitHubAPI, change_id: str) -> list[dict[str, Any]]:
    matches: dict[tuple[str, str], dict[str, Any]] = {}
    for query in (f"hash:{change_id}", change_id):
        document = api.get(
            "/search/commits",
            params={"q": query, "per_page": 100},
            accept="application/vnd.github+json",
        )
        if not isinstance(document, dict):
            continue
        for item in document.get("items", []):
            if not isinstance(item, dict):
                continue
            sha = str(item.get("sha", ""))
            repository = item.get("repository") if isinstance(item.get("repository"), dict) else {}
            full_name = str(repository.get("full_name", ""))
            if HEX40.fullmatch(sha) is None or not sha.startswith(change_id) or full_name.count("/") != 1:
                continue
            key = (full_name, sha)
            commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
            tree = commit.get("tree") if isinstance(commit.get("tree"), dict) else {}
            matches[key] = {
                "repository": full_name,
                "change_id": change_id,
                "full_sha": sha,
                "tree_sha": tree.get("sha"),
                "message": commit.get("message"),
                "html_url": item.get("html_url"),
                "discovery": f"global-commit-search:{query}",
            }
    return sorted(matches.values(), key=lambda row: (row["repository"], row["full_sha"]))


def fetch_changelog(api: GitHubAPI, repository: str, sha: str) -> str | None:
    document = api.get(
        f"/repos/{repository}/contents/debian/changelog",
        params={"ref": sha},
    )
    if not isinstance(document, dict):
        return None
    content = document.get("content")
    if not isinstance(content, str):
        return None
    try:
        return base64.b64decode(content, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return None


def verify_changelog(text: str | None, target: Target) -> dict[str, Any]:
    if text is None:
        return {
            "changelog_available": False,
            "changelog_head": "",
            "changelog_source": "",
            "changelog_version": "",
            "exact_changelog_head": False,
        }
    head = text.splitlines()[0] if text.splitlines() else ""
    match = CHANGELOG_HEAD.match(head)
    source = match.group("source") if match else ""
    version = match.group("version") if match else ""
    return {
        "changelog_available": True,
        "changelog_head": head,
        "changelog_source": source,
        "changelog_version": version,
        "exact_changelog_head": source == target.source and version == target.version,
    }


def list_forks(api: GitHubAPI, repository: str, limit: int) -> list[str]:
    names: list[str] = []
    page = 1
    while len(names) < limit and page <= 2:
        document = api.get(
            f"/repos/{repository}/forks",
            params={"sort": "oldest", "per_page": 100, "page": page},
        )
        if not isinstance(document, list) or not document:
            break
        for item in document:
            if not isinstance(item, dict):
                continue
            full_name = item.get("full_name")
            if isinstance(full_name, str) and full_name.count("/") == 1:
                names.append(full_name)
                if len(names) >= limit:
                    break
        if len(document) < 100:
            break
        page += 1
    return names


def clone_and_search(
    repository: str,
    target: Target,
    output_root: Path,
) -> dict[str, Any]:
    destination = output_root / repository.replace("/", "__")
    record: dict[str, Any] = {
        "repository": repository,
        "status": "not-started",
        "resolved": [],
    }
    clone = run(
        [
            "git",
            "clone",
            "--mirror",
            "--filter=blob:none",
            f"https://github.com/{repository}.git",
            str(destination),
        ],
        timeout=240,
    )
    record.update(
        {
            "clone_exit_code": clone.returncode,
            "clone_stdout_tail": clone.stdout[-3000:],
            "clone_stderr_tail": clone.stderr[-3000:],
        }
    )
    if clone.returncode != 0:
        record["status"] = "clone-failed"
        shutil.rmtree(destination, ignore_errors=True)
        return record

    pull_fetch = run(
        [
            "git",
            f"--git-dir={destination}",
            "fetch",
            "--force",
            "origin",
            "+refs/pull/*/head:refs/pull/*/head",
            "+refs/pull/*/merge:refs/pull/*/merge",
        ],
        timeout=180,
    )
    refs = run(
        ["git", f"--git-dir={destination}", "for-each-ref", "--format=%(refname)\t%(objectname)"],
        timeout=60,
    )
    commits = run(
        ["git", f"--git-dir={destination}", "rev-list", "--all"],
        timeout=180,
    )
    record.update(
        {
            "pull_ref_fetch_exit_code": pull_fetch.returncode,
            "pull_ref_fetch_stderr_tail": pull_fetch.stderr[-3000:],
            "ref_count": len(refs.stdout.splitlines()) if refs.returncode == 0 else 0,
            "rev_list_exit_code": commits.returncode,
            "commit_count": len(commits.stdout.splitlines()) if commits.returncode == 0 else 0,
        }
    )
    if commits.returncode != 0:
        record["status"] = "rev-list-failed"
        shutil.rmtree(destination, ignore_errors=True)
        return record

    commit_shas = commits.stdout.splitlines()
    for change_id in target.change_ids:
        matches = [sha for sha in commit_shas if sha.startswith(change_id)]
        for sha in matches:
            tree = run(["git", f"--git-dir={destination}", "rev-parse", f"{sha}^{{tree}}"], timeout=30)
            message = run(
                ["git", f"--git-dir={destination}", "show", "-s", "--format=%B", sha],
                timeout=30,
            )
            changelog = run(
                ["git", f"--git-dir={destination}", "show", f"{sha}:debian/changelog"],
                timeout=60,
            )
            verification = verify_changelog(changelog.stdout if changelog.returncode == 0 else None, target)
            record["resolved"].append(
                {
                    "repository": repository,
                    "change_id": change_id,
                    "full_sha": sha,
                    "tree_sha": tree.stdout.strip() if tree.returncode == 0 else "",
                    "message": message.stdout.strip() if message.returncode == 0 else "",
                    "html_url": f"https://github.com/{repository}/commit/{sha}",
                    "discovery": "complete-advertised-and-pull-ref-clone",
                    **verification,
                }
            )
    record["status"] = "resolved" if record["resolved"] else "no-prefix-match"
    shutil.rmtree(destination, ignore_errors=True)
    return record


def deduplicate_resolutions(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (str(row.get("repository", "")), str(row.get("change_id", "")), str(row.get("full_sha", "")))
        if not all(key):
            continue
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(row)
            continue
        discoveries = set(str(existing.get("discovery", "")).split(";"))
        discoveries.add(str(row.get("discovery", "")))
        existing.update({k: v for k, v in row.items() if v not in {None, "", False}})
        existing["discovery"] = ";".join(sorted(value for value in discoveries if value))
    return sorted(merged.values(), key=lambda row: (row["change_id"], row["repository"], row["full_sha"]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--archaeology-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--github-token", default=os.environ.get("GH_TOKEN", ""))
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    api_evidence: list[dict[str, Any]] = []
    api = GitHubAPI(args.github_token, api_evidence)
    targets = load_targets(args.targets)
    target_results: list[dict[str, Any]] = []
    clone_evidence: list[dict[str, Any]] = []

    global_searches: dict[str, list[dict[str, Any]]] = {}
    for change_id in sorted({value for target in targets for value in target.change_ids}):
        global_searches[change_id] = global_commit_search(api, change_id)

    with tempfile.TemporaryDirectory(prefix="changelog-object-audit-") as temporary:
        clone_root = Path(temporary)
        for target in targets:
            candidates, archaeology_paths = archaeology_candidates(args.archaeology_root, target)
            candidates = sorted(candidates, key=lambda value: repository_score(value, target.source))

            metadata: dict[str, dict[str, Any]] = {}
            valid_candidates: list[str] = []
            for repository in candidates[:MAX_REPOSITORIES_PER_TARGET]:
                document = api.get(f"/repos/{repository}")
                if not isinstance(document, dict) or not document.get("full_name"):
                    continue
                full_name = str(document["full_name"])
                metadata[full_name] = compact_repository_metadata(document)
                valid_candidates.append(full_name)

            official_roots = [
                repository
                for repository in valid_candidates
                if repository.split("/", 1)[0].lower() in PREFERRED_OWNERS
                and repository.split("/", 1)[1].lower() == target.source.lower()
            ][:MAX_CLONES_PER_TARGET]

            fork_candidates: list[str] = []
            if target.source not in {"linux", "qtbase-opensource-src"}:
                for repository in official_roots:
                    remaining = MAX_FORKS_PER_TARGET - len(fork_candidates)
                    if remaining <= 0:
                        break
                    fork_candidates.extend(list_forks(api, repository, remaining))
            fork_candidates = list(dict.fromkeys(fork_candidates))[:MAX_FORKS_PER_TARGET]

            resolutions: list[dict[str, Any]] = []
            for change_id in target.change_ids:
                for row in global_searches.get(change_id, []):
                    verification = verify_changelog(
                        fetch_changelog(api, row["repository"], row["full_sha"]),
                        target,
                    )
                    resolutions.append({**row, **verification})

            direct_pairs = [
                (repository, change_id)
                for repository in valid_candidates
                for change_id in target.change_ids
            ]
            fork_pairs = [
                (repository, change_id)
                for repository in fork_candidates
                for change_id in target.change_ids
            ]

            def resolve_pair(pair: tuple[str, str]) -> dict[str, Any] | None:
                return resolve_commit_api(api, pair[0], pair[1])

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                for row in executor.map(resolve_pair, direct_pairs + fork_pairs):
                    if row is None:
                        continue
                    verification = verify_changelog(
                        fetch_changelog(api, row["repository"], row["full_sha"]),
                        target,
                    )
                    resolutions.append({**row, **verification})

            clone_roots = []
            for repository in official_roots:
                size = metadata.get(repository, {}).get("size_kb")
                if isinstance(size, int) and size > MAX_CLONE_REPOSITORY_KB:
                    clone_evidence.append(
                        {
                            "repository": repository,
                            "source": target.source,
                            "status": "skipped-size-limit",
                            "size_kb": size,
                            "limit_kb": MAX_CLONE_REPOSITORY_KB,
                        }
                    )
                    continue
                clone_roots.append(repository)

            for repository in clone_roots:
                record = clone_and_search(repository, target, clone_root)
                record["source"] = target.source
                record["source_version"] = target.version
                clone_evidence.append(record)
                resolutions.extend(record.get("resolved", []))

            resolutions = deduplicate_resolutions(resolutions)
            final_resolutions = [row for row in resolutions if row["change_id"] == target.final_change_id]
            exact_final = [row for row in final_resolutions if row.get("exact_changelog_head") is True]
            if exact_final:
                status = "exact-source-candidate-found"
            elif resolutions:
                status = "change-object-found-without-exact-changelog-head"
            else:
                status = "unresolved"

            target_results.append(
                {
                    "source": target.source,
                    "source_version": target.version,
                    "final_change_id": target.final_change_id,
                    "change_ids": list(target.change_ids),
                    "status": status,
                    "archaeology_evidence_paths": archaeology_paths,
                    "candidate_repository_count": len(valid_candidates),
                    "candidate_repositories": valid_candidates,
                    "fork_repository_count": len(fork_candidates),
                    "fork_repositories": fork_candidates,
                    "resolution_count": len(resolutions),
                    "resolved_change_ids": sorted({row["change_id"] for row in resolutions}),
                    "final_change_resolution_count": len(final_resolutions),
                    "exact_final_candidate_count": len(exact_final),
                    "resolutions": resolutions,
                    "source_lock_candidate": exact_final[0] if len(exact_final) == 1 else None,
                    "promotion_allowed": False,
                }
            )

    exact_candidates = [row for row in target_results if row["status"] == "exact-source-candidate-found"]
    object_only = [row for row in target_results if row["status"] == "change-object-found-without-exact-changelog-head"]
    unresolved = [row for row in target_results if row["status"] == "unresolved"]
    summary = {
        "schema": 1,
        "policy": "short-changelog-object-resolution-plus-exact-debian-changelog-head-required",
        "target_count": len(target_results),
        "change_id_count": len({value for target in targets for value in target.change_ids}),
        "exact_source_candidate_count": len(exact_candidates),
        "change_object_only_target_count": len(object_only),
        "unresolved_target_count": len(unresolved),
        "exact_source_candidates": [
            {
                "source": row["source"],
                "source_version": row["source_version"],
                "candidate": row["source_lock_candidate"],
            }
            for row in exact_candidates
        ],
        "unresolved_sources": [row["source"] for row in unresolved],
        "promotion_allowed": False,
    }

    write_json(args.output_dir / "summary.json", summary)
    write_json(args.output_dir / "target-results.json", target_results)
    write_json(args.output_dir / "global-commit-searches.json", global_searches)
    write_json(args.output_dir / "api-evidence.json", api_evidence)
    write_json(args.output_dir / "clone-evidence.json", clone_evidence)
    (args.output_dir / "targets.tsv").write_text(
        "source\tsource_version\tstatus\tresolved_change_ids\tresolution_count\texact_final_candidates\n"
        + "".join(
            "\t".join(
                [
                    row["source"],
                    row["source_version"],
                    row["status"],
                    ",".join(row["resolved_change_ids"]),
                    str(row["resolution_count"]),
                    str(row["exact_final_candidate_count"]),
                ]
            )
            + "\n"
            for row in target_results
        ),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
