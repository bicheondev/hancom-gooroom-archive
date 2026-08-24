#!/usr/bin/env python3
"""Recover exact source commits preserved in forks of official repositories.

Only repositories returned by GitHub's forks endpoint for an official
`hancomgooroom`, `hancom-io`, or `gooroom` repository are eligible. A fork is
not trusted by name: the candidate commit must be reachable from one of its
refs, contain `debian/changelog`, and declare the exact AMD64 reference Source
and Version. Conflicting exact trees fail closed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


OWNERS = ("hancomgooroom", "hancom-io", "gooroom")
CHANGELOG_RE = re.compile(r"^([^\s(]+)\s+\(([^)]+)\)\s+")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def sha_component(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:20]


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if check and process.returncode != 0:
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(command)}\n"
            f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        )
    return process


class GitHub:
    def __init__(self, token: str | None) -> None:
        self.token = token
        self.request_count = 0

    def get(self, url: str) -> tuple[Any, dict[str, str]]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "hancom-gooroom-arm64-fork-source-recovery/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        error: Exception | None = None
        for attempt in range(1, 6):
            try:
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=90) as response:
                    self.request_count += 1
                    payload = json.loads(response.read().decode("utf-8"))
                    response_headers = {key.lower(): value for key, value in response.headers.items()}
                    return payload, response_headers
            except urllib.error.HTTPError as exception:
                self.request_count += 1
                if exception.code == 404:
                    return None, {}
                error = exception
                if exception.code not in {403, 429, 500, 502, 503, 504}:
                    break
            except Exception as exception:
                error = exception
            if attempt < 5:
                time.sleep(2 ** (attempt - 1))
        assert error is not None
        raise error

    def paged(self, url: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        page = 1
        while True:
            separator = "&" if "?" in url else "?"
            payload, _ = self.get(f"{url}{separator}per_page=100&page={page}")
            if not isinstance(payload, list) or not payload:
                break
            rows.extend(row for row in payload if isinstance(row, dict))
            if limit is not None and len(rows) >= limit:
                return rows[:limit]
            if len(payload) < 100:
                break
            page += 1
        return rows

    def organization_repositories(self, owner: str) -> list[dict[str, Any]]:
        return self.paged(f"https://api.github.com/orgs/{owner}/repos?type=all")

    def forks(self, repository_full_name: str, limit: int) -> list[dict[str, Any]]:
        quoted = urllib.parse.quote(repository_full_name, safe="/")
        return self.paged(
            f"https://api.github.com/repos/{quoted}/forks?sort=oldest",
            limit=limit,
        )


def target_rows(reference: dict[str, Any]) -> list[dict[str, Any]]:
    packages: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for package in reference.get("packages", []):
        packages[(package["source"], package["source_version"])].append(package)
    rows = []
    for source in reference.get("sources", []):
        if not source.get("custom_candidate"):
            continue
        key = (source["source"], source["source_version"])
        members = packages.get(key, [])
        architectures = sorted({row.get("architecture", "") for row in members})
        rows.append(
            {
                "source": key[0],
                "source_version": key[1],
                "role": "reuse-all" if architectures == ["all"] else "rebuild-arm64",
                "binary_packages": sorted({row["package"] for row in members}),
                "binary_architectures": architectures,
            }
        )
    return sorted(rows, key=lambda row: (row["source"], row["source_version"]))


def evidence_repositories(document: dict[str, Any]) -> dict[tuple[str, str], set[str]]:
    result: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in document.get("sources", []):
        source = row.get("source")
        version = row.get("source_version")
        if not source or not version:
            continue
        key = (source, version)
        selected = row.get("selected")
        if isinstance(selected, dict) and selected.get("repository_full_name"):
            result[key].add(selected["repository_full_name"])
        for field in ("repositories_found", "candidate_repositories", "repositories"):
            values = row.get(field)
            if not isinstance(values, list):
                continue
            for value in values:
                if isinstance(value, str) and "/" in value:
                    result[key].add(value)
                elif isinstance(value, dict):
                    name = value.get("full_name") or value.get("repository_full_name")
                    if isinstance(name, str) and "/" in name:
                        result[key].add(name)
        for value in row.get("exact_matches", []) if isinstance(row.get("exact_matches"), list) else []:
            if isinstance(value, dict):
                name = value.get("repository_full_name")
                if isinstance(name, str):
                    result[key].add(name)
    return result


def resolved_keys(documents: Iterable[dict[str, Any]]) -> set[tuple[str, str]]:
    result = set()
    for document in documents:
        for row in document.get("sources", []):
            selected = row.get("selected")
            if row.get("status") != "resolved" or not isinstance(selected, dict):
                continue
            source = row.get("source")
            version = row.get("source_version")
            if (
                source
                and version
                and selected.get("declared_source") == source
                and selected.get("declared_version") == version
                and selected.get("commit_sha")
                and selected.get("tree_sha")
            ):
                result.add((source, version))
    return result


def candidate_official_repositories(
    target: dict[str, Any],
    repositories: list[dict[str, Any]],
    evidence: set[str],
    maximum: int,
) -> list[str]:
    allowed = {
        row["full_name"]: row
        for row in repositories
        if isinstance(row.get("full_name"), str)
        and row.get("owner", {}).get("login", "").lower() in OWNERS
    }
    selected = {name for name in evidence if name in allowed}
    source = target["source"]
    source_norm = normalize(source)
    package_norms = {normalize(value) for value in target.get("binary_packages", [])}
    scored = []
    for full_name, row in allowed.items():
        name = row.get("name", "")
        name_norm = normalize(name)
        score = 99
        if name.lower() == source.lower():
            score = 0
        elif name_norm == source_norm:
            score = 1
        elif source_norm and (name_norm.endswith(source_norm) or source_norm.endswith(name_norm)):
            score = 2
        elif name_norm in package_norms or any(
            value and (name_norm.endswith(value) or value.endswith(name_norm))
            for value in package_norms
        ):
            score = 3
        elif source_norm and source_norm in name_norm:
            score = 4
        if score < 99:
            scored.append((score, full_name))
    for _, full_name in sorted(scored):
        selected.add(full_name)
        if len(selected) >= maximum:
            break
    return sorted(selected)[:maximum]


def clone_and_index(
    fork: dict[str, Any],
    work_dir: Path,
    target_keys: set[tuple[str, str]],
    max_history: int,
) -> dict[str, Any]:
    full_name = fork["full_name"]
    clone_url = fork.get("clone_url") or f"https://github.com/{full_name}.git"
    repository_dir = work_dir / sha_component(full_name)
    result: dict[str, Any] = {
        "fork_repository_full_name": full_name,
        "clone_url": clone_url,
        "default_branch": fork.get("default_branch"),
        "matches": [],
        "status": "clone-failed",
    }
    try:
        if repository_dir.exists():
            shutil.rmtree(repository_dir)
        run(
            [
                "git",
                "clone",
                "--mirror",
                "--filter=blob:none",
                "--no-single-branch",
                clone_url,
                str(repository_dir),
            ],
            timeout=1200,
        )
        revisions = run(
            ["git", "rev-list", "--all", "--", "debian/changelog"],
            cwd=repository_dir,
            timeout=600,
        ).stdout.splitlines()
        if max_history > 0:
            revisions = revisions[:max_history]
        seen: set[tuple[str, str, str]] = set()
        for commit in revisions:
            process = run(
                ["git", "show", f"{commit}:debian/changelog"],
                cwd=repository_dir,
                check=False,
                timeout=60,
            )
            if process.returncode != 0:
                continue
            first_line = process.stdout.splitlines()[0] if process.stdout.splitlines() else ""
            match = CHANGELOG_RE.match(first_line)
            if not match:
                continue
            source, version = match.groups()
            if (source, version) not in target_keys:
                continue
            tree = run(
                ["git", "rev-parse", f"{commit}^{{tree}}"],
                cwd=repository_dir,
                timeout=60,
            ).stdout.strip()
            identity = (source, version, tree)
            if identity in seen:
                continue
            seen.add(identity)
            result["matches"].append(
                {
                    "source": source,
                    "source_version": version,
                    "repository_full_name": full_name,
                    "commit_sha": commit,
                    "tree_sha": tree,
                    "declared_source": source,
                    "declared_version": version,
                    "ref_kind": "official-fork-history",
                    "ref_name": full_name,
                    "match_scope": "reachable-fork-ref-history",
                    "source_archive": f"https://codeload.github.com/{full_name}/tar.gz/{commit}",
                }
            )
        result["status"] = "scanned"
        result["history_commit_count"] = len(revisions)
    except Exception as exception:
        result["error"] = f"{type(exception).__name__}: {exception}"
    finally:
        shutil.rmtree(repository_dir, ignore_errors=True)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--existing-lock", type=Path, action="append", default=[])
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--forks-per-repository", type=int, default=100)
    parser.add_argument("--repositories-per-target", type=int, default=6)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--max-history", type=int, default=0)
    args = parser.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    github = GitHub(token)
    reference = load_json(args.reference)
    existing_documents = [load_json(path) for path in args.existing_lock if path.exists()]
    already_resolved = resolved_keys(existing_documents)
    evidence: dict[tuple[str, str], set[str]] = defaultdict(set)
    for document in existing_documents:
        for key, values in evidence_repositories(document).items():
            evidence[key].update(values)

    targets = [
        row
        for row in target_rows(reference)
        if (row["source"], row["source_version"]) not in already_resolved
        and row["source"] != "linux-signed-amd64"
    ]
    official_repositories = []
    for owner in OWNERS:
        official_repositories.extend(github.organization_repositories(owner))

    target_networks: dict[tuple[str, str], list[str]] = {}
    official_to_targets: dict[str, set[tuple[str, str]]] = defaultdict(set)
    target_by_key = {(row["source"], row["source_version"]): row for row in targets}
    for target in targets:
        key = (target["source"], target["source_version"])
        repositories = candidate_official_repositories(
            target,
            official_repositories,
            evidence.get(key, set()),
            max(1, args.repositories_per_target),
        )
        target_networks[key] = repositories
        for repository in repositories:
            official_to_targets[repository].add(key)

    fork_to_targets: dict[str, set[tuple[str, str]]] = defaultdict(set)
    fork_records: dict[str, dict[str, Any]] = {}
    fork_networks: dict[str, set[str]] = defaultdict(set)
    fork_query_errors = []
    for official, keys in sorted(official_to_targets.items()):
        try:
            forks = github.forks(official, max(0, args.forks_per_repository))
        except Exception as exception:
            fork_query_errors.append(
                {
                    "official_repository_full_name": official,
                    "error": f"{type(exception).__name__}: {exception}",
                }
            )
            continue
        for fork in forks:
            full_name = fork.get("full_name")
            if not isinstance(full_name, str):
                continue
            fork_records[full_name] = fork
            fork_to_targets[full_name].update(keys)
            fork_networks[full_name].add(official)

    args.work_dir.mkdir(parents=True, exist_ok=True)
    scans: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, args.workers)
    ) as executor:
        future_map = {
            executor.submit(
                clone_and_index,
                fork_records[full_name],
                args.work_dir,
                keys,
                args.max_history,
            ): full_name
            for full_name, keys in fork_to_targets.items()
        }
        for future in concurrent.futures.as_completed(future_map):
            full_name = future_map[future]
            try:
                scan = future.result()
            except Exception as exception:
                scan = {
                    "fork_repository_full_name": full_name,
                    "status": "worker-exception",
                    "error": f"{type(exception).__name__}: {exception}",
                    "matches": [],
                }
            scan["official_repository_networks"] = sorted(fork_networks[full_name])
            scans.append(scan)
            print(
                f"{scan['status']}: {full_name} matches={len(scan.get('matches', []))}",
                file=sys.stderr,
                flush=True,
            )

    matches_by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for scan in scans:
        for match in scan.get("matches", []):
            key = (match["source"], match["source_version"])
            if key not in target_by_key:
                continue
            matches_by_key[key].append(
                {
                    **match,
                    "official_repository_networks": scan[
                        "official_repository_networks"
                    ],
                }
            )

    rows = []
    for target in targets:
        key = (target["source"], target["source_version"])
        matches = matches_by_key.get(key, [])
        trees = {row["tree_sha"] for row in matches}
        status = "missing-exact-fork-history"
        selected = None
        if len(trees) == 1 and matches:
            matches.sort(
                key=lambda row: (
                    row["repository_full_name"],
                    row["commit_sha"],
                )
            )
            selected = matches[0]
            status = "resolved"
        elif len(trees) > 1:
            status = "ambiguous-exact-fork-trees"
        rows.append(
            {
                **target,
                "status": status,
                "candidate_official_repositories": target_networks.get(key, []),
                "exact_matches": matches,
                "selected": selected,
            }
        )

    unresolved = [row for row in rows if row["status"] != "resolved"]
    rebuild_unresolved = [
        row for row in unresolved if row["role"] == "rebuild-arm64"
    ]
    summary = {
        "schema": 1,
        "policy": "exact-changelog-identity-in-github-official-fork-network",
        "target_count": len(rows),
        "resolved_count": sum(row["status"] == "resolved" for row in rows),
        "unresolved_count": len(unresolved),
        "rebuild_unresolved_count": len(rebuild_unresolved),
        "official_repository_count": len(official_repositories),
        "official_network_count": len(official_to_targets),
        "fork_repository_count": len(fork_records),
        "fork_repository_scanned_count": sum(
            scan.get("status") == "scanned" for scan in scans
        ),
        "fork_scan_error_count": sum(
            scan.get("status") != "scanned" for scan in scans
        ),
        "fork_query_error_count": len(fork_query_errors),
        "github_api_request_count": github.request_count,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "source-lock.json").write_text(
        json.dumps({"summary": summary, "sources": rows}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "source-lock-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "unresolved-sources.json").write_text(
        json.dumps(unresolved, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "rebuild-blockers.json").write_text(
        json.dumps(rebuild_unresolved, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "fork-scans.json").write_text(
        json.dumps(scans, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "fork-query-errors.json").write_text(
        json.dumps(fork_query_errors, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    with (args.output_dir / "source-lock.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        fields = [
            "source",
            "source_version",
            "role",
            "status",
            "official_repository_networks",
            "repository_full_name",
            "commit_sha",
            "tree_sha",
        ]
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
                    "official_repository_networks": ",".join(
                        selected.get("official_repository_networks", [])
                    ),
                    "repository_full_name": selected.get(
                        "repository_full_name", ""
                    ),
                    "commit_sha": selected.get("commit_sha", ""),
                    "tree_sha": selected.get("tree_sha", ""),
                }
            )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not rebuild_unresolved else 2


if __name__ == "__main__":
    raise SystemExit(main())
