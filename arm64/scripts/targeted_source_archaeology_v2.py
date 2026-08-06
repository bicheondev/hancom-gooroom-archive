#!/usr/bin/env python3
"""Prioritized exact-source archaeology built on the v1 Git verifier."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

import targeted_source_archaeology as v1


def deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def sanitize(value: Any, secret: str | None) -> Any:
    if isinstance(value, str):
        return value.replace(secret, "***") if secret else value
    if isinstance(value, list):
        return [sanitize(item, secret) for item in value]
    if isinstance(value, dict):
        return {key: sanitize(item, secret) for key, item in value.items()}
    return value


def related_name(full_name: str, source: str) -> bool:
    name = full_name.split("/", 1)[-1].lower()
    normalized = re.sub(r"[^a-z0-9]", "", name)
    terms = {
        re.sub(r"[^a-z0-9]", "", source.lower()),
        re.sub(
            r"[^a-z0-9]", "", source.lower().replace("-opensource-src", "")
        ),
    }
    if any(term and term in normalized for term in terms):
        return True
    source_prefix = source.lower().split("-", 1)[0]
    return len(source_prefix) >= 3 and source_prefix in name


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--owner", action="append", default=["hancomgooroom", "hancom-io", "gooroom"]
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--maximum-repositories", type=int, default=40)
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    api_evidence: list[dict[str, Any]] = []
    organization_repositories: list[str] = []
    for owner in args.owner:
        values, evidence = v1.paginate_repositories(owner, token)
        organization_repositories.extend(values)
        api_evidence.extend(evidence)

    code_repositories: list[str] = []
    for query in [
        *(f'"{args.version}" org:{owner}' for owner in args.owner),
        f'"{args.version}" "{args.source}"',
        f'"{args.version}" path:debian/changelog',
    ]:
        values, evidence = v1.search_code(query, token)
        code_repositories.extend(values)
        api_evidence.append(evidence)
        time.sleep(1.2)

    named_repositories: list[str] = []
    for query in (
        f"{args.source} in:name",
        f"{args.source.replace('-opensource-src', '')} in:name",
    ):
        values, evidence = v1.search_repositories(query, token)
        named_repositories.extend(values)
        api_evidence.append(evidence)

    related_organization_repositories = sorted(
        {
            full_name
            for full_name in organization_repositories
            if related_name(full_name, args.source)
        },
        key=lambda value: v1.repository_score(value, args.source),
    )
    candidates = deduplicate(
        [
            *code_repositories,
            *named_repositories,
            *related_organization_repositories,
        ]
    )[: args.maximum_repositories]

    work_root = Path(tempfile.mkdtemp(prefix="source-archaeology-v2-"))
    all_matches: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    try:
        for full_name in candidates:
            matches, attempt = v1.inspect_repository(
                full_name,
                args.source,
                args.version,
                work_root,
                token,
            )
            all_matches.extend(sanitize(matches, token))
            attempts.append(sanitize(attempt, token))
    finally:
        shutil.rmtree(work_root, ignore_errors=True)

    trees = {match.get("tree_sha") for match in all_matches if match.get("tree_sha")}
    selected = None
    status = "unresolved"
    reason = "no exact changelog commit was found in prioritized candidates"
    if all_matches and len(trees) == 1:
        all_matches.sort(
            key=lambda match: (
                v1.repository_score(match["repository_full_name"], args.source),
                match.get("committer_date") or "",
                match.get("commit_sha") or "",
            )
        )
        selected = all_matches[0]
        status = "resolved"
        reason = "all exact matches identify one immutable Git tree"
    elif all_matches:
        status = "ambiguous"
        reason = "exact changelog matches identify multiple Git trees"

    result = {
        "schema": "hancom-gooroom-targeted-source-archaeology-v2",
        "generated_at": v1.now(),
        "status": status,
        "reason": reason,
        "source": args.source,
        "version": args.version,
        "owners": args.owner,
        "candidate_policy": [
            "exact-version code-search repositories",
            "source-name repository-search results",
            "source-related repositories in requested organizations",
        ],
        "repository_candidate_count": len(candidates),
        "repository_candidates": candidates,
        "exact_match_count": len(all_matches),
        "exact_tree_count": len(trees),
        "selected": selected,
        "exact_matches": all_matches,
        "repository_attempts": attempts,
        "api_evidence": sanitize(api_evidence, token),
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
