#!/usr/bin/env python3
"""Patch source archaeology to support user-owned mirrors without rate storms."""

from __future__ import annotations

from pathlib import Path


TARGET = Path("arm64/scripts/targeted_source_archaeology.py")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    text = TARGET.read_text(encoding="utf-8")
    if '"account_kind": account_kind' in text and "--enable-code-search" in text:
        print(f"already patched: {TARGET}")
        return 0

    old_paginate = '''def paginate_repositories(owner: str, token: str | None) -> tuple[list[str], list[dict[str, Any]]]:
    repositories: list[str] = []
    requests: list[dict[str, Any]] = []
    page = 1
    while page <= 10:
        value, evidence = api(
            f"orgs/{owner}/repos?type=all&per_page=100&page={page}", token
        )
        requests.append(evidence)
        if not isinstance(value, list):
            break
        repositories.extend(
            item["full_name"]
            for item in value
            if isinstance(item, dict) and item.get("full_name")
        )
        if len(value) < 100:
            break
        page += 1
    return repositories, requests
'''
    new_paginate = '''def paginate_repositories(owner: str, token: str | None) -> tuple[list[str], list[dict[str, Any]]]:
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
'''
    text = replace_once(text, old_paginate, new_paginate, "repository pagination")

    old_parser = '''    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--maximum-repositories", type=int, default=30)
    args = parser.parse_args()
'''
    new_parser = '''    parser.add_argument("--output-dir", type=Path, required=True)
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
'''
    text = replace_once(text, old_parser, new_parser, "argument parser")

    old_search = '''    code_queries = [
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

    for query in (
        f"{args.source} in:name",
        f"{args.source.replace('-opensource-src', '')} in:name",
    ):
        values, evidence = search_repositories(query, token)
        repositories.update(values)
        api_evidence.append(evidence)
'''
    new_search = '''    if args.enable_code_search:
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
'''
    text = replace_once(text, old_search, new_search, "search policy")

    TARGET.write_text(text, encoding="utf-8")
    print(f"patched: {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
