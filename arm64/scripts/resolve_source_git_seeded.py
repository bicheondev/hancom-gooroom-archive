#!/usr/bin/env python3
"""Resolve only gaps in a previously verified exact source lock.

The baseline lock already contains exact changelog matches for most of the
Hancom Gooroom 3.3 source set. Re-scanning every repository is wasteful and can
hide useful evidence behind timeouts. This front-end:

1. preserves every baseline row that is already resolved;
2. repairs stale-changelog tag ambiguity only when one tag's *name* itself
   identifies the exact ISO source version;
3. probes only the remaining unresolved rows;
4. still emits a complete 74-source lock and fails closed for every unresolved
   ARM64 rebuild source.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import resolve_source_git as resolver
import resolve_source_git_public  # noqa: F401 - force anonymous public Git


def key(row: dict[str, Any]) -> tuple[str, str]:
    return row["source"], row["source_version"]


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def exact_version_tag(ref_name: str, version: str) -> bool:
    """Accept only a tag whose complete final path component is the version."""

    return ref_name == version or ref_name.endswith("/" + version)


def canonicalize_seed_row(
    target: dict[str, Any], seed: dict[str, Any]
) -> dict[str, Any]:
    row = dict(seed)
    row.update(
        source=target["source"],
        source_version=target["source_version"],
        binary_packages=target["binary_packages"],
        binary_architectures=target["binary_architectures"],
        role=target["role"],
    )
    selected = row.get("selected")
    if selected:
        selected = dict(selected)
        selected.setdefault("type", "git")
        row["selected"] = selected
    return row


def repair_exact_tag_ambiguity(
    target: dict[str, Any], seed: dict[str, Any]
) -> dict[str, Any] | None:
    """Resolve a stale changelog only through an exact version-named tag.

    Several repositories created a later release tag without bumping the first
    changelog entry. Those later trees must not compete with the historical tag
    whose own name exactly equals the AMD64 source version.
    """

    if seed.get("status") != "ambiguous-exact-version":
        return None
    candidates = [
        dict(match)
        for match in seed.get("exact_matches", [])
        if match.get("ref_kind") == "tag"
        and exact_version_tag(match.get("ref_name", ""), target["source_version"])
        and match.get("declared_source") == target["source"]
        and match.get("declared_version") == target["source_version"]
    ]
    if not candidates:
        return None

    owner_rank = {
        owner: index for index, owner in enumerate(resolver.owner_order(target))
    }
    best_owner = min(owner_rank.get(candidate.get("owner", ""), 99) for candidate in candidates)
    authoritative = [
        candidate
        for candidate in candidates
        if owner_rank.get(candidate.get("owner", ""), 99) == best_owner
    ]
    trees = {candidate.get("tree_sha") for candidate in authoritative}
    if None in trees or len(trees) != 1:
        return None

    authoritative.sort(
        key=lambda candidate: (
            candidate.get("committer_date") or "",
            candidate.get("commit_sha") or "",
        ),
        reverse=True,
    )
    selected = authoritative[0]
    selected.setdefault("type", "git")
    selected.setdefault(
        "source_archive",
        f"https://github.com/{selected['repository_full_name']}/archive/"
        f"{selected['commit_sha']}.tar.gz",
    )
    row = canonicalize_seed_row(target, seed)
    row.update(
        status="resolved",
        reason="exact ISO source version is named by the selected Git tag; later stale-changelog tags are excluded",
        selected=selected,
        exact_matches=candidates,
        resolution_policy="exact-version-tag-name",
    )
    return row


def install_exact_tag_first_probe() -> None:
    original = resolver.RepositoryProbe.find_exact

    def exact_tag_first(
        self: resolver.RepositoryProbe,
        target: dict[str, Any],
        max_depth: int,
    ) -> list[dict[str, Any]]:
        _, tags = self.refs()
        records: list[dict[str, Any]] = []
        for tag, sha in sorted(tags.items()):
            if not exact_version_tag(tag, target["source_version"]):
                continue
            changelog = self.raw_changelog(sha)
            if resolver.parse_head(changelog) != (
                target["source"],
                target["source_version"],
            ):
                continue
            record = self.commit_record(
                sha,
                ref_kind="tag",
                ref_name=tag,
                match_scope="exact-version-tag-tip",
                target=target,
            )
            if record:
                record.setdefault("type", "git")
                records.append(record)
        if records:
            return records
        return original(self, target, max_depth)

    resolver.RepositoryProbe.find_exact = exact_tag_first


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--seed-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--max-depth", type=int, default=800)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    targets = resolver.target_rows(args.reference)
    seed_document = json.loads(args.seed_lock.read_text(encoding="utf-8"))
    seed_rows = {key(row): row for row in seed_document.get("sources", [])}
    rows: list[dict[str, Any] | None] = [None] * len(targets)
    pending: list[tuple[int, dict[str, Any]]] = []

    for index, target in enumerate(targets):
        seed = seed_rows.get(key(target))
        if target["source"] in resolver.ARCH_SOURCE_EXCEPTIONS:
            exception = resolver.ARCH_SOURCE_EXCEPTIONS[target["source"]]
            rows[index] = {
                **target,
                "status": exception["status"],
                "reason": exception["reason"],
                "repositories_found": [],
                "exact_matches": [],
                "selected": None,
            }
            continue
        if seed and seed.get("status") == "resolved" and seed.get("selected"):
            selected = seed["selected"]
            if (
                selected.get("declared_source") == target["source"]
                and selected.get("declared_version") == target["source_version"]
            ):
                rows[index] = canonicalize_seed_row(target, seed)
                continue
        if seed:
            repaired = repair_exact_tag_ambiguity(target, seed)
            if repaired is not None:
                rows[index] = repaired
                continue
        pending.append((index, target))

    print(
        f"seed preserved/repaired {len(targets) - len(pending)} of {len(targets)}; "
        f"deep probing {len(pending)}",
        file=sys.stderr,
        flush=True,
    )

    token = os.getenv("GITHUB_TOKEN")
    github = resolver.GitHub(token)
    indexes: dict[str, dict[str, dict[str, Any]]] = {}
    if pending:
        for owner in resolver.OWNERS:
            repositories = github.repositories(owner)
            indexes[owner] = {
                repository["name"].lower(): repository for repository in repositories
            }
            print(
                f"indexed {owner}: {len(repositories)} repositories",
                file=sys.stderr,
            )

    install_exact_tag_first_probe()
    args.work_dir.mkdir(parents=True, exist_ok=True)

    def resolve_one(item: tuple[int, dict[str, Any]]) -> tuple[int, dict[str, Any]]:
        index, target = item
        work_dir = args.work_dir / (
            f"{index:03d}-{safe_component(target['source'])}-"
            f"{safe_component(target['source_version'])}"
        )
        print(
            f"[{index + 1}/{len(targets)}] probe {target['source']} "
            f"{target['source_version']}",
            file=sys.stderr,
            flush=True,
        )
        row = resolver.resolve_target(
            target,
            indexes,
            work_dir,
            token,
            args.max_depth,
        )
        selected = row.get("selected")
        if selected:
            selected = dict(selected)
            selected.setdefault("type", "git")
            row["selected"] = selected
        return index, row

    workers = max(1, min(args.workers, len(pending) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(resolve_one, item): item for item in pending}
        for future in concurrent.futures.as_completed(futures):
            index, target = futures[future]
            try:
                resolved_index, row = future.result()
            except Exception as error:
                resolved_index = index
                row = {
                    **target,
                    "status": "resolver-exception",
                    "reason": repr(error),
                    "repositories_found": [],
                    "exact_matches": [],
                    "selected": None,
                }
            rows[resolved_index] = row
            selected = row.get("selected") or {}
            suffix = ""
            if selected:
                suffix = (
                    f" {selected.get('repository_full_name', '')}@"
                    f"{selected.get('commit_sha', '')[:12]}"
                )
            print(
                f"[{resolved_index + 1}/{len(targets)}] {row['status']} "
                f"{target['source']}{suffix}",
                file=sys.stderr,
                flush=True,
            )

    complete_rows = [row for row in rows if row is not None]
    if len(complete_rows) != len(targets):
        raise RuntimeError("seeded resolver lost one or more target results")

    summary = resolver.write_outputs(
        args.output_dir,
        complete_rows,
        github.request_count,
    )
    summary["seed_source"] = str(args.seed_lock)
    summary["deep_probe_count"] = len(pending)
    (args.output_dir / "source-lock-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    document = json.loads((args.output_dir / "source-lock.json").read_text(encoding="utf-8"))
    document["summary"] = summary
    (args.output_dir / "source-lock.json").write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 2 if summary["rebuild_unresolved_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
