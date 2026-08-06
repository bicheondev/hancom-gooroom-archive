#!/usr/bin/env python3
"""Parallel front-end for the fail-closed exact Git source resolver."""

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
import resolve_source_git_public  # noqa: F401 - applies anonymous Git transport patch


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--max-depth", type=int, default=2000)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    github = resolver.GitHub(token)
    indexes: dict[str, dict[str, dict[str, Any]]] = {}
    for owner in resolver.OWNERS:
        repositories = github.repositories(owner)
        indexes[owner] = {
            repository["name"].lower(): repository for repository in repositories
        }
        print(f"indexed {owner}: {len(repositories)} repositories", file=sys.stderr)

    targets = resolver.target_rows(args.reference)
    args.work_dir.mkdir(parents=True, exist_ok=True)

    def resolve_one(item: tuple[int, dict[str, Any]]) -> tuple[int, dict[str, Any]]:
        index, target = item
        work_dir = args.work_dir / (
            f"{index:03d}-{safe_component(target['source'])}-"
            f"{safe_component(target['source_version'])}"
        )
        print(
            f"[{index + 1}/{len(targets)}] start {target['source']} "
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
        selected = row.get("selected") or {}
        suffix = ""
        if selected:
            suffix = (
                f" {selected.get('repository_full_name', '')}@"
                f"{selected.get('commit_sha', '')[:12]}"
            )
        print(
            f"[{index + 1}/{len(targets)}] {row['status']} "
            f"{target['source']}{suffix}",
            file=sys.stderr,
            flush=True,
        )
        return index, row

    rows: list[dict[str, Any] | None] = [None] * len(targets)
    workers = max(1, min(args.workers, len(targets)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(resolve_one, item): item[0]
            for item in enumerate(targets)
        }
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            try:
                resolved_index, row = future.result()
            except Exception as error:
                target = targets[index]
                row = {
                    **target,
                    "status": "resolver-exception",
                    "reason": repr(error),
                    "repositories_found": [],
                    "exact_matches": [],
                    "selected": None,
                }
                resolved_index = index
            rows[resolved_index] = row

    complete_rows = [row for row in rows if row is not None]
    if len(complete_rows) != len(targets):
        raise RuntimeError("parallel resolver lost one or more target results")

    summary = resolver.write_outputs(
        args.output_dir,
        complete_rows,
        github.request_count,
    )
    print(json.dumps(summary, indent=2))
    return 2 if summary["rebuild_unresolved_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
