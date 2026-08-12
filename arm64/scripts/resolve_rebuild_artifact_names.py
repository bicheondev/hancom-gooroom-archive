#!/usr/bin/env python3
"""Resolve stale rebuilt-package artifact names against immutable Actions runs.

The rebuild index records an Actions run and artifact name for every verified
DEB. Historical import jobs occasionally retained a short display name instead
of the uploaded artifact's full name. This resolver never guesses an arbitrary
artifact: it accepts the declared exact name, then a unique source-qualified
suffix match, or finally one unique non-expired artifact containing the locked
source name.
The downstream repository materializer still verifies every DEB by package,
version, architecture, size, and SHA-256.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable


def load_rows(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise SystemExit("rebuild package index must be a JSON array")
    rows = [row for row in value if isinstance(row, dict)]
    if len(rows) != len(value):
        raise SystemExit("rebuild package index contains a non-object row")
    return rows


def artifact_pages(repository: str, run_id: str) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    page = 1
    while True:
        endpoint = (
            f"repos/{repository}/actions/runs/{run_id}/artifacts"
            f"?per_page=100&page={page}"
        )
        process = subprocess.run(
            ["gh", "api", endpoint],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode:
            raise RuntimeError(
                f"unable to list artifacts for run {run_id}: {process.stderr.strip()}"
            )
        value = json.loads(process.stdout)
        if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
            raise RuntimeError(f"malformed artifact listing for run {run_id}")
        rows = [row for row in value["artifacts"] if isinstance(row, dict)]
        artifacts.extend(rows)
        if len(rows) < 100:
            total = value.get("total_count")
            if isinstance(total, int) and total > len(artifacts):
                raise RuntimeError(
                    f"incomplete artifact listing for run {run_id}: "
                    f"{len(artifacts)} of {total}"
                )
            break
        page += 1
        if page > 100:
            raise RuntimeError(f"artifact pagination limit exceeded for run {run_id}")
    return artifacts


def source_prefixes(rows: list[dict[str, Any]]) -> set[str]:
    prefixes: set[str] = set()
    for row in rows:
        source = str(row.get("source") or "").strip()
        if source:
            prefixes.add(source.replace("+", "-").replace("_", "-"))
            prefixes.add(source)
    return prefixes


def resolve_artifact(
    declared: str,
    rows: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    available = [
        row
        for row in artifacts
        if row.get("expired") is not True
        and isinstance(row.get("name"), str)
        and row.get("name")
        and row.get("id") not in (None, "")
    ]
    exact = [row for row in available if row["name"] == declared]
    if len(exact) == 1:
        return exact[0], "exact"
    if len(exact) > 1:
        raise RuntimeError(f"duplicate exact artifact name: {declared}")

    prefixes = source_prefixes(rows)
    suffix = "-" + declared
    candidates = [
        row
        for row in available
        if row["name"].endswith(suffix)
        and any(
            row["name"] == prefix + suffix
            or row["name"].startswith(prefix + "-")
            for prefix in prefixes
        )
    ]
    if len(candidates) == 1:
        return candidates[0], "unique-source-suffix"
    if len(candidates) > 1:
        names = sorted(str(row["name"]) for row in candidates)
        raise RuntimeError(
            f"artifact name {declared!r} has {len(candidates)} "
            f"source-qualified suffix matches: {names}"
        )

    source_candidates = [
        row
        for row in available
        if any(prefix in row["name"] for prefix in prefixes)
    ]
    if len(source_candidates) != 1:
        names = sorted(str(row["name"]) for row in source_candidates)
        raise RuntimeError(
            f"artifact name {declared!r} has {len(source_candidates)} "
            f"source-qualified matches: {names}"
        )
    return source_candidates[0], "unique-source-qualified"


def resolve_rows(
    rows: list[dict[str, Any]],
    repository: str,
    list_artifacts: Callable[[str, str], list[dict[str, Any]]] = artifact_pages,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    groups: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for index, row in enumerate(rows):
        run_id = str(row.get("actions_run_id") or "").strip()
        artifact_name = str(row.get("artifact_name") or "").strip()
        if not run_id or not artifact_name:
            raise RuntimeError(f"row {index} lacks actions_run_id or artifact_name")
        groups[(run_id, artifact_name)].append((index, row))

    output = [dict(row) for row in rows]
    evidence: list[dict[str, Any]] = []
    listings: dict[str, list[dict[str, Any]]] = {}
    for (run_id, declared), members in sorted(groups.items()):
        artifacts = listings.setdefault(run_id, list_artifacts(repository, run_id))
        group_rows = [row for _, row in members]
        artifact, method = resolve_artifact(declared, group_rows, artifacts)
        resolved = str(artifact["name"])
        artifact_id = str(artifact["id"])
        for index, _ in members:
            output[index]["declared_artifact_name"] = declared
            output[index]["artifact_name"] = resolved
            output[index]["resolved_artifact_id"] = artifact_id
            output[index]["artifact_name_resolution"] = method
        evidence.append(
            {
                "actions_run_id": run_id,
                "declared_artifact_name": declared,
                "resolved_artifact_name": resolved,
                "resolved_artifact_id": artifact_id,
                "resolution": method,
                "package_count": len(members),
                "packages": sorted(str(row.get("package") or "") for row in group_rows),
            }
        )
    return output, evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--github-repository", required=True)
    args = parser.parse_args()

    resolved, evidence = resolve_rows(load_rows(args.input), args.github_repository)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(resolved, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.evidence.write_text(
        json.dumps(
            {
                "schema": 1,
                "policy": "exact-or-unique-source-qualified-artifact-resolution",
                "group_count": len(evidence),
                "rewritten_group_count": sum(
                    row["resolution"] != "exact" for row in evidence
                ),
                "groups": evidence,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
