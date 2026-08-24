#!/usr/bin/env python3
"""Merge exact Git and exact signed vendor-APT source authorities.

Git is the preferred provenance. A signed vendor .dsc is used only when no
exact Git source exists. Both must independently prove the exact Source and
Version extracted from the AMD64 ISO. Native ARM64 builds remain blocked for
any unresolved or conflicting source.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def rows_by_key(document: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    result: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in document.get("sources", []):
        source = row.get("source")
        version = row.get("source_version")
        if source and version:
            result[(source, version)].append(row)
    return result


def exact_git(target: dict[str, Any], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches = []
    for row in rows:
        selected = row.get("selected")
        if row.get("status") != "resolved" or not isinstance(selected, dict):
            continue
        if selected.get("type") not in (None, "git"):
            continue
        if selected.get("declared_source") != target["source"]:
            continue
        if selected.get("declared_version") != target["source_version"]:
            continue
        if not all(
            selected.get(field)
            for field in ("repository_full_name", "commit_sha", "tree_sha")
        ):
            continue
        matches.append(selected)
    return matches


def exact_dsc(target: dict[str, Any], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches = []
    for row in rows:
        selected = row.get("selected")
        if row.get("status") != "resolved" or not isinstance(selected, dict):
            continue
        if selected.get("type") != "dsc":
            continue
        if selected.get("declared_source") != target["source"]:
            continue
        if selected.get("declared_version") != target["source_version"]:
            continue
        if selected.get("signature_valid") is not True:
            continue
        if not all(selected.get(field) for field in ("url", "dsc_sha256", "components")):
            continue
        if not all(component.get("verified") is True for component in selected["components"]):
            continue
        matches.append(selected)
    return matches


def git_identity(selected: dict[str, Any]) -> tuple[str, str, str]:
    return (
        selected["repository_full_name"],
        selected["commit_sha"],
        selected["tree_sha"],
    )


def dsc_identity(selected: dict[str, Any]) -> tuple[Any, ...]:
    return (
        selected["dsc_sha256"],
        tuple(
            sorted(
                (
                    component["name"],
                    int(component["size"]),
                    component["sha256"],
                )
                for component in selected["components"]
            )
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--git-lock", type=Path, required=True)
    parser.add_argument("--apt-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = load(args.reference)
    git_document = load(args.git_lock)
    apt_document = load(args.apt_lock)
    git_rows = rows_by_key(git_document)
    apt_rows = rows_by_key(apt_document)

    packages: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for package in reference.get("packages", []):
        packages[(package["source"], package["source_version"])].append(package)

    targets = [
        source
        for source in reference.get("sources", [])
        if source.get("custom_candidate")
    ]
    rows: list[dict[str, Any]] = []
    for target in sorted(targets, key=lambda row: (row["source"], row["source_version"])):
        key = (target["source"], target["source_version"])
        members = packages.get(key, [])
        native_packages = sorted(
            {member["package"] for member in members if member["architecture"] == "amd64"}
        )
        all_packages = sorted(
            {member["package"] for member in members if member["architecture"] == "all"}
        )
        role = "rebuild-arm64" if native_packages else "reuse-all"
        row: dict[str, Any] = {
            "source": target["source"],
            "source_version": target["source_version"],
            "role": role,
            "binary_packages": sorted(member["package"] for member in members),
            "native_binary_packages": native_packages,
            "reused_all_packages": all_packages,
            "status": "unresolved",
            "provenance": None,
            "selected": None,
            "git_candidates": [],
            "apt_candidates": [],
        }

        if target["source"] == "linux-signed-amd64":
            row.update(
                status="arch-replace",
                provenance="architecture-replacement",
                selected={
                    "type": "arch-replace",
                    "replacement": "linux-image-arm64 built from the exact linux source",
                },
            )
            rows.append(row)
            continue

        git_candidates = exact_git(target, git_rows.get(key, []))
        row["git_candidates"] = git_candidates
        git_identities = {git_identity(candidate) for candidate in git_candidates}
        if len(git_identities) == 1:
            selected = sorted(
                git_candidates,
                key=lambda candidate: (
                    candidate.get("committer_date", ""),
                    candidate["commit_sha"],
                ),
                reverse=True,
            )[0]
            selected = dict(selected)
            selected["type"] = "git"
            row.update(
                status="resolved",
                provenance="github-exact-commit",
                selected=selected,
            )
            rows.append(row)
            continue
        if len(git_identities) > 1:
            row["status"] = "ambiguous-exact-git-source"
            rows.append(row)
            continue

        apt_candidates = exact_dsc(target, apt_rows.get(key, []))
        row["apt_candidates"] = apt_candidates
        apt_identities = {dsc_identity(candidate) for candidate in apt_candidates}
        if len(apt_identities) == 1:
            selected = sorted(
                apt_candidates,
                key=lambda candidate: (
                    0 if candidate.get("repository") == (
                        "hancom" if "+han" in target["source_version"].lower() else "gooroom"
                    ) else 1,
                    candidate["url"],
                ),
            )[0]
            row.update(
                status="resolved",
                provenance="vendor-apt-exact-signed-dsc",
                selected=selected,
            )
        elif len(apt_identities) > 1:
            row["status"] = "ambiguous-exact-apt-source"
        rows.append(row)

    unresolved = [row for row in rows if row["status"] == "unresolved"]
    ambiguous = [row for row in rows if row["status"].startswith("ambiguous-")]
    native_blockers = [
        row
        for row in rows
        if row["role"] == "rebuild-arm64"
        and row["status"] not in {"resolved", "arch-replace"}
    ]
    summary = {
        "schema": 2,
        "policy": "exact-git-preferred-else-exact-signed-vendor-dsc",
        "source_count": len(rows),
        "git_resolved_count": sum(
            row["provenance"] == "github-exact-commit" for row in rows
        ),
        "apt_resolved_count": sum(
            row["provenance"] == "vendor-apt-exact-signed-dsc" for row in rows
        ),
        "reuse_all_source_count": sum(row["role"] == "reuse-all" for row in rows),
        "arch_replace_count": sum(row["status"] == "arch-replace" for row in rows),
        "unresolved_count": len(unresolved),
        "ambiguous_count": len(ambiguous),
        "native_rebuild_blocker_count": len(native_blockers),
        "native_rebuilds_allowed": not native_blockers,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "effective-source-lock-v2.json").write_text(
        json.dumps({"summary": summary, "sources": rows}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "unresolved.json").write_text(
        json.dumps(unresolved, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "ambiguous.json").write_text(
        json.dumps(ambiguous, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "native-rebuild-blockers.json").write_text(
        json.dumps(native_blockers, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with (args.output_dir / "effective-source-lock-v2.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        fields = [
            "source",
            "source_version",
            "role",
            "status",
            "provenance",
            "repository",
            "commit_or_dsc_sha256",
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
                    "provenance": row["provenance"] or "",
                    "repository": selected.get("repository_full_name")
                    or selected.get("repository")
                    or "",
                    "commit_or_dsc_sha256": selected.get("commit_sha")
                    or selected.get("dsc_sha256")
                    or "",
                }
            )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not native_blockers else 2


if __name__ == "__main__":
    raise SystemExit(main())
