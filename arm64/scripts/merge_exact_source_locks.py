#!/usr/bin/env python3
"""Merge all exact Git and signed vendor-pool source locks into one authority.

Multiple Git evidence files are accepted. A resolved baseline therefore remains
usable while deeper history probes run. If the same source version resolves to
more than one distinct Git tree, the result is deliberately ambiguous and the
build remains blocked.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def keyed_many(documents: list[dict[str, Any]], field: str = "sources") -> dict[tuple[str, str], list[dict[str, Any]]]:
    rows: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for document in documents:
        for row in document.get(field, []):
            rows[(row["source"], row["source_version"])].append(row)
    return dict(rows)


def exact_git_rows(target: dict[str, Any], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        selected = row.get("selected") or {}
        if (
            row.get("status") == "resolved"
            and selected
            and selected.get("declared_source") == target["source"]
            and selected.get("declared_version") == target["source_version"]
            and selected.get("commit_sha")
            and selected.get("tree_sha")
        ):
            result.append(row)
    return result


def git_rank(row: dict[str, Any]) -> tuple[int, int, str, str]:
    selected = row["selected"]
    kind = selected.get("ref_kind", "")
    scope = selected.get("match_scope", "")
    return (
        0 if kind == "tag" else 1 if kind == "branch" else 2,
        0 if scope == "ref-tip" else 1,
        selected.get("ref_name", ""),
        selected.get("commit_sha", ""),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--git-lock", type=Path, action="append", default=[])
    parser.add_argument("--vendor-pool-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    git_documents = [
        json.loads(path.read_text(encoding="utf-8")) for path in args.git_lock
    ]
    vendor_document = json.loads(args.vendor_pool_lock.read_text(encoding="utf-8"))
    git_rows = keyed_many(git_documents)
    vendor_rows = keyed_many([vendor_document])

    targets = [row for row in reference["sources"] if row.get("custom_candidate")]
    rows: list[dict[str, Any]] = []
    for target in sorted(targets, key=lambda row: row["source"]):
        key = (target["source"], target["source_version"])
        all_git_rows = git_rows.get(key, [])
        all_vendor_rows = vendor_rows.get(key, [])
        exact_git = exact_git_rows(target, all_git_rows)
        vendor_row = next(
            (
                row
                for row in all_vendor_rows
                if row.get("status") == "resolved" and row.get("selected")
            ),
            all_vendor_rows[0] if all_vendor_rows else None,
        )

        role = "rebuild-arm64"
        binary_architectures: list[str] = []
        binary_packages = target.get("binary_packages", [])
        evidence_row = exact_git[0] if exact_git else (all_git_rows[0] if all_git_rows else vendor_row)
        if evidence_row:
            role = evidence_row.get("role", role)
            binary_architectures = evidence_row.get("binary_architectures", [])
            binary_packages = evidence_row.get("binary_packages", binary_packages)

        row: dict[str, Any] = {
            "source": target["source"],
            "source_version": target["source_version"],
            "binary_packages": binary_packages,
            "binary_architectures": binary_architectures,
            "role": role,
            "status": "unresolved-exact-source",
            "provenance": None,
            "selected": None,
            "git_evidence": all_git_rows,
            "vendor_pool_evidence": all_vendor_rows,
        }

        if exact_git:
            distinct_trees = {
                evidence["selected"]["tree_sha"] for evidence in exact_git
            }
            if len(distinct_trees) > 1:
                row.update(
                    status="ambiguous-exact-git-source",
                    provenance="conflicting-exact-git-trees",
                )
            else:
                selected_row = sorted(exact_git, key=git_rank)[0]
                selected = selected_row["selected"]
                row.update(
                    status="resolved",
                    provenance="github-exact-commit",
                    selected={
                        "type": "git",
                        "repository_full_name": selected["repository_full_name"],
                        "commit_sha": selected["commit_sha"],
                        "tree_sha": selected["tree_sha"],
                        "ref_kind": selected.get("ref_kind", ""),
                        "ref_name": selected.get("ref_name", ""),
                        "match_scope": selected.get("match_scope", ""),
                        "source_archive": selected.get("source_archive", ""),
                        "declared_source": selected["declared_source"],
                        "declared_version": selected["declared_version"],
                    },
                )
        elif vendor_row and vendor_row.get("status") == "resolved" and vendor_row.get("selected"):
            selected = vendor_row["selected"]
            if (
                selected.get("signed_source") == target["source"]
                and selected.get("signed_version") == target["source_version"]
                and selected.get("signature_valid") is True
            ):
                row.update(
                    status="resolved",
                    provenance="vendor-pool-exact-signed-dsc",
                    selected={
                        "type": "dsc",
                        "repository": selected["repository"],
                        "suite": selected["suite"],
                        "url": selected["url"],
                        "dsc_name": selected["dsc_name"],
                        "dsc_sha256": selected["dsc_sha256"],
                        "dsc_size": selected["dsc_size"],
                        "files": selected["files"],
                        "source_urls": selected["source_urls"],
                        "signed_source": selected["signed_source"],
                        "signed_version": selected["signed_version"],
                    },
                )
        elif target["source"] == "linux-signed-amd64" or any(
            evidence.get("status") == "arch-replace" for evidence in all_git_rows
        ):
            row.update(
                status="arch-replace",
                provenance="architecture-replacement",
                selected={
                    "type": "arch-replace",
                    "replacement": "linux-image-arm64 built from exact linux source",
                },
            )
        rows.append(row)

    unresolved = [
        row
        for row in rows
        if row["status"] in {"unresolved-exact-source", "ambiguous-exact-git-source"}
    ]
    rebuild_blockers = [
        row
        for row in unresolved
        if row["role"] == "rebuild-arm64" and row["source"] != "linux-signed-amd64"
    ]
    summary = {
        "schema": 2,
        "policy": "all-exact-git-locks-then-exact-signed-vendor-dsc",
        "git_lock_input_count": len(git_documents),
        "source_target_count": len(rows),
        "resolved_count": sum(row["status"] == "resolved" for row in rows),
        "git_resolved_count": sum(row["provenance"] == "github-exact-commit" for row in rows),
        "vendor_pool_resolved_count": sum(row["provenance"] == "vendor-pool-exact-signed-dsc" for row in rows),
        "arch_replace_count": sum(row["status"] == "arch-replace" for row in rows),
        "ambiguous_git_tree_count": sum(row["status"] == "ambiguous-exact-git-source" for row in rows),
        "unresolved_count": len(unresolved),
        "rebuild_blocker_count": len(rebuild_blockers),
        "build_allowed": len(rebuild_blockers) == 0,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "effective-source-lock.json").write_text(
        json.dumps({"summary": summary, "sources": rows}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "effective-source-lock-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output_dir / "effective-source-unresolved.json").write_text(
        json.dumps(unresolved, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output_dir / "effective-source-rebuild-blockers.json").write_text(
        json.dumps(rebuild_blockers, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    fields = [
        "source",
        "source_version",
        "role",
        "status",
        "provenance",
        "repository",
        "commit_or_dsc_sha256",
    ]
    with (args.output_dir / "effective-source-lock.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
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

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["build_allowed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
