#!/usr/bin/env python3
"""Merge exact Git and signed vendor-pool source locks into one build authority."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def keyed(document: dict[str, Any], field: str = "sources") -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (row["source"], row["source_version"]): row
        for row in document.get(field, [])
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--git-lock", type=Path, required=True)
    parser.add_argument("--vendor-pool-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    git_document = json.loads(args.git_lock.read_text(encoding="utf-8"))
    vendor_document = json.loads(args.vendor_pool_lock.read_text(encoding="utf-8"))
    git_rows = keyed(git_document)
    vendor_rows = keyed(vendor_document)

    targets = [row for row in reference["sources"] if row.get("custom_candidate")]
    rows: list[dict[str, Any]] = []
    for target in sorted(targets, key=lambda row: row["source"]):
        key = (target["source"], target["source_version"])
        git_row = git_rows.get(key)
        vendor_row = vendor_rows.get(key)
        role = "rebuild-arm64"
        binary_architectures: list[str] = []
        binary_packages = target.get("binary_packages", [])
        if git_row:
            role = git_row.get("role", role)
            binary_architectures = git_row.get("binary_architectures", [])
            binary_packages = git_row.get("binary_packages", binary_packages)
        elif vendor_row:
            role = vendor_row.get("role", role)
            binary_architectures = vendor_row.get("binary_architectures", [])
            binary_packages = vendor_row.get("binary_packages", binary_packages)

        row: dict[str, Any] = {
            "source": target["source"],
            "source_version": target["source_version"],
            "binary_packages": binary_packages,
            "binary_architectures": binary_architectures,
            "role": role,
            "status": "unresolved-exact-source",
            "provenance": None,
            "selected": None,
            "git_evidence": git_row,
            "vendor_pool_evidence": vendor_row,
        }

        if git_row and git_row.get("status") == "resolved" and git_row.get("selected"):
            selected = git_row["selected"]
            if (
                selected.get("declared_source") == target["source"]
                and selected.get("declared_version") == target["source_version"]
            ):
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
                        "source_archive": selected.get("source_archive", ""),
                        "declared_source": selected["declared_source"],
                        "declared_version": selected["declared_version"],
                    },
                )
        elif (
            vendor_row
            and vendor_row.get("status") == "resolved"
            and vendor_row.get("selected")
        ):
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
        elif (
            target["source"] == "linux-signed-amd64"
            or (git_row and git_row.get("status") == "arch-replace")
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

    unresolved = [row for row in rows if row["status"] == "unresolved-exact-source"]
    rebuild_blockers = [
        row
        for row in unresolved
        if row["role"] == "rebuild-arm64"
        and row["source"] != "linux-signed-amd64"
    ]
    summary = {
        "schema": 1,
        "policy": "github-exact-commit-else-exact-signed-vendor-dsc",
        "source_target_count": len(rows),
        "resolved_count": sum(row["status"] == "resolved" for row in rows),
        "git_resolved_count": sum(
            row["provenance"] == "github-exact-commit" for row in rows
        ),
        "vendor_pool_resolved_count": sum(
            row["provenance"] == "vendor-pool-exact-signed-dsc" for row in rows
        ),
        "arch_replace_count": sum(row["status"] == "arch-replace" for row in rows),
        "unresolved_count": len(unresolved),
        "rebuild_blocker_count": len(rebuild_blockers),
        "build_allowed": len(rebuild_blockers) == 0,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "effective-source-lock.json").write_text(
        json.dumps({"summary": summary, "sources": rows}, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "effective-source-lock-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output_dir / "effective-source-unresolved.json").write_text(
        json.dumps(unresolved, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output_dir / "effective-source-rebuild-blockers.json").write_text(
        json.dumps(rebuild_blockers, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
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
