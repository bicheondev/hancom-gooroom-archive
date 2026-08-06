#!/usr/bin/env python3
"""Merge exact Git and signed source-package evidence into one build authority.

Authority order is deliberately provenance-first:

1. An exact signed vendor `.dsc` whose complete payload is hash-locked. A
   persistent Wayback release asset is preferred over the mutable live pool
   when both describe the same signed source identity.
2. An exact public Git commit/tree whose `debian/changelog` Source and Version
   match the AMD64 reference.
3. A declared architecture replacement for source packages that are meaningful
   only on AMD64 (currently `linux-signed-amd64`).

Conflicting signed source identities or conflicting Git trees fail closed.
Version equality alone never resolves a conflict.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit


def load_json(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


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
        architectures = sorted({member.get("architecture", "") for member in members})
        rows.append(
            {
                "source": source["source"],
                "source_version": source["source_version"],
                "role": "reuse-all" if architectures == ["all"] else "rebuild-arm64",
                "binary_packages": sorted({member["package"] for member in members}),
                "binary_architectures": architectures,
            }
        )
    return sorted(rows, key=lambda row: (row["source"], row["source_version"]))


def git_candidates(
    documents: Iterable[dict[str, Any]], target: dict[str, Any]
) -> list[dict[str, Any]]:
    candidates = []
    for document in documents:
        for row in document.get("sources", []):
            if (row.get("source"), row.get("source_version")) != (
                target["source"],
                target["source_version"],
            ):
                continue
            selected = row.get("selected")
            if row.get("status") != "resolved" or not isinstance(selected, dict):
                continue
            if selected.get("type") not in (None, "git"):
                continue
            if (
                selected.get("declared_source") != target["source"]
                or selected.get("declared_version") != target["source_version"]
            ):
                continue
            repository = selected.get("repository_full_name")
            commit_sha = selected.get("commit_sha")
            tree_sha = selected.get("tree_sha")
            if not all((repository, commit_sha, tree_sha)):
                continue
            candidates.append(
                {
                    "type": "git",
                    "provenance": "github-exact-commit",
                    "repository_full_name": repository,
                    "commit_sha": commit_sha,
                    "tree_sha": tree_sha,
                    "ref_kind": selected.get("ref_kind", ""),
                    "ref_name": selected.get("ref_name", ""),
                    "match_scope": selected.get("match_scope", ""),
                    "declared_source": selected["declared_source"],
                    "declared_version": selected["declared_version"],
                    "source_archive": selected.get("source_archive", ""),
                }
            )
    return candidates


def repository_rank(repository: str, version: str) -> tuple[int, str]:
    owner = repository.split("/", 1)[0].lower()
    if "+han" in version.lower():
        order = {"hancomgooroom": 0, "hancom-io": 1, "gooroom": 2}
    else:
        order = {"gooroom": 0, "hancomgooroom": 1, "hancom-io": 2}
    return order.get(owner, 99), repository


def git_rank(candidate: dict[str, Any], version: str) -> tuple[Any, ...]:
    kind = candidate.get("ref_kind", "")
    scope = candidate.get("match_scope", "")
    return (
        *repository_rank(candidate["repository_full_name"], version),
        0 if kind == "tag" else 1 if kind == "branch" else 2,
        0 if scope == "ref-tip" else 1,
        candidate.get("ref_name", ""),
        candidate["commit_sha"],
    )


def basename_from_url(url: str) -> str:
    return Path(unquote(urlsplit(url).path)).name


def normalize_payloads(
    files: list[dict[str, Any]], urls: list[str]
) -> list[dict[str, Any]] | None:
    if len(files) != len(urls):
        return None
    rows = []
    for file_row, url in zip(files, urls):
        name = file_row.get("name")
        sha256 = file_row.get("sha256")
        size = file_row.get("size")
        if not all((name, sha256, size is not None, url)):
            return None
        if basename_from_url(url) != name:
            return None
        rows.append(
            {
                "filename": name,
                "size": int(size),
                "sha256": str(sha256).lower(),
                "url": url,
            }
        )
    return sorted(rows, key=lambda row: row["filename"])


def live_dsc_candidates(
    document: dict[str, Any], target: dict[str, Any]
) -> list[dict[str, Any]]:
    candidates = []
    for row in document.get("sources", []):
        if (row.get("source"), row.get("source_version")) != (
            target["source"],
            target["source_version"],
        ):
            continue
        selected = row.get("selected")
        if row.get("status") != "resolved" or not isinstance(selected, dict):
            continue
        if selected.get("signature_valid") is not True:
            continue
        if (
            selected.get("signed_source") != target["source"]
            or selected.get("signed_version") != target["source_version"]
        ):
            continue
        dsc_name = selected.get("dsc_name")
        dsc_sha256 = selected.get("dsc_sha256")
        dsc_size = selected.get("dsc_size")
        dsc_url = selected.get("url")
        if not all((dsc_name, dsc_sha256, dsc_size is not None, dsc_url)):
            continue
        payloads = normalize_payloads(
            selected.get("files", []), selected.get("source_urls", [])
        )
        if not payloads:
            continue
        candidates.append(
            {
                "type": "dsc",
                "provenance": "vendor-pool-live-exact-signed-dsc",
                "repository": selected.get("repository"),
                "suite": selected.get("suite"),
                "signed_source": selected["signed_source"],
                "signed_version": selected["signed_version"],
                "signature_verified": True,
                "signature_policy": "gpgv-against-reference-iso-keyrings",
                "dsc": {
                    "filename": dsc_name,
                    "size": int(dsc_size),
                    "sha256": str(dsc_sha256).lower(),
                    "url": dsc_url,
                },
                "files": payloads,
            }
        )
    return candidates


def wayback_dsc_candidates(
    document: dict[str, Any], target: dict[str, Any]
) -> list[dict[str, Any]]:
    summary = document.get("summary", {})
    if summary.get("release_complete") is not True:
        return []
    release_tag = summary.get("release_tag")
    candidates = []
    for row in document.get("sources", []):
        if (row.get("source"), row.get("source_version")) != (
            target["source"],
            target["source_version"],
        ):
            continue
        dsc_sha256 = row.get("dsc_sha256")
        files = row.get("files", [])
        if not dsc_sha256 or not isinstance(files, list):
            continue
        dsc_rows = [
            file_row
            for file_row in files
            if file_row.get("sha256") == dsc_sha256
            and str(file_row.get("filename", "")).endswith(".dsc")
        ]
        if len(dsc_rows) != 1:
            continue
        dsc_row = dsc_rows[0]
        if not all(
            (
                dsc_row.get("filename"),
                dsc_row.get("size") is not None,
                dsc_row.get("sha256"),
                dsc_row.get("browser_download_url"),
            )
        ):
            continue
        payloads = []
        valid = True
        for file_row in files:
            if file_row is dsc_row:
                continue
            if not all(
                (
                    file_row.get("filename"),
                    file_row.get("size") is not None,
                    file_row.get("sha256"),
                    file_row.get("browser_download_url"),
                )
            ):
                valid = False
                break
            payloads.append(
                {
                    "filename": file_row["filename"],
                    "size": int(file_row["size"]),
                    "sha256": str(file_row["sha256"]).lower(),
                    "url": file_row["browser_download_url"],
                    "release_asset_id": file_row.get("release_asset_id"),
                    "release_digest": file_row.get("release_digest"),
                }
            )
        if not valid or not payloads:
            continue
        candidates.append(
            {
                "type": "dsc",
                "provenance": "wayback-release-exact-signed-dsc",
                "release_tag": release_tag,
                "release_id": summary.get("release_id"),
                "release_url": summary.get("release_url"),
                "capture_timestamp": row.get("capture_timestamp"),
                "signed_source": target["source"],
                "signed_version": target["source_version"],
                "signature_verified": True,
                "signature_policy": "verified-during-wayback-recovery-against-reference-iso-keyrings",
                "dsc": {
                    "filename": dsc_row["filename"],
                    "size": int(dsc_row["size"]),
                    "sha256": str(dsc_row["sha256"]).lower(),
                    "url": dsc_row["browser_download_url"],
                    "release_asset_id": dsc_row.get("release_asset_id"),
                    "release_digest": dsc_row.get("release_digest"),
                },
                "files": sorted(payloads, key=lambda item: item["filename"]),
            }
        )
    return candidates


def dsc_identity(candidate: dict[str, Any]) -> tuple[Any, ...]:
    return (
        candidate["dsc"]["sha256"],
        int(candidate["dsc"]["size"]),
        tuple(
            (row["filename"], int(row["size"]), row["sha256"])
            for row in sorted(candidate["files"], key=lambda item: item["filename"])
        ),
    )


def dsc_rank(candidate: dict[str, Any]) -> tuple[Any, ...]:
    provenance = candidate.get("provenance", "")
    return (
        0 if provenance.startswith("wayback-release") else 1,
        candidate.get("release_tag", ""),
        candidate.get("capture_timestamp", ""),
        candidate["dsc"]["url"],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--git-lock", type=Path, action="append", default=[])
    parser.add_argument("--vendor-pool-lock", type=Path)
    parser.add_argument("--wayback-release-lock", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = load_json(args.reference)
    git_documents = [load_json(path) for path in args.git_lock if path.exists()]
    vendor_document = load_json(args.vendor_pool_lock)
    wayback_document = load_json(args.wayback_release_lock)

    rows = []
    for target in target_rows(reference):
        git = git_candidates(git_documents, target)
        signed = live_dsc_candidates(vendor_document, target)
        signed.extend(wayback_dsc_candidates(wayback_document, target))
        row: dict[str, Any] = {
            **target,
            "status": "unresolved-exact-source",
            "provenance": None,
            "selected": None,
            "git_candidate_count": len(git),
            "signed_dsc_candidate_count": len(signed),
            "git_candidates": git,
            "signed_dsc_candidates": signed,
        }

        if signed:
            identities = {dsc_identity(candidate) for candidate in signed}
            if len(identities) != 1:
                row.update(
                    status="ambiguous-exact-signed-source",
                    provenance="conflicting-exact-signed-dsc-identities",
                )
            else:
                selected = sorted(signed, key=dsc_rank)[0]
                row.update(
                    status="resolved",
                    provenance=selected["provenance"],
                    selected=selected,
                )
        elif git:
            trees = {candidate["tree_sha"] for candidate in git}
            if len(trees) != 1:
                row.update(
                    status="ambiguous-exact-git-source",
                    provenance="conflicting-exact-git-trees",
                )
            else:
                selected = sorted(
                    git,
                    key=lambda candidate: git_rank(
                        candidate, target["source_version"]
                    ),
                )[0]
                row.update(
                    status="resolved",
                    provenance=selected["provenance"],
                    selected=selected,
                )
        elif target["source"] == "linux-signed-amd64":
            row.update(
                status="arch-replace",
                provenance="architecture-replacement",
                selected={
                    "type": "arch-replace",
                    "replacement": "linux-image-arm64 built from the exact linux source",
                },
            )
        rows.append(row)

    unresolved_statuses = {
        "unresolved-exact-source",
        "ambiguous-exact-signed-source",
        "ambiguous-exact-git-source",
    }
    unresolved = [row for row in rows if row["status"] in unresolved_statuses]
    rebuild_blockers = [
        row
        for row in unresolved
        if row["role"] == "rebuild-arm64"
        and row["source"] != "linux-signed-amd64"
    ]
    summary = {
        "schema": 3,
        "policy": "exact-signed-dsc-preferred-then-exact-git-tree",
        "source_target_count": len(rows),
        "resolved_count": sum(row["status"] == "resolved" for row in rows),
        "signed_dsc_resolved_count": sum(
            row["status"] == "resolved"
            and isinstance(row.get("selected"), dict)
            and row["selected"].get("type") == "dsc"
            for row in rows
        ),
        "git_resolved_count": sum(
            row["status"] == "resolved"
            and isinstance(row.get("selected"), dict)
            and row["selected"].get("type") == "git"
            for row in rows
        ),
        "arch_replace_count": sum(row["status"] == "arch-replace" for row in rows),
        "unresolved_count": len(unresolved),
        "rebuild_blocker_count": len(rebuild_blockers),
        "build_allowed": not rebuild_blockers,
        "wayback_release_lock_present": bool(wayback_document),
        "wayback_release_complete": wayback_document.get("summary", {}).get(
            "release_complete"
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "effective-source-lock.json").write_text(
        json.dumps({"summary": summary, "sources": rows}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "effective-source-lock-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "effective-source-unresolved.json").write_text(
        json.dumps(unresolved, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "effective-source-rebuild-blockers.json").write_text(
        json.dumps(rebuild_blockers, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    fields = [
        "source",
        "source_version",
        "role",
        "status",
        "provenance",
        "selected_type",
        "authority",
        "commit_or_dsc_sha256",
    ]
    with (args.output_dir / "effective-source-lock.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in rows:
            selected = row.get("selected") or {}
            selected_type = selected.get("type", "")
            authority = (
                selected.get("repository_full_name")
                or selected.get("release_tag")
                or selected.get("repository")
                or ""
            )
            identity = selected.get("commit_sha") or (
                selected.get("dsc", {}).get("sha256")
                if isinstance(selected.get("dsc"), dict)
                else ""
            )
            writer.writerow(
                {
                    "source": row["source"],
                    "source_version": row["source_version"],
                    "role": row["role"],
                    "status": row["status"],
                    "provenance": row["provenance"] or "",
                    "selected_type": selected_type,
                    "authority": authority,
                    "commit_or_dsc_sha256": identity or "",
                }
            )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["build_allowed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
