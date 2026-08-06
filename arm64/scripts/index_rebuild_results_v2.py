#!/usr/bin/env python3
"""Index verified native ARM64 rebuild results from all provenance paths."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_id(row: dict[str, Any]) -> int:
    try:
        return int(str(row.get("actions_run_id", "0")))
    except ValueError:
        return 0


def normalize_result(path: Path, root: Path) -> dict[str, Any] | None:
    try:
        row = load(path)
    except Exception:
        return None
    source = row.get("source")
    version = row.get("source_version")
    if not source or not version:
        return None

    verification = row.get("verification")
    if verification is None:
        candidate = path.parent / "verification.json"
        if candidate.exists():
            try:
                verification = load(candidate)
            except Exception:
                verification = None
    packages: list[dict[str, Any]] = []
    if isinstance(verification, dict):
        for package in verification.get("packages", []):
            if not isinstance(package, dict):
                continue
            if not all(
                package.get(field)
                for field in ("package", "version", "architecture", "filename", "sha256")
            ):
                continue
            if package.get("architecture") not in {"arm64", "all"}:
                continue
            packages.append(
                {
                    "package": package["package"],
                    "version": package["version"],
                    "architecture": package["architecture"],
                    "filename": package["filename"],
                    "sha256": package["sha256"],
                    "size": int(package.get("size", 0)),
                    "source": package.get("source", source),
                    "source_version": package.get("source_version", version),
                }
            )

    passed = bool(row.get("passed"))
    if isinstance(verification, dict):
        passed = passed and verification.get("passed") is True
    if passed and not packages:
        passed = False

    provenance = row.get("provenance")
    if not provenance:
        if row.get("dsc_sha256"):
            provenance = "vendor-apt-exact-signed-dsc"
        elif row.get("commit_sha"):
            provenance = "github-exact-commit"
        else:
            provenance = "unknown"

    artifact_name = row.get("artifact_name")
    if not artifact_name:
        artifact_name = path.parents[0].name

    return {
        "source": source,
        "source_version": version,
        "provenance": provenance,
        "repository": row.get("repository_full_name") or row.get("repository"),
        "commit_sha": row.get("commit_sha"),
        "tree_sha": row.get("tree_sha"),
        "dsc_sha256": row.get("dsc_sha256"),
        "actions_run_id": str(row.get("actions_run_id", "")),
        "actions_run_url": row.get("actions_run_url"),
        "artifact_name": artifact_name,
        "passed": passed,
        "packages": sorted(packages, key=lambda item: item["package"]),
        "verification_errors": (
            verification.get("errors", []) if isinstance(verification, dict) else []
        ),
        "evidence_path": str(path.relative_to(root)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    parse_errors: list[dict[str, str]] = []
    for root in args.root:
        if not root.exists():
            continue
        for path in sorted(root.rglob("result.json")):
            try:
                row = normalize_result(path, root)
            except Exception as error:
                parse_errors.append({"path": str(path), "error": repr(error)})
                continue
            if row:
                candidates[(row["source"], row["source_version"])].append(row)

    rows: list[dict[str, Any]] = []
    package_index: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for key, attempts in sorted(candidates.items()):
        attempts.sort(
            key=lambda row: (
                1 if row["passed"] else 0,
                run_id(row),
                row.get("artifact_name") or "",
            ),
            reverse=True,
        )
        selected = attempts[0]
        record = {
            "source": key[0],
            "source_version": key[1],
            "status": "verified" if selected["passed"] else "failed",
            "selected": selected,
            "attempt_count": len(attempts),
            "attempts": attempts,
        }
        rows.append(record)
        if selected["passed"]:
            for package in selected["packages"]:
                package_index[(package["package"], package["version"])].append(
                    {
                        **package,
                        "source": key[0],
                        "source_version": key[1],
                        "provenance": selected["provenance"],
                        "actions_run_id": selected["actions_run_id"],
                        "actions_run_url": selected["actions_run_url"],
                        "artifact_name": selected["artifact_name"],
                        "commit_sha": selected.get("commit_sha"),
                        "tree_sha": selected.get("tree_sha"),
                        "dsc_sha256": selected.get("dsc_sha256"),
                    }
                )

    package_rows = []
    ambiguous_packages = []
    for key, entries in sorted(package_index.items()):
        identities = {
            (
                entry["architecture"],
                entry["filename"],
                entry["sha256"],
                entry["size"],
            )
            for entry in entries
        }
        if len(identities) != 1:
            ambiguous_packages.append(
                {"package": key[0], "version": key[1], "entries": entries}
            )
            continue
        package_rows.append(entries[0])

    summary = {
        "schema": 2,
        "policy": "latest-verified-exact-source-native-arm64-result",
        "source_result_count": len(rows),
        "verified_source_count": sum(row["status"] == "verified" for row in rows),
        "failed_source_count": sum(row["status"] == "failed" for row in rows),
        "verified_binary_package_count": len(package_rows),
        "ambiguous_binary_package_count": len(ambiguous_packages),
        "parse_error_count": len(parse_errors),
        "package_index_usable": not ambiguous_packages and not parse_errors,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "rebuild-result-index.json").write_text(
        json.dumps({"summary": summary, "sources": rows}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "verified-binary-packages.json").write_text(
        json.dumps(package_rows, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "ambiguous-binary-packages.json").write_text(
        json.dumps(ambiguous_packages, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "parse-errors.json").write_text(
        json.dumps(parse_errors, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["package_index_usable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
