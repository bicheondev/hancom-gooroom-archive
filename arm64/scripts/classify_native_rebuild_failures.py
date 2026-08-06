#!/usr/bin/env python3
"""Classify the latest native ARM64 rebuild failure for every source.

Classification is deliberately diagnostic, not permissive: no category changes
whether a package is accepted. It only decides which failed sources may be
retried after the verified build-dependency repository changes.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


CATEGORY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "timeout",
        (
            "timed out",
            "timeout",
            "exit code 124",
            "terminated by signal",
            "received signal term",
        ),
    ),
    (
        "source-or-tree-verification",
        (
            "commit mismatch",
            "tree mismatch",
            "debian/changelog missing",
            "source mismatch",
            "version mismatch",
            "submodules without independent commit locks",
            "couldn't find remote ref",
            "fatal: couldn't find",
        ),
    ),
    (
        "snapshot-or-bootstrap",
        (
            "debootstrap",
            "snapshot.debian.org",
            "release file expired",
            "failed to fetch",
            "temporary failure resolving",
            "could not resolve",
            "connection timed out",
            "connection reset",
            "tls connection was non-properly terminated",
        ),
    ),
    (
        "dependency-resolution",
        (
            "mk-build-deps: unable to install",
            "unable to install all build-dep packages",
            "unmet build dependencies",
            "unmet dependencies",
            "depends: ",
            "but it is not installable",
            "but it is not going to be installed",
            "unable to locate package",
            "has no installation candidate",
            "held broken packages",
            "pkgproblemresolver",
            "dpkg-checkbuilddeps",
            "build-dependency-metapackage",
            "correcting dependencies... failed",
        ),
    ),
    (
        "test-failure",
        (
            "tests failed",
            "test suite failed",
            "failures:",
            "meson test",
            "ctest",
            "autopkgtest",
            "test result: failed",
        ),
    ),
    (
        "compile-or-link",
        (
            "error: command",
            "fatal error:",
            "undefined reference",
            "collect2: error",
            "linker command failed",
            "ninja: build stopped",
            "make: ***",
            "meson.build:",
            "compiler cannot create executables",
            "compilation terminated",
        ),
    ),
    (
        "packaging-output",
        (
            "no .deb output was produced",
            "expected architecture-dependent binary package was not built",
            "unexpected output architecture",
            "output version mismatch",
            "dh_missing",
            "not installed to anywhere",
            "dpkg-buildpackage: error",
        ),
    ),
    (
        "post-build-verification",
        (
            "verification missing",
            "x86 elf",
            "foreign-architecture elf",
            "binary source version",
            "missing iso architecture-dependent binary packages",
            "build-lock",
            "verified git tree does not match",
        ),
    ),
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def latest_results(root: Path) -> dict[tuple[str, str], tuple[dict[str, Any], Path]]:
    rows: dict[tuple[str, str], tuple[dict[str, Any], Path]] = {}
    if not root.exists():
        return rows
    for path in root.rglob("result.json"):
        try:
            row = load_json(path)
        except Exception:
            continue
        source = row.get("source")
        version = row.get("source_version")
        if not source or not version:
            continue
        key = (source, version)
        try:
            run_id = int(str(row.get("actions_run_id", "0")))
        except ValueError:
            run_id = 0
        previous = rows.get(key)
        try:
            previous_id = int(str(previous[0].get("actions_run_id", "0"))) if previous else -1
        except ValueError:
            previous_id = -1
        if previous is None or run_id >= previous_id:
            rows[key] = (row, path)
    return rows


def diagnostic_text(row: dict[str, Any]) -> str:
    pieces: list[str] = []
    for diagnostic in row.get("diagnostics", []):
        if isinstance(diagnostic, dict):
            pieces.append(str(diagnostic.get("filename", "")))
            pieces.append(str(diagnostic.get("tail", "")))
    pieces.extend(str(value) for value in row.get("verification_errors", []))
    pieces.append(str(row.get("build_outcome", "")))
    pieces.append(str(row.get("build_exit_code", "")))
    pieces.append(str(row.get("verify_outcome", "")))
    return "\n".join(pieces).lower()


def classify(text: str, row: dict[str, Any]) -> tuple[str, list[str]]:
    matches: list[tuple[str, list[str]]] = []
    for category, patterns in CATEGORY_RULES:
        found = sorted({pattern for pattern in patterns if pattern in text})
        if found:
            matches.append((category, found))

    # A verifier failure after a successful compile is always post-build even
    # if an old diagnostic tail also contains compiler warnings.
    if row.get("build_outcome") == "success" and row.get("verify_outcome") not in {
        "success",
        None,
        "",
    }:
        return "post-build-verification", ["build succeeded but verifier failed"]
    if not matches:
        if str(row.get("build_exit_code", "")) in {"124", "137", "143"}:
            return "timeout", [f"exit code {row.get('build_exit_code')}"]
        return "unknown", []

    priority = {category: index for index, (category, _) in enumerate(CATEGORY_RULES)}
    matches.sort(key=lambda item: priority[item[0]])
    category, evidence = matches[0]
    return category, evidence[:16]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    latest = latest_results(args.results)
    classifications: list[dict[str, Any]] = []
    for (source, version), (row, path) in sorted(latest.items()):
        if row.get("passed") is True:
            category = "passed"
            evidence: list[str] = []
        else:
            category, evidence = classify(diagnostic_text(row), row)
        classifications.append(
            {
                "source": source,
                "source_version": version,
                "actions_run_id": row.get("actions_run_id"),
                "actions_run_url": row.get("actions_run_url"),
                "batch": row.get("batch"),
                "passed": bool(row.get("passed")),
                "category": category,
                "classification_evidence": evidence,
                "build_outcome": row.get("build_outcome"),
                "build_exit_code": row.get("build_exit_code"),
                "verify_outcome": row.get("verify_outcome"),
                "dependency_repository_packages_sha256": row.get(
                    "dependency_repository_packages_sha256"
                ),
                "dependency_release_lock_sha256": row.get(
                    "dependency_release_lock_sha256"
                ),
                "retry_reason": row.get("retry_reason"),
                "result_path": str(path),
            }
        )

    category_counts: dict[str, int] = {}
    for row in classifications:
        category_counts[row["category"]] = category_counts.get(row["category"], 0) + 1
    dependency_failures = [
        row for row in classifications if row["category"] == "dependency-resolution"
    ]
    unknown_failures = [
        row for row in classifications if row["category"] == "unknown"
    ]
    summary = {
        "schema": 1,
        "policy": "diagnostic-only-failure-classification",
        "latest_result_count": len(classifications),
        "passed_count": category_counts.get("passed", 0),
        "failed_count": len(classifications) - category_counts.get("passed", 0),
        "dependency_resolution_failure_count": len(dependency_failures),
        "unknown_failure_count": len(unknown_failures),
        "category_counts": dict(sorted(category_counts.items())),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "classifications.json").write_text(
        json.dumps(
            {"summary": summary, "sources": classifications},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "dependency-failures.json").write_text(
        json.dumps(dependency_failures, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "unknown-failures.json").write_text(
        json.dumps(unknown_failures, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
