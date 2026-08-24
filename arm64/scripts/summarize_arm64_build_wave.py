#!/usr/bin/env python3
"""Create a complete, fail-closed summary from same-run build artifacts."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VALIDATION_NAMES = (
    "arm64-source-output-validation-v4.json",
    "arm64-source-output-validation-v3.json",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return value


def infer_source(path: Path, expected: list[str]) -> str | None:
    source_file = path.parent / "source-name.txt"
    if source_file.is_file():
        value = source_file.read_text(encoding="utf-8", errors="replace").strip()
        if value:
            return value
    joined = "/".join(path.parts)
    matches = [
        source
        for source in expected
        if re.search(rf"(?:^|[/_.-]){re.escape(source)}(?:$|[/_.-])", joined)
    ]
    if matches:
        return sorted(matches, key=lambda value: (-len(value), value))[0]
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--expected-source", action="append", default=[])
    parser.add_argument("--selection-json", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    parser.add_argument("--head-sha")
    parser.add_argument("--head-branch")
    parser.add_argument("--workflow-name")
    parser.add_argument("--repository")
    parser.add_argument("--server-url")
    parser.add_argument("--download-status", default="success")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    selection: dict[str, Any] | None = None
    expected = list(dict.fromkeys(args.expected_source))
    if args.selection_json:
        if args.selection_json.is_file():
            selection = load(args.selection_json)
            selected = selection.get("selected", [])
            selected_sources = [
                item.get("source")
                for item in selected
                if isinstance(item, dict) and item.get("source")
            ]
            expected = list(dict.fromkeys([*expected, *selected_sources]))
        else:
            selection = {
                "status": "missing",
                "path": str(args.selection_json),
            }

    validation_paths: list[Path] = []
    for name in VALIDATION_NAMES:
        validation_paths.extend(args.artifacts_root.rglob(name))
    # Prefer v4 when both versions somehow coexist in one artifact directory.
    validation_paths = sorted(
        set(validation_paths),
        key=lambda path: (
            path.name != "arm64-source-output-validation-v4.json",
            str(path),
        ),
    )

    packages: list[dict[str, Any]] = []
    seen: set[str] = set()
    duplicate_validations: list[dict[str, Any]] = []
    for path in validation_paths:
        value = load(path)
        source = value.get("source") or infer_source(path, expected)
        if not source:
            duplicate_validations.append(
                {
                    "path": str(path.relative_to(args.artifacts_root)),
                    "reason": "source name cannot be determined",
                }
            )
            continue
        if source in seen:
            duplicate_validations.append(
                {
                    "source": source,
                    "path": str(path.relative_to(args.artifacts_root)),
                    "reason": "duplicate validation document",
                }
            )
            continue
        seen.add(source)
        packages.append(
            {
                "source": source,
                "source_version": value.get("source_version"),
                "status": value.get("status"),
                "validation_schema": value.get("schema"),
                "artifact_directory": str(path.parent.relative_to(args.artifacts_root)),
                "selected_source": value.get("selected_source"),
                "required_native_packages": value.get("required_native_packages", []),
                "exact_reuse_architecture_all_packages": value.get(
                    "exact_reuse_architecture_all_packages", []
                ),
                "legacy_builder_missing_packages": value.get(
                    "legacy_builder_missing_packages", []
                ),
                "built_packages": value.get("built_packages", []),
                "missing_required_packages": value.get(
                    "missing_required_packages", []
                ),
                "issues": value.get("issues", []),
            }
        )

    unvalidated: list[dict[str, Any]] = []
    for log in sorted(args.artifacts_root.rglob("legacy-run.log")):
        source = infer_source(log, expected)
        if source and source in seen:
            continue
        exit_path = log.parent / "legacy-run.exit-code"
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        unvalidated.append(
            {
                "source": source,
                "artifact_directory": str(log.parent.relative_to(args.artifacts_root)),
                "legacy_exit_code": (
                    exit_path.read_text(encoding="utf-8", errors="replace").strip()
                    if exit_path.is_file()
                    else None
                ),
                "reason": (
                    "no exact output validation document was produced"
                    if source
                    else "source name and exact output validation are both absent"
                ),
                "log_tail": lines[-160:],
            }
        )

    recorded = sorted(
        {item["source"] for item in packages if item.get("source")}
        | {item["source"] for item in unvalidated if item.get("source")}
    )
    missing = sorted(set(expected) - set(recorded))
    failed = sorted(
        {item["source"] for item in packages if item.get("status") != "passed"}
        | {item["source"] for item in unvalidated if item.get("source")}
    )
    unknown_artifacts = [
        item for item in unvalidated if not item.get("source")
    ]

    reasons: list[str] = []
    if args.download_status != "success":
        reasons.append(f"artifact download status={args.download_status}")
    if not expected:
        reasons.append("expected source set is empty")
    if missing:
        reasons.append(f"missing source evidence: {', '.join(missing)}")
    if failed:
        reasons.append(f"failed source evidence: {', '.join(failed)}")
    if unknown_artifacts:
        reasons.append("one or more artifacts cannot be assigned to a source")
    if duplicate_validations:
        reasons.append("duplicate or source-less validation documents were found")
    if selection is not None and selection.get("status") == "missing":
        reasons.append("dynamic wave selection document is missing")

    run_url = None
    if args.server_url and args.repository and args.run_id:
        run_url = (
            f"{args.server_url.rstrip('/')}/{args.repository}/actions/runs/{args.run_id}"
        )
    result = {
        "schema": args.schema,
        "generated_at": now(),
        "status": "failed" if reasons else "passed",
        "reasons": reasons,
        "workflow_run": {
            "workflow_name": args.workflow_name,
            "repository": args.repository,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "head_branch": args.head_branch,
            "head_sha": args.head_sha,
            "url": run_url,
        },
        "artifact_download_status": args.download_status,
        "selection": selection,
        "expected_sources": expected,
        "recorded_sources": recorded,
        "missing_sources": missing,
        "failed_sources": failed,
        "duplicate_validations": duplicate_validations,
        "packages": sorted(packages, key=lambda item: item["source"]),
        "unvalidated_failures": unvalidated,
    }
    summary_path = args.output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    with (args.output_dir / "packages.tsv").open("w", encoding="utf-8") as stream:
        stream.write(
            "source\tsource_version\tvalidation_status\tpackage\tversion\t"
            "architecture\tfilename\n"
        )
        for item in sorted(packages, key=lambda row: row["source"]):
            for package in item.get("built_packages", []):
                stream.write(
                    "\t".join(
                        [
                            str(item.get("source") or ""),
                            str(item.get("source_version") or ""),
                            str(item.get("status") or ""),
                            str(package.get("package") or ""),
                            str(package.get("version") or ""),
                            str(package.get("architecture") or ""),
                            str(package.get("filename") or ""),
                        ]
                    )
                    + "\n"
                )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if not reasons else 8


if __name__ == "__main__":
    raise SystemExit(main())
