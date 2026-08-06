#!/usr/bin/env python3
"""Normalize generated Debian ARM64 mapping evidence to one fail-closed schema."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable


PACKAGE_KEYS = ("package", "binary_package", "name")
STATUS_KEYS = ("status", "mapping_status", "classification", "action", "result")
VERSION_KEYS = ("reference_version", "amd64_version", "version")
ARCH_KEYS = ("reference_architecture", "amd64_architecture", "architecture")


def first_value(containers: Iterable[dict[str, Any]], keys: Iterable[str]) -> Any:
    for container in containers:
        for key in keys:
            value = container.get(key)
            if value not in (None, ""):
                return value
    return None


def canonical_status(value: Any) -> str:
    raw = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    exact_aliases = {
        "exact-arm64",
        "arm64-exact",
        "exact-binary-arm64",
        "debian-arm64-exact",
        "use-arm64",
        "download-arm64",
        "exact",
    }
    all_aliases = {
        "reuse-all",
        "architecture-all",
        "arch-all",
        "use-all",
        "all",
        "reuse-architecture-all",
    }
    rebuild_aliases = {
        "rebuild-arm64",
        "native-rebuild",
        "source-rebuild",
        "build-arm64",
        "rebuild",
    }
    replacement_aliases = {
        "arch-replace",
        "architecture-replace",
        "replace",
        "replacement",
    }
    exclusion_aliases = {
        "exclude",
        "architecture-exclude",
        "drop",
        "remove",
        "omit",
    }
    unresolved_aliases = {"unresolved", "missing", "blocked", "unknown", "none", ""}
    if raw in exact_aliases or ("arm64" in raw and "exact" in raw):
        return "exact-arm64"
    if raw in all_aliases or ("all" in raw and any(token in raw for token in ("reuse", "arch", "use"))):
        return "reuse-all"
    if raw in rebuild_aliases or "rebuild" in raw:
        return "rebuild-arm64"
    if raw in replacement_aliases or "replace" in raw:
        return "arch-replace"
    if raw in exclusion_aliases or any(token in raw for token in ("exclude", "omit", "drop")):
        return "exclude"
    if raw in unresolved_aliases or any(token in raw for token in ("unresolved", "missing", "blocked")):
        return "unresolved"
    return f"unknown:{raw}"


def candidate_lists(document: Any, path: Path) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if isinstance(document, list):
        candidates.append({"path": str(path), "field": None, "rows": document})
    elif isinstance(document, dict):
        for field, value in document.items():
            if isinstance(value, list):
                candidates.append({"path": str(path), "field": field, "rows": value})
    return candidates


def row_package(row: dict[str, Any]) -> Any:
    nested = [value for value in row.values() if isinstance(value, dict)]
    return first_value([row, *nested], PACKAGE_KEYS)


def row_status(row: dict[str, Any]) -> Any:
    nested = [value for value in row.values() if isinstance(value, dict)]
    return first_value([row, *nested], STATUS_KEYS)


def score_candidate(candidate: dict[str, Any]) -> tuple[int, int, int]:
    rows = candidate["rows"]
    if not rows:
        return (0, 0, 0)
    sample = [row for row in rows[:50] if isinstance(row, dict)]
    package_hits = sum(row_package(row) is not None for row in sample)
    status_hits = sum(row_status(row) is not None for row in sample)
    return (status_hits, package_hits, len(rows))


def selected_container(row: dict[str, Any]) -> dict[str, Any]:
    for key in ("selected", "arm64", "candidate", "resolution", "target", "binary"):
        value = row.get(key)
        if isinstance(value, dict):
            return value
    return {}


def normalize_selected(row: dict[str, Any]) -> dict[str, Any] | None:
    selected = selected_container(row)
    nested = [value for value in row.values() if isinstance(value, dict)]
    containers = [selected, row, *nested]
    filename = first_value(containers, ("filename", "Filename", "path", "pool_path"))
    base_url = first_value(containers, ("base_url", "repository_url", "mirror"))
    url = first_value(containers, ("url", "download_url", "uri"))
    if not url and base_url and filename:
        url = f"{str(base_url).rstrip('/')}/{str(filename).lstrip('/')}"
    sha256 = first_value(containers, ("sha256", "SHA256", "checksum_sha256"))
    size = first_value(containers, ("size", "Size", "file_size"))
    package = first_value(containers, PACKAGE_KEYS)
    version = first_value(
        containers,
        ("target_version", "arm64_version", "selected_version", "version", "Version"),
    )
    architecture = first_value(
        containers,
        ("target_architecture", "arm64_architecture", "selected_architecture", "architecture", "Architecture"),
    )
    repository = first_value(containers, ("repository", "archive", "origin"))
    suite = first_value(containers, ("suite", "distribution", "codename"))
    if not any(value not in (None, "") for value in (filename, url, sha256, package, version, architecture)):
        return None
    try:
        parsed_size = int(size) if size not in (None, "") else None
    except (TypeError, ValueError):
        parsed_size = None
    return {
        "package": package,
        "version": version,
        "architecture": architecture,
        "filename": filename,
        "url": url,
        "sha256": str(sha256).lower() if sha256 else None,
        "size": parsed_size,
        "repository": repository,
        "suite": suite,
        "base_url": base_url,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--map-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    candidates: list[dict[str, Any]] = []
    parse_errors: list[dict[str, str]] = []
    for path in sorted(args.map_dir.rglob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            candidates.extend(candidate_lists(document, path))
        except Exception as error:
            parse_errors.append({"path": str(path), "error": repr(error)})

    scored = sorted(
        ((score_candidate(candidate), candidate) for candidate in candidates),
        key=lambda item: item[0],
        reverse=True,
    )
    if not scored or scored[0][0][0] == 0 or scored[0][0][1] == 0:
        raise SystemExit("no package/status mapping list was found in the lock directory")
    score, selected_list = scored[0]
    raw_rows = [row for row in selected_list["rows"] if isinstance(row, dict)]

    rows_by_package: dict[str, list[dict[str, Any]]] = {}
    for raw in raw_rows:
        package = row_package(raw)
        if package:
            rows_by_package.setdefault(str(package), []).append(raw)

    normalized: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for reference_row in reference.get("packages", []):
        package = reference_row["package"]
        raw_candidates = rows_by_package.get(package, [])
        exact_candidates = []
        for raw in raw_candidates:
            selected = selected_container(raw)
            nested = [value for value in raw.values() if isinstance(value, dict)]
            containers = [raw, selected, *nested]
            version = first_value(containers, VERSION_KEYS)
            reference_version = first_value(
                containers,
                ("reference_version", "amd64_version", "installed_version"),
            )
            if reference_version in (None, ""):
                reference_version = version
            if reference_version in (None, reference_row["version"]):
                exact_candidates.append(raw)

        if len(exact_candidates) != 1:
            errors.append(
                {
                    "package": package,
                    "reference_version": reference_row["version"],
                    "reason": "missing-or-ambiguous-map-row",
                    "candidate_count": len(exact_candidates),
                }
            )
            continue

        raw = exact_candidates[0]
        status = canonical_status(row_status(raw))
        selected = normalize_selected(raw)
        replacement = raw.get("replacement")
        if not isinstance(replacement, (dict, str, list, type(None))):
            replacement = repr(replacement)
        normalized.append(
            {
                "package": package,
                "reference_version": reference_row["version"],
                "reference_architecture": reference_row["architecture"],
                "source": reference_row["source"],
                "source_version": reference_row["source_version"],
                "custom_candidate": bool(reference_row.get("custom_candidate")),
                "status": status,
                "selected": selected,
                "replacement": replacement,
                "source_map_file": selected_list["path"],
                "source_map_field": selected_list["field"],
            }
        )

    status_counts: dict[str, int] = {}
    for row in normalized:
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
    unknown = [row for row in normalized if row["status"].startswith("unknown:")]
    unresolved = [row for row in normalized if row["status"] == "unresolved"]
    incomplete_exact = [
        row
        for row in normalized
        if row["status"] in {"exact-arm64", "reuse-all"}
        and (
            not row.get("selected")
            or row["selected"].get("version") not in (None, row["reference_version"])
        )
    ]
    summary = {
        "schema": 1,
        "policy": "one-normalized-row-per-iso-binary-package",
        "selected_source_file": selected_list["path"],
        "selected_source_field": selected_list["field"],
        "selection_score": {
            "status_hits": score[0],
            "package_hits": score[1],
            "row_count": score[2],
        },
        "reference_package_count": len(reference.get("packages", [])),
        "normalized_package_count": len(normalized),
        "status_counts": dict(sorted(status_counts.items())),
        "missing_or_ambiguous_count": len(errors),
        "unknown_status_count": len(unknown),
        "unresolved_count": len(unresolved),
        "incomplete_exact_metadata_count": len(incomplete_exact),
        "parse_error_count": len(parse_errors),
        "complete": (
            len(normalized) == len(reference.get("packages", []))
            and not errors
            and not unknown
            and not unresolved
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "debian-arm64-map-normalized.json").write_text(
        json.dumps({"summary": summary, "packages": normalized}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "normalization-errors.json").write_text(
        json.dumps(errors, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "unknown-statuses.json").write_text(
        json.dumps(unknown, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "unresolved.json").write_text(
        json.dumps(unresolved, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "incomplete-exact-metadata.json").write_text(
        json.dumps(incomplete_exact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "parse-errors.json").write_text(
        json.dumps(parse_errors, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
