#!/usr/bin/env python3
"""Shared helpers for Git-or-DSC exact ARM64 source build selectors."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")


def source_packages(
    reference: dict[str, Any], source: str, source_version: str
) -> list[dict[str, Any]]:
    return [
        row
        for row in reference.get("packages", [])
        if row.get("source") == source
        and row.get("source_version") == source_version
    ]


def source_matrix(
    reference: dict[str, Any], row: dict[str, Any]
) -> dict[str, Any] | None:
    if row.get("status") != "resolved" or not isinstance(row.get("selected"), dict):
        return None
    selected = row["selected"]
    selected_type = selected.get("type", "git")
    source = row.get("source")
    version = row.get("source_version")
    if not source or not version:
        return None

    if selected_type == "git":
        if not all(
            (
                selected.get("repository_full_name"),
                selected.get("commit_sha"),
                selected.get("tree_sha"),
            )
        ):
            return None
        if selected.get("declared_source") not in (None, source):
            return None
        if selected.get("declared_version") not in (None, version):
            return None
        authority = {
            "source_type": "git",
            "repository_full_name": selected["repository_full_name"],
            "commit_sha": selected["commit_sha"],
            "tree_sha": selected["tree_sha"],
            "dsc_filename": "",
            "dsc_sha256": "",
        }
    elif selected_type == "dsc":
        dsc = selected.get("dsc") if isinstance(selected.get("dsc"), dict) else {}
        if selected.get("signature_verified") is not True:
            return None
        if selected.get("signed_source") != source:
            return None
        if selected.get("signed_version") != version:
            return None
        if not all((dsc.get("filename"), dsc.get("sha256"), dsc.get("url"))):
            return None
        if not selected.get("files"):
            return None
        authority = {
            "source_type": "dsc",
            "repository_full_name": "",
            "commit_sha": "",
            "tree_sha": "",
            "dsc_filename": dsc["filename"],
            "dsc_sha256": dsc["sha256"],
        }
    else:
        return None

    packages = source_packages(reference, source, version)
    required_native = sorted(
        {
            package["package"]
            for package in packages
            if package.get("architecture") == "amd64"
        }
    )
    reused_all = sorted(
        {
            package["package"]
            for package in packages
            if package.get("architecture") == "all"
        }
    )
    if not required_native:
        return None

    return {
        "source": source,
        "source_version": version,
        "authority_provenance": row.get("provenance"),
        **authority,
        "required_native_packages": required_native,
        "required_native_packages_space": " ".join(required_native),
        "reused_all_packages": reused_all,
        "artifact_name": (
            f"arm64-rebuild-{safe_component(source)}-"
            f"{safe_component(version)}"
        ),
    }


def exact_build_candidates(
    lock: dict[str, Any], reference: dict[str, Any]
) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    ambiguous: set[tuple[str, str]] = set()
    for row in lock.get("sources", []):
        matrix = source_matrix(reference, row)
        if matrix is None:
            continue
        key = (matrix["source"], matrix["source_version"])
        previous = result.get(key)
        if previous is None:
            result[key] = matrix
            continue
        identity = (
            matrix["source_type"],
            matrix["tree_sha"] or matrix["dsc_sha256"],
        )
        previous_identity = (
            previous["source_type"],
            previous["tree_sha"] or previous["dsc_sha256"],
        )
        if identity != previous_identity:
            ambiguous.add(key)
    for key in ambiguous:
        result.pop(key, None)
    return result


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
        try:
            run_id = int(str(row.get("actions_run_id", "0")))
        except ValueError:
            run_id = 0
        key = (source, version)
        previous = rows.get(key)
        try:
            previous_id = int(str(previous[0].get("actions_run_id", "0"))) if previous else -1
        except ValueError:
            previous_id = -1
        if previous is None or run_id >= previous_id:
            rows[key] = (row, path)
    return rows


def extract_source_names(value: Any) -> set[str]:
    """Extract source names from deliberately flexible batch-plan schemas."""
    names: set[str] = set()
    if isinstance(value, str):
        if value and not value.startswith(("http://", "https://")):
            names.add(value)
        return names
    if isinstance(value, list):
        for item in value:
            names.update(extract_source_names(item))
        return names
    if not isinstance(value, dict):
        return names

    source = value.get("source")
    if isinstance(source, str):
        names.add(source)
    for key in ("sources", "members", "items", "entries"):
        if key in value:
            names.update(extract_source_names(value[key]))

    # Common plan form: {"source-name": {metadata...}, ...}. Avoid treating
    # known metadata keys as source names.
    metadata_keys = {
        "source",
        "sources",
        "members",
        "items",
        "entries",
        "description",
        "name",
        "notes",
        "reason",
        "priority",
        "known_success",
        "batches",
    }
    for key, child in value.items():
        if key in metadata_keys:
            continue
        if isinstance(child, (dict, list)) and re.fullmatch(
            r"[a-z0-9][a-z0-9+.-]*", key
        ):
            names.add(key)
    return names


def batch_source_names(plan: dict[str, Any], batch: str) -> set[str]:
    batches = plan.get("batches")
    if isinstance(batches, dict) and batch in batches:
        return extract_source_names(batches[batch])
    if batch in plan:
        return extract_source_names(plan[batch])
    return set()


def known_success_names(plan: dict[str, Any]) -> set[str]:
    value = plan.get("known_success", {})
    names = extract_source_names(value)
    if isinstance(value, dict):
        names.update(
            key
            for key in value
            if re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", key)
        )
    return names


def all_reserved_names(plan: dict[str, Any]) -> set[str]:
    names = known_success_names(plan)
    batches = plan.get("batches", {})
    if isinstance(batches, dict):
        for value in batches.values():
            names.update(extract_source_names(value))
    return names


def matrix_document(selected: list[dict[str, Any]]) -> dict[str, Any]:
    return {"include": selected}
