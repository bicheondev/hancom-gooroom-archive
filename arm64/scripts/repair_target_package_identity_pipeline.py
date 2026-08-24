#!/usr/bin/env python3
"""Propagate ARM64 target package identity through normalization/materialization."""

from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text and new in text:
        return text
    count = text.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def patch_normalizer(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''    if raw in exact_aliases or ("arm64" in raw and "exact" in raw):
        return "exact-arm64"
''',
        '''    if raw == "source-exact-arch-binnmu":
        return "arch-replace"
    if raw in exact_aliases or ("arm64" in raw and "exact" in raw):
        return "exact-arm64"
''',
        "architecture replacement binNMU status",
    )
    text = replace_once(
        text,
        '''    repository = first_value(containers, ("repository", "archive", "origin"))
    suite = first_value(containers, ("suite", "distribution", "codename"))
''',
        '''    repository = first_value(containers, ("repository", "archive", "origin"))
    suite = first_value(containers, ("suite", "distribution", "codename"))
    source = first_value(containers, ("source", "Source", "source_package"))
    source_version = first_value(
        containers,
        ("source_version", "Source-Version", "selected_source_version"),
    )
''',
        "selected source identity",
    )
    text = replace_once(
        text,
        '''        "repository": repository,
        "suite": suite,
        "base_url": base_url,
''',
        '''        "repository": repository,
        "suite": suite,
        "base_url": base_url,
        "source": source,
        "source_version": source_version,
''',
        "selected source output",
    )
    text = replace_once(
        text,
        '''        status = canonical_status(row_status(raw))
        selected = normalize_selected(raw)
        replacement = raw.get("replacement")
''',
        '''        raw_mapping_status = str(row_status(raw) or "")
        raw_status_slug = re.sub(
            r"[^a-z0-9]+", "-", raw_mapping_status.lower()
        ).strip("-")
        status = canonical_status(raw_mapping_status)
        selected = normalize_selected(raw)
        version_policy = (
            "source-exact-binnmu"
            if raw_status_slug == "source-exact-binnmu"
            else "binary-exact"
        )
        target_package = (
            selected.get("package")
            if isinstance(selected, dict) and selected.get("package")
            else package
        )
        target_version = (
            selected.get("version")
            if isinstance(selected, dict) and selected.get("version")
            else reference_row["version"]
        )
        target_architecture = (
            selected.get("architecture")
            if isinstance(selected, dict) and selected.get("architecture")
            else ("all" if reference_row["architecture"] == "all" else "arm64")
        )
        replacement = raw.get("replacement")
''',
        "normalized target identity calculation",
    )
    text = replace_once(
        text,
        '''                "status": status,
                "selected": selected,
                "replacement": replacement,
''',
        '''                "status": status,
                "mapping_status_raw": raw_mapping_status,
                "version_policy": version_policy,
                "target_package": target_package,
                "target_version": target_version,
                "target_architecture": target_architecture,
                "selected": selected,
                "replacement": replacement,
''',
        "normalized target fields",
    )
    incomplete_old = '''    incomplete_exact = [
        row
        for row in normalized
        if row["status"] in {"exact-arm64", "reuse-all"}
        and (
            not row.get("selected")
            or row["selected"].get("version") not in (None, row["reference_version"])
        )
    ]
'''
    incomplete_new = '''    def exact_asset_error(row: dict[str, Any]) -> str | None:
        if row["status"] not in {"exact-arm64", "reuse-all"}:
            return None
        selected = row.get("selected")
        if row["status"] == "reuse-all" and row.get("custom_candidate"):
            # Exact vendor Architecture: all assets are acquired through the
            # separately hash-verified vendor binary lock.
            return None
        if not isinstance(selected, dict):
            return "selected-asset-missing"
        for field in ("package", "version", "architecture", "filename", "url", "sha256", "size"):
            if selected.get(field) in (None, ""):
                return f"selected-asset-field-missing:{field}"
        if selected.get("package") != row.get("target_package"):
            return "selected-package-does-not-match-target"
        if selected.get("version") != row.get("target_version"):
            return "selected-version-does-not-match-target"
        if selected.get("architecture") != row.get("target_architecture"):
            return "selected-architecture-does-not-match-target"
        if row.get("version_policy") == "binary-exact":
            if row.get("target_version") != row.get("reference_version"):
                return "binary-exact-target-version-differs"
        elif row.get("version_policy") == "source-exact-binnmu":
            if selected.get("source") != row.get("source"):
                return "binnmu-source-name-mismatch"
            if selected.get("source_version") != row.get("source_version"):
                return "binnmu-source-version-mismatch"
        return None

    incomplete_exact = []
    for row in normalized:
        reason = exact_asset_error(row)
        if reason:
            incomplete_exact.append({**row, "incomplete_reason": reason})
'''
    text = replace_once(text, incomplete_old, incomplete_new, "exact asset completeness")
    text = replace_once(
        text,
        '''            and not unknown
            and not unresolved
        ),
''',
        '''            and not unknown
            and not unresolved
            and not incomplete_exact
        ),
''',
        "complete summary exact metadata gate",
    )
    path.write_text(text, encoding="utf-8")


def patch_planner(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''    selected_package = selected.get("package") or row["package"]
    selected_version = selected.get("version") or row["reference_version"]
    selected_architecture = selected.get("architecture")
    if not permit_replacement_identity:
        if selected_package != row["package"] or selected_version != row["reference_version"]:
            return None
''',
        '''    target_package = row.get("target_package") or row["package"]
    target_version = row.get("target_version") or row["reference_version"]
    target_architecture = row.get("target_architecture")
    selected_package = selected.get("package") or target_package
    selected_version = selected.get("version") or target_version
    selected_architecture = selected.get("architecture") or target_architecture
    if not permit_replacement_identity:
        if selected_package != target_package or selected_version != target_version:
            return None
''',
        "planner target identity comparison",
    )
    text = replace_once(
        text,
        '''            "mapping_status": status,
            "acquisition": acquisition,
            "ready": acquisition is not None,
''',
        '''            "mapping_status": status,
            "version_policy": row.get("version_policy", "binary-exact"),
            "target_package": row.get("target_package") or row["package"],
            "target_version": row.get("target_version") or row["reference_version"],
            "target_architecture": row.get("target_architecture"),
            "acquisition": acquisition,
            "ready": acquisition is not None,
''',
        "planner output target identity",
    )
    path.write_text(text, encoding="utf-8")


def patch_materializer(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''    expected_package = task["package"]
    expected_version = task["reference_version"]
    mapping = task["mapping_status"]
''',
        '''    expected_package = task.get("target_package") or task["package"]
    expected_version = task.get("target_version") or task["reference_version"]
    expected_target_architecture = task.get("target_architecture")
    mapping = task["mapping_status"]
''',
        "materializer target package identity",
    )
    text = replace_once(
        text,
        '''    expected_architectures = {
        "exact-arm64": {"arm64"},
        "rebuild-arm64": {"arm64"},
        "reuse-all": {"all"},
    }.get(mapping, {"arm64", "all"})
''',
        '''    expected_architectures = (
        {expected_target_architecture}
        if expected_target_architecture in {"arm64", "all"}
        else {
            "exact-arm64": {"arm64"},
            "rebuild-arm64": {"arm64"},
            "reuse-all": {"all"},
        }.get(mapping, {"arm64", "all"})
    )
''',
        "materializer target architecture",
    )
    text = replace_once(
        text,
        '''    if replacement_package:
        normalized["package"] = replacement_package
    if replacement_version:
        normalized["reference_version"] = replacement_version
    normalized["mapping_status"] = route.get("mapping_status", "architecture-replacement")
''',
        '''    if replacement_package:
        normalized["target_package"] = replacement_package
    if replacement_version:
        normalized["target_version"] = replacement_version
    normalized["target_architecture"] = route.get("architecture", "arm64")
    normalized["mapping_status"] = route.get("mapping_status", "architecture-replacement")
''',
        "materializer replacement target identity",
    )
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normalizer", type=Path, required=True)
    parser.add_argument("--planner", type=Path, required=True)
    parser.add_argument("--materializer", type=Path, required=True)
    args = parser.parse_args()
    patch_normalizer(args.normalizer)
    patch_planner(args.planner)
    patch_materializer(args.materializer)
    print("target identity pipeline repaired")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
