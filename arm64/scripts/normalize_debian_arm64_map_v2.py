#!/usr/bin/env python3
"""Normalize ARM64 package mappings while preserving architecture replacements.

The v1 normalizer correctly validates ordinary ARM64 binaries and source-exact
binNMUs, but its generic package lookup prefers the reference `package` field
over an explicit `arm64_package` replacement. For records such as
`linux-image-5.10.0-23-amd64 -> linux-image-5.10.0-23-arm64`, that silently
reverted the target name to the AMD64 package.

This wrapper changes only selected-target extraction. All fail-closed scoring,
version checks, checksum requirements, and output generation remain in the v1
implementation.
"""

from __future__ import annotations

from typing import Any

import normalize_debian_arm64_map as normalizer


_original_normalize_selected = normalizer.normalize_selected


def normalize_selected_v2(row: dict[str, Any]) -> dict[str, Any] | None:
    selected = _original_normalize_selected(row)
    if selected is None:
        selected = {}

    nested = [value for value in row.values() if isinstance(value, dict)]
    containers = [normalizer.selected_container(row), row, *nested]

    replacement_package = normalizer.first_value(
        containers,
        (
            "target_package",
            "arm64_package",
            "replacement_package",
            "selected_package",
        ),
    )
    replacement_version = normalizer.first_value(
        containers,
        (
            "target_version",
            "arm64_version",
            "replacement_version",
            "selected_version",
        ),
    )
    replacement_architecture = normalizer.first_value(
        containers,
        (
            "target_architecture",
            "arm64_architecture",
            "replacement_architecture",
            "selected_architecture",
        ),
    )

    if replacement_package not in (None, ""):
        selected["package"] = replacement_package
    if replacement_version not in (None, ""):
        selected["version"] = replacement_version
    if replacement_architecture not in (None, ""):
        selected["architecture"] = replacement_architecture

    if not selected:
        return None
    return selected


normalizer.normalize_selected = normalize_selected_v2

if __name__ == "__main__":
    raise SystemExit(normalizer.main())
