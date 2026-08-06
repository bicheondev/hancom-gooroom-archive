#!/usr/bin/env python3
"""Materialize only Debian-owned exact ARM64/all package routes.

Architecture replacements are intentionally not Debian reference packages.
Examples include the Gooroom-patched ARM64 kernel replacing an AMD64 kernel
package. Those exact replacement DEBs belong to the separately verified custom
rebuild repository and are resolved only when both repositories are merged.

The underlying v2 downloader, source/version checks, checksum audit, and local
APT repository construction are unchanged.
"""

from __future__ import annotations

from typing import Any

import materialize_debian_arm64_reference_repo_v2 as materializer


_original_acquisition_targets = materializer.acquisition_targets


def acquisition_targets_v3(
    normalized: dict[str, Any], reference: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    targets, skipped, blockers = _original_acquisition_targets(normalized, reference)
    debian_targets: list[dict[str, Any]] = []
    for target in targets:
        if target.get("mapping_status") == "arch-replace":
            skipped.append(
                {
                    **target,
                    "reason": "architecture-replacement-from-custom-exact-repository",
                }
            )
        else:
            debian_targets.append(target)
    return debian_targets, skipped, blockers


materializer.acquisition_targets = acquisition_targets_v3

if __name__ == "__main__":
    raise SystemExit(materializer.main())
