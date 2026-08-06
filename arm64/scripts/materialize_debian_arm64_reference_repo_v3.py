#!/usr/bin/env python3
"""Materialize Debian-owned exact ARM64/all package routes.

Architecture replacements are split by source provenance:

* ordinary Debian replacements such as binutils-aarch64-linux-gnu and
  grub-efi-arm64 remain in the Debian reference repository at the exact source
  version recorded by the AMD64 image;
* Gooroom/Hancom-patched replacements such as the ARM64 kernel remain in the
  separately verified custom rebuild repository.

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

    custom_source_identities = {
        (str(row.get("source", "")), str(row.get("source_version", "")))
        for row in reference.get("packages", [])
        if row.get("custom_candidate")
    }

    debian_targets: list[dict[str, Any]] = []
    for target in targets:
        if target.get("mapping_status") != "arch-replace":
            debian_targets.append(target)
            continue

        identity = (
            str(target.get("source", "")),
            str(target.get("source_version", "")),
        )
        if identity in custom_source_identities:
            skipped.append(
                {
                    **target,
                    "reason": "custom-architecture-replacement-from-exact-rebuild-repository",
                }
            )
            continue

        # This is a Debian-owned architecture replacement. The v2 verifier will
        # still require the replacement binary's Source and source Version to
        # match target['source']/target['source_version'] exactly.
        debian_targets.append(target)

    return debian_targets, skipped, blockers


materializer.acquisition_targets = acquisition_targets_v3

if __name__ == "__main__":
    raise SystemExit(materializer.main())
