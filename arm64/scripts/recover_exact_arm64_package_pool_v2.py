#!/usr/bin/env python3
"""Version-2 policy front-end for exact ARM64 package-pool recovery."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import recover_exact_arm64_package_pool as base


REFERENCE_ISO_SHA256 = "ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a"
ORIGINAL_REFERENCE_TARGETS = base.reference_targets
ORIGINAL_CANDIDATE_METADATA = base.candidate_metadata


def reference_targets_v2(reference: dict[str, Any]) -> list[dict[str, Any]]:
    rows = ORIGINAL_REFERENCE_TARGETS(reference)
    linux_sources = [
        source
        for source in reference.get("sources", [])
        if source.get("source") == "linux"
    ]
    if len(linux_sources) != 1:
        raise RuntimeError(f"expected one exact linux source lock, got {len(linux_sources)}")
    linux_source_version = linux_sources[0]["source_version"]

    for row in rows:
        row["target_source"] = row["source"]
        row["target_source_version"] = row["source_version"]
        row["generated_replacement_policy"] = None
        if row["package"] == "linux-image-5.10.0-23-amd64":
            row["target_source"] = "linux"
            row["target_source_version"] = linux_source_version
            row["reason"] = (
                "real ARM64 kernel must come from the exact linux source version "
                f"{linux_source_version}"
            )
        elif row["package"] == "linux-image-amd64":
            row["target_source"] = "hancom-gooroom-arm64-arch-replacements"
            row["target_source_version"] = None
            row["generated_replacement_policy"] = (
                "config-only-arm64-metapackage"
            )
            row["reason"] = (
                "config-only metapackage with immutable reference fields and an "
                "exact dependency on linux-image-5.10.0-23-arm64"
            )
    return rows


def candidate_metadata_v2(path: Path) -> dict[str, Any]:
    row = ORIGINAL_CANDIDATE_METADATA(path)
    for field, key in (
        ("X-Hancom-Gooroom-Reference-Package", "reference_package"),
        ("X-Hancom-Gooroom-Reference-Version", "reference_version"),
        ("X-Hancom-Gooroom-Reference-Architecture", "reference_architecture"),
        ("X-Hancom-Gooroom-Reference-ISO-SHA256", "reference_iso_sha256"),
        ("X-Hancom-Gooroom-Replacement-Policy", "replacement_policy"),
        ("X-Hancom-Gooroom-Required-Kernel", "required_kernel"),
    ):
        row[key] = base.deb_field(path, field)
    return row


def match_quality_v2(
    target: dict[str, Any], candidate: dict[str, Any]
) -> tuple[int, str]:
    if candidate["package"] != target["target_package"]:
        return 0, "package-name"
    if candidate["architecture"] != target["target_architecture"]:
        return 0, "architecture"

    if target.get("generated_replacement_policy"):
        fields_match = (
            candidate.get("source") == "hancom-gooroom-arm64-arch-replacements"
            and candidate.get("reference_package") == target["package"]
            and candidate.get("reference_version") == target["version"]
            and candidate.get("reference_architecture")
            == target["architecture"]
            and candidate.get("reference_iso_sha256") == REFERENCE_ISO_SHA256
            and candidate.get("replacement_policy")
            == target["generated_replacement_policy"]
            and candidate.get("version") == target["version"]
        )
        if fields_match:
            return 4, "audited-config-only-architecture-replacement"
        return 0, "generated-replacement-control-fields"

    if candidate["source"] != target.get("target_source", target["source"]):
        return 0, "source-name"
    if candidate["source_version"] != target.get(
        "target_source_version", target["source_version"]
    ):
        return 0, "source-version"
    if candidate["version"] == target["version"]:
        return 3, "exact-binary-and-source-version"
    if base.strip_binnmu(candidate["version"]) == base.strip_binnmu(
        target["version"]
    ):
        return 2, "exact-source-version-architecture-binnmu"
    if target["disposition"] == "arch-replace":
        return 1, "exact-source-version-architecture-replacement"
    return 0, "binary-version"


base.reference_targets = reference_targets_v2
base.candidate_metadata = candidate_metadata_v2
base.match_quality = match_quality_v2

if __name__ == "__main__":
    raise SystemExit(base.main())
