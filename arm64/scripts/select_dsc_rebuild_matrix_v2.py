#!/usr/bin/env python3
"""Select exact signed .dsc sources that require native ARM64 rebuilds."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    document = json.loads(args.lock.read_text(encoding="utf-8"))
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for row in document.get("sources", []):
        source = row.get("source")
        version = row.get("source_version")
        selection = row.get("selected") or {}
        if row.get("role") != "rebuild-arm64":
            continue
        if row.get("status") != "resolved" or selection.get("type") != "dsc":
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "not-a-resolved-dsc-rebuild",
                    "status": row.get("status"),
                    "selected_type": selection.get("type"),
                }
            )
            continue
        if selection.get("signature_valid") is not True:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "signature-not-verified",
                }
            )
            continue
        components = selection.get("components") or []
        if not components or not all(component.get("verified") is True for component in components):
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "source-components-not-verified",
                }
            )
            continue
        native_packages = row.get("native_binary_packages") or []
        if not native_packages:
            skipped.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "no-native-binary-package",
                }
            )
            continue
        selected.append(
            {
                "source": source,
                "source_version": version,
                "required_native_packages": native_packages,
                "required_native_packages_space": " ".join(native_packages),
                "artifact_name": (
                    f"arm64-dsc-rebuild-{safe(source)}-{safe(version)}"
                ),
                "dsc_url": selection["url"],
                "dsc_sha256": selection["dsc_sha256"],
                "dsc_size": int(selection["dsc_size"]),
                "repository": selection.get("repository"),
            }
        )

    selected.sort(key=lambda row: (row["source"], row["source_version"]))
    result = {
        "schema": 1,
        "policy": "resolved-exact-signed-dsc-native-rebuilds-only",
        "selected_count": len(selected),
        "skipped_count": len(skipped),
        "selected": selected,
        "skipped": skipped,
        "matrix": {"include": selected},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
