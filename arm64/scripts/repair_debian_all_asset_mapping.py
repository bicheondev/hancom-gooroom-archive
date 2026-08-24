#!/usr/bin/env python3
"""Lock exact Debian assets for non-vendor Architecture: all packages."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()

    text = args.target.read_text(encoding="utf-8")
    old = '''        if package["architecture"] == "all":
            row.update(
                status="reuse-exact-all",
                arm64_package=package["package"],
                arm64_version=package["version"],
                reason="Architecture: all payload is preserved from the AMD64 reference",
            )
        elif package["package"] in CUSTOM_REPLACE:
'''
    new = '''        if package["architecture"] == "all":
            row["arm64_package"] = package["package"]
            if (package["source"], package["source_version"]) in custom:
                row.update(
                    status="reuse-exact-all",
                    arm64_version=package["version"],
                    reason=(
                        "exact vendor Architecture: all payload is preserved from "
                        "the AMD64 reference and acquired through the vendor lock"
                    ),
                )
            else:
                selected_record, mode, error = select_package(
                    args.apt_config,
                    package["package"],
                    package["version"],
                    package["source"],
                    package["source_version"],
                )
                if selected_record is None or mode != "exact":
                    row.update(
                        status="missing-exact-all",
                        arm64_version=package["version"],
                        reason=(
                            "no unambiguous Architecture: all binary from the exact "
                            "Debian source and binary version"
                            + (f": {error}" if error else "")
                        ),
                    )
                else:
                    metadata, metadata_error = selected_metadata(
                        args.apt_config,
                        package["package"],
                        selected_record,
                        uri_cache,
                    )
                    if metadata is None or metadata.get("architecture") != "all":
                        row.update(
                            status="missing-download-metadata",
                            arm64_version=package["version"],
                            reason=metadata_error or "selected package is not Architecture: all",
                        )
                    else:
                        row.update(
                            status="reuse-exact-all",
                            arm64_version=metadata["version"],
                            selected=metadata,
                            reason=(
                                "exact Architecture: all binary, source version, URL, "
                                "size and SHA-256 locked"
                            ),
                        )
        elif package["package"] in CUSTOM_REPLACE:
'''
    if old not in text and "missing-exact-all" in text:
        print("non-vendor Architecture: all asset mapping already installed")
        return 0
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one Architecture: all branch, found {count}")
    args.target.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"updated {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
