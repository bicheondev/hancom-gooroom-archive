#!/usr/bin/env python3
"""Apply the final one-byte Hancom applauncher indicator-size source delta."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SOURCE_PATH = Path("src/applauncher-indicator.c")
BEFORE_SHA256 = "9f7f964da0646718d23b949d0ab256bb4dc8a5582e33ae215d58ba9f39827ebd"
AFTER_SHA256 = "08d312123f530f2d13908fea61498ed4e0b28b1bab24a197c95ba55d948c00f0"
OLD = "gtk_image_set_pixel_size (GTK_IMAGE (icon), 16);"
NEW = "gtk_image_set_pixel_size (GTK_IMAGE (icon), 6);"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = args.source_dir.resolve() / SOURCE_PATH
    if not source.is_file():
        raise SystemExit(f"source file is missing: {source}")

    before = sha256_file(source)
    if before != BEFORE_SHA256:
        raise RuntimeError(
            f"unexpected preimage for {SOURCE_PATH}: {before} != {BEFORE_SHA256}"
        )

    text = source.read_text(encoding="utf-8")
    count = text.count(OLD)
    if count != 1:
        raise RuntimeError(f"expected one indicator-size expression, found {count}")
    source.write_text(text.replace(OLD, NEW), encoding="utf-8")

    after = sha256_file(source)
    if after != AFTER_SHA256:
        raise RuntimeError(
            f"unexpected reconstructed hash for {SOURCE_PATH}: "
            f"{after} != {AFTER_SHA256}"
        )

    evidence = {
        "schema": 1,
        "reconstruction_complete": True,
        "source_path": SOURCE_PATH.as_posix(),
        "before_sha256": before,
        "after_sha256": after,
        "source_delta": {
            "function": "applauncher_indicator_append",
            "call": "gtk_image_set_pixel_size",
            "public_value": 16,
            "hancom_value": 6,
        },
        "binary_evidence": {
            "section": ".text",
            "file_offset": "0x96cf",
            "target_byte": "0x06",
            "reconstructed_preimage_byte": "0x10",
            "note": "The surrounding instruction is mov esi, imm32; all other .text bytes matched before this source correction.",
        },
        "claims": {
            "source_status": "reconstructed-candidate",
            "binary_validation_status": "not-yet-run",
            "byte_identity_claimed": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
