#!/usr/bin/env python3
"""Make the exact Git builder checksum manifest independent of runner paths."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()

    text = args.target.read_text(encoding="utf-8")
    old = '''find "$OUTPUT_DIR_ABS" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \\
  | sort -z \\
  | xargs -0 sha256sum \\
  > "$OUTPUT_DIR_ABS/SHA256SUMS"
'''
    new = '''(
  cd "$OUTPUT_DIR_ABS"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \\
    | sort -z \\
    | xargs -0 sha256sum \\
    > SHA256SUMS
)
'''
    if old not in text and new in text:
        print("portable checksum block already installed")
        return 0
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one absolute checksum block, found {count}")
    args.target.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"updated {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
