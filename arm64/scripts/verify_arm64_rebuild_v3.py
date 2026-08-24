#!/usr/bin/env python3
"""Dispatch ARM64 rebuild verification by exact source authority type."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--source", required=True)
    known, _ = parser.parse_known_args()

    document = json.loads(known.lock.read_text(encoding="utf-8"))
    matches = [
        row
        for row in document.get("sources", [])
        if row.get("source") == known.source
        and row.get("status") == "resolved"
        and isinstance(row.get("selected"), dict)
    ]
    if len(matches) != 1:
        print(
            f"expected one resolved source authority for {known.source}, found {len(matches)}",
            file=sys.stderr,
        )
        return 2
    selected_type = matches[0]["selected"].get("type", "git")
    if selected_type == "git":
        script = Path(__file__).with_name("verify_arm64_rebuild.py")
    elif selected_type == "dsc":
        script = Path(__file__).with_name("verify_arm64_dsc_rebuild.py")
    else:
        print(
            f"unsupported source authority type for {known.source}: {selected_type}",
            file=sys.stderr,
        )
        return 2
    return subprocess.call([sys.executable, str(script), *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
