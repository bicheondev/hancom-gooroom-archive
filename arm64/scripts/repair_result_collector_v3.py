#!/usr/bin/env python3
"""Preserve infrastructure retry identity in compact rebuild results."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()

    text = args.target.read_text(encoding="utf-8")
    anchor = '''            "retry_reason": job.get("retry_reason"),
'''
    insertion = anchor + '''            "builder_sha256": job.get("builder_sha256"),
            "previous_builder_sha256": job.get("previous_builder_sha256"),
            "infrastructure_evidence": job.get("infrastructure_evidence", []),
'''
    if '"builder_sha256": job.get("builder_sha256")' in text:
        print("collector identity fields already installed")
        return 0
    count = text.count(anchor)
    if count != 1:
        raise SystemExit(f"expected one retry_reason field, found {count}")
    args.target.write_text(text.replace(anchor, insertion, 1), encoding="utf-8")
    print(f"updated {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
