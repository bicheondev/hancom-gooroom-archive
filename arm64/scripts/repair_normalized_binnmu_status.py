#!/usr/bin/env python3
"""Teach the package-map normalizer the source-exact binNMU dispositions."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()

    text = args.target.read_text(encoding="utf-8")
    anchor = '''        "exact",
    }
'''
    replacement = '''        "exact",
        "source-exact-binnmu",
        "source-exact-arch-binnmu",
    }
'''
    if '"source-exact-binnmu"' in text:
        print("source-exact binNMU aliases already installed")
        return 0
    count = text.count(anchor)
    if count != 1:
        raise SystemExit(f"expected one exact alias terminator, found {count}")
    args.target.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")
    print(f"updated {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
