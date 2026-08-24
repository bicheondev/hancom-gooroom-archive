#!/usr/bin/env python3
"""Install a backward-compatible dependency materializer summary schema."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()

    text = args.target.read_text(encoding="utf-8")
    old = '''    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\\n", encoding="utf-8"
    )
'''
    new = '''    # Preserve the original top-level summary fields for workflow shell
    # consumers while also exposing the complete lock shape expected by the
    # dependency retry selector. This is intentionally redundant and hashed.
    summary_document = {
        **summary,
        "summary": summary,
        "packages": package_rows,
        "blockers": blockers,
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary_document, ensure_ascii=False, indent=2) + "\\n",
        encoding="utf-8",
    )
'''
    count = text.count(old)
    if count == 0 and "summary_document = {" in text:
        print("compatibility schema already installed")
        return 0
    if count != 1:
        raise SystemExit(f"expected one summary writer, found {count}")
    args.target.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"updated {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
