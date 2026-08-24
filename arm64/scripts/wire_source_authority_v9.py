#!/usr/bin/env python3
"""Apply full source integration with collector CLI compatibility v4."""

from __future__ import annotations

import argparse
from pathlib import Path

import wire_source_authority_v8 as previous


OLD = "arm64/scripts/collect_native_rebuild_results_v3.py"
NEW = "arm64/scripts/collect_native_rebuild_results_v4.py"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    args = parser.parse_args()
    previous.main()
    root = args.repository_root
    for path in sorted((root / ".github/workflows").glob("*.yml")):
        path.write_text(
            path.read_text(encoding="utf-8").replace(OLD, NEW),
            encoding="utf-8",
        )
    for path in (
        root / "arm64/scripts/wire_progress_dispatches.py",
        root / "arm64/scripts/audit_active_arm64_pipeline.py",
    ):
        if path.exists():
            path.write_text(
                path.read_text(encoding="utf-8").replace(OLD, NEW),
                encoding="utf-8",
            )
    audit = root / "arm64/scripts/audit_active_arm64_pipeline.py"
    if audit.exists():
        text = audit.read_text(encoding="utf-8")
        line = '    "arm64/scripts/collect_native_rebuild_results_v4.py",\n'
        if '"arm64/scripts/collect_native_rebuild_results_v4.py"' not in text:
            text = text.replace("REQUIRED_SCRIPTS = {\n", "REQUIRED_SCRIPTS = {\n" + line, 1)
        audit.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
