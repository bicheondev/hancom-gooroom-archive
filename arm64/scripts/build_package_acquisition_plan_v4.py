#!/usr/bin/env python3
"""Normalize acquisition v3 methods to the strict materializer contract."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import build_package_acquisition_plan_v3 as base


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args, _ = parser.parse_known_args()

    rc = base.main()
    plan_path = args.output_dir / "package-acquisition-plan.json"
    if not plan_path.exists():
        return rc or 2
    document = json.loads(plan_path.read_text(encoding="utf-8"))
    for row in document.get("packages", []):
        acquisition = row.get("acquisition")
        if not isinstance(acquisition, dict):
            continue
        if acquisition.get("method") == "download-architecture-replacement":
            acquisition["method"] = "download-debian-exact"
            acquisition["architecture_replacement"] = True

    methods = Counter(
        row["acquisition"]["method"]
        for row in document.get("packages", [])
        if isinstance(row.get("acquisition"), dict)
    )
    summary = document.get("summary", {})
    summary.update(
        {
            "schema": 4,
            "policy": "persistent-exact-downloads-with-materializer-compatible-methods",
            "method_counts": dict(sorted(methods.items())),
        }
    )
    document["summary"] = summary
    plan_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
