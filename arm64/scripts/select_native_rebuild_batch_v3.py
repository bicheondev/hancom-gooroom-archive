#!/usr/bin/env python3
"""Select one curated native ARM64 batch from Git-or-DSC authorities."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from source_authority_v3 import (
    batch_source_names,
    exact_build_candidates,
    load_json,
    matrix_document,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--batch", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lock = load_json(args.lock)
    reference = load_json(args.reference)
    plan = load_json(args.plan)
    requested = sorted(batch_source_names(plan, args.batch))
    candidates = exact_build_candidates(lock, reference)

    selected = []
    blockers = []
    for source in requested:
        matches = [
            row for (name, _), row in candidates.items() if name == source
        ]
        if len(matches) != 1:
            blockers.append(
                {
                    "source": source,
                    "reason": "no-single-exact-build-authority",
                    "match_count": len(matches),
                }
            )
            continue
        selected.append(matches[0])

    selected.sort(key=lambda row: (row["source"], row["source_version"]))
    summary = {
        "schema": 3,
        "policy": "curated-exact-source-authority-batch",
        "batch": args.batch,
        "requested_count": len(requested),
        "selected_count": len(selected),
        "blocker_count": len(blockers),
        "complete": bool(requested) and not blockers,
        "source_type_counts": {
            source_type: sum(row["source_type"] == source_type for row in selected)
            for source_type in sorted({row["source_type"] for row in selected})
        },
    }
    output = {
        "summary": summary,
        "requested_sources": requested,
        "selected": selected,
        "blockers": blockers,
        "matrix": matrix_document(selected),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if summary["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
