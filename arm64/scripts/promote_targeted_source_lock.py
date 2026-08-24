#!/usr/bin/env python3
"""Promote one exact targeted Git result into an effective source lock copy."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root is not an object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--effective-lock", type=Path, required=True)
    parser.add_argument("--targeted-lock", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-lock", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()

    effective = load(args.effective_lock)
    targeted = load(args.targeted_lock)
    if targeted.get("status") != "resolved":
        raise SystemExit(f"targeted lock is not resolved: {targeted.get('status')}")
    if targeted.get("source") != args.source:
        raise SystemExit("targeted lock source does not match requested source")
    if targeted.get("version") != args.version:
        raise SystemExit("targeted lock version does not match requested version")
    selected = targeted.get("selected")
    if not isinstance(selected, dict):
        raise SystemExit("targeted lock has no selected Git record")
    if selected.get("type") not in (None, "git"):
        raise SystemExit("targeted lock selection is not Git")
    if selected.get("declared_source") != args.source:
        raise SystemExit("selected commit changelog declares another source")
    if selected.get("declared_version") != args.version:
        raise SystemExit("selected commit changelog declares another version")
    for field in ("repository_full_name", "commit_sha", "tree_sha"):
        if not selected.get(field):
            raise SystemExit(f"selected exact Git record lacks {field}")

    rows = effective.get("sources")
    if not isinstance(rows, list):
        raise SystemExit("effective source lock lacks a sources list")
    matches = [
        index
        for index, row in enumerate(rows)
        if isinstance(row, dict)
        and row.get("source") == args.source
        and row.get("source_version") == args.version
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one effective row for {args.source} {args.version}; "
            f"found {len(matches)}"
        )
    index = matches[0]
    original = dict(rows[index])
    promoted = dict(original)
    promoted.update(
        {
            "status": "resolved",
            "reason": (
                "promoted from checksum-backed targeted Git history archaeology; "
                "exact debian/changelog Source and Version verified"
            ),
            "selected": selected,
            "exact_matches": targeted.get("exact_matches", [selected]),
            "resolution_policy": "targeted-complete-changelog-history",
            "promotion_evidence": str(args.targeted_lock),
        }
    )
    rows[index] = promoted
    effective["generated_at"] = now()
    effective["promotion"] = {
        "source": args.source,
        "version": args.version,
        "targeted_lock": str(args.targeted_lock),
        "selected": selected,
    }
    args.output_lock.parent.mkdir(parents=True, exist_ok=True)
    args.output_lock.write_text(
        json.dumps(effective, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    evidence = {
        "schema": "hancom-gooroom-targeted-source-promotion-v1",
        "generated_at": now(),
        "status": "promoted",
        "source": args.source,
        "version": args.version,
        "original_status": original.get("status"),
        "original_reason": original.get("reason"),
        "selected": selected,
        "targeted_lock": str(args.targeted_lock),
        "output_lock": str(args.output_lock),
    }
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(evidence, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
