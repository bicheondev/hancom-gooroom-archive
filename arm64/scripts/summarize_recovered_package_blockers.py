#!/usr/bin/env python3
"""Create a compact, reviewable summary of recovered ARM64 package blockers."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--blockers", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    blockers = load(args.blockers)
    recovery_summary = load(args.summary)
    if not isinstance(blockers, list):
        raise SystemExit("blockers document must be a JSON list")
    expected = int(recovery_summary.get("blocker_count", -1))
    if expected != len(blockers):
        raise SystemExit(
            f"blocker count mismatch: summary={expected}, blockers={len(blockers)}"
        )

    rows: list[dict[str, Any]] = []
    reason_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    source_packages: dict[str, list[str]] = defaultdict(list)

    for blocker in blockers:
        candidate = blocker.get("candidate") or {}
        payload = blocker.get("payload_audit") or {}
        available = blocker.get("available_candidates") or []
        source = blocker.get("source") or candidate.get("source") or "unknown"
        source_version = (
            blocker.get("source_version")
            or candidate.get("source_version")
            or ""
        )
        reason = blocker.get("reason") or "unknown"
        reference_package = blocker.get("reference_package") or ""
        available_identities = [
            {
                "filename": item.get("filename") or "",
                "version": item.get("version") or "",
                "architecture": item.get("architecture") or "",
                "source": item.get("source") or "",
                "source_version": item.get("source_version") or "",
            }
            for item in available
        ]
        row = {
            "reference_package": reference_package,
            "target_package": blocker.get("target_package") or "",
            "reason": reason,
            "source": source,
            "source_version": source_version,
            "disposition": blocker.get("disposition") or "",
            "target_architecture": blocker.get("target_architecture") or "",
            "candidate_version": candidate.get("version") or "",
            "candidate_architecture": candidate.get("architecture") or "",
            "candidate_sha256": candidate.get("sha256") or "",
            "x86_payload_count": len(payload.get("x86") or []),
            "foreign_payload_count": len(payload.get("foreign") or []),
            "embedded_firmware_payload_count": len(
                payload.get("embedded_firmware") or []
            ),
            "available_candidate_count": len(available),
            "available_candidates": available_identities,
        }
        rows.append(row)
        reason_counts[reason] += 1
        source_counts[f"{source}={source_version}"] += 1
        source_packages[f"{source}={source_version}"].append(reference_package)

    rows.sort(
        key=lambda row: (
            row["reason"],
            row["source"],
            row["source_version"],
            row["reference_package"],
        )
    )
    source_groups = [
        {
            "source": identity.split("=", 1)[0],
            "source_version": identity.split("=", 1)[1],
            "blocker_count": count,
            "reference_packages": sorted(source_packages[identity]),
        }
        for identity, count in sorted(source_counts.items())
    ]
    compact = {
        "schema": 1,
        "recovery_policy": recovery_summary.get("policy"),
        "reference_package_count": recovery_summary.get("reference_package_count"),
        "selected_package_count": recovery_summary.get("selected_package_count"),
        "excluded_package_count": recovery_summary.get("excluded_package_count"),
        "blocker_count": len(rows),
        "reason_counts": dict(sorted(reason_counts.items())),
        "source_group_count": len(source_groups),
        "source_groups": source_groups,
        "blockers": rows,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "compact-blockers.json").write_text(
        json.dumps(compact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with (args.output_dir / "compact-blockers.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(rows[0]) if rows else [],
            delimiter="\t",
        )
        if rows:
            writer.writeheader()
            writer.writerows(rows)
    print(json.dumps(compact, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
