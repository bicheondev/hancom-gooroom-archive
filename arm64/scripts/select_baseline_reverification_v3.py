#!/usr/bin/env python3
"""Select known-success sources that need verification under authority v3."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from source_authority_v3 import (
    exact_build_candidates,
    known_success_names,
    latest_results,
    load_json,
    matrix_document,
)


def current_identity(candidate: dict[str, Any]) -> tuple[str, str]:
    return (
        candidate["source_type"],
        candidate["tree_sha"]
        if candidate["source_type"] == "git"
        else candidate["dsc_sha256"],
    )


def result_identity(row: dict[str, Any]) -> tuple[str, str] | None:
    build_lock = row.get("build_lock") if isinstance(row.get("build_lock"), dict) else {}
    evidence = (
        row.get("source_lock_evidence")
        if isinstance(row.get("source_lock_evidence"), dict)
        else {}
    )
    source_type = row.get("source_type") or build_lock.get("source_type") or evidence.get(
        "source_type"
    )
    if source_type in (None, "", "git"):
        tree = row.get("tree_sha") or build_lock.get("tree_sha") or evidence.get(
            "tree_sha"
        )
        return ("git", tree) if tree else None
    if source_type == "dsc":
        dsc = build_lock.get("dsc") if isinstance(build_lock.get("dsc"), dict) else {}
        if not dsc:
            dsc = evidence.get("dsc") if isinstance(evidence.get("dsc"), dict) else {}
        return ("dsc", dsc.get("sha256")) if dsc.get("sha256") else None
    return None


def verification_passed(path: Path) -> bool:
    verification = path.parent / "verification.json"
    if not verification.exists():
        return False
    try:
        return load_json(verification).get("passed") is True
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lock = load_json(args.lock)
    reference = load_json(args.reference)
    plan = load_json(args.plan)
    candidates = exact_build_candidates(lock, reference)
    latest = latest_results(args.results)
    names = sorted(known_success_names(plan))

    selected = []
    current = []
    blockers = []
    for source in names:
        matches = [row for (name, _), row in candidates.items() if name == source]
        if len(matches) != 1:
            blockers.append(
                {
                    "source": source,
                    "reason": "no-single-exact-build-authority",
                    "match_count": len(matches),
                }
            )
            continue
        candidate = matches[0]
        key = (candidate["source"], candidate["source_version"])
        previous = latest.get(key)
        if previous:
            result, path = previous
            if (
                result.get("passed") is True
                and verification_passed(path)
                and result_identity(result) == current_identity(candidate)
            ):
                current.append(
                    {
                        "source": candidate["source"],
                        "source_version": candidate["source_version"],
                        "source_type": candidate["source_type"],
                        "actions_run_id": result.get("actions_run_id"),
                    }
                )
                continue
        selected.append(candidate)

    selected.sort(key=lambda row: (row["source"], row["source_version"]))
    summary = {
        "schema": 3,
        "policy": "reverify-known-success-on-authority-or-verifier-change",
        "known_success_count": len(names),
        "selected_count": len(selected),
        "already_current_count": len(current),
        "blocker_count": len(blockers),
        "complete_authority_coverage": not blockers,
        "source_type_counts": {
            source_type: sum(row["source_type"] == source_type for row in selected)
            for source_type in sorted({row["source_type"] for row in selected})
        },
    }
    output = {
        "summary": summary,
        "selected": selected,
        "already_current": current,
        "blockers": blockers,
        "matrix": matrix_document(selected),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if not blockers else 2


if __name__ == "__main__":
    raise SystemExit(main())
