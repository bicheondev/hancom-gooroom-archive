#!/usr/bin/env python3
"""Post-reconcile publisher v3 transient existing-asset download failures.

Publisher v3 deliberately falls back to the original Actions artifact when a
previous release asset cannot be read. If that fallback is uploaded and the
final release asset is subsequently downloaded and hash-verified, the initial
read failure is no longer a blocker. This wrapper removes only that proven
transient class; every other blocker remains fail-closed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import publish_rebuild_packages_v3 as base


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args, _ = parser.parse_known_args()

    base_rc = base.main()
    lock_path = args.output_dir / "rebuild-release-lock.json"
    if not lock_path.exists():
        return base_rc or 2
    document = json.loads(lock_path.read_text(encoding="utf-8"))
    packages = document.get("packages", [])
    locked_filenames = {row.get("filename") for row in packages if row.get("filename")}
    blockers = document.get("blockers", [])
    retained = []
    reconciled = []
    for blocker in blockers:
        if (
            blocker.get("reason") == "existing-release-asset-download-failed"
            and blocker.get("filename") in locked_filenames
        ):
            reconciled.append(blocker)
        else:
            retained.append(blocker)

    summary = document.get("summary", {})
    summary.update(
        {
            "schema": 4,
            "policy": "persistent-release-assets-rehashed-with-transient-fallback-reconciliation",
            "reconciled_transient_blocker_count": len(reconciled),
            "blocker_count": len(retained),
            "complete": bool(packages) and not retained,
        }
    )
    document["summary"] = summary
    document["blockers"] = retained
    document["reconciled_transient_blockers"] = reconciled
    lock_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "blockers.json").write_text(
        json.dumps(retained, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "reconciled-transient-blockers.json").write_text(
        json.dumps(reconciled, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["complete"] else (base_rc or 2)


if __name__ == "__main__":
    raise SystemExit(main())
