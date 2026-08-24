#!/usr/bin/env python3
"""Promote one exact Debian source archive into an effective lock copy."""

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
    parser.add_argument("--archive-lock", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-lock", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()

    effective = load(args.effective_lock)
    archive = load(args.archive_lock)
    if archive.get("status") != "resolved":
        raise SystemExit(f"source archive is not resolved: {archive.get('status')}")
    if archive.get("source") != args.source or archive.get("version") != args.version:
        raise SystemExit("source archive identity does not match requested source/version")
    dsc = archive.get("dsc")
    files = archive.get("files")
    if not isinstance(dsc, dict) or not dsc.get("sha256") or not dsc.get("filename"):
        raise SystemExit("source archive lock lacks an immutable .dsc record")
    if not isinstance(files, list) or not files:
        raise SystemExit("source archive lock lacks verified source files")
    for item in files:
        if not isinstance(item, dict) or item.get("status") != "verified":
            raise SystemExit("source archive contains an unverified file record")
        for field in ("filename", "size", "sha256"):
            if item.get(field) in (None, ""):
                raise SystemExit(f"source archive file record lacks {field}")

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
            f"expected one effective row for {args.source} {args.version}; "
            f"found {len(matches)}"
        )
    index = matches[0]
    original = dict(rows[index])
    selected = {
        "type": "debian-source-archive",
        "declared_source": args.source,
        "declared_version": args.version,
        "dsc_filename": dsc["filename"],
        "dsc_url": dsc.get("url"),
        "dsc_sha256": dsc["sha256"],
        "dsc_size": dsc.get("size"),
        "files": files,
    }
    promoted = dict(original)
    promoted.update(
        {
            "status": "resolved",
            "reason": (
                "promoted from an exact Debian source archive whose .dsc and "
                "every Checksums-Sha256 file were verified"
            ),
            "selected": selected,
            "resolution_policy": "exact-dsc-checksums-sha256",
            "promotion_evidence": str(args.archive_lock),
        }
    )
    rows[index] = promoted
    effective["generated_at"] = now()
    effective["promotion"] = {
        "source": args.source,
        "version": args.version,
        "archive_lock": str(args.archive_lock),
        "selected": selected,
    }
    args.output_lock.parent.mkdir(parents=True, exist_ok=True)
    args.output_lock.write_text(
        json.dumps(effective, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    evidence = {
        "schema": "hancom-gooroom-source-archive-promotion-v1",
        "generated_at": now(),
        "status": "promoted",
        "source": args.source,
        "version": args.version,
        "original_status": original.get("status"),
        "original_reason": original.get("reason"),
        "selected": selected,
        "archive_lock": str(args.archive_lock),
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
