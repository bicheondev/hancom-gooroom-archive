#!/usr/bin/env python3
"""Recover exact vendor .deb files from the historical indexes embedded in the ISO.

The AMD64 ISO's preserved Packages files are authoritative for filename, size,
and SHA-256. A file is accepted only if all three match the installed package
name/version/architecture from the immutable reference manifest.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable


def parse_deb822(text: str) -> Iterable[dict[str, str]]:
    stanza: dict[str, str] = {}
    current: str | None = None
    for raw in text.splitlines():
        if not raw.strip():
            if stanza:
                yield stanza
                stanza = {}
                current = None
            continue
        if raw[0].isspace():
            if current:
                stanza[current] += "\n" + raw[1:]
            continue
        if ":" not in raw:
            continue
        current, value = raw.split(":", 1)
        stanza[current] = value.lstrip()
    if stanza:
        yield stanza


def load_indexes(paths: list[Path], metadata_json: list[str]) -> list[dict[str, Any]]:
    if len(paths) != len(metadata_json):
        raise ValueError("--packages and --packages-metadata counts must match")
    rows: list[dict[str, Any]] = []
    for path, raw_meta in zip(paths, metadata_json):
        meta = json.loads(raw_meta)
        for stanza in parse_deb822(path.read_text(encoding="utf-8", errors="replace")):
            if not all(stanza.get(key) for key in ("Package", "Version", "Architecture", "Filename", "Size", "SHA256")):
                continue
            row: dict[str, Any] = dict(stanza)
            row["index"] = {**meta, "path": str(path)}
            rows.append(row)
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def choose(candidates: list[dict[str, Any]], version: str) -> tuple[dict[str, Any] | None, str]:
    if not candidates:
        return None, "absent-from-iso-preserved-indexes"
    identities = {(row["Size"], row["SHA256"], row["Filename"]) for row in candidates}
    if len(identities) == 1:
        return sorted(candidates, key=lambda row: row["index"]["repository"])[0], "identical-index-records"
    preferred = "hancom" if "+han" in version else "gooroom"
    preferred_rows = [row for row in candidates if row["index"].get("repository") == preferred]
    if len(preferred_rows) == 1:
        return preferred_rows[0], f"preferred-{preferred}-repository"
    return None, "ambiguous-nonidentical-index-records"


def download_one(task: dict[str, Any], download_dir: Path, attempts: int) -> dict[str, Any]:
    row = task["selected"]
    base_url = row["index"]["base_url"].rstrip("/")
    url = f"{base_url}/{row['Filename'].lstrip('/')}"
    filename = Path(row["Filename"]).name
    destination = download_dir / filename
    temporary = destination.with_suffix(destination.suffix + ".partial")
    expected_size = int(row["Size"])
    expected_sha256 = row["SHA256"].lower()

    error = ""
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "hancom-gooroom-arm64-lock/1"})
            with urllib.request.urlopen(request, timeout=180) as response, temporary.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            actual_size = temporary.stat().st_size
            actual_sha256 = sha256_file(temporary)
            if actual_size != expected_size:
                raise RuntimeError(f"size mismatch {actual_size} != {expected_size}")
            if actual_sha256 != expected_sha256:
                raise RuntimeError(f"sha256 mismatch {actual_sha256} != {expected_sha256}")
            temporary.replace(destination)
            task.update(
                status="verified",
                url=url,
                local_filename=filename,
                actual_size=actual_size,
                actual_sha256=actual_sha256,
                attempts=attempt,
            )
            return task
        except Exception as exc:  # preserve exact failure evidence
            error = f"{type(exc).__name__}: {exc}"
            temporary.unlink(missing_ok=True)
    task.update(status="download-failed", url=url, error=error, attempts=attempts)
    return task


def inspect_deb(path: Path) -> dict[str, Any]:
    fields = subprocess.check_output(
        ["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture", "Source"],
        text=True,
        stderr=subprocess.STDOUT,
    ).splitlines()
    while len(fields) < 4:
        fields.append("")
    listing = subprocess.check_output(["dpkg-deb", "-c", str(path)], text=True, stderr=subprocess.STDOUT)
    return {
        "control_package": fields[0],
        "control_version": fields[1],
        "control_architecture": fields[2],
        "control_source": fields[3],
        "payload_entry_count": len([line for line in listing.splitlines() if line.strip()]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--packages", action="append", required=True, type=Path)
    parser.add_argument("--packages-metadata", action="append", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--download-dir", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--attempts", type=int, default=4)
    args = parser.parse_args()

    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    records = load_indexes(args.packages, args.packages_metadata)
    by_identity: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in records:
        by_identity.setdefault((row["Package"], row["Version"], row["Architecture"]), []).append(row)

    custom_sources = {
        (source["source"], source["source_version"])
        for source in reference["sources"]
        if source.get("custom_candidate")
    }
    targets = [
        package
        for package in reference["packages"]
        if (package["source"], package["source_version"]) in custom_sources
    ]

    tasks: list[dict[str, Any]] = []
    for package in sorted(targets, key=lambda row: row["package"]):
        candidates = by_identity.get((package["package"], package["version"], package["architecture"]), [])
        selected, reason = choose(candidates, package["version"])
        tasks.append(
            {
                "package": package["package"],
                "version": package["version"],
                "architecture": package["architecture"],
                "source": package["source"],
                "source_version": package["source_version"],
                "status": "selected" if selected else "unresolved-index",
                "selection_reason": reason,
                "selected": selected,
                "candidate_count": len(candidates),
            }
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.download_dir.mkdir(parents=True, exist_ok=True)
    selected_tasks = [task for task in tasks if task["selected"] is not None]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_map = {
            executor.submit(download_one, task, args.download_dir, args.attempts): task
            for task in selected_tasks
        }
        for future in concurrent.futures.as_completed(future_map):
            result = future.result()
            print(f"{result['status']}: {result['package']} {result['version']}", file=sys.stderr)

    for task in tasks:
        if task.get("status") != "verified":
            continue
        deb_path = args.download_dir / task["local_filename"]
        inspection = inspect_deb(deb_path)
        task["inspection"] = inspection
        if (
            inspection["control_package"] != task["package"]
            or inspection["control_version"] != task["version"]
            or inspection["control_architecture"] != task["architecture"]
        ):
            task["status"] = "control-mismatch"

    status_counts: dict[str, int] = {}
    for task in tasks:
        status_counts[task["status"]] = status_counts.get(task["status"], 0) + 1
    summary = {
        "schema": 1,
        "policy": "exact-binary-from-iso-preserved-vendor-index",
        "target_count": len(tasks),
        "status_counts": dict(sorted(status_counts.items())),
        "verified_count": status_counts.get("verified", 0),
        "unresolved_count": len(tasks) - status_counts.get("verified", 0),
        "verified_bytes": sum(int(task.get("actual_size", 0)) for task in tasks),
        "index_record_count": len(records),
    }
    manifest = {"summary": summary, "packages": tasks}
    (args.output_dir / "vendor-binary-lock.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "vendor-binary-lock-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "vendor-binary-unresolved.json").write_text(
        json.dumps([task for task in tasks if task["status"] != "verified"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["unresolved_count"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
