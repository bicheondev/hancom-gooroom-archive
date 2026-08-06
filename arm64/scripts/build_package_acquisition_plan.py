#!/usr/bin/env python3
"""Merge normalized mappings, vendor locks, and rebuild evidence into fetch plan."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def artifact_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")


def latest_rebuild_results(root: Path) -> dict[tuple[str, str], tuple[dict[str, Any], Path]]:
    rows: dict[tuple[str, str], tuple[dict[str, Any], Path]] = {}
    if not root.exists():
        return rows
    for path in root.rglob("result.json"):
        try:
            row = load_json(path)
        except Exception:
            continue
        source = row.get("source")
        version = row.get("source_version")
        if not source or not version:
            continue
        key = (source, version)
        try:
            run_id = int(str(row.get("actions_run_id", "0")))
        except ValueError:
            run_id = 0
        current = rows.get(key)
        try:
            current_run_id = int(str(current[0].get("actions_run_id", "0"))) if current else -1
        except ValueError:
            current_run_id = -1
        if current is None or run_id >= current_run_id:
            rows[key] = (row, path)
    return rows


def vendor_index(document: dict[str, Any]) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    result: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in document.get("packages", []):
        key = (row.get("package"), row.get("version"), row.get("architecture"))
        if all(key):
            result.setdefault(key, []).append(row)
    return result


def verified_vendor(row: dict[str, Any]) -> dict[str, Any] | None:
    if row.get("status") != "verified":
        return None
    url = row.get("url")
    sha256 = row.get("actual_sha256") or (
        (row.get("selected") or {}).get("SHA256")
        if isinstance(row.get("selected"), dict)
        else None
    )
    size = row.get("actual_size") or (
        (row.get("selected") or {}).get("Size")
        if isinstance(row.get("selected"), dict)
        else None
    )
    filename = row.get("local_filename") or (
        Path((row.get("selected") or {}).get("Filename", "")).name
        if isinstance(row.get("selected"), dict)
        else None
    )
    if not all((url, sha256, size, filename)):
        return None
    return {
        "method": "download-vendor-exact",
        "url": url,
        "filename": filename,
        "sha256": str(sha256).lower(),
        "size": int(size),
    }


def normalized_download(row: dict[str, Any], expected_architecture: str) -> dict[str, Any] | None:
    selected = row.get("selected") or {}
    if not isinstance(selected, dict):
        return None
    package = selected.get("package")
    version = selected.get("version")
    architecture = selected.get("architecture")
    if package not in (None, row["package"]):
        return None
    if version not in (None, row["reference_version"]):
        return None
    if architecture not in (None, expected_architecture):
        return None
    url = selected.get("url")
    filename = selected.get("filename")
    sha256 = selected.get("sha256")
    size = selected.get("size")
    if not filename and url:
        filename = Path(str(url)).name
    if not all((url, filename, sha256, size)):
        return None
    return {
        "method": "download-normalized-exact",
        "url": url,
        "filename": filename,
        "sha256": str(sha256).lower(),
        "size": int(size),
    }


def rebuilt_binary(
    result_entry: tuple[dict[str, Any], Path] | None,
    package: str,
    source: str,
    source_version: str,
) -> dict[str, Any] | None:
    if not result_entry:
        return None
    result, result_path = result_entry
    if result.get("passed") is not True:
        return None
    verification_path = result_path.parent / "verification.json"
    if not verification_path.exists():
        return None
    verification = load_json(verification_path)
    if verification.get("passed") is not True:
        return None
    package_rows = [
        row for row in verification.get("packages", []) if row.get("package") == package
    ]
    if len(package_rows) != 1:
        return None
    binary = package_rows[0]
    if binary.get("version") != source_version:
        return None
    if binary.get("architecture") != "arm64":
        return None
    run_id = str(result.get("actions_run_id", ""))
    if not run_id:
        return None
    return {
        "method": "download-actions-rebuild-artifact",
        "actions_run_id": run_id,
        "actions_run_url": result.get("actions_run_url"),
        "artifact_name": (
            f"arm64-rebuild-{artifact_component(source)}-"
            f"{artifact_component(source_version)}"
        ),
        "filename": binary.get("filename"),
        "sha256": binary.get("sha256"),
        "size": binary.get("size"),
        "architecture": "arm64",
        "commit_sha": result.get("commit_sha"),
        "tree_sha": result.get("tree_sha"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normalized-map", type=Path, required=True)
    parser.add_argument("--vendor-binary-lock", type=Path, required=True)
    parser.add_argument("--rebuild-results", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    normalized_document = load_json(args.normalized_map)
    vendor_document = load_json(args.vendor_binary_lock)
    vendor_rows = vendor_index(vendor_document)
    rebuild_rows = latest_rebuild_results(args.rebuild_results)

    rows: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()

    for row in normalized_document.get("packages", []):
        identity = (
            row["package"],
            row["reference_version"],
            row["reference_architecture"],
        )
        if identity in identities:
            blockers.append({"identity": identity, "reason": "duplicate-normalized-identity"})
            continue
        identities.add(identity)
        status = row["status"]
        acquisition: dict[str, Any] | None = None

        if status == "exact-arm64":
            acquisition = normalized_download(row, "arm64")
        elif status == "reuse-all":
            acquisition = normalized_download(row, "all")
            if acquisition is None:
                matches = vendor_rows.get(
                    (row["package"], row["reference_version"], "all"), []
                )
                verified = [candidate for candidate in (verified_vendor(item) for item in matches) if candidate]
                unique = {
                    (candidate["url"], candidate["filename"], candidate["sha256"], candidate["size"])
                    for candidate in verified
                }
                if len(unique) == 1:
                    acquisition = verified[0]
        elif status == "rebuild-arm64":
            acquisition = rebuilt_binary(
                rebuild_rows.get((row["source"], row["source_version"])),
                row["package"],
                row["source"],
                row["source_version"],
            )
        elif status == "arch-replace":
            replacement = row.get("replacement")
            if replacement not in (None, "", [], {}):
                acquisition = {
                    "method": "architecture-replacement",
                    "replacement": replacement,
                }
        elif status == "exclude":
            acquisition = {"method": "exclude-from-arm64"}

        output = {
            "package": row["package"],
            "reference_version": row["reference_version"],
            "reference_architecture": row["reference_architecture"],
            "source": row["source"],
            "source_version": row["source_version"],
            "mapping_status": status,
            "acquisition": acquisition,
            "ready": acquisition is not None,
        }
        rows.append(output)
        if acquisition is None:
            blockers.append({**output, "reason": "no-exact-acquisition-route"})

    method_counts: dict[str, int] = {}
    for row in rows:
        method = (row.get("acquisition") or {}).get("method", "blocked")
        method_counts[method] = method_counts.get(method, 0) + 1
    summary = {
        "schema": 1,
        "policy": "one-exact-acquisition-route-per-reference-package",
        "normalized_map_complete": normalized_document.get("summary", {}).get("complete"),
        "package_count": len(rows),
        "ready_count": sum(row["ready"] for row in rows),
        "blocker_count": len(blockers),
        "method_counts": dict(sorted(method_counts.items())),
        "ready_for_fetch": (
            normalized_document.get("summary", {}).get("complete") is True
            and not blockers
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "package-acquisition-plan.json").write_text(
        json.dumps({"summary": summary, "packages": rows}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "blockers.json").write_text(
        json.dumps(blockers, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["ready_for_fetch"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
