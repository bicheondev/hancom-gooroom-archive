#!/usr/bin/env python3
"""Build one exact, persistent acquisition route per reference package."""

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
        previous = rows.get(key)
        try:
            previous_id = int(str(previous[0].get("actions_run_id", "0"))) if previous else -1
        except ValueError:
            previous_id = -1
        if previous is None or run_id >= previous_id:
            rows[key] = (row, path)
    return rows


def vendor_index(document: dict[str, Any]) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    result: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in document.get("packages", []):
        key = (row.get("package"), row.get("version"), row.get("architecture"))
        if all(key):
            result.setdefault(key, []).append(row)
    return result


def release_index(document: dict[str, Any]) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    result: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    if document.get("summary", {}).get("complete") is not True:
        return result
    for row in document.get("packages", []):
        asset = row.get("release_asset") or {}
        key = (row.get("package"), row.get("version"), row.get("architecture"))
        if all(key) and asset.get("browser_download_url"):
            result.setdefault(key, []).append(row)
    return result


def verified_vendor(row: dict[str, Any]) -> dict[str, Any] | None:
    if row.get("status") != "verified":
        return None
    selected = row.get("selected") if isinstance(row.get("selected"), dict) else {}
    url = row.get("url")
    sha256 = row.get("actual_sha256") or selected.get("SHA256")
    size = row.get("actual_size") or selected.get("Size")
    filename = row.get("local_filename") or Path(selected.get("Filename", "")).name
    if not all((url, sha256, size, filename)):
        return None
    return {
        "method": "download-vendor-exact",
        "url": url,
        "filename": filename,
        "sha256": str(sha256).lower(),
        "size": int(size),
    }


def selected_route(
    row: dict[str, Any], *, permit_replacement_identity: bool = False
) -> dict[str, Any] | None:
    selected = row.get("selected") or {}
    if not isinstance(selected, dict):
        return None
    selected_package = selected.get("package") or row["package"]
    selected_version = selected.get("version") or row["reference_version"]
    selected_architecture = selected.get("architecture")
    if not permit_replacement_identity:
        if selected_package != row["package"] or selected_version != row["reference_version"]:
            return None
    if selected_architecture not in {"arm64", "all", None}:
        return None
    url = selected.get("url")
    filename = selected.get("filename") or (Path(str(url)).name if url else None)
    sha256 = selected.get("sha256")
    size = selected.get("size")
    if not all((url, filename, sha256, size)):
        return None
    return {
        "method": "download-normalized-exact",
        "package": selected_package,
        "version": selected_version,
        "architecture": selected_architecture,
        "url": url,
        "filename": filename,
        "sha256": str(sha256).lower(),
        "size": int(size),
        "repository": selected.get("repository"),
        "suite": selected.get("suite"),
    }


def release_route(
    rows: list[dict[str, Any]], source: str, source_version: str
) -> dict[str, Any] | None:
    exact = [
        row
        for row in rows
        if row.get("source") == source
        and row.get("source_version") == source_version
        and (row.get("release_asset") or {}).get("browser_download_url")
    ]
    identities = {
        (
            row["filename"],
            int(row["size"]),
            row["sha256"],
            row["release_asset"]["browser_download_url"],
        )
        for row in exact
    }
    if len(identities) != 1:
        return None
    row = exact[0]
    asset = row["release_asset"]
    return {
        "method": "download-release-exact",
        "package": row["package"],
        "version": row["version"],
        "architecture": row["architecture"],
        "url": asset["browser_download_url"],
        "filename": row["filename"],
        "sha256": row["sha256"],
        "size": int(row["size"]),
        "release_tag": None,
        "release_asset_id": asset.get("id"),
        "release_digest": asset.get("digest"),
        "commit_sha": row.get("commit_sha"),
        "tree_sha": row.get("tree_sha"),
    }


def actions_route(
    result_entry: tuple[dict[str, Any], Path] | None,
    package: str,
    expected_version: str,
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
        row
        for row in verification.get("packages", [])
        if row.get("package") == package
        and row.get("version") == expected_version
        and row.get("architecture") == "arm64"
    ]
    if len(package_rows) != 1:
        return None
    binary = package_rows[0]
    run_id = str(result.get("actions_run_id", ""))
    if not run_id.isdigit():
        return None
    return {
        "method": "download-actions-rebuild-artifact",
        "package": package,
        "version": expected_version,
        "architecture": "arm64",
        "actions_run_id": run_id,
        "actions_run_url": result.get("actions_run_url"),
        "artifact_name": (
            f"arm64-rebuild-{artifact_component(source)}-"
            f"{artifact_component(source_version)}"
        ),
        "filename": binary.get("filename"),
        "sha256": binary.get("sha256"),
        "size": binary.get("size"),
        "commit_sha": result.get("commit_sha"),
        "tree_sha": result.get("tree_sha"),
    }


def replacement_route(row: dict[str, Any]) -> dict[str, Any] | None:
    direct = selected_route(row, permit_replacement_identity=True)
    if direct and direct.get("package") != row["package"]:
        return {
            "method": "architecture-replacement",
            "replaces_package": row["package"],
            "replaces_version": row["reference_version"],
            "replacement": direct,
        }
    replacement = row.get("replacement")
    if not isinstance(replacement, dict):
        return None
    candidate = replacement.get("selected") if isinstance(replacement.get("selected"), dict) else replacement
    if not isinstance(candidate, dict):
        return None
    package = candidate.get("package") or candidate.get("name")
    version = candidate.get("version")
    architecture = candidate.get("architecture") or "arm64"
    url = candidate.get("url") or candidate.get("download_url")
    filename = candidate.get("filename") or (Path(str(url)).name if url else None)
    sha256 = candidate.get("sha256") or candidate.get("SHA256")
    size = candidate.get("size") or candidate.get("Size")
    if not all((package, version, url, filename, sha256, size)):
        return None
    return {
        "method": "architecture-replacement",
        "replaces_package": row["package"],
        "replaces_version": row["reference_version"],
        "replacement": {
            "method": "download-normalized-exact",
            "package": package,
            "version": version,
            "architecture": architecture,
            "url": url,
            "filename": filename,
            "sha256": str(sha256).lower(),
            "size": int(size),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normalized-map", type=Path, required=True)
    parser.add_argument("--vendor-binary-lock", type=Path, required=True)
    parser.add_argument("--rebuild-results", type=Path, required=True)
    parser.add_argument("--rebuild-release-lock", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    normalized_document = load_json(args.normalized_map)
    vendor_document = load_json(args.vendor_binary_lock)
    release_document = (
        load_json(args.rebuild_release_lock)
        if args.rebuild_release_lock and args.rebuild_release_lock.exists()
        else {"summary": {"complete": False}, "packages": []}
    )
    vendor_rows = vendor_index(vendor_document)
    release_rows = release_index(release_document)
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
            acquisition = selected_route(row)
        elif status == "reuse-all":
            acquisition = selected_route(row)
            if acquisition is None:
                candidates = vendor_rows.get(
                    (row["package"], row["reference_version"], "all"), []
                )
                verified = [
                    candidate
                    for candidate in (verified_vendor(item) for item in candidates)
                    if candidate
                ]
                unique = {
                    (
                        candidate["url"],
                        candidate["filename"],
                        candidate["sha256"],
                        candidate["size"],
                    )
                    for candidate in verified
                }
                if len(unique) == 1:
                    acquisition = verified[0]
        elif status == "rebuild-arm64":
            candidates = release_rows.get(
                (row["package"], row["reference_version"], "arm64"), []
            )
            acquisition = release_route(
                candidates, row["source"], row["source_version"]
            )
            if acquisition is None:
                acquisition = actions_route(
                    rebuild_rows.get((row["source"], row["source_version"])),
                    row["package"],
                    row["reference_version"],
                    row["source"],
                    row["source_version"],
                )
        elif status == "arch-replace":
            acquisition = replacement_route(row)
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
        "schema": 2,
        "policy": "persistent-release-preferred-one-exact-route-per-package",
        "normalized_map_complete": normalized_document.get("summary", {}).get("complete"),
        "rebuild_release_complete": release_document.get("summary", {}).get("complete"),
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
