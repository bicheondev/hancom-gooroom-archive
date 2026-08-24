#!/usr/bin/env python3
"""Build the final exact ARM64 package acquisition plan from persistent inputs.

The plan is source-authority agnostic: a rebuilt package may be tied to an
exact Git tree or an exact signed DSC hash. Final rootfs construction never
uses expiring Actions artifact URLs; rebuilt packages must be represented by a
re-hashed persistent release asset.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def filename_from_url(url: str) -> str:
    return Path(unquote(urlsplit(url).path)).name


def exact_download(
    selected: dict[str, Any] | None,
    *,
    expected_version: str | None = None,
    allowed_architectures: set[str] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(selected, dict):
        return None
    url = selected.get("url") or selected.get("browser_download_url")
    filename = selected.get("filename") or (
        filename_from_url(url) if isinstance(url, str) and url else None
    )
    sha256 = selected.get("sha256")
    size = selected.get("size")
    version = selected.get("version")
    architecture = selected.get("architecture")
    if not all((url, filename, sha256, size is not None)):
        return None
    if expected_version is not None and version not in (None, expected_version):
        return None
    if allowed_architectures is not None and architecture not in (
        None,
        *allowed_architectures,
    ):
        return None
    if filename_from_url(url) != filename:
        return None
    return {
        "url": url,
        "filename": filename,
        "size": int(size),
        "sha256": str(sha256).lower(),
        "package": selected.get("package"),
        "version": version,
        "architecture": architecture,
    }


def vendor_index(document: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    rows = {}
    for row in document.get("packages", []):
        if row.get("status") != "verified":
            continue
        key = (row.get("package"), row.get("version"), row.get("architecture"))
        if not all(key):
            continue
        candidate = exact_download(
            {
                "package": row.get("package"),
                "version": row.get("version"),
                "architecture": row.get("architecture"),
                "url": row.get("url"),
                "filename": row.get("local_filename")
                or Path(str(row.get("selected", {}).get("Filename", ""))).name,
                "size": row.get("actual_size"),
                "sha256": row.get("actual_sha256"),
            }
        )
        if candidate:
            rows[key] = candidate
    return rows


def release_index(document: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    rows = {}
    for row in document.get("packages", []):
        key = (row.get("package"), row.get("version"), row.get("architecture"))
        if not all(key):
            continue
        asset = row.get("release_asset") if isinstance(row.get("release_asset"), dict) else {}
        candidate = exact_download(
            {
                "package": row.get("package"),
                "version": row.get("version"),
                "architecture": row.get("architecture"),
                "url": asset.get("browser_download_url"),
                "filename": row.get("filename") or asset.get("name"),
                "size": row.get("size"),
                "sha256": row.get("sha256"),
            }
        )
        if not candidate:
            continue
        digest = asset.get("digest")
        if digest and digest != f"sha256:{candidate['sha256']}":
            continue
        rows[key] = {
            **candidate,
            "source": row.get("source"),
            "source_version": row.get("source_version"),
            "source_type": row.get("source_type", "git"),
            "repository_full_name": row.get("repository_full_name"),
            "commit_sha": row.get("commit_sha"),
            "tree_sha": row.get("tree_sha"),
            "dsc_filename": row.get("dsc_filename"),
            "dsc_sha256": row.get("dsc_sha256"),
            "release_asset_id": asset.get("id"),
            "release_digest": digest,
        }
    return rows


def selected_direct(row: dict[str, Any]) -> dict[str, Any] | None:
    selected = row.get("selected")
    if not isinstance(selected, dict):
        return None
    return exact_download(
        {
            "package": selected.get("package") or row.get("package"),
            "version": selected.get("version"),
            "architecture": selected.get("architecture"),
            "url": selected.get("url"),
            "filename": selected.get("filename"),
            "size": selected.get("size"),
            "sha256": selected.get("sha256"),
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normalized-map", type=Path, required=True)
    parser.add_argument("--vendor-binary-lock", type=Path, required=True)
    parser.add_argument("--rebuild-results", type=Path, required=True)
    parser.add_argument("--rebuild-release-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    normalized = load_json(args.normalized_map)
    vendor = load_json(args.vendor_binary_lock)
    release = load_json(args.rebuild_release_lock)
    vendor_rows = vendor_index(vendor)
    release_rows = release_index(release)

    packages = []
    blockers = []
    for row in normalized.get("packages", []):
        package = row.get("package")
        version = row.get("reference_version") or row.get("version")
        architecture = row.get("reference_architecture") or row.get("architecture")
        source = row.get("source")
        source_version = row.get("source_version")
        status = row.get("status")
        plan: dict[str, Any] = {
            "package": package,
            "reference_version": version,
            "reference_architecture": architecture,
            "source": source,
            "source_version": source_version,
            "status": status,
            "acquisition": None,
        }

        if status in {"exclude", "arch-exclude"}:
            plan["acquisition"] = {
                "method": "exclude-from-arm64",
                "reason": row.get("reason") or "architecture-specific exclusion",
            }
        elif status == "reuse-all":
            candidate = vendor_rows.get((package, version, "all"))
            method = "download-vendor-exact"
            if candidate is None:
                direct = selected_direct(row)
                if direct and direct.get("architecture") in {None, "all"}:
                    candidate = direct
                    method = "download-debian-exact"
            if candidate is None:
                blockers.append(
                    {
                        "package": package,
                        "version": version,
                        "architecture": architecture,
                        "status": status,
                        "reason": "exact-architecture-all-binary-not-locked",
                    }
                )
            else:
                plan["acquisition"] = {"method": method, **candidate}
        elif status == "rebuild-arm64":
            candidate = release_rows.get((package, version, "arm64"))
            if candidate is None:
                blockers.append(
                    {
                        "package": package,
                        "version": version,
                        "architecture": architecture,
                        "source": source,
                        "source_version": source_version,
                        "status": status,
                        "reason": "persistent-exact-arm64-rebuild-asset-not-locked",
                    }
                )
            elif (
                candidate.get("source") not in (None, source)
                or candidate.get("source_version") not in (None, source_version)
            ):
                blockers.append(
                    {
                        "package": package,
                        "version": version,
                        "status": status,
                        "reason": "persistent-rebuild-source-identity-mismatch",
                        "candidate": candidate,
                    }
                )
            elif candidate.get("source_type") == "git" and not all(
                (candidate.get("commit_sha"), candidate.get("tree_sha"))
            ):
                blockers.append(
                    {
                        "package": package,
                        "version": version,
                        "status": status,
                        "reason": "git-rebuild-release-asset-has-no-commit-tree-lock",
                    }
                )
            elif candidate.get("source_type") == "dsc" and not candidate.get(
                "dsc_sha256"
            ):
                blockers.append(
                    {
                        "package": package,
                        "version": version,
                        "status": status,
                        "reason": "dsc-rebuild-release-asset-has-no-dsc-lock",
                    }
                )
            else:
                plan["acquisition"] = {
                    "method": "download-release-exact",
                    **candidate,
                }
        elif status in {"exact-arm64", "arch-replace"}:
            candidate = selected_direct(row)
            if candidate is None:
                blockers.append(
                    {
                        "package": package,
                        "version": version,
                        "architecture": architecture,
                        "status": status,
                        "reason": "normalized-map-has-no-exact-download-record",
                    }
                )
            else:
                plan["acquisition"] = {
                    "method": (
                        "download-architecture-replacement"
                        if status == "arch-replace"
                        else "download-debian-exact"
                    ),
                    **candidate,
                }
        else:
            blockers.append(
                {
                    "package": package,
                    "version": version,
                    "architecture": architecture,
                    "status": status,
                    "reason": "unsupported-or-unresolved-package-map-status",
                }
            )
        packages.append(plan)

    method_counts = Counter(
        row["acquisition"]["method"]
        for row in packages
        if isinstance(row.get("acquisition"), dict)
    )
    summary = {
        "schema": 3,
        "policy": "persistent-exact-downloads-with-git-or-signed-dsc-rebuild-authority",
        "normalized_map_complete": normalized.get("summary", {}).get("complete"),
        "rebuild_release_complete": release.get("summary", {}).get("complete"),
        "package_count": len(packages),
        "planned_count": sum(row.get("acquisition") is not None for row in packages),
        "blocker_count": len(blockers),
        "method_counts": dict(sorted(method_counts.items())),
        "ready_for_fetch": bool(packages) and not blockers,
    }
    output = {"summary": summary, "packages": packages, "blockers": blockers}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "package-acquisition-plan.json").write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
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
