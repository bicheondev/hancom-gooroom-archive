#!/usr/bin/env python3
"""Compare rebuilt AMD64 .debs with exact reference packages, fail-closed."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = 1


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def deb_field(path: Path, field: str) -> str:
    process = subprocess.run(
        ["dpkg-deb", "-f", str(path), field],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return process.stdout.strip() if process.returncode == 0 else ""


def index_built_debs(directory: Path) -> dict[tuple[str, str], list[Path]]:
    rows: dict[tuple[str, str], list[Path]] = {}
    for path in sorted(directory.rglob("*.deb")):
        package = deb_field(path, "Package")
        version = deb_field(path, "Version")
        if package and version:
            rows.setdefault((package, version), []).append(path)
    return rows


def extract_deb(path: Path, destination: Path) -> None:
    data_dir = destination / "data"
    control_dir = destination / "control"
    data_dir.mkdir(parents=True, exist_ok=True)
    control_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["dpkg-deb", "-x", str(path), str(data_dir)], check=True)
    subprocess.run(["dpkg-deb", "-e", str(path), str(control_dir)], check=True)


def tree_manifest(root: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if path.is_symlink():
            rows[relative] = {
                "type": "symlink",
                "mode": mode,
                "target": os.readlink(path),
            }
        elif path.is_dir():
            rows[relative] = {"type": "directory", "mode": mode}
        elif path.is_file():
            rows[relative] = {
                "type": "file",
                "mode": mode,
                "size": info.st_size,
                "sha256": hash_file(path),
            }
        else:
            rows[relative] = {"type": "other", "mode": mode}
    return rows


def compare_manifests(
    reference: dict[str, dict[str, Any]], rebuilt: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    reference_paths = set(reference)
    rebuilt_paths = set(rebuilt)
    only_reference = sorted(reference_paths - rebuilt_paths)
    only_rebuilt = sorted(rebuilt_paths - reference_paths)
    different = []
    equal = []
    for path in sorted(reference_paths & rebuilt_paths):
        if reference[path] == rebuilt[path]:
            equal.append(path)
        else:
            different.append(
                {
                    "path": path,
                    "reference": reference[path],
                    "rebuilt": rebuilt[path],
                }
            )
    return {
        "path_set_equal": not only_reference and not only_rebuilt,
        "content_equal": not only_reference and not only_rebuilt and not different,
        "reference_path_count": len(reference),
        "rebuilt_path_count": len(rebuilt),
        "equal_path_count": len(equal),
        "different_path_count": len(different),
        "only_reference": only_reference[:2000],
        "only_rebuilt": only_rebuilt[:2000],
        "different": different[:2000],
        "truncated": len(only_reference) > 2000 or len(only_rebuilt) > 2000 or len(different) > 2000,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--reference-manifest", type=Path, required=True)
    parser.add_argument("--reference-root", type=Path, required=True)
    parser.add_argument("--built-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sources = json.loads(args.reference_manifest.read_text(encoding="utf-8"))
    source_row = next((row for row in sources if row.get("source") == args.source), None)
    if source_row is None:
        raise SystemExit(f"reference manifest lacks source {args.source}")

    built_index = index_built_debs(args.built_root)
    package_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="deb-compare-") as temporary:
        temporary_root = Path(temporary)
        for index, package_row in enumerate(source_row.get("packages", [])):
            package = package_row["package"]
            expected_version = package_row["version"]
            reference_path = args.reference_root / package_row["artifact_path"]
            candidates = built_index.get((package, expected_version), [])
            result: dict[str, Any] = {
                "package": package,
                "expected_version": expected_version,
                "reference_path": str(reference_path),
                "reference_present": reference_path.is_file(),
                "rebuilt_candidate_count": len(candidates),
                "rebuilt_candidates": [str(path) for path in candidates],
                "status": "missing",
                "authorized_match": False,
            }
            if not reference_path.is_file() or len(candidates) != 1:
                result["status"] = (
                    "missing-reference" if not reference_path.is_file() else "missing-or-ambiguous-rebuilt-package"
                )
                package_results.append(result)
                continue
            rebuilt_path = candidates[0]
            reference_extract = temporary_root / f"{index}-reference"
            rebuilt_extract = temporary_root / f"{index}-rebuilt"
            extract_deb(reference_path, reference_extract)
            extract_deb(rebuilt_path, rebuilt_extract)
            reference_data = tree_manifest(reference_extract / "data")
            rebuilt_data = tree_manifest(rebuilt_extract / "data")
            reference_control = tree_manifest(reference_extract / "control")
            rebuilt_control = tree_manifest(rebuilt_extract / "control")
            data_comparison = compare_manifests(reference_data, rebuilt_data)
            control_comparison = compare_manifests(reference_control, rebuilt_control)
            byte_identical = (
                reference_path.stat().st_size == rebuilt_path.stat().st_size
                and hash_file(reference_path) == hash_file(rebuilt_path)
            )
            authorized_match = bool(
                data_comparison["content_equal"] and control_comparison["content_equal"]
            )
            result.update(
                {
                    "status": "exact-extracted-package-match" if authorized_match else "package-differs",
                    "authorized_match": authorized_match,
                    "byte_identical": byte_identical,
                    "reference_sha256": hash_file(reference_path),
                    "rebuilt_sha256": hash_file(rebuilt_path),
                    "reference_size": reference_path.stat().st_size,
                    "rebuilt_size": rebuilt_path.stat().st_size,
                    "reference_architecture": deb_field(reference_path, "Architecture"),
                    "rebuilt_architecture": deb_field(rebuilt_path, "Architecture"),
                    "data": data_comparison,
                    "control": control_comparison,
                }
            )
            package_results.append(result)

    all_packages_match = bool(package_results) and all(
        row["authorized_match"] for row in package_results
    )
    summary = {
        "schema": SCHEMA,
        "policy": "all-exact-reference-binary-packages-must-match-extracted-data-and-control-trees",
        "source": args.source,
        "version": args.version,
        "reference_package_count": len(package_results),
        "exact_package_match_count": sum(row["authorized_match"] for row in package_results),
        "byte_identical_package_count": sum(row.get("byte_identical", False) for row in package_results),
        "all_reference_packages_match": all_packages_match,
        "promotion_allowed": all_packages_match,
    }
    write_json(output / "summary.json", summary)
    write_json(output / "package-results.json", package_results)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
