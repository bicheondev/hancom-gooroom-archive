#!/usr/bin/env python3
"""Recover passed rebuild artifacts and prepare a persistent release cache."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_artifact_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")


def safe_release_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.+-]+", "_", value)


def latest_passed(root: Path) -> dict[tuple[str, str], tuple[dict[str, Any], Path]]:
    rows: dict[tuple[str, str], tuple[dict[str, Any], Path]] = {}
    if not root.exists():
        return rows
    for path in root.rglob("result.json"):
        try:
            row = load_json(path)
        except Exception:
            continue
        if row.get("passed") is not True:
            continue
        source = row.get("source")
        version = row.get("source_version")
        run_id = str(row.get("actions_run_id", ""))
        if not source or not version or not run_id.isdigit():
            continue
        key = (source, version)
        previous = rows.get(key)
        try:
            previous_id = int(str(previous[0].get("actions_run_id", "0"))) if previous else -1
        except ValueError:
            previous_id = -1
        if previous is None or int(run_id) >= previous_id:
            rows[key] = (row, path)
    return rows


def run_download(
    repository: str, run_id: str, artifact_name: str, destination: Path
) -> None:
    process = subprocess.run(
        [
            "gh",
            "run",
            "download",
            run_id,
            "--repo",
            repository,
            "--name",
            artifact_name,
            "--dir",
            str(destination),
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"gh run download {run_id}/{artifact_name} failed: "
            f"{process.stderr.strip()}"
        )


def find_one(root: Path, name: str) -> Path | None:
    matches = [path for path in root.rglob(name) if path.is_file()]
    return matches[0] if len(matches) == 1 else None


def build_evidence_archive(
    source: str,
    version: str,
    artifact_root: Path,
    result_path: Path,
    destination: Path,
) -> dict[str, Any]:
    include_names = {
        "job-result.json",
        "verification.json",
        "build-lock.json",
        "source-lock-evidence.json",
        "SHA256SUMS",
        "build-environment-packages.tsv",
        "key-build-dependency-policy.txt",
        "build-dependency-metapackage.txt",
        "apt-solver-simulation.log",
        "workflow-build.log",
        "chroot-build.log",
        "chroot-build.stderr.log",
    }
    with tarfile.open(destination, "w:xz", preset=9) as archive:
        used_names: set[str] = set()
        for path in sorted(artifact_root.rglob("*")):
            if not path.is_file() or path.name not in include_names:
                continue
            arcname = path.name
            if arcname in used_names:
                arcname = str(path.relative_to(artifact_root)).replace("/", "__")
            used_names.add(arcname)
            archive.add(path, arcname=arcname, recursive=False)
        archive.add(result_path, arcname="committed-result.json", recursive=False)
        sibling_verification = result_path.parent / "verification.json"
        if sibling_verification.exists():
            archive.add(
                sibling_verification,
                arcname="committed-verification.json",
                recursive=False,
            )
    return {
        "filename": destination.name,
        "size": destination.stat().st_size,
        "sha256": sha256_file(destination),
        "source": source,
        "source_version": version,
        "kind": "source-build-evidence",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    passed = latest_passed(args.results)
    args.assets_dir.mkdir(parents=True, exist_ok=True)
    packages: list[dict[str, Any]] = []
    evidence_assets: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    filenames: dict[str, str] = {}

    for (source, version), (result, result_path) in sorted(passed.items()):
        run_id = str(result["actions_run_id"])
        artifact_name = (
            f"arm64-rebuild-{safe_artifact_component(source)}-"
            f"{safe_artifact_component(version)}"
        )
        expected = {
            row["filename"]: row
            for row in result.get("deb_artifacts", [])
            if row.get("filename") and row.get("sha256") and row.get("size")
        }
        if not expected:
            errors.append(
                {
                    "source": source,
                    "source_version": version,
                    "reason": "passed-result-has-no-deb-artifact-hashes",
                    "result_path": str(result_path),
                }
            )
            continue

        with tempfile.TemporaryDirectory(prefix="arm64-rebuild-release-") as temporary:
            artifact_root = Path(temporary)
            try:
                run_download(
                    args.github_repository, run_id, artifact_name, artifact_root
                )
            except Exception as exception:
                errors.append(
                    {
                        "source": source,
                        "source_version": version,
                        "reason": "actions-artifact-download-failed",
                        "error": f"{type(exception).__name__}: {exception}",
                        "actions_run_id": run_id,
                        "artifact_name": artifact_name,
                    }
                )
                continue

            source_failed = False
            verification_path = find_one(artifact_root, "verification.json")
            verification = load_json(verification_path) if verification_path else {}
            if verification.get("passed") is not True:
                errors.append(
                    {
                        "source": source,
                        "source_version": version,
                        "reason": "downloaded-artifact-lacks-passed-verification",
                        "artifact_name": artifact_name,
                    }
                )
                continue

            for filename, expected_row in sorted(expected.items()):
                path = find_one(artifact_root, filename)
                if path is None:
                    errors.append(
                        {
                            "source": source,
                            "source_version": version,
                            "reason": "deb-file-missing-or-ambiguous",
                            "filename": filename,
                        }
                    )
                    source_failed = True
                    continue
                actual_size = path.stat().st_size
                actual_sha256 = sha256_file(path)
                if (
                    actual_size != int(expected_row["size"])
                    or actual_sha256 != expected_row["sha256"]
                ):
                    errors.append(
                        {
                            "source": source,
                            "source_version": version,
                            "reason": "deb-file-hash-or-size-mismatch",
                            "filename": filename,
                            "expected_size": expected_row["size"],
                            "actual_size": actual_size,
                            "expected_sha256": expected_row["sha256"],
                            "actual_sha256": actual_sha256,
                        }
                    )
                    source_failed = True
                    continue

                previous_hash = filenames.get(filename)
                if previous_hash and previous_hash != actual_sha256:
                    errors.append(
                        {
                            "source": source,
                            "source_version": version,
                            "reason": "release-asset-filename-collision",
                            "filename": filename,
                            "previous_sha256": previous_hash,
                            "new_sha256": actual_sha256,
                        }
                    )
                    source_failed = True
                    continue
                filenames[filename] = actual_sha256
                destination = args.assets_dir / filename
                shutil.copyfile(path, destination)

                binary_rows = [
                    row
                    for row in verification.get("packages", [])
                    if row.get("filename") == filename
                ]
                if len(binary_rows) != 1:
                    errors.append(
                        {
                            "source": source,
                            "source_version": version,
                            "reason": "verification-binary-row-missing-or-ambiguous",
                            "filename": filename,
                            "match_count": len(binary_rows),
                        }
                    )
                    source_failed = True
                    continue
                binary = binary_rows[0]
                packages.append(
                    {
                        "package": binary.get("package"),
                        "version": binary.get("version"),
                        "architecture": binary.get("architecture"),
                        "source": source,
                        "source_version": version,
                        "filename": filename,
                        "size": actual_size,
                        "sha256": actual_sha256,
                        "repository_full_name": result.get("repository_full_name"),
                        "commit_sha": result.get("commit_sha"),
                        "tree_sha": result.get("tree_sha"),
                        "actions_run_id": run_id,
                        "actions_run_url": result.get("actions_run_url"),
                        "actions_artifact_name": artifact_name,
                    }
                )

            if source_failed:
                continue
            evidence_name = (
                f"{safe_release_component(source)}_"
                f"{safe_release_component(version)}_arm64-build-evidence.tar.xz"
            )
            evidence_assets.append(
                build_evidence_archive(
                    source,
                    version,
                    artifact_root,
                    result_path,
                    args.assets_dir / evidence_name,
                )
            )

    packages.sort(
        key=lambda row: (
            row.get("package") or "",
            row.get("version") or "",
            row.get("architecture") or "",
        )
    )
    summary = {
        "schema": 2,
        "policy": "passed-verifier-plus-actions-artifact-hash-before-release",
        "passed_source_count": len(passed),
        "prepared_package_asset_count": len(packages),
        "prepared_evidence_asset_count": len(evidence_assets),
        "error_count": len(errors),
        "ready_to_publish": bool(packages) and not errors,
    }
    result = {
        "summary": summary,
        "packages": packages,
        "evidence_assets": evidence_assets,
        "errors": errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if errors:
        print(json.dumps(errors, ensure_ascii=False, indent=2), file=sys.stderr)
    return 0 if summary["ready_to_publish"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
