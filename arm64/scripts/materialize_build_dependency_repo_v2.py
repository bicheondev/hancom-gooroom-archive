#!/usr/bin/env python3
"""Materialize exact ARM64/all build dependencies into a flat APT repository.

Inputs are two independently verified authorities:

* the original ISO vendor-binary lock, from which only Architecture: all
  packages are reusable on ARM64;
* the unified native rebuild index, whose ARM64/all DEBs are downloaded from
  the exact Actions run and artifact recorded in the lock.

Every file is gated by expected size, SHA-256, Package, Version and Architecture
before entering the repository.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def nested_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from nested_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from nested_dicts(child)


def first(containers: list[dict[str, Any]], names: tuple[str, ...]) -> Any:
    for container in containers:
        for name in names:
            value = container.get(name)
            if value not in (None, ""):
                return value
    return None


def vendor_all_candidates(document: Any) -> list[dict[str, Any]]:
    candidates: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in nested_dicts(document):
        nested = [value for value in row.values() if isinstance(value, dict)]
        containers = [row, *nested]
        package = first(containers, ("package", "Package", "binary_package"))
        version = first(containers, ("version", "Version", "binary_version"))
        architecture = first(containers, ("architecture", "Architecture"))
        status = str(first(containers, ("status", "verification_status")) or "").lower()
        url = first(containers, ("url", "download_url", "browser_download_url"))
        filename = first(containers, ("local_filename", "filename", "Filename"))
        expected_sha256 = first(
            containers,
            ("actual_sha256", "sha256", "SHA256", "expected_sha256"),
        )
        size = first(containers, ("actual_size", "size", "Size", "expected_size"))
        if architecture != "all" or not all((package, version, url, expected_sha256, size)):
            continue
        if status and status not in {"verified", "resolved", "ok", "success"}:
            continue
        if not filename:
            filename = Path(str(url)).name
        key = (str(package), str(version), "all", str(expected_sha256).lower())
        candidates[key] = {
            "package": str(package),
            "version": str(version),
            "architecture": "all",
            "filename": Path(str(filename)).name,
            "url": str(url),
            "sha256": str(expected_sha256).lower(),
            "size": int(size),
            "provenance": "iso-vendor-binary-lock",
        }
    return sorted(candidates.values(), key=lambda row: (row["package"], row["version"]))


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        **kwargs,
    )


def deb_field(path: Path, name: str) -> str:
    process = run(["dpkg-deb", "-f", str(path), name])
    if process.returncode:
        raise RuntimeError(f"dpkg-deb {name}: {process.stderr.strip()}")
    return process.stdout.strip()


def validate(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    actual_size = path.stat().st_size
    actual_sha256 = sha256(path)
    if actual_size != int(expected["size"]):
        raise RuntimeError(f"size {actual_size} != {expected['size']}")
    if actual_sha256 != expected["sha256"]:
        raise RuntimeError(f"sha256 {actual_sha256} != {expected['sha256']}")
    package = deb_field(path, "Package")
    version = deb_field(path, "Version")
    architecture = deb_field(path, "Architecture")
    if package != expected["package"]:
        raise RuntimeError(f"Package {package} != {expected['package']}")
    if version != expected["version"]:
        raise RuntimeError(f"Version {version} != {expected['version']}")
    if architecture != expected["architecture"]:
        raise RuntimeError(
            f"Architecture {architecture} != {expected['architecture']}"
        )
    return {
        **expected,
        "actual_size": actual_size,
        "actual_sha256": actual_sha256,
        "validated": True,
    }


def download_vendor(task: dict[str, Any], staging: Path) -> dict[str, Any]:
    destination = staging / task["filename"]
    error = ""
    for attempt in range(1, 6):
        temporary = destination.with_suffix(destination.suffix + ".partial")
        try:
            request = urllib.request.Request(
                task["url"],
                headers={"User-Agent": "hancom-gooroom-arm64-build-dep-repo/1"},
            )
            with urllib.request.urlopen(request, timeout=240) as response, temporary.open(
                "wb"
            ) as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            record = validate(temporary, task)
            temporary.replace(destination)
            return {**record, "path": str(destination), "attempts": attempt}
        except Exception as exception:
            error = f"{type(exception).__name__}: {exception}"
            temporary.unlink(missing_ok=True)
            if attempt < 5:
                time.sleep(2 ** (attempt - 1))
    return {**task, "validated": False, "error": error, "attempts": 5}


def rebuilt_candidates(document: Any) -> list[dict[str, Any]]:
    rows = document if isinstance(document, list) else document.get("packages", [])
    candidates = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        required = (
            "package",
            "version",
            "architecture",
            "filename",
            "sha256",
            "size",
            "actions_run_id",
            "artifact_name",
        )
        if not all(row.get(field) not in (None, "") for field in required):
            continue
        if row["architecture"] not in {"arm64", "all"}:
            continue
        candidates.append(
            {
                "package": row["package"],
                "version": row["version"],
                "architecture": row["architecture"],
                "filename": Path(row["filename"]).name,
                "sha256": row["sha256"].lower(),
                "size": int(row["size"]),
                "actions_run_id": str(row["actions_run_id"]),
                "actions_run_url": row.get("actions_run_url"),
                "artifact_name": row["artifact_name"],
                "source": row.get("source"),
                "source_version": row.get("source_version"),
                "commit_sha": row.get("commit_sha"),
                "tree_sha": row.get("tree_sha"),
                "dsc_sha256": row.get("dsc_sha256"),
                "provenance": row.get("provenance", "verified-native-rebuild"),
            }
        )
    return sorted(candidates, key=lambda row: (row["package"], row["version"]))


def package_triplet(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row["package"]),
        str(row["version"]),
        str(row["architecture"]),
    )


def apply_vendor_all_precedence(
    vendor: list[dict[str, Any]],
    rebuilt: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Prefer exact ISO Architecture: all packages over rebuilt duplicates.

    Architecture: all payloads from the original ISO are already native on ARM64
    and remain the byte authority. A rebuilt package with the same Package,
    Version and Architecture is therefore redundant, even when its container
    bytes differ because of build metadata. Ambiguous vendor authority remains a
    hard failure.
    """

    vendor_identities: dict[
        tuple[str, str, str], set[tuple[str, str, int]]
    ] = defaultdict(set)
    for row in vendor:
        if row.get("architecture") != "all":
            raise RuntimeError("vendor precedence received a non-all package")
        vendor_identities[package_triplet(row)].add(
            (str(row["filename"]), str(row["sha256"]), int(row["size"]))
        )

    ambiguous = [
        {
            "package": key[0],
            "version": key[1],
            "architecture": key[2],
            "identities": sorted(identities),
        }
        for key, identities in vendor_identities.items()
        if len(identities) != 1
    ]
    if ambiguous:
        raise RuntimeError(
            "vendor Architecture: all authority is ambiguous: "
            + json.dumps(ambiguous, ensure_ascii=False, sort_keys=True)
        )

    retained: list[dict[str, Any]] = []
    shadowed: list[dict[str, Any]] = []
    for row in rebuilt:
        key = package_triplet(row)
        identities = vendor_identities.get(key)
        if not identities:
            retained.append(row)
            continue
        filename, digest, size = next(iter(identities))
        shadowed.append(
            {
                **row,
                "shadowed_by": "iso-vendor-binary-lock",
                "vendor_authority": {
                    "filename": filename,
                    "sha256": digest,
                    "size": size,
                },
            }
        )
    return retained, shadowed


def download_rebuild_group(
    repository: str,
    run_id: str,
    artifact_name: str,
    tasks: list[dict[str, Any]],
    staging: Path,
) -> list[dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rebuild-dep-artifact-") as temporary:
        root = Path(temporary)
        process = run(
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
                str(root),
            ]
        )
        if process.returncode:
            error = f"gh run download: {process.stderr.strip()}"
            return [{**task, "validated": False, "error": error} for task in tasks]
        results = []
        for task in tasks:
            matches = [path for path in root.rglob(task["filename"]) if path.is_file()]
            if len(matches) != 1:
                results.append(
                    {
                        **task,
                        "validated": False,
                        "error": f"{task['filename']}: {len(matches)} artifact matches",
                    }
                )
                continue
            try:
                record = validate(matches[0], task)
                destination = staging / task["filename"]
                if destination.exists() and sha256(destination) != record["sha256"]:
                    raise RuntimeError(f"filename collision: {destination.name}")
                shutil.copyfile(matches[0], destination)
                results.append({**record, "path": str(destination)})
            except Exception as exception:
                results.append(
                    {
                        **task,
                        "validated": False,
                        "error": f"{type(exception).__name__}: {exception}",
                    }
                )
        return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor-lock", type=Path, required=True)
    parser.add_argument("--rebuild-packages", type=Path, required=True)
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--repository-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    vendor = vendor_all_candidates(load(args.vendor_lock))
    rebuilt_before_vendor_precedence = rebuilt_candidates(load(args.rebuild_packages))
    rebuilt, shadowed_rebuilt = apply_vendor_all_precedence(
        vendor, rebuilt_before_vendor_precedence
    )
    args.repository_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    staging = args.output_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, args.workers)
    ) as executor:
        futures = [executor.submit(download_vendor, task, staging) for task in vendor]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for task in rebuilt:
        groups[(task["actions_run_id"], task["artifact_name"])].append(task)
    for (run_id, artifact_name), tasks in sorted(groups.items()):
        results.extend(
            download_rebuild_group(
                args.github_repository,
                run_id,
                artifact_name,
                tasks,
                staging,
            )
        )

    failures = [result for result in results if result.get("validated") is not True]
    verified = [result for result in results if result.get("validated") is True]
    identities: dict[tuple[str, str, str], set[tuple[str, int]]] = defaultdict(set)
    for result in verified:
        identities[
            (result["package"], result["version"], result["architecture"])
        ].add((result["sha256"], result["size"]))
    ambiguous = [
        {
            "package": key[0],
            "version": key[1],
            "architecture": key[2],
            "identities": sorted(list(values)),
        }
        for key, values in identities.items()
        if len(values) != 1
    ]

    if not failures and not ambiguous:
        copied: set[tuple[str, str]] = set()
        for result in sorted(
            verified,
            key=lambda row: (row["package"], row["version"], row["architecture"]),
        ):
            identity = (result["filename"], result["sha256"])
            if identity in copied:
                continue
            source = Path(result["path"])
            destination = args.repository_dir / result["filename"]
            if destination.exists() and sha256(destination) != result["sha256"]:
                failures.append({**result, "error": "repository filename collision"})
                break
            shutil.copyfile(source, destination)
            copied.add(identity)

    if not failures and not ambiguous:
        scan = run(
            ["dpkg-scanpackages", "--multiversion", "."],
            cwd=args.repository_dir,
        )
        if scan.returncode:
            failures.append({"error": f"dpkg-scanpackages: {scan.stderr}"})
        else:
            (args.repository_dir / "Packages").write_text(scan.stdout, encoding="utf-8")
            release = run(["apt-ftparchive", "release", "."], cwd=args.repository_dir)
            if release.returncode:
                failures.append({"error": f"apt-ftparchive: {release.stderr}"})
            else:
                (args.repository_dir / "Release").write_text(
                    release.stdout, encoding="utf-8"
                )

    repository_files = []
    for path in sorted(args.repository_dir.glob("*")):
        if path.is_file():
            repository_files.append(
                {
                    "filename": path.name,
                    "size": path.stat().st_size,
                    "sha256": sha256(path),
                }
            )
    summary = {
        "schema": 1,
        "policy": "verified-architecture-all-vendor-plus-verified-native-arm64",
        "vendor_all_candidate_count": len(vendor),
        "rebuilt_candidate_count_before_vendor_precedence": len(
            rebuilt_before_vendor_precedence
        ),
        "rebuilt_candidate_count": len(rebuilt),
        "vendor_precedence_shadowed_rebuild_count": len(shadowed_rebuilt),
        "verified_package_file_count": len(verified),
        "failure_count": len(failures),
        "ambiguous_count": len(ambiguous),
        "repository_file_count": len(repository_files),
        "repository_ready": not failures and not ambiguous,
    }
    manifest = {
        "summary": summary,
        "verified": verified,
        "shadowed_rebuilt": shadowed_rebuilt,
        "failures": failures,
        "ambiguous": ambiguous,
        "repository_files": repository_files,
    }
    (args.output_dir / "build-dependency-repository.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "failures.json").write_text(
        json.dumps(failures, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["repository_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
