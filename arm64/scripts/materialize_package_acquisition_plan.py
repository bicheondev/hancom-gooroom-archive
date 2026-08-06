#!/usr/bin/env python3
"""Materialize an exact ARM64 package acquisition plan into a local APT repo."""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DIRECT_METHODS = {"download-normalized-exact", "download-vendor-exact"}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_filename(value: str) -> str:
    name = Path(value).name
    if not name or name in {".", ".."} or "\x00" in name:
        raise ValueError(f"invalid filename: {value!r}")
    return name


def download_direct(task: dict[str, Any], staging: Path) -> dict[str, Any]:
    acquisition = task["acquisition"]
    url = acquisition["url"]
    filename = safe_filename(acquisition["filename"])
    destination = staging / filename
    partial = destination.with_suffix(destination.suffix + ".partial")
    expected_sha256 = str(acquisition["sha256"]).lower()
    expected_size = int(acquisition["size"])
    error = ""
    for attempt in range(1, 6):
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "hancom-gooroom-arm64-materializer/1"},
            )
            with urllib.request.urlopen(request, timeout=240) as response, partial.open(
                "wb"
            ) as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            actual_size = partial.stat().st_size
            actual_sha256 = sha256_file(partial)
            if actual_size != expected_size:
                raise RuntimeError(
                    f"size mismatch for {filename}: {actual_size} != {expected_size}"
                )
            if actual_sha256 != expected_sha256:
                raise RuntimeError(
                    f"sha256 mismatch for {filename}: {actual_sha256} != {expected_sha256}"
                )
            partial.replace(destination)
            return {
                **task,
                "status": "downloaded",
                "local_path": str(destination),
                "actual_size": actual_size,
                "actual_sha256": actual_sha256,
                "attempts": attempt,
            }
        except Exception as exception:
            error = f"{type(exception).__name__}: {exception}"
            partial.unlink(missing_ok=True)
            if attempt < 5:
                time.sleep(2 ** (attempt - 1))
    return {**task, "status": "download-failed", "error": error, "attempts": 5}


def run_checked(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )


def deb_field(path: Path, field: str) -> str:
    return run_checked(["dpkg-deb", "-f", str(path), field]).stdout.strip()


def validate_deb(task: dict[str, Any], path: Path) -> dict[str, Any]:
    package = deb_field(path, "Package")
    version = deb_field(path, "Version")
    architecture = deb_field(path, "Architecture")
    expected_package = task["package"]
    expected_version = task["reference_version"]
    mapping = task["mapping_status"]
    if package != expected_package:
        raise RuntimeError(f"{path.name}: package {package} != {expected_package}")
    if version != expected_version:
        raise RuntimeError(f"{path.name}: version {version} != {expected_version}")
    expected_architectures = {
        "exact-arm64": {"arm64"},
        "rebuild-arm64": {"arm64"},
        "reuse-all": {"all"},
    }.get(mapping, {"arm64", "all"})
    if architecture not in expected_architectures:
        raise RuntimeError(
            f"{path.name}: architecture {architecture} not in {sorted(expected_architectures)}"
        )
    return {
        "package": package,
        "version": version,
        "architecture": architecture,
        "filename": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "source": deb_field(path, "Source"),
    }


def download_actions_group(
    repository: str,
    run_id: str,
    artifact_name: str,
    group_tasks: list[dict[str, Any]],
    staging: Path,
) -> list[dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="arm64-actions-artifact-") as temporary:
        destination = Path(temporary)
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
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode != 0:
            error = (
                f"gh run download failed ({process.returncode}): "
                f"{process.stderr.strip()}"
            )
            return [{**task, "status": "artifact-download-failed", "error": error} for task in group_tasks]

        results: list[dict[str, Any]] = []
        for task in group_tasks:
            acquisition = task["acquisition"]
            filename = safe_filename(acquisition["filename"])
            matches = [path for path in destination.rglob(filename) if path.is_file()]
            if len(matches) != 1:
                results.append(
                    {
                        **task,
                        "status": "artifact-file-missing-or-ambiguous",
                        "error": f"{filename}: {len(matches)} matches",
                    }
                )
                continue
            source = matches[0]
            expected_size = int(acquisition["size"])
            expected_sha256 = str(acquisition["sha256"]).lower()
            actual_size = source.stat().st_size
            actual_sha256 = sha256_file(source)
            if actual_size != expected_size or actual_sha256 != expected_sha256:
                results.append(
                    {
                        **task,
                        "status": "artifact-checksum-mismatch",
                        "expected_size": expected_size,
                        "actual_size": actual_size,
                        "expected_sha256": expected_sha256,
                        "actual_sha256": actual_sha256,
                    }
                )
                continue
            local = staging / filename
            if local.exists() and sha256_file(local) != actual_sha256:
                results.append(
                    {
                        **task,
                        "status": "filename-collision",
                        "error": filename,
                    }
                )
                continue
            shutil.copyfile(source, local)
            results.append(
                {
                    **task,
                    "status": "downloaded",
                    "local_path": str(local),
                    "actual_size": actual_size,
                    "actual_sha256": actual_sha256,
                }
            )
        return results


def replacement_download(task: dict[str, Any]) -> dict[str, Any] | None:
    acquisition = task["acquisition"]
    replacement = acquisition.get("replacement")
    if not isinstance(replacement, dict):
        return None
    route = replacement.get("acquisition") if isinstance(replacement.get("acquisition"), dict) else replacement
    if not isinstance(route, dict):
        return None
    method = route.get("method")
    if method not in DIRECT_METHODS | {"download-actions-rebuild-artifact"}:
        return None
    normalized = {**task, "acquisition": route}
    replacement_package = route.get("package") or replacement.get("package")
    replacement_version = route.get("version") or replacement.get("version")
    if replacement_package:
        normalized["package"] = replacement_package
    if replacement_version:
        normalized["reference_version"] = replacement_version
    normalized["mapping_status"] = route.get("mapping_status", "architecture-replacement")
    return normalized


def write_repository(repo_dir: Path) -> None:
    packages = run_checked(["dpkg-scanpackages", "--multiversion", "."], cwd=repo_dir).stdout
    (repo_dir / "Packages").write_text(packages, encoding="utf-8")
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=(repo_dir / "Packages.gz").open("wb"), mtime=0
    ) as output:
        output.write(packages.encode("utf-8"))
    release = run_checked(["apt-ftparchive", "release", "."], cwd=repo_dir).stdout
    (repo_dir / "Release").write_text(release, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repository-dir", type=Path, required=True)
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    plan = load_json(args.plan)
    if plan.get("summary", {}).get("ready_for_fetch") is not True:
        raise SystemExit("acquisition plan is not ready_for_fetch")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.repository_dir.mkdir(parents=True, exist_ok=True)
    staging = args.output_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)

    direct_tasks: list[dict[str, Any]] = []
    actions_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    excluded: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for row in plan.get("packages", []):
        acquisition = row.get("acquisition") or {}
        method = acquisition.get("method")
        task = dict(row)
        if method in DIRECT_METHODS:
            direct_tasks.append(task)
        elif method == "download-actions-rebuild-artifact":
            key = (str(acquisition["actions_run_id"]), acquisition["artifact_name"])
            actions_groups.setdefault(key, []).append(task)
        elif method == "exclude-from-arm64":
            excluded.append(task)
        elif method == "architecture-replacement":
            normalized = replacement_download(task)
            if normalized is None:
                blocked.append({**task, "status": "unsupported-replacement-route"})
            elif normalized["acquisition"]["method"] in DIRECT_METHODS:
                direct_tasks.append(normalized)
            else:
                route = normalized["acquisition"]
                key = (str(route["actions_run_id"]), route["artifact_name"])
                actions_groups.setdefault(key, []).append(normalized)
        else:
            blocked.append({**task, "status": "unsupported-acquisition-method"})

    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, args.workers)
    ) as executor:
        futures = [executor.submit(download_direct, task, staging) for task in direct_tasks]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            print(f"{result['status']}: {result['package']}", file=sys.stderr)
            results.append(result)

    for (run_id, artifact_name), group_tasks in sorted(actions_groups.items()):
        group_results = download_actions_group(
            args.github_repository,
            run_id,
            artifact_name,
            group_tasks,
            staging,
        )
        for result in group_results:
            print(f"{result['status']}: {result['package']}", file=sys.stderr)
        results.extend(group_results)

    validated: list[dict[str, Any]] = []
    for result in results:
        if result.get("status") != "downloaded":
            blocked.append(result)
            continue
        path = Path(result["local_path"])
        try:
            control = validate_deb(result, path)
        except Exception as exception:
            blocked.append(
                {
                    **result,
                    "status": "deb-control-validation-failed",
                    "error": f"{type(exception).__name__}: {exception}",
                }
            )
            continue
        destination = args.repository_dir / path.name
        if destination.exists() and sha256_file(destination) != control["sha256"]:
            blocked.append(
                {**result, "status": "repository-filename-collision", "control": control}
            )
            continue
        shutil.copyfile(path, destination)
        validated.append({**result, "status": "verified", "control": control})

    if not blocked:
        write_repository(args.repository_dir)

    repository_files = []
    if args.repository_dir.exists():
        for path in sorted(args.repository_dir.iterdir()):
            if path.is_file():
                repository_files.append(
                    {
                        "filename": path.name,
                        "size": path.stat().st_size,
                        "sha256": sha256_file(path),
                    }
                )

    status_counts: dict[str, int] = {}
    for row in validated + blocked:
        status = row.get("status", "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    summary = {
        "schema": 1,
        "policy": "download-size-sha256-and-deb-control-gated",
        "planned_package_count": len(plan.get("packages", [])),
        "excluded_count": len(excluded),
        "verified_deb_count": len(validated),
        "blocked_count": len(blocked),
        "status_counts": dict(sorted(status_counts.items())),
        "repository_file_count": len(repository_files),
        "repository_ready": not blocked,
    }
    manifest = {
        "summary": summary,
        "verified_packages": validated,
        "excluded_packages": excluded,
        "blocked_packages": blocked,
        "repository_files": repository_files,
    }
    (args.output_dir / "materialization.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "blocked.json").write_text(
        json.dumps(blocked, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["repository_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
