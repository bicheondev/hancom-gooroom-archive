#!/usr/bin/env python3
"""Collect compact native ARM64 rebuild evidence for Git or signed DSC sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any


DIAGNOSTIC_NAMES = {
    "workflow-build.log",
    "chroot-build.log",
    "chroot-build.stderr.log",
    "apt-solver-simulation.log",
    "debootstrap.log",
    "gpgv-source.log",
    "dpkg-source-extract.log",
}
DIAGNOSTIC_SUFFIXES = (".log", ".stderr", ".txt")
TAIL_LIMIT = 65536


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def bounded_tail(path: Path) -> str:
    data = path.read_bytes()
    if len(data) > TAIL_LIMIT:
        data = data[-TAIL_LIMIT:]
    return data.decode("utf-8", "replace")


def authority(
    job: dict[str, Any], build_lock: dict[str, Any], evidence: dict[str, Any]
) -> dict[str, Any]:
    source_type = (
        job.get("source_type")
        or build_lock.get("source_type")
        or evidence.get("source_type")
        or "git"
    )
    if source_type == "dsc":
        dsc = build_lock.get("dsc") if isinstance(build_lock.get("dsc"), dict) else {}
        if not dsc:
            dsc = evidence.get("dsc") if isinstance(evidence.get("dsc"), dict) else {}
        return {
            "source_type": "dsc",
            "repository_full_name": None,
            "commit_sha": None,
            "tree_sha": None,
            "dsc_filename": dsc.get("filename"),
            "dsc_sha256": dsc.get("sha256"),
        }
    return {
        "source_type": "git",
        "repository_full_name": job.get("repository_full_name")
        or build_lock.get("repository"),
        "commit_sha": job.get("commit_sha") or build_lock.get("commit_sha"),
        "tree_sha": job.get("tree_sha") or build_lock.get("tree_sha"),
        "dsc_filename": None,
        "dsc_sha256": None,
    }


def find_document(root: Path, filename: str) -> dict[str, Any]:
    path = root / filename
    if not path.exists():
        return {}
    try:
        return load_json(path)
    except Exception:
        return {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--batch", required=True)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    collection_errors: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []

    job_results = sorted(args.artifacts_dir.rglob("job-result.json"))
    for job_path in job_results:
        artifact_root = job_path.parent
        try:
            job = load_json(job_path)
        except Exception as exception:
            collection_errors.append(
                {
                    "path": str(job_path),
                    "reason": "job-result-json-invalid",
                    "error": f"{type(exception).__name__}: {exception}",
                }
            )
            continue
        source = job.get("source")
        version = job.get("source_version")
        if not source or not version:
            collection_errors.append(
                {"path": str(job_path), "reason": "source-identity-missing"}
            )
            continue

        build_lock = find_document(artifact_root, "build-lock.json")
        source_evidence = find_document(artifact_root, "source-lock-evidence.json")
        verification = find_document(artifact_root, "verification.json")
        selected_authority = authority(job, build_lock, source_evidence)

        deb_artifacts = []
        for deb in sorted(artifact_root.glob("*.deb")):
            deb_artifacts.append(
                {
                    "filename": deb.name,
                    "size": deb.stat().st_size,
                    "sha256": sha256_file(deb),
                }
            )
        verification_packages = (
            verification.get("packages", [])
            if isinstance(verification.get("packages"), list)
            else []
        )
        verified_by_filename = {
            row.get("filename"): row
            for row in verification_packages
            if row.get("filename")
        }
        for deb in deb_artifacts:
            verified = verified_by_filename.get(deb["filename"])
            if verified:
                deb.update(
                    {
                        key: verified.get(key)
                        for key in (
                            "package",
                            "version",
                            "architecture",
                            "parsed_source",
                            "parsed_source_version",
                            "source_field",
                        )
                        if verified.get(key) is not None
                    }
                )

        diagnostics = []
        for path in sorted(artifact_root.rglob("*")):
            if not path.is_file():
                continue
            if path.name in {
                "job-result.json",
                "build-lock.json",
                "source-lock-evidence.json",
                "verification.json",
                "SHA256SUMS",
            } or path.suffix == ".deb":
                continue
            if path.name not in DIAGNOSTIC_NAMES and not path.name.endswith(
                DIAGNOSTIC_SUFFIXES
            ):
                continue
            diagnostics.append(
                {
                    "filename": str(path.relative_to(artifact_root)),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "tail": bounded_tail(path),
                }
            )

        verification_passed = verification.get("passed") is True
        job_passed = job.get("passed") is True
        passed = job_passed and verification_passed and bool(deb_artifacts)
        result = {
            "schema": 3,
            "source": source,
            "source_version": version,
            **selected_authority,
            "authority_provenance": job.get("authority_provenance"),
            "actions_run_id": str(args.run_id),
            "actions_run_url": args.run_url,
            "batch": args.batch,
            "artifact_name": artifact_root.name,
            "build_outcome": job.get("build_outcome"),
            "build_exit_code": job.get("build_exit_code"),
            "verify_outcome": job.get("verify_outcome"),
            "retry_reason": job.get("retry_reason"),
            "dependency_repository_packages_sha256": job.get(
                "dependency_repository_packages_sha256"
            )
            or build_lock.get("dependency_repository_packages_sha256"),
            "dependency_release_lock_sha256": job.get(
                "dependency_release_lock_sha256"
            ),
            "previous_dependency_repository_packages_sha256": job.get(
                "previous_dependency_repository_packages_sha256"
            ),
            "previous_actions_run_id": job.get("previous_actions_run_id"),
            "required_native_packages": job.get("required_native_packages", []),
            "reused_all_packages": job.get("reused_all_packages", []),
            "job_passed": job_passed,
            "verification_passed": verification_passed,
            "passed": passed,
            "deb_artifacts": deb_artifacts,
            "verification_errors": verification.get("errors", []),
            "verification_warnings": verification.get("warnings", []),
            "build_lock": build_lock,
            "source_lock_evidence": source_evidence,
            "diagnostics": diagnostics,
        }
        destination = (
            args.output_dir
            / safe_component(source)
            / safe_component(version)
        )
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if verification:
            (destination / "verification.json").write_text(
                json.dumps(verification, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        if build_lock:
            (destination / "build-lock.json").write_text(
                json.dumps(build_lock, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        if source_evidence:
            (destination / "source-lock-evidence.json").write_text(
                json.dumps(source_evidence, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        (destination / "deb-artifacts.json").write_text(
            json.dumps(deb_artifacts, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        rows.append(result)

    passed_rows = [row for row in rows if row["passed"]]
    failed_rows = [row for row in rows if not row["passed"]]
    summary = {
        "schema": 3,
        "policy": "compact-git-or-signed-dsc-native-rebuild-evidence",
        "actions_run_id": str(args.run_id),
        "actions_run_url": args.run_url,
        "batch": args.batch,
        "artifact_job_count": len(job_results),
        "collected_count": len(rows),
        "passed_count": len(passed_rows),
        "failed_count": len(failed_rows),
        "collection_error_count": len(collection_errors),
        "source_type_counts": {
            source_type: sum(row["source_type"] == source_type for row in rows)
            for source_type in sorted({row["source_type"] for row in rows})
        },
        "complete": len(rows) == len(job_results) and not collection_errors,
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "failed.json").write_text(
        json.dumps(failed_rows, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "collection-errors.json").write_text(
        json.dumps(collection_errors, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
