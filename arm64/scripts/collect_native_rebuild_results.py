#!/usr/bin/env python3
"""Collect matrix rebuild artifacts into compact, persistent lock evidence.

Binary .deb files remain Actions artifacts. This script commits only immutable
hashes, control metadata, verification results, and bounded failure diagnostics
so the repository stays small while every retry remains auditable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any


MAX_DIAGNOSTIC_BYTES = 64 * 1024
MAX_DIAGNOSTIC_LINES = 240


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.+-]+", "_", value)


def bounded_tail(path: Path) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file():
        return None
    data = path.read_bytes()
    tail = data[-MAX_DIAGNOSTIC_BYTES:]
    text = tail.decode("utf-8", "replace")
    lines = text.splitlines()[-MAX_DIAGNOSTIC_LINES:]
    return {
        "filename": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "truncated": len(data) > len(tail) or len(text.splitlines()) > len(lines),
        "tail": "\n".join(lines),
    }


def copy_json_if_present(source_dir: Path, output_dir: Path, name: str) -> None:
    path = source_dir / name
    if path.exists():
        shutil.copyfile(path, output_dir / name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--batch", required=True)
    args = parser.parse_args()

    result_files = sorted(args.artifacts_dir.rglob("job-result.json"))
    results: list[dict[str, Any]] = []
    args.output_dir.mkdir(parents=True, exist_ok=True)

    for result_file in result_files:
        artifact_dir = result_file.parent
        job = load_json(result_file)
        source = job["source"]
        version = job["source_version"]
        destination = (
            args.output_dir / safe_component(source) / safe_component(version)
        )
        destination.mkdir(parents=True, exist_ok=True)

        verification_path = artifact_dir / "verification.json"
        verification = load_json(verification_path) if verification_path.exists() else None
        build_lock_path = artifact_dir / "build-lock.json"
        build_lock = load_json(build_lock_path) if build_lock_path.exists() else None
        source_evidence_path = artifact_dir / "source-lock-evidence.json"
        source_evidence = (
            load_json(source_evidence_path) if source_evidence_path.exists() else None
        )

        debs = []
        for deb in sorted(artifact_dir.glob("*.deb")):
            debs.append(
                {
                    "filename": deb.name,
                    "size": deb.stat().st_size,
                    "sha256": sha256_file(deb),
                }
            )

        diagnostics = []
        for name in (
            "workflow-build.log",
            "chroot-build.stderr.log",
            "chroot-build.log",
            "apt-solver-simulation.log",
            "debootstrap.log",
        ):
            record = bounded_tail(artifact_dir / name)
            if record:
                diagnostics.append(record)

        passed = bool(job.get("passed")) and bool(
            verification and verification.get("passed") is True
        )
        compact = {
            "schema": 1,
            "batch": args.batch,
            "actions_run_id": args.run_id,
            "actions_run_url": args.run_url,
            "source": source,
            "source_version": version,
            "repository_full_name": job.get("repository_full_name"),
            "commit_sha": job.get("commit_sha"),
            "tree_sha": job.get("tree_sha"),
            "required_native_packages": job.get("required_native_packages", []),
            "reused_all_packages": job.get("reused_all_packages", []),
            "build_outcome": job.get("build_outcome"),
            "build_exit_code": job.get("build_exit_code"),
            "verify_outcome": job.get("verify_outcome"),
            "passed": passed,
            "deb_artifacts": debs,
            "verification_errors": (
                verification.get("errors", []) if verification else ["verification missing"]
            ),
            "verification_warnings": (
                verification.get("warnings", []) if verification else []
            ),
            "build_lock": build_lock,
            "source_lock_evidence": source_evidence,
            "diagnostics": diagnostics,
        }
        (destination / "result.json").write_text(
            json.dumps(compact, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        copy_json_if_present(artifact_dir, destination, "verification.json")
        copy_json_if_present(artifact_dir, destination, "build-lock.json")
        copy_json_if_present(artifact_dir, destination, "source-lock-evidence.json")
        results.append(compact)

    results.sort(key=lambda row: (row["source"], row["source_version"]))
    passed = [row for row in results if row["passed"]]
    failed = [row for row in results if not row["passed"]]
    summary = {
        "schema": 1,
        "batch": args.batch,
        "actions_run_id": args.run_id,
        "actions_run_url": args.run_url,
        "result_count": len(results),
        "passed_count": len(passed),
        "failed_count": len(failed),
        "passed_sources": [row["source"] for row in passed],
        "failed_sources": [row["source"] for row in failed],
        "complete_success": bool(results) and not failed,
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "failed.json").write_text(
        json.dumps(failed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
