#!/usr/bin/env python3
"""Audit small source-blocked Gooroom packages against public Git histories.

The exact AMD64 DEB and vendor lock are the binary authority.  Public Git is
used only to identify byte-identical installed files and historical context.
The output classifies reconstruction scope but never promotes reconstructed or
approximate source automatically.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SIMPLE_SOURCES = (
    "gooroom-dockbarx-applet",
    "gooroom-guide",
    "gooroom-integration-applet",
    "gooroom-session-manager",
)
PREFERRED_OWNERS = {"gooroom", "hancom-io", "hancomgooroom"}
MAX_REPOSITORIES = 12
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_versions(path: Path) -> dict[str, str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    versions = {
        str(row.get("source")): str(row.get("source_version"))
        for row in document.get("targets", [])
        if row.get("source") in SIMPLE_SOURCES
    }
    missing = sorted(set(SIMPLE_SOURCES) - set(versions))
    if missing:
        raise SystemExit(f"target versions are missing: {missing}")
    return versions


def load_vendor_records(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    rows = document.get("packages")
    if not isinstance(rows, list):
        raise SystemExit("vendor lock lacks a packages array")
    return [row for row in rows if isinstance(row, dict)]


def select_vendor_record(
    records: list[dict[str, Any]], source: str, version: str
) -> dict[str, Any]:
    matches = [
        row
        for row in records
        if row.get("status") == "verified"
        and row.get("package") == source
        and row.get("version") == version
        and row.get("source") == source
        and row.get("source_version") == version
        and row.get("architecture") in {"amd64", "all"}
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"exact verified vendor record is not unique for {source} {version}: {len(matches)}"
        )
    return matches[0]


def locate_vendor_deb(root: Path, filename: str) -> Path:
    matches = sorted(path for path in root.rglob(filename) if path.is_file())
    if len(matches) != 1:
        raise SystemExit(f"vendor DEB is not unique for {filename}: {matches}")
    return matches[0]


def candidate_repositories(root: Path, source: str, version: str) -> tuple[list[str], list[str]]:
    repositories: set[str] = set()
    evidence_paths: list[str] = []
    for path in sorted(root.rglob("targeted-source-archaeology.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        candidate_version = document.get("version") or document.get("source_version")
        if document.get("source") != source or candidate_version != version:
            continue
        evidence_paths.append(path.as_posix())
        for value in document.get("repository_candidates", []):
            if isinstance(value, str) and value.count("/") == 1:
                repositories.add(value)
        for row in document.get("repository_attempts", []):
            if not isinstance(row, dict):
                continue
            value = row.get("repository_full_name")
            if isinstance(value, str) and value.count("/") == 1:
                repositories.add(value)
    for owner in PREFERRED_OWNERS:
        repositories.add(f"{owner}/{source}")

    def score(repository: str) -> tuple[int, str]:
        owner, name = repository.lower().split("/", 1)
        value = 0
        if owner in PREFERRED_OWNERS:
            value += 50
        if name == source.lower():
            value += 100
        elif source.lower() in name:
            value += 25
        if owner == "gooroom":
            value += 10
        return (-value, repository)

    return sorted(repositories, key=score)[:MAX_REPOSITORIES], evidence_paths


def clone_repositories(
    repositories: list[str], destination: Path
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    destination.mkdir(parents=True, exist_ok=True)
    for repository in repositories:
        key = re.sub(r"[^A-Za-z0-9._-]", "_", repository)
        repo_dir = destination / f"{key}.git"
        clone = run(
            [
                "git",
                "clone",
                "--mirror",
                "--filter=blob:none",
                f"https://github.com/{repository}.git",
                str(repo_dir),
            ],
            timeout=240,
        )
        row: dict[str, Any] = {
            "repository": repository,
            "clone_exit_code": clone.returncode,
            "clone_stdout_tail": clone.stdout[-3000:],
            "clone_stderr_tail": clone.stderr[-3000:],
        }
        if clone.returncode != 0:
            shutil.rmtree(repo_dir, ignore_errors=True)
            row["status"] = "clone-failed"
            rows.append(row)
            continue

        pull_fetch = run(
            [
                "git",
                f"--git-dir={repo_dir}",
                "fetch",
                "--force",
                "origin",
                "+refs/pull/*/head:refs/pull/*/head",
                "+refs/pull/*/merge:refs/pull/*/merge",
            ],
            timeout=180,
        )
        refs = run(
            ["git", f"--git-dir={repo_dir}", "for-each-ref", "--format=%(refname)"],
            timeout=60,
        )
        row.update(
            {
                "status": "cloned",
                "pull_ref_fetch_exit_code": pull_fetch.returncode,
                "pull_ref_fetch_stderr_tail": pull_fetch.stderr[-3000:],
                "ref_count": len(refs.stdout.splitlines()) if refs.returncode == 0 else 0,
            }
        )
        rows.append(row)
    return rows


def extract_documentation(rootfs: Path, evidence: Path) -> None:
    for path in sorted((rootfs / "usr/share/doc").rglob("*")) if (rootfs / "usr/share/doc").is_dir() else []:
        if not path.is_file() or path.is_symlink():
            continue
        lower = path.name.lower()
        if "changelog" in lower and lower.endswith(".gz"):
            try:
                text = gzip.decompress(path.read_bytes()).decode("utf-8", errors="replace")
            except Exception:
                continue
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", path.relative_to(rootfs).as_posix())
            (evidence / f"packaged-{safe.removesuffix('.gz')}.txt").write_text(text, encoding="utf-8")
        elif lower == "copyright":
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", path.relative_to(rootfs).as_posix())
            shutil.copy2(path, evidence / f"packaged-{safe}.txt")


def audit_one(
    *,
    source: str,
    version: str,
    vendor_records: list[dict[str, Any]],
    vendor_dir: Path,
    archaeology_root: Path,
    auditor: Path,
    output_root: Path,
    work_root: Path,
) -> dict[str, Any]:
    record = select_vendor_record(vendor_records, source, version)
    filename = str(record.get("local_filename", ""))
    expected_size = int(record.get("actual_size", 0))
    expected_sha256 = str(record.get("actual_sha256", ""))
    if not filename or expected_size <= 0 or HEX64.fullmatch(expected_sha256) is None:
        raise SystemExit(f"invalid vendor lock record for {source}")
    deb = locate_vendor_deb(vendor_dir, filename)
    actual_size = deb.stat().st_size
    actual_sha256 = sha256_file(deb)
    if actual_size != expected_size or actual_sha256 != expected_sha256:
        raise SystemExit(f"vendor DEB identity mismatch for {source}")

    target_output = output_root / source
    target_work = work_root / source
    rootfs = target_work / "rootfs"
    control = target_work / "control"
    git_root = target_work / "git"
    target_output.mkdir(parents=True, exist_ok=True)
    rootfs.mkdir(parents=True, exist_ok=True)
    control.mkdir(parents=True, exist_ok=True)

    extraction = run(["dpkg-deb", "-x", str(deb), str(rootfs)], timeout=180)
    control_extraction = run(["dpkg-deb", "-e", str(deb), str(control)], timeout=60)
    if extraction.returncode != 0 or control_extraction.returncode != 0:
        raise SystemExit(
            f"unable to extract {source}: {extraction.stderr[-1000:]} {control_extraction.stderr[-1000:]}"
        )

    control_package = run(["dpkg-deb", "-f", str(deb), "Package"], timeout=30).stdout.strip()
    control_version = run(["dpkg-deb", "-f", str(deb), "Version"], timeout=30).stdout.strip()
    control_architecture = run(["dpkg-deb", "-f", str(deb), "Architecture"], timeout=30).stdout.strip()
    if control_package != source or control_version != version or control_architecture not in {"amd64", "all"}:
        raise SystemExit(f"DEB control identity mismatch for {source}")

    lock_record = {
        "schema": 1,
        "package": source,
        "source": source,
        "source_version": version,
        "architecture": control_architecture,
        "filename": filename,
        "size": actual_size,
        "sha256": actual_sha256,
        "vendor_lock_path": "arm64/locks/vendor-binaries/vendor-binary-lock.json",
        "vendor_run_id": "31097604490",
        "verified": True,
    }
    write_json(target_output / "exact-amd64-package-lock.json", lock_record)
    extract_documentation(rootfs, target_output)

    repositories, archaeology_paths = candidate_repositories(archaeology_root, source, version)
    clone_rows = clone_repositories(repositories, git_root)
    write_json(
        target_output / "repository-clones.json",
        {
            "schema": 1,
            "source": source,
            "source_version": version,
            "archaeology_evidence_paths": archaeology_paths,
            "candidate_repositories": repositories,
            "clones": clone_rows,
        },
    )
    if not any(row.get("status") == "cloned" for row in clone_rows):
        raise SystemExit(f"no public repository cloned for {source}")

    audit = run(
        [
            "python3",
            str(auditor),
            "--rootfs",
            str(rootfs),
            "--control",
            str(control),
            "--evidence",
            str(target_output),
            "--git-root",
            str(git_root),
            "--source",
            source,
            "--version",
            version,
        ],
        timeout=900,
    )
    (target_output / "auditor.stdout.txt").write_text(audit.stdout, encoding="utf-8")
    (target_output / "auditor.stderr.txt").write_text(audit.stderr, encoding="utf-8")
    (target_output / "auditor.exit-code").write_text(f"{audit.returncode}\n", encoding="utf-8")
    if audit.returncode != 0:
        raise SystemExit(f"payload auditor failed for {source}: {audit.stderr[-3000:]}")

    summary = json.loads((target_output / "summary.json").read_text(encoding="utf-8"))
    native_count = int(summary.get("native_payload_count", 0))
    unmatched_count = int(summary.get("unmatched_file_count", 0))
    regular_count = int(summary.get("regular_file_count", 0))
    if native_count == 0:
        reconstruction_profile = "data-script-package-candidate"
    elif native_count <= 3:
        reconstruction_profile = "bounded-native-payload-reconstruction-candidate"
    else:
        reconstruction_profile = "complex-native-reconstruction-candidate"
    return {
        "source": source,
        "source_version": version,
        "package_architecture": control_architecture,
        "package_sha256": actual_sha256,
        "regular_file_count": regular_count,
        "matched_file_count": int(summary.get("matched_in_any_repository_count", 0)),
        "unmatched_file_count": unmatched_count,
        "native_payload_count": native_count,
        "packaged_change_id_count": int(summary.get("packaged_change_id_count", 0)),
        "resolved_packaged_change_id_count": int(summary.get("resolved_packaged_change_id_count", 0)),
        "exact_version_history_hit_count": int(summary.get("exact_version_history_hit_count", 0)),
        "repository_clone_success_count": sum(row.get("status") == "cloned" for row in clone_rows),
        "reconstruction_profile": reconstruction_profile,
        "audit_path": target_output.as_posix(),
        "source_promotion_allowed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--vendor-dir", type=Path, required=True)
    parser.add_argument("--vendor-lock", type=Path, required=True)
    parser.add_argument("--archaeology-root", type=Path, required=True)
    parser.add_argument("--auditor", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    versions = load_versions(args.targets)
    vendor_records = load_vendor_records(args.vendor_lock)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="blocked-package-payload-audit-") as temporary:
        work_root = Path(temporary)
        for source in SIMPLE_SOURCES:
            results.append(
                audit_one(
                    source=source,
                    version=versions[source],
                    vendor_records=vendor_records,
                    vendor_dir=args.vendor_dir,
                    archaeology_root=args.archaeology_root,
                    auditor=args.auditor,
                    output_root=args.output_dir,
                    work_root=work_root,
                )
            )

    summary = {
        "schema": 1,
        "policy": "exact-amd64-package-payload-versus-complete-public-git-histories",
        "target_count": len(results),
        "audited_target_count": len(results),
        "data_script_candidate_count": sum(
            row["reconstruction_profile"] == "data-script-package-candidate" for row in results
        ),
        "bounded_native_candidate_count": sum(
            row["reconstruction_profile"] == "bounded-native-payload-reconstruction-candidate"
            for row in results
        ),
        "complex_native_candidate_count": sum(
            row["reconstruction_profile"] == "complex-native-reconstruction-candidate"
            for row in results
        ),
        "total_regular_file_count": sum(row["regular_file_count"] for row in results),
        "total_matched_file_count": sum(row["matched_file_count"] for row in results),
        "total_unmatched_file_count": sum(row["unmatched_file_count"] for row in results),
        "total_native_payload_count": sum(row["native_payload_count"] for row in results),
        "targets": results,
        "source_promotion_allowed": False,
    }
    write_json(args.output_dir / "summary.json", summary)
    (args.output_dir / "targets.tsv").write_text(
        "source\tsource_version\tarchitecture\tregular\tmatched\tunmatched\tnative_payloads\tchange_ids\tresolved_change_ids\tprofile\n"
        + "".join(
            "\t".join(
                [
                    row["source"],
                    row["source_version"],
                    row["package_architecture"],
                    str(row["regular_file_count"]),
                    str(row["matched_file_count"]),
                    str(row["unmatched_file_count"]),
                    str(row["native_payload_count"]),
                    str(row["packaged_change_id_count"]),
                    str(row["resolved_packaged_change_id_count"]),
                    row["reconstruction_profile"],
                ]
            )
            + "\n"
            for row in results
        ),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
