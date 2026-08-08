#!/usr/bin/env python3
"""Promote an already verified exact-Git native ARM64 build artifact.

The artifact is accepted only when its build lock, source-lock evidence,
verification summary, DEB metadata, and executable payloads all match the
current canonical source authority. The script intentionally performs an
independent package scan rather than trusting a previous workflow conclusion.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
X86_PATTERN = re.compile(
    r"ELF (?:32|64)-bit .* (?:x86-64|Intel 80386)|"
    r"PE32(?:\+)? executable .* (?:x86-64|Intel 80386)",
    re.IGNORECASE,
)
FOREIGN_ELF_PATTERN = re.compile(r"ELF (?:32|64)-bit", re.IGNORECASE)
AARCH64_PATTERN = re.compile(r"(?:ARM aarch64|AArch64)", re.IGNORECASE)


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable to read JSON {path}: {exc}")
    require(isinstance(value, dict), f"JSON document is not an object: {path}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(*argv: str, cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        fail(f"required command is missing: {argv[0]}")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        fail(f"command failed ({' '.join(argv)}): {detail}")
    return result.stdout.strip()


def canonical_row(lock: dict[str, Any], source: str) -> dict[str, Any]:
    rows = [
        row
        for row in lock.get("sources", [])
        if isinstance(row, dict)
        and row.get("source") == source
        and row.get("role") == "rebuild-arm64"
    ]
    require(len(rows) == 1, f"expected one canonical rebuild authority for {source}")
    row = rows[0]
    require(row.get("status") == "resolved", f"canonical source is not resolved: {source}")
    selected = row.get("selected")
    require(isinstance(selected, dict), f"canonical selected source is missing: {source}")
    require(selected.get("type", "git") == "git", f"canonical source is not exact Git: {source}")
    return row


def expected_packages(
    reference: dict[str, Any], source: str, version: str
) -> list[str]:
    names = sorted(
        {
            str(row.get("package"))
            for row in reference.get("packages", [])
            if isinstance(row, dict)
            and row.get("source") == source
            and row.get("source_version") == version
            and row.get("architecture") != "all"
            and row.get("package")
        }
    )
    require(names, f"reference contains no architecture-dependent packages for {source} {version}")
    return names


def parse_source_field(value: str, package: str, version: str) -> tuple[str, str]:
    value = value.strip()
    if not value:
        return package, version
    match = re.fullmatch(r"([^\s(]+)(?:\s*\(([^)]+)\))?", value)
    require(match is not None, f"unable to parse DEB Source field: {value!r}")
    return match.group(1), match.group(2) or version


def scan_package(deb: Path, source: str, version: str) -> dict[str, Any]:
    package = run("dpkg-deb", "-f", str(deb), "Package")
    package_version = run("dpkg-deb", "-f", str(deb), "Version")
    architecture = run("dpkg-deb", "-f", str(deb), "Architecture")
    source_field = run("dpkg-deb", "-f", str(deb), "Source")
    parsed_source, parsed_source_version = parse_source_field(
        source_field, package, package_version
    )

    require(package_version == version, f"package version mismatch in {deb.name}")
    require(architecture in {"arm64", "all"}, f"unexpected architecture in {deb.name}: {architecture}")
    require(parsed_source == source, f"package source mismatch in {deb.name}: {parsed_source}")
    require(
        parsed_source_version == version,
        f"package source version mismatch in {deb.name}: {parsed_source_version}",
    )

    x86_count = 0
    foreign_count = 0
    executable_elf_count = 0
    aarch64_elf_count = 0
    with tempfile.TemporaryDirectory(prefix="arm64-promote-") as temporary:
        root = Path(temporary)
        run("dpkg-deb", "-x", str(deb), str(root))
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            description = run("file", "-b", str(path))
            if X86_PATTERN.search(description):
                x86_count += 1
            if FOREIGN_ELF_PATTERN.search(description):
                executable_elf_count += 1
                if AARCH64_PATTERN.search(description):
                    aarch64_elf_count += 1
                else:
                    foreign_count += 1

    require(x86_count == 0, f"x86 payload survived in {deb.name}")
    require(foreign_count == 0, f"non-AArch64 ELF survived in {deb.name}")
    digest = sha256(deb)
    require(HEX64.fullmatch(digest) is not None, f"invalid SHA-256 for {deb.name}")
    return {
        "filename": deb.name,
        "size": deb.stat().st_size,
        "sha256": digest,
        "package": package,
        "version": package_version,
        "architecture": architecture,
        "parsed_source": parsed_source,
        "parsed_source_version": parsed_source_version,
        "source_field": source_field,
        "executable_elf_count": executable_elf_count,
        "aarch64_elf_count": aarch64_elf_count,
        "x86_payload_count": x86_count,
        "foreign_payload_count": foreign_count,
    }


def verify_dependency_chain(
    artifact_dir: Path,
    dependency_source: str | None,
    dependency_version: str | None,
    required_packages: list[str],
) -> dict[str, Any] | None:
    if dependency_source is None:
        require(dependency_version is None and not required_packages, "incomplete dependency arguments")
        return None
    require(dependency_version is not None, "dependency version is required")
    path = artifact_dir / "local-build-dependencies.json"
    require(path.is_file(), f"local dependency evidence is missing: {path}")
    evidence = load(path)
    require(
        evidence.get("policy") == "exact-locally-built-source-dependency-repository",
        "unexpected local dependency policy",
    )
    dependency = evidence.get("dependency_source")
    require(isinstance(dependency, dict), "dependency source identity is missing")
    require(dependency.get("source") == dependency_source, "dependency source mismatch")
    require(
        dependency.get("source_version") == dependency_version,
        "dependency source version mismatch",
    )
    packages = evidence.get("packages")
    require(isinstance(packages, list), "dependency package list is missing")
    index = {
        str(row.get("package")): row
        for row in packages
        if isinstance(row, dict) and row.get("package")
    }
    for package in required_packages:
        require(package in index, f"required local dependency package is missing: {package}")
        row = index[package]
        require(row.get("source") == dependency_source, f"dependency source mismatch: {package}")
        require(
            row.get("source_version") == dependency_version,
            f"dependency source version mismatch: {package}",
        )
        require(
            row.get("architecture") in {"arm64", "all"},
            f"dependency architecture mismatch: {package}",
        )
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--result-path", type=Path, required=True)
    parser.add_argument("--dependency-source")
    parser.add_argument("--dependency-version")
    parser.add_argument("--required-local-package", action="append", default=[])
    args = parser.parse_args()

    require(args.run_id.isdigit(), "workflow run id must be numeric")
    require(
        args.run_url.endswith(f"/actions/runs/{args.run_id}"),
        "workflow run URL does not match run id",
    )
    artifact = args.artifact_dir
    require(artifact.is_dir(), f"artifact directory is missing: {artifact}")

    lock = load(args.source_lock)
    reference = load(args.reference)
    row = canonical_row(lock, args.source)
    selected = row["selected"]
    version = str(row.get("source_version", ""))
    repository = str(selected.get("repository_full_name", ""))
    commit = str(selected.get("commit_sha", ""))
    tree = str(selected.get("tree_sha", ""))
    require(version, "canonical source version is missing")
    require("/" in repository, "canonical repository is invalid")
    require(HEX40.fullmatch(commit) is not None, "canonical commit SHA is invalid")
    require(HEX40.fullmatch(tree) is not None, "canonical tree SHA is invalid")

    build_lock = load(artifact / "build-lock.json")
    source_evidence = load(artifact / "source-lock-evidence.json")
    verification = load(artifact / "verification-summary.json")

    for document, label in (
        (build_lock, "build lock"),
        (source_evidence, "source evidence"),
        (verification, "verification summary"),
    ):
        require(document.get("source") == args.source, f"{label} source mismatch")
        require(document.get("source_version") == version, f"{label} version mismatch")

    require(build_lock.get("repository") == repository, "build lock repository mismatch")
    require(build_lock.get("commit_sha") == commit, "build lock commit mismatch")
    require(build_lock.get("tree_sha") == tree, "build lock tree mismatch")
    require(build_lock.get("target_architecture") == "arm64", "build target is not ARM64")
    require(
        build_lock.get("build_mode") == "native-arm64-historical-chroot-binary-arch",
        "unexpected build mode",
    )

    require(source_evidence.get("repository") == repository, "source evidence repository mismatch")
    require(source_evidence.get("commit_sha") == commit, "source evidence commit mismatch")
    require(source_evidence.get("verified_commit_sha") == commit, "source evidence verified commit mismatch")
    require(source_evidence.get("tree_sha") == tree, "source evidence tree mismatch")
    require(source_evidence.get("verified_tree_sha") == tree, "source evidence verified tree mismatch")

    require(verification.get("verified") is True, "artifact verification did not pass")
    require(verification.get("commit_sha") == commit, "verification commit mismatch")
    require(verification.get("tree_sha") == tree, "verification tree mismatch")
    require(
        int(verification.get("wrong_architecture_executable_count", -1)) == 0,
        "verification reports wrong-architecture executables",
    )

    expected = expected_packages(reference, args.source, version)
    verification_expected = sorted(
        str(value) for value in verification.get("expected_architecture_dependent_packages", [])
    )
    require(verification_expected == expected, "verified expected package set differs from reference")

    debs = sorted(artifact.glob("*.deb"))
    require(debs, f"artifact contains no DEB packages: {artifact}")
    records = [scan_package(deb, args.source, version) for deb in debs]
    produced = {record["package"] for record in records}
    for package in expected:
        require(package in produced, f"expected architecture-dependent package is missing: {package}")

    verified_produced = sorted(
        str(value) for value in verification.get("produced_binary_packages", [])
    )
    require(verified_produced == sorted(produced), "produced package set differs from verification summary")
    require(int(verification.get("deb_count", -1)) == len(records), "DEB count mismatch")

    dependency = verify_dependency_chain(
        artifact,
        args.dependency_source,
        args.dependency_version,
        args.required_local_package,
    )

    result = {
        "schema": 4,
        "batch": "verified-existing-workflow-artifact-promotion",
        "actions_run_id": args.run_id,
        "actions_run_url": args.run_url,
        "artifact_name": args.artifact_name,
        "source": args.source,
        "source_version": version,
        "source_type": "git",
        "authority_provenance": row.get("provenance", "github-exact-commit"),
        "repository_full_name": repository,
        "commit_sha": commit,
        "tree_sha": tree,
        "required_native_packages": expected,
        "reused_all_packages": [],
        "build_outcome": "success",
        "build_exit_code": "0",
        "verify_outcome": "success",
        "job_passed": True,
        "verification_passed": True,
        "passed": True,
        "deb_artifacts": records,
        "verification_errors": [],
        "verification_warnings": [],
        "verification": {
            "passed": True,
            "policy": "canonical-exact-git-artifact-independent-arm64-rescan",
            "wrong_architecture_executable_count": 0,
            "packages": records,
            "artifact_verification_summary": verification,
            "local_dependency_chain": dependency,
        },
        "build_lock": build_lock,
        "source_lock_evidence": source_evidence,
        "promotion": {
            "source_lock": args.source_lock.as_posix(),
            "reference": args.reference.as_posix(),
            "artifact_directory": artifact.as_posix(),
            "independent_deb_rescan": True,
            "dependency_source": args.dependency_source,
            "dependency_version": args.dependency_version,
            "required_local_packages": args.required_local_package,
        },
    }

    args.result_path.parent.mkdir(parents=True, exist_ok=True)
    args.result_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
