#!/usr/bin/env python3
"""Index verified native ARM64 rebuild results from all provenance paths."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_SORT_FIELDS = (
    "package",
    "version",
    "architecture",
    "filename",
    "sha256",
)


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_id(row: dict[str, Any]) -> int:
    try:
        return int(str(row.get("actions_run_id", "0")))
    except ValueError:
        return 0


def append_errors(target: list[Any], value: Any) -> None:
    if value in (None, "", []):
        return
    if isinstance(value, list):
        target.extend(value)
    else:
        target.append(value)


def normalize_packages(
    value: Any,
    *,
    source: str,
    version: str,
    label: str,
    strict: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    packages: list[dict[str, Any]] = []
    if value is None:
        return packages, errors
    if not isinstance(value, list):
        return packages, [f"{label} must be an array"]

    seen: set[tuple[Any, ...]] = set()
    for index, package in enumerate(value):
        location = f"{label}[{index}]"
        if not isinstance(package, dict):
            errors.append(f"{location} must be an object")
            continue

        required = ("package", "version", "architecture", "filename", "sha256")
        missing = [field for field in required if not package.get(field)]
        if strict:
            missing.extend(
                field
                for field in ("size", "source", "source_version")
                if package.get(field) in (None, "")
            )
        if missing:
            errors.append(f"{location} missing required fields: {sorted(set(missing))}")
            continue

        architecture = str(package["architecture"])
        if architecture not in {"arm64", "all"}:
            errors.append(f"{location} has unsupported architecture: {architecture}")
            continue

        digest = str(package["sha256"])
        if not SHA256_RE.fullmatch(digest):
            errors.append(f"{location} has invalid SHA-256")
            continue

        raw_size = package.get("size", 0)
        try:
            size = int(raw_size)
        except (TypeError, ValueError):
            errors.append(f"{location} has a non-integer size")
            continue
        if size < 0 or (strict and size == 0):
            errors.append(f"{location} has an invalid size: {size}")
            continue

        package_source = str(package.get("source") or source)
        package_source_version = str(package.get("source_version") or version)
        if strict and package_source != source:
            errors.append(
                f"{location} source mismatch: {package_source!r} != {source!r}"
            )
            continue
        if strict and package_source_version != version:
            errors.append(
                f"{location} source version mismatch: "
                f"{package_source_version!r} != {version!r}"
            )
            continue

        normalized = {
            "package": str(package["package"]),
            "version": str(package["version"]),
            "architecture": architecture,
            "filename": str(package["filename"]),
            "sha256": digest,
            "size": size,
            "source": package_source,
            "source_version": package_source_version,
        }
        identity = tuple(
            normalized[field]
            for field in (
                *PACKAGE_SORT_FIELDS,
                "size",
                "source",
                "source_version",
            )
        )
        if identity in seen:
            if strict:
                errors.append(f"{location} duplicates an earlier package record")
            continue
        seen.add(identity)
        packages.append(normalized)

    packages.sort(key=lambda item: tuple(item[field] for field in PACKAGE_SORT_FIELDS))
    return packages, errors


def package_identities(packages: list[dict[str, Any]]) -> set[tuple[Any, ...]]:
    return {
        tuple(
            package[field]
            for field in (
                "package",
                "version",
                "architecture",
                "filename",
                "sha256",
                "size",
                "source",
                "source_version",
            )
        )
        for package in packages
    }


def normalize_result(path: Path, root: Path) -> dict[str, Any] | None:
    try:
        row = load(path)
    except Exception:
        return None
    source = row.get("source")
    version = row.get("source_version")
    if not source or not version:
        return None
    source = str(source)
    version = str(version)

    verification = row.get("verification")
    if verification is None:
        candidate = path.parent / "verification.json"
        if candidate.exists():
            try:
                verification = load(candidate)
            except Exception:
                verification = None
    verification_summary = row.get("verification_summary")

    internal_errors: list[str] = []
    legacy_packages: list[dict[str, Any]] = []
    if isinstance(verification, dict):
        legacy_packages, errors = normalize_packages(
            verification.get("packages"),
            source=source,
            version=version,
            label="verification.packages",
            strict=False,
        )
        internal_errors.extend(errors)

    reconstructed = row.get("source_type") == "verified-reconstructed-git-tree"
    top_level_packages, errors = normalize_packages(
        row.get("deb_artifacts"),
        source=source,
        version=version,
        label="deb_artifacts",
        strict=reconstructed,
    )
    internal_errors.extend(errors)

    summary_packages: list[dict[str, Any]] = []
    if isinstance(verification_summary, dict):
        summary_packages, errors = normalize_packages(
            verification_summary.get("deb_artifacts"),
            source=source,
            version=version,
            label="verification_summary.deb_artifacts",
            strict=reconstructed,
        )
        internal_errors.extend(errors)

    if reconstructed:
        packages = top_level_packages
        if row.get("schema") != 4:
            internal_errors.append("verified reconstructed result must use schema 4")
        for field in ("passed", "verification_passed", "job_passed"):
            if row.get(field) is not True:
                internal_errors.append(f"{field} must be true")
        if row.get("build_outcome") != "success":
            internal_errors.append("build_outcome must be success")
        if row.get("verify_outcome") != "success":
            internal_errors.append("verify_outcome must be success")
        if not top_level_packages:
            internal_errors.append("deb_artifacts must contain verified packages")
        if not isinstance(verification_summary, dict):
            internal_errors.append("verification_summary must be an object")
        else:
            if verification_summary.get("verified") is not True:
                internal_errors.append("verification_summary.verified must be true")
            if verification_summary.get("source") != source:
                internal_errors.append("verification_summary source mismatch")
            if verification_summary.get("source_version") != version:
                internal_errors.append("verification_summary source version mismatch")
            if verification_summary.get("wrong_architecture_executables") != []:
                internal_errors.append(
                    "verification_summary contains foreign executable payloads"
                )
            if not summary_packages:
                internal_errors.append(
                    "verification_summary.deb_artifacts must contain verified packages"
                )
            elif package_identities(summary_packages) != package_identities(
                top_level_packages
            ):
                internal_errors.append(
                    "deb_artifacts disagree with verification_summary.deb_artifacts"
                )
        passed = not internal_errors
    else:
        packages = top_level_packages or summary_packages or legacy_packages
        passed = bool(row.get("passed"))
        if isinstance(verification, dict):
            passed = passed and verification.get("passed") is True
        if row.get("verification_passed") is not None:
            passed = passed and row.get("verification_passed") is True
        if row.get("job_passed") is not None:
            passed = passed and row.get("job_passed") is True
        if passed and not packages:
            passed = False

    verification_errors: list[Any] = []
    append_errors(verification_errors, row.get("verification_errors"))
    if isinstance(verification, dict):
        append_errors(verification_errors, verification.get("errors"))
        append_errors(verification_errors, verification.get("verification_errors"))
    if isinstance(verification_summary, dict):
        append_errors(
            verification_errors, verification_summary.get("verification_errors")
        )
    append_errors(verification_errors, internal_errors)

    provenance = row.get("provenance") or row.get("source_type")
    if not provenance:
        if row.get("dsc_sha256"):
            provenance = "vendor-apt-exact-signed-dsc"
        elif row.get("commit_sha"):
            provenance = "github-exact-commit"
        else:
            provenance = "unknown"

    artifact_name = row.get("artifact_name")
    if not artifact_name:
        artifact_name = path.parents[0].name

    return {
        "source": source,
        "source_version": version,
        "provenance": provenance,
        "repository": row.get("repository_full_name") or row.get("repository"),
        "commit_sha": row.get("commit_sha"),
        "tree_sha": row.get("tree_sha"),
        "dsc_sha256": row.get("dsc_sha256"),
        "actions_run_id": str(row.get("actions_run_id", "")),
        "actions_run_url": row.get("actions_run_url"),
        "artifact_name": artifact_name,
        "passed": passed,
        "packages": packages,
        "verification_errors": verification_errors,
        "evidence_path": str(path.relative_to(root)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    parse_errors: list[dict[str, str]] = []
    for root in args.root:
        if not root.exists():
            continue
        for path in sorted(root.rglob("result.json")):
            try:
                row = normalize_result(path, root)
            except Exception as error:
                parse_errors.append({"path": str(path), "error": repr(error)})
                continue
            if row:
                candidates[(row["source"], row["source_version"])].append(row)

    rows: list[dict[str, Any]] = []
    package_index: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for key, attempts in sorted(candidates.items()):
        attempts.sort(
            key=lambda row: (
                1 if row["passed"] else 0,
                run_id(row),
                row.get("artifact_name") or "",
            ),
            reverse=True,
        )
        selected = attempts[0]
        record = {
            "source": key[0],
            "source_version": key[1],
            "status": "verified" if selected["passed"] else "failed",
            "selected": selected,
            "attempt_count": len(attempts),
            "attempts": attempts,
        }
        rows.append(record)
        if selected["passed"]:
            for package in selected["packages"]:
                package_index[(package["package"], package["version"])].append(
                    {
                        **package,
                        "source": key[0],
                        "source_version": key[1],
                        "provenance": selected["provenance"],
                        "actions_run_id": selected["actions_run_id"],
                        "actions_run_url": selected["actions_run_url"],
                        "artifact_name": selected["artifact_name"],
                        "commit_sha": selected.get("commit_sha"),
                        "tree_sha": selected.get("tree_sha"),
                        "dsc_sha256": selected.get("dsc_sha256"),
                    }
                )

    package_rows = []
    ambiguous_packages = []
    for key, entries in sorted(package_index.items()):
        identities = {
            (
                entry["architecture"],
                entry["filename"],
                entry["sha256"],
                entry["size"],
            )
            for entry in entries
        }
        if len(identities) != 1:
            ambiguous_packages.append(
                {"package": key[0], "version": key[1], "entries": entries}
            )
            continue
        package_rows.append(entries[0])

    summary = {
        "schema": 2,
        "policy": "latest-verified-exact-source-native-arm64-result",
        "source_result_count": len(rows),
        "verified_source_count": sum(row["status"] == "verified" for row in rows),
        "failed_source_count": sum(row["status"] == "failed" for row in rows),
        "verified_binary_package_count": len(package_rows),
        "ambiguous_binary_package_count": len(ambiguous_packages),
        "parse_error_count": len(parse_errors),
        "package_index_usable": not ambiguous_packages and not parse_errors,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "rebuild-result-index.json").write_text(
        json.dumps({"summary": summary, "sources": rows}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "verified-binary-packages.json").write_text(
        json.dumps(package_rows, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "ambiguous-binary-packages.json").write_text(
        json.dumps(ambiguous_packages, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "parse-errors.json").write_text(
        json.dumps(parse_errors, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["package_index_usable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
