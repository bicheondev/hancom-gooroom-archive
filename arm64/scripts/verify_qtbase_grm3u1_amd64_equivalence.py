#!/usr/bin/env python3
"""Verify reconstructed QtBase grm3u1 AMD64 packages against immutable vendor DEBs.

This verifier deliberately reuses the locked gnome-flashback AMD64 comparison
engine. It therefore enforces complete semantic control identity, exact
auxiliary control members, identical installed path/type/mode/symlink sets,
byte identity for architecture-neutral payloads (or decompressed gzip
identity), and normalized ELF identity after removing only the locked
non-deterministic sections and canonicalizing semantically proven dynamic
string storage.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

SOURCE = "qtbase-opensource-src"
VERSION = "5.15.2+dfsg-9+grm3u1"
TARGET_ARCHITECTURES = {"amd64", "all"}
REQUIRED_PACKAGES = {
    "libqt5core5a",
    "libqt5dbus5",
    "libqt5gui5",
    "libqt5network5",
    "libqt5printsupport5",
    "libqt5sql5",
    "libqt5test5",
    "libqt5widgets5",
    "libqt5xml5",
}


def load_comparison_engine() -> ModuleType:
    path = Path(__file__).with_name("verify_gnome_flashback_han3u4_amd64.py")
    if not path.is_file():
        raise SystemExit(f"missing locked AMD64 comparison engine: {path}")
    spec = importlib.util.spec_from_file_location(
        "_hancom_gooroom_amd64_equivalence_engine", path
    )
    if spec is None or spec.loader is None:
        raise SystemExit(f"unable to load AMD64 comparison engine: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENGINE = load_comparison_engine()


def write_json(path: Path, value: Any) -> None:
    ENGINE.write_json(path, value)


def package_row(path: Path) -> dict[str, Any]:
    control = ENGINE.deb_control(path)
    return {
        "package": control.get("Package", ""),
        "version": control.get("Version", ""),
        "architecture": control.get("Architecture", ""),
        "source": ENGINE.declared_source(control),
        "filename": path.name,
        "path": path.as_posix(),
        "size": path.stat().st_size,
        "sha256": ENGINE.sha256_file(path),
        "control": control,
    }


def discover_debs(
    directory: Path,
) -> tuple[dict[str, tuple[Path, dict[str, Any]]], list[dict[str, Any]]]:
    selected: dict[str, tuple[Path, dict[str, Any]]] = {}
    other: list[dict[str, Any]] = []
    for deb in sorted(directory.rglob("*.deb")):
        row = package_row(deb)
        package = row["package"]
        is_target = (
            row["source"] == SOURCE
            and row["version"] == VERSION
            and row["architecture"] in TARGET_ARCHITECTURES
            and not package.endswith("-dbgsym")
        )
        if not is_target:
            other.append({key: value for key, value in row.items() if key != "control"})
            continue
        if package in selected:
            previous = selected[package][0]
            raise SystemExit(
                f"duplicate {SOURCE} package {package}: {previous} and {deb}"
            )
        selected[package] = (deb, row)
    return selected, other


def load_vendor_lock(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("packages"), list):
        raise SystemExit(f"invalid vendor binary lock schema: {path}")
    return value


def validate_vendor_authority(
    target: dict[str, tuple[Path, dict[str, Any]]],
    lock: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    authority_rows: list[dict[str, Any]] = []
    fatal: list[dict[str, Any]] = []
    rows = lock["packages"]
    for package in sorted(target):
        path, observed = target[package]
        matches = [
            row
            for row in rows
            if row.get("package") == package
            and row.get("version") == VERSION
            and row.get("architecture") == observed["architecture"]
            and row.get("status") == "verified"
        ]
        if len(matches) != 1:
            fatal.append(
                {
                    "kind": "vendor-lock-uniqueness",
                    "package": package,
                    "architecture": observed["architecture"],
                    "match_count": len(matches),
                }
            )
            continue
        authority = matches[0]
        checks = {
            "filename": authority.get("local_filename") == path.name,
            "size": int(authority.get("actual_size", -1)) == path.stat().st_size,
            "sha256": authority.get("actual_sha256") == ENGINE.sha256_file(path),
        }
        authority_rows.append(
            {
                "package": package,
                "architecture": observed["architecture"],
                "observed": {
                    "filename": path.name,
                    "size": path.stat().st_size,
                    "sha256": ENGINE.sha256_file(path),
                },
                "locked": {
                    "filename": authority.get("local_filename"),
                    "size": authority.get("actual_size"),
                    "sha256": authority.get("actual_sha256"),
                    "status": authority.get("status"),
                },
                "checks": checks,
                "verified": all(checks.values()),
            }
        )
        if not all(checks.values()):
            fatal.append(
                {
                    "kind": "vendor-lock-mismatch",
                    "package": package,
                    "checks": checks,
                }
            )
    return authority_rows, fatal


def compact_rows(
    packages: dict[str, tuple[Path, dict[str, Any]]]
) -> list[dict[str, Any]]:
    return [
        {
            key: value
            for key, value in packages[package][1].items()
            if key not in {"control", "path"}
        }
        for package in sorted(packages)
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-deb-dir", type=Path, required=True)
    parser.add_argument("--candidate-deb-dir", type=Path, required=True)
    parser.add_argument("--vendor-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    target_dir = args.target_deb_dir.resolve()
    candidate_dir = args.candidate_deb_dir.resolve()
    vendor_lock_path = args.vendor_lock.resolve()
    output = args.output_dir.resolve()

    for path, kind in (
        (target_dir, "target DEB directory"),
        (candidate_dir, "candidate DEB directory"),
        (vendor_lock_path, "vendor lock"),
    ):
        if not path.exists():
            raise SystemExit(f"missing {kind}: {path}")

    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)

    target, target_other = discover_debs(target_dir)
    candidate, candidate_other = discover_debs(candidate_dir)
    vendor_lock = load_vendor_lock(vendor_lock_path)

    fatal: list[dict[str, Any]] = []
    target_names = set(target)
    candidate_names = set(candidate)
    missing_required = sorted(REQUIRED_PACKAGES - target_names)
    if missing_required:
        fatal.append(
            {
                "kind": "required-vendor-package-set",
                "missing": missing_required,
                "required": sorted(REQUIRED_PACKAGES),
                "actual": sorted(target_names),
            }
        )

    missing_candidates = sorted(target_names - candidate_names)
    if missing_candidates:
        fatal.append(
            {
                "kind": "missing-candidate-packages",
                "packages": missing_candidates,
            }
        )

    target_authority_rows, authority_fatal = validate_vendor_authority(
        target, vendor_lock
    )
    fatal.extend(authority_fatal)

    # The source build may legitimately emit development, tooling, examples,
    # translations, and dbgsym packages that were not selected into the
    # reference ISO. They are recorded but do not weaken or expand the target
    # authority. Any target package must nevertheless have exactly one
    # candidate counterpart.
    comparison_names = sorted(target_names & candidate_names)
    package_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="qtbase-grm3u1-amd64-") as temp:
        temporary = Path(temp)
        for package in comparison_names:
            result, differences = ENGINE.compare_package(
                package,
                target[package][0],
                candidate[package][0],
                temporary,
                output,
            )
            package_results.append(result)
            fatal.extend(differences)

    write_json(output / "target-packages.json", compact_rows(target))
    write_json(output / "candidate-packages.json", compact_rows(candidate))
    write_json(output / "target-other-debs.json", target_other)
    write_json(output / "candidate-other-debs.json", candidate_other)
    write_json(output / "vendor-authority.json", target_authority_rows)
    write_json(output / "package-comparisons.json", package_results)
    write_json(output / "differences.json", fatal)

    all_vendor_authority = (
        len(target_authority_rows) == len(target)
        and bool(target_authority_rows)
        and all(row["verified"] for row in target_authority_rows)
    )
    all_controls = bool(package_results) and all(
        row["control_fields_identical"] for row in package_results
    )
    all_auxiliary = bool(package_results) and all(
        row["auxiliary_control_members_identical"] for row in package_results
    )
    all_paths = bool(package_results) and all(
        row["same_payload_path_set"] for row in package_results
    )
    all_non_elf = bool(package_results) and all(
        row["non_elf_payload_identity"] for row in package_results
    )
    elf_count = sum(row["elf_file_count"] for row in package_results)
    all_normalized_elf = elf_count > 0 and all(
        row["normalized_elf_identity"] for row in package_results
    )
    all_raw_elf = elf_count > 0 and all(
        row["raw_elf_identity"] for row in package_results
    )

    verified = (
        not missing_required
        and not missing_candidates
        and len(comparison_names) == len(target)
        and len(target) >= len(REQUIRED_PACKAGES)
        and all_vendor_authority
        and all_controls
        and all_auxiliary
        and all_paths
        and all_non_elf
        and all_normalized_elf
        and not fatal
    )
    summary = {
        "schema": 1,
        "source": SOURCE,
        "source_version": VERSION,
        "target_architecture": "amd64",
        "policy": (
            "immutable-vendor-lock-plus-exact-semantic-control-plus-exact-"
            "auxiliary-control-plus-exact-path-type-mode-symlink-plus-non-elf-"
            "byte-or-decompressed-identity-plus-elf-byte-identity-after-build-"
            "metadata-removal-and-semantically-proven-dynamic-string-storage-"
            "canonicalization"
        ),
        "required_package_count": len(REQUIRED_PACKAGES),
        "target_package_count": len(target),
        "candidate_source_package_count": len(candidate),
        "compared_package_count": len(package_results),
        "required_packages_present": not missing_required,
        "all_target_candidates_present": not missing_candidates,
        "vendor_lock_verified": all_vendor_authority,
        "control_fields_identical": all_controls,
        "auxiliary_control_members_identical": all_auxiliary,
        "same_payload_path_sets": all_paths,
        "non_elf_payload_identity": all_non_elf,
        "elf_file_count": elf_count,
        "normalized_elf_identity": all_normalized_elf,
        "raw_elf_identity": all_raw_elf,
        "candidate_extra_source_packages": sorted(candidate_names - target_names),
        "fatal_difference_count": len(fatal),
        "package_results": package_results,
        "verified": verified,
    }
    write_json(output / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    if fatal:
        print(json.dumps(fatal, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
