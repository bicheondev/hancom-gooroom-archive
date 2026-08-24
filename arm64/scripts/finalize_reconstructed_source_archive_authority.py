#!/usr/bin/env python3
"""Apply independently verified reconstructed source-archive overlays.

Git-tree and signed-DSC authorities remain owned by effective-sources-v3. This
finalizer adds a deliberately separate authority type for a reconstructed
Debian source archive whose native ARM64 output has passed an independent AMD64
vendor-equivalence gate. No Git commit or tree identity is invented.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, NoReturn

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SELECTED_TYPE = "reconstructed-source-archive"
RESULT_SOURCE_TYPE = "verified-reconstructed-source-archive"
UNRESOLVED_STATUSES = {
    "unresolved-exact-source",
    "ambiguous-exact-signed-source",
    "ambiguous-exact-git-source",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable to read JSON {path}: {exc}")
    require(isinstance(value, dict), f"JSON document must be an object: {path}")
    return value


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def key(row: dict[str, Any]) -> tuple[str, str]:
    return str(row.get("source", "")), str(row.get("source_version", ""))


def positions(rows: list[dict[str, Any]]) -> dict[tuple[str, str], int]:
    result: dict[tuple[str, str], int] = {}
    for index, row in enumerate(rows):
        identity = key(row)
        require(all(identity), f"malformed source authority row at index {index}")
        require(identity not in result, f"duplicate source authority row: {identity}")
        result[identity] = index
    return result


def validate_members(value: Any, identity: tuple[str, str]) -> list[dict[str, Any]]:
    require(isinstance(value, list) and value, f"archive members are missing: {identity}")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for row in value:
        require(isinstance(row, dict), f"malformed archive member: {identity}")
        filename = str(row.get("filename", ""))
        digest = str(row.get("sha256", ""))
        try:
            size = int(row.get("size"))
        except (TypeError, ValueError):
            fail(f"invalid archive member size: {identity}: {row}")
        require(filename and filename not in names, f"duplicate/empty archive member: {identity}: {filename}")
        require(size > 0, f"empty archive member: {identity}: {filename}")
        require(HEX64.fullmatch(digest) is not None, f"invalid archive member hash: {identity}: {filename}")
        names.add(filename)
        result.append({"filename": filename, "size": size, "sha256": digest})
    result.sort(key=lambda row: row["filename"])
    return result


def canonical_selected(selected: dict[str, Any], identity: tuple[str, str]) -> dict[str, Any]:
    source, version = identity
    require(selected.get("type") == SELECTED_TYPE, f"unexpected source archive type: {identity}")
    require(selected.get("declared_source") == source, f"declared source mismatch: {identity}")
    require(selected.get("declared_version") == version, f"declared version mismatch: {identity}")
    manifest = str(selected.get("source_tree_manifest_sha256", ""))
    require(HEX64.fullmatch(manifest) is not None, f"invalid source-tree manifest hash: {identity}")
    dsc = selected.get("dsc")
    require(isinstance(dsc, dict), f"reconstructed DSC authority is missing: {identity}")
    require(dsc.get("reconstructed") is True, f"DSC is not marked reconstructed: {identity}")
    require(dsc.get("signature_verified") is False, f"reconstructed DSC must not claim a signature: {identity}")
    require(str(dsc.get("filename", "")), f"DSC filename is missing: {identity}")
    require(HEX64.fullmatch(str(dsc.get("sha256", ""))) is not None, f"invalid DSC hash: {identity}")
    require(
        HEX64.fullmatch(str(selected.get("reconstruction_authority_sha256", ""))) is not None,
        f"invalid reconstruction authority hash: {identity}",
    )
    require(
        HEX64.fullmatch(str(selected.get("amd64_equivalence_authority_sha256", ""))) is not None,
        f"invalid AMD64 equivalence authority hash: {identity}",
    )
    require(
        HEX64.fullmatch(str(selected.get("native_arm64_authority_sha256", ""))) is not None,
        f"invalid ARM64 authority hash: {identity}",
    )
    normalized = deepcopy(selected)
    normalized_members = validate_members(selected.get("archive_members"), identity)
    normalized["archive_members"] = normalized_members
    member_set_digest = hashlib.sha256(
        json.dumps(normalized_members, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    require(
        selected.get("source_archive_member_set_sha256") == member_set_digest,
        f"source archive member-set authority mismatch: {identity}",
    )
    return normalized


def verification_passed(result: dict[str, Any]) -> bool:
    if result.get("passed") is not True or result.get("verification_passed") is not True:
        return False
    verification = result.get("verification")
    return isinstance(verification, dict) and verification.get("passed") is True


def validate_result(
    path: Path,
    identity: tuple[str, str],
    selected: dict[str, Any],
    expected_packages: set[str],
) -> dict[str, Any]:
    result = load(path)
    source, version = identity
    require(int(result.get("schema", 0)) >= 4, f"source archive result schema is too old: {path}")
    require(result.get("source") == source, f"result source mismatch: {path}")
    require(result.get("source_version") == version, f"result version mismatch: {path}")
    require(result.get("source_type") == RESULT_SOURCE_TYPE, f"result source type mismatch: {path}")
    require(verification_passed(result), f"source archive result did not pass: {path}")
    manifest = selected["source_tree_manifest_sha256"]
    require(result.get("source_authority_sha256") == manifest, f"result source authority mismatch: {path}")
    require(result.get("original_source_archive_recovered") is False, f"result falsely claims original source recovery: {path}")
    require(result.get("byte_identity_claimed") is False, f"result falsely claims raw source identity: {path}")

    source_evidence = result.get("source_lock_evidence")
    require(isinstance(source_evidence, dict), f"result source evidence is missing: {path}")
    evidence_selected = source_evidence.get("selected")
    require(isinstance(evidence_selected, dict), f"result selected source evidence is missing: {path}")
    require(canonical_selected(evidence_selected, identity) == selected, f"result selected authority differs from overlay: {path}")

    verification = result["verification"]
    require(verification.get("source") == source, f"verification source mismatch: {path}")
    require(verification.get("source_version") == version, f"verification version mismatch: {path}")
    require(verification.get("source_type") == RESULT_SOURCE_TYPE, f"verification source type mismatch: {path}")
    require(verification.get("source_authority_sha256") == manifest, f"verification source authority mismatch: {path}")
    require(verification.get("amd64_equivalence_verified") is True, f"AMD64 equivalence gate missing: {path}")
    require(verification.get("native_arm64_build_verified") is True, f"native ARM64 gate missing: {path}")
    require(verification.get("original_source_archive_recovered") is False, f"verification source recovery claim changed: {path}")
    require(int(verification.get("foreign_payload_count", -1)) == 0, f"foreign payloads survived: {path}")
    require(int(verification.get("wrong_architecture_executable_count", -1)) == 0, f"wrong architecture payloads survived: {path}")

    packages = verification.get("packages")
    require(isinstance(packages, list) and packages, f"verified packages are missing: {path}")
    names: set[str] = set()
    for row in packages:
        require(isinstance(row, dict), f"malformed verified package: {path}")
        package = str(row.get("package", ""))
        require(package and package not in names, f"duplicate verified package: {path}: {package}")
        names.add(package)
        require(row.get("version") == version, f"verified package version mismatch: {path}: {package}")
        require(row.get("architecture") in {"arm64", "all"}, f"non-ARM64 package: {path}: {package}")
        require(row.get("source") in {None, "", source}, f"verified package source mismatch: {path}: {package}")
        require(row.get("source_version") in {None, "", version}, f"verified package source version mismatch: {path}: {package}")
        require(int(row.get("foreign_payload_count", 0) or 0) == 0, f"foreign package payload: {path}: {package}")
        require(int(row.get("x86_payload_count", 0) or 0) == 0, f"x86 package payload: {path}: {package}")
        require(HEX64.fullmatch(str(row.get("sha256", ""))) is not None, f"invalid package hash: {path}: {package}")
        require(int(row.get("size", 0) or 0) > 0, f"invalid package size: {path}: {package}")
    require(names == expected_packages, f"verified package set differs from reference source row: {path}: {sorted(names ^ expected_packages)}")
    return {
        "result_path": path.as_posix(),
        "actions_run_id": str(result.get("actions_run_id", "")),
        "actions_run_url": result.get("actions_run_url"),
        "artifact_name": result.get("artifact_name"),
        "verified_package_count": len(packages),
        "source_authority_sha256": manifest,
        "passed": True,
    }


def write_tsv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "source",
        "source_version",
        "role",
        "status",
        "provenance",
        "selected_type",
        "source_authority_sha256",
        "dsc_sha256",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in rows:
            selected = row.get("selected") if isinstance(row.get("selected"), dict) else {}
            dsc = selected.get("dsc") if isinstance(selected.get("dsc"), dict) else {}
            writer.writerow(
                {
                    "source": row.get("source", ""),
                    "source_version": row.get("source_version", ""),
                    "role": row.get("role", ""),
                    "status": row.get("status", ""),
                    "provenance": row.get("provenance") or "",
                    "selected_type": selected.get("type", ""),
                    "source_authority_sha256": selected.get("source_tree_manifest_sha256", ""),
                    "dsc_sha256": dsc.get("sha256", ""),
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-lock", type=Path, required=True)
    parser.add_argument("--archive-overlays", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    base = load(args.base_lock)
    rows = base.get("sources")
    require(isinstance(rows, list), "base authority must contain a sources array")
    rows = deepcopy(rows)
    index = positions(rows)

    overlay_document = load(args.archive_overlays)
    overlays = overlay_document.get("sources")
    require(isinstance(overlays, list) and overlays, "source archive overlay lock must contain sources")
    declared_count = overlay_document.get("source_count")
    if declared_count is not None:
        require(int(declared_count) == len(overlays), "source archive overlay count mismatch")

    applied: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for overlay in overlays:
        require(isinstance(overlay, dict), "malformed source archive overlay")
        identity = key(overlay)
        require(all(identity), "source archive overlay identity is incomplete")
        require(identity not in seen, f"duplicate source archive overlay: {identity}")
        seen.add(identity)
        require(identity in index, f"source archive overlay is absent from base authority: {identity}")
        require(overlay.get("status") == "resolved", f"source archive overlay is not resolved: {identity}")
        selected_value = overlay.get("selected")
        require(isinstance(selected_value, dict), f"source archive selected authority is missing: {identity}")
        selected = canonical_selected(selected_value, identity)
        verification = overlay.get("verification")
        require(isinstance(verification, dict) and verification.get("passed") is True, f"source archive overlay verification did not pass: {identity}")
        result_value = verification.get("result_path")
        require(result_value, f"source archive overlay result path is missing: {identity}")

        original = rows[index[identity]]
        expected_packages = {str(value) for value in original.get("binary_packages", []) if value}
        require(expected_packages, f"base source row contains no binary package authority: {identity}")
        result_evidence = validate_result(Path(str(result_value)), identity, selected, expected_packages)

        merged = deepcopy(original)
        merged.update(
            {
                "status": "resolved",
                "provenance": overlay.get("provenance", "verified-reconstructed-source-archive"),
                "selected": selected,
                "reconstructed_source_archive_evidence": {
                    **deepcopy(verification),
                    **result_evidence,
                    "authority_lock": args.archive_overlays.as_posix(),
                    "original_status": original.get("status"),
                    "original_provenance": original.get("provenance"),
                },
            }
        )
        rows[index[identity]] = merged
        applied.append(
            {
                "source": identity[0],
                "source_version": identity[1],
                "source_tree_manifest_sha256": selected["source_tree_manifest_sha256"],
                "dsc_sha256": selected["dsc"]["sha256"],
                "result_path": str(result_value),
                "verified_package_count": result_evidence["verified_package_count"],
            }
        )

    unresolved = [row for row in rows if row.get("status") in UNRESOLVED_STATUSES]
    blockers = [
        row
        for row in unresolved
        if row.get("role") == "rebuild-arm64" and row.get("source") != "linux-signed-amd64"
    ]
    base_summary = base.get("summary") if isinstance(base.get("summary"), dict) else {}
    summary = deepcopy(base_summary)
    summary.update(
        {
            "schema": max(int(summary.get("schema", 1)), 5),
            "policy": (
                "exact-signed-dsc-then-exact-git-then-verified-build-selection-"
                "then-verified-reconstructed-git-tree-then-verified-reconstructed-source-archive"
            ),
            "source_target_count": len(rows),
            "resolved_count": sum(row.get("status") == "resolved" for row in rows),
            "unresolved_count": len(unresolved),
            "rebuild_blocker_count": len(blockers),
            "build_allowed": not blockers,
            "reconstructed_source_archive_resolved_count": len(applied),
            "reconstructed_source_archive_overlays": applied,
        }
    )

    source_overlays = deepcopy(base.get("source_overlays")) if isinstance(base.get("source_overlays"), dict) else {"schema": 1}
    source_overlays.update(
        {
            "schema": max(int(source_overlays.get("schema", 1)), 2),
            "reconstructed_source_archive_authority": args.archive_overlays.as_posix(),
            "reconstructed_source_archive_applied": applied,
        }
    )
    output = {
        "summary": summary,
        "sources": rows,
        "source_overlays": source_overlays,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write(args.output_dir / "effective-source-lock.json", output)
    write(args.output_dir / "effective-source-lock-summary.json", summary)
    write(args.output_dir / "effective-source-unresolved.json", unresolved)
    write(args.output_dir / "effective-source-rebuild-blockers.json", blockers)
    write(
        args.output_dir / "source-archive-overlay-report.json",
        {
            "schema": 1,
            "base_authority": args.base_lock.as_posix(),
            "source_archive_authority": args.archive_overlays.as_posix(),
            "applied_count": len(applied),
            "applied": applied,
            "passed": True,
        },
    )
    write_tsv(args.output_dir / "effective-source-lock.tsv", rows)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
