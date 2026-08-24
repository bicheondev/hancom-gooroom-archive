#!/usr/bin/env python3
"""Prepare deterministic bundles from exact-source recovery artifacts.

Authorized and candidate material are never mixed:

* historical InRelease -> Sources -> .dsc/member chains are authorized;
* exact .dsc archives whose signature verified against the locked ISO keyring
  are authorized;
* complete exact .dsc archives without a verified signature are quarantined as
  candidates for AMD64 reconstruction comparison; and
* incomplete or ambiguous material is not bundled.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Iterable

SCHEMA = 1
SAFE_RE = re.compile(r"[^A-Za-z0-9._+~-]")
SOURCE_MEMBER_RE = re.compile(
    r"(?:\.dsc|\.diff\.gz|\.debian\.tar\.(?:gz|xz|bz2|zst)|"
    r"\.orig(?:-[^.]+)?\.tar\.(?:gz|xz|bz2|zst)|\.tar\.(?:gz|xz|bz2|zst))$",
    re.I,
)


def safe(value: str) -> str:
    return SAFE_RE.sub("_", value)


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def find_manifests(root: Path | None, name: str) -> list[Path]:
    if root is None or not root.exists():
        return []
    return sorted(root.rglob(name))


def member_expectations(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for member in manifest.get("members", []):
        filename = member.get("filename", "")
        if filename:
            rows[filename] = member
    return rows


def source_files_near_manifest(path: Path, manifest: dict[str, Any]) -> list[Path]:
    expected = member_expectations(manifest)
    files: list[Path] = []
    for filename in sorted(expected):
        direct = path.parent / filename
        if direct.is_file():
            files.append(direct)
            continue
        matches = [item for item in path.parent.rglob(filename) if item.is_file()]
        if len(matches) == 1:
            files.append(matches[0])
    # Historical recovery manifests may describe the .dsc as a Sources member;
    # candidate manifests store it separately at the candidate directory root.
    dsc_name = manifest.get("dsc_filename", "")
    if dsc_name and not any(item.name == dsc_name for item in files):
        candidate = path.parent / dsc_name
        if candidate.is_file():
            files.append(candidate)
    return sorted(set(files), key=lambda item: item.name)


def validate_material(
    manifest_path: Path,
    manifest: dict[str, Any],
    authority: str,
) -> tuple[bool, str, list[dict[str, Any]]]:
    source = manifest.get("source", "")
    version = manifest.get("version", "")
    if not source or not version:
        return False, "manifest lacks source/version", []
    files = source_files_near_manifest(manifest_path, manifest)
    expected = member_expectations(manifest)
    if not files:
        return False, "no source members found beside manifest", []

    records: list[dict[str, Any]] = []
    for path in files:
        if not SOURCE_MEMBER_RE.search(path.name):
            continue
        record = {
            "filename": path.name,
            "size": path.stat().st_size,
            "sha256": hash_file(path),
            "path": str(path),
        }
        expectation = expected.get(path.name)
        if expectation:
            record["expected_size"] = expectation.get("size")
            record["expected_sha256"] = expectation.get(
                "sha256", expectation.get("verified_sha256", "")
            )
            record["size_match"] = record["size"] == expectation.get("size")
            expected_hash = record["expected_sha256"]
            record["sha256_match"] = bool(expected_hash and record["sha256"] == expected_hash)
        else:
            # In candidate manifests the .dsc is described by top-level fields.
            if path.name == manifest.get("dsc_filename"):
                record["expected_size"] = manifest.get("dsc_size")
                record["expected_sha256"] = manifest.get("dsc_sha256", "")
                record["size_match"] = record["size"] == manifest.get("dsc_size")
                record["sha256_match"] = record["sha256"] == manifest.get("dsc_sha256")
            else:
                record["size_match"] = False
                record["sha256_match"] = False
        records.append(record)

    expected_names = set(expected)
    present_names = {record["filename"] for record in records}
    dsc_name = manifest.get("dsc_filename", "")
    if dsc_name:
        expected_names.add(dsc_name)
    missing = sorted(expected_names - present_names)
    invalid = [
        record["filename"]
        for record in records
        if not record.get("size_match") or not record.get("sha256_match")
    ]
    if missing:
        return False, f"missing source members: {', '.join(missing)}", records
    if invalid:
        return False, f"member checksum mismatch: {', '.join(invalid)}", records
    if authority == "historical-inrelease-chain" and not manifest.get("complete"):
        return False, "historical recovery manifest is not complete", records
    if authority == "iso-keyring-signed-dsc" and not (
        manifest.get("complete")
        and manifest.get("promotion_allowed")
        and manifest.get("signature", {}).get("verified")
    ):
        return False, "candidate lacks complete ISO-keyring signature authority", records
    if authority == "unverified-exact-dsc-candidate" and not (
        manifest.get("complete") and not manifest.get("promotion_allowed")
    ):
        return False, "candidate is not complete or is already authorized", records
    return True, "all source members verified", records


def deterministic_tar(source_dir: Path, tar_path: Path) -> None:
    def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        info.mtime = 0
        info.mode = 0o755 if info.isdir() else 0o644
        return info

    with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(source_dir.rglob("*"), key=lambda item: item.relative_to(source_dir).as_posix()):
            relative = path.relative_to(source_dir)
            archive.add(path, arcname=relative.as_posix(), recursive=False, filter=normalize)


def make_bundle(
    output_dir: Path,
    category: str,
    authority: str,
    manifest_path: Path,
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    source = manifest["source"]
    version = manifest["version"]
    content_identity = hashlib.sha256(
        json.dumps(
            [(row["filename"], row["size"], row["sha256"]) for row in sorted(records, key=lambda row: row["filename"])],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    stem = f"{safe(source)}--{safe(version)}--{safe(authority)}--{content_identity[:16]}"
    staging = output_dir / "staging" / category / stem
    staging.mkdir(parents=True, exist_ok=True)
    for row in records:
        source_path = Path(row["path"])
        shutil.copy2(source_path, staging / row["filename"])

    bundle_manifest = {
        "schema": SCHEMA,
        "category": category,
        "authority": authority,
        "source": source,
        "version": version,
        "content_identity_sha256": content_identity,
        "origin_manifest": str(manifest_path),
        "source_members": [
            {key: row[key] for key in ("filename", "size", "sha256")}
            for row in sorted(records, key=lambda row: row["filename"])
        ],
    }
    write_json(staging / "BUNDLE-MANIFEST.json", bundle_manifest)
    lock_lines = [
        f"{hash_file(path)}  {path.name}"
        for path in sorted(staging.iterdir())
        if path.is_file() and path.name != "LOCKSUMS.sha256"
    ]
    (staging / "LOCKSUMS.sha256").write_text("\n".join(lock_lines) + "\n", encoding="utf-8")

    bundle_dir = output_dir / "bundles" / category
    bundle_dir.mkdir(parents=True, exist_ok=True)
    tar_path = bundle_dir / f"{stem}.tar"
    final_path = bundle_dir / f"{stem}.tar.zst"
    deterministic_tar(staging, tar_path)
    process = subprocess.run(
        ["zstd", "-19", "-T0", "--no-progress", "-f", str(tar_path), "-o", str(final_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    tar_path.unlink(missing_ok=True)
    if process.returncode:
        raise RuntimeError(f"zstd failed: {process.stderr[-4000:]}")
    return {
        **bundle_manifest,
        "asset_name": final_path.name,
        "bundle_path": str(final_path.relative_to(output_dir)),
        "bundle_size": final_path.stat().st_size,
        "bundle_sha256": hash_file(final_path),
    }


def collect_inputs(
    historical_root: Path | None,
    dsc_root: Path | None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in find_manifests(historical_root, "RECOVERY-MANIFEST.json"):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        rows.append(
            {
                "manifest_path": path,
                "manifest": manifest,
                "category": "authorized",
                "authority": "historical-inrelease-chain",
            }
        )
    for path in find_manifests(dsc_root, "CANDIDATE-MANIFEST.json"):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("complete") and manifest.get("promotion_allowed"):
            category = "authorized"
            authority = "iso-keyring-signed-dsc"
        elif manifest.get("complete"):
            category = "candidate"
            authority = "unverified-exact-dsc-candidate"
        else:
            continue
        rows.append(
            {
                "manifest_path": path,
                "manifest": manifest,
                "category": category,
                "authority": authority,
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--historical-artifact", type=Path)
    parser.add_argument("--dsc-artifact", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    inputs = collect_inputs(args.historical_artifact, args.dsc_artifact)
    validations: list[dict[str, Any]] = []
    eligible: list[dict[str, Any]] = []
    for row in inputs:
        valid, reason, records = validate_material(
            row["manifest_path"], row["manifest"], row["authority"]
        )
        validation = {
            "source": row["manifest"].get("source", ""),
            "version": row["manifest"].get("version", ""),
            "category": row["category"],
            "authority": row["authority"],
            "manifest_path": str(row["manifest_path"]),
            "valid": valid,
            "reason": reason,
            "members": [
                {key: record.get(key) for key in ("filename", "size", "sha256", "size_match", "sha256_match")}
                for record in records
            ],
        }
        validations.append(validation)
        if valid:
            eligible.append({**row, "records": records})

    # Fail closed on conflicting authorized content for one exact source/version.
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in eligible:
        key = (
            row["category"],
            row["manifest"]["source"],
            row["manifest"]["version"],
        )
        grouped.setdefault(key, []).append(row)

    bundles: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    authority_rank = {
        "historical-inrelease-chain": 0,
        "iso-keyring-signed-dsc": 1,
        "unverified-exact-dsc-candidate": 2,
    }
    for (category, source, version), rows in sorted(grouped.items()):
        identities: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            identity = hashlib.sha256(
                json.dumps(
                    sorted(
                        (record["filename"], record["size"], record["sha256"])
                        for record in row["records"]
                    ),
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            identities.setdefault(identity, []).append(row)
        if len(identities) > 1:
            conflicts.append(
                {
                    "category": category,
                    "source": source,
                    "version": version,
                    "content_identities": sorted(identities),
                    "reason": "multiple different complete source archives",
                }
            )
            continue
        row = sorted(rows, key=lambda item: authority_rank[item["authority"]])[0]
        bundles.append(
            make_bundle(
                output,
                category,
                row["authority"],
                row["manifest_path"],
                row["manifest"],
                row["records"],
            )
        )

    authorized = [row for row in bundles if row["category"] == "authorized"]
    candidates = [row for row in bundles if row["category"] == "candidate"]
    summary = {
        "schema": SCHEMA,
        "policy": "separate-authorized-and-quarantined-exact-source-bundles",
        "input_manifest_count": len(inputs),
        "valid_input_count": len(eligible),
        "invalid_input_count": len(inputs) - len(eligible),
        "conflict_count": len(conflicts),
        "authorized_bundle_count": len(authorized),
        "candidate_bundle_count": len(candidates),
        "authorized_sources": [row["source"] for row in authorized],
        "candidate_sources": [row["source"] for row in candidates],
        "release_upload_performed": False,
    }
    write_json(output / "summary.json", summary)
    write_json(output / "validations.json", validations)
    write_json(output / "conflicts.json", conflicts)
    write_json(output / "bundle-plan.json", bundles)

    lines = [
        "# Recovered exact-source bundle plan",
        "",
        f"- Authorized bundles: **{len(authorized)}**",
        f"- Quarantined candidates: **{len(candidates)}**",
        f"- Conflicts: **{len(conflicts)}**",
        "",
        "| Class | Source | Version | Authority | SHA-256 |",
        "|---|---|---|---|---|",
    ]
    for row in bundles:
        lines.append(
            f"| {row['category']} | `{row['source']}` | `{row['version']}` | "
            f"{row['authority']} | `{row['bundle_sha256']}` |"
        )
    lines.append("")
    (output / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")
    shutil.rmtree(output / "staging", ignore_errors=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
