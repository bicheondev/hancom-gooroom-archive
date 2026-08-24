#!/usr/bin/env python3
"""Probe deterministic .dsc pool paths for unresolved exact source versions.

This is the second recovery tier.  It derives source pool directories only from
exact binary Package stanzas preserved in the locked reference ISO, then probes
the matching official Hancom Gooroom repository paths and their archived copies.
A candidate is considered complete only when the .dsc names the exact source and
version, every member matches the .dsc SHA-256/size, and the unpacked
`debian/changelog` begins with the same exact version.

A complete candidate remains non-promotable unless its OpenPGP signature verifies
against a keyring extracted from the same locked reference ISO (or another
higher-tier historical Sources-index authority has already accepted it).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recover_exact_sources_from_reference_apt import (  # noqa: E402
    download_url,
    dsc_payload_fields,
    fetch_matching_bytes,
    hash_file,
    load_repo_entries,
    normalized_source_from_dsc,
    safe,
    sha256_bytes,
    source_members,
    url_join,
    variant_uris,
    wayback_captures,
    write_json,
)

SCHEMA = 1
DSC_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*_.+\.dsc$")
CHANGELOG_HEADER_RE = re.compile(r"^[^\s]+\s+\(([^)]+)\)")


def version_without_epoch(version: str) -> str:
    return version.split(":", 1)[-1]


def dsc_filename(source: str, version: str) -> str:
    value = f"{source}_{version_without_epoch(version)}.dsc"
    if not DSC_RE.match(value):
        raise ValueError(f"unsafe or non-Debian .dsc filename: {value}")
    return value


def family_from_index_path(index_path: str) -> str | None:
    value = index_path.lower()
    if (
        "update.hancomgooroom.com_hancom_" in value
        or "hancom_dists_hancom" in value
        or "iso:/dists/hancom" in value
    ):
        return "hancom"
    if (
        "update.hancomgooroom.com_gooroom_" in value
        or "gooroom_dists_gooroom" in value
        or "iso:/dists/gooroom" in value
    ):
        return "gooroom"
    return None


def derive_pool_candidates(
    target: dict[str, Any], repo_entries: Sequence[Any]
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    stanzas = target.get("package_index_stanzas", []) + target.get(
        "installed_status_stanzas", []
    )
    for stanza in stanzas:
        filename = stanza.get("filename", "")
        if not filename or "/" not in filename:
            continue
        directory = filename.rsplit("/", 1)[0].strip("/")
        if not directory.startswith("pool/"):
            continue
        family = family_from_index_path(stanza.get("index_path", ""))
        for entry in repo_entries:
            entry_family = entry.path.rsplit("/", 1)[-1]
            if family and entry_family != family:
                continue
            for uri in variant_uris(entry.uri):
                rows.append(
                    {
                        "repository_uri": uri,
                        "suite": entry.suite,
                        "family": entry_family,
                        "pool_directory": directory,
                        "index_path": stanza.get("index_path", ""),
                        "binary_filename": filename,
                    }
                )
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (row["repository_uri"], row["pool_directory"])
        if key not in seen:
            seen.add(key)
            deduped.append(row)
    return deduped


def parse_exact_dsc(path: Path, source: str, version: str) -> tuple[bool, dict[str, str]]:
    try:
        fields = dsc_payload_fields(path)
    except OSError:
        return False, {}
    return (
        normalized_source_from_dsc(fields) == source
        and fields.get("Version", "") == version,
        fields,
    )


def gpgv_verify(path: Path, keyrings: Sequence[Path]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "attempted": bool(keyrings),
        "verified": False,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "keyrings": [str(item) for item in keyrings],
    }
    if not keyrings:
        return result
    command = ["gpgv"]
    for keyring in keyrings:
        command.extend(["--keyring", str(keyring)])
    command.append(str(path))
    process = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    result.update(
        {
            "verified": process.returncode == 0,
            "returncode": process.returncode,
            "stdout": process.stdout[-8000:],
            "stderr": process.stderr[-8000:],
        }
    )
    return result


def gpg_packet_metadata(path: Path) -> dict[str, Any]:
    process = subprocess.run(
        ["gpg", "--batch", "--list-packets", str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    packet_text = process.stdout + "\n" + process.stderr
    issuer_fingerprints = sorted(
        set(re.findall(r"issuer fpr v\d+ ([0-9A-Fa-f]{40,64})", packet_text))
    )
    keyids = sorted(set(re.findall(r"keyid ([0-9A-Fa-f]{16})", packet_text)))
    return {
        "returncode": process.returncode,
        "issuer_fingerprints": issuer_fingerprints,
        "keyids": keyids,
        "output_tail": packet_text[-12000:],
    }


def first_changelog_version(source_tree: Path) -> str:
    path = source_tree / "debian" / "changelog"
    if not path.is_file():
        return ""
    first_line = path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    match = CHANGELOG_HEADER_RE.match(first_line)
    return match.group(1) if match else ""


def recover_candidate(
    source: str,
    version: str,
    dsc_path: Path,
    origin_url: str,
    keyrings: Sequence[Path],
    work_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fields = dsc_payload_fields(dsc_path)
    members = source_members(fields)
    dsc_sha256 = hash_file(dsc_path)
    candidate_id = dsc_sha256[:20]
    candidate_dir = (
        work_dir / "candidates" / safe(source) / safe(version) / candidate_id
    )
    candidate_dir.mkdir(parents=True, exist_ok=True)
    destination_dsc = candidate_dir / dsc_path.name
    shutil.copy2(dsc_path, destination_dsc)

    base_url = origin_url.rsplit("/", 1)[0] + "/"
    member_results: list[dict[str, Any]] = []
    probes: list[dict[str, Any]] = []
    downloaded: dict[str, Path] = {}
    for member in members:
        urls = [url_join(base_url, member["filename"])]
        found, member_probes = fetch_matching_bytes(
            urls,
            member["sha256"],
            member["size"],
            work_dir,
            f"pool-dsc-member-{source}-{candidate_id}-{member['filename']}",
        )
        probes.extend(member_probes)
        row = dict(member)
        row["urls"] = urls
        row["recovered"] = found is not None
        if found is not None:
            destination = candidate_dir / member["filename"]
            shutil.copy2(found, destination)
            downloaded[member["filename"]] = destination
            row["verified_sha256"] = hash_file(destination)
            row["artifact_path"] = str(destination.relative_to(work_dir))
        member_results.append(row)

    signature = gpgv_verify(destination_dsc, keyrings)
    packets = gpg_packet_metadata(destination_dsc)
    source_tree = candidate_dir / "source-tree"
    unpack = subprocess.run(
        ["dpkg-source", "--no-check", "-x", str(destination_dsc), str(source_tree)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd=candidate_dir,
    )
    changelog_version = first_changelog_version(source_tree) if unpack.returncode == 0 else ""
    every_member = bool(members) and all(row["recovered"] for row in member_results)
    exact_identity = (
        normalized_source_from_dsc(fields) == source
        and fields.get("Version", "") == version
    )
    changelog_match = changelog_version == version
    complete = bool(every_member and exact_identity and unpack.returncode == 0 and changelog_match)
    result = {
        "source": source,
        "version": version,
        "candidate_id": candidate_id,
        "origin_url": origin_url,
        "dsc_filename": dsc_path.name,
        "dsc_sha256": dsc_sha256,
        "dsc_size": destination_dsc.stat().st_size,
        "dsc_source": normalized_source_from_dsc(fields),
        "dsc_version": fields.get("Version", ""),
        "exact_identity": exact_identity,
        "member_count": len(members),
        "members": member_results,
        "all_members_recovered": every_member,
        "signature": signature,
        "signature_packets": packets,
        "unpack": {
            "returncode": unpack.returncode,
            "stdout": unpack.stdout[-8000:],
            "stderr": unpack.stderr[-8000:],
            "changelog_version": changelog_version,
            "changelog_version_match": changelog_match,
        },
        "complete": complete,
        "promotion_allowed": bool(complete and signature["verified"]),
        "artifact_directory": str(candidate_dir.relative_to(work_dir)),
    }
    write_json(candidate_dir / "CANDIDATE-MANIFEST.json", result)
    lock_lines = []
    for path in sorted(candidate_dir.iterdir()):
        if path.is_file() and path.name != "LOCKSUMS.sha256":
            lock_lines.append(f"{hash_file(path)}  {path.name}")
    (candidate_dir / "LOCKSUMS.sha256").write_text(
        "\n".join(lock_lines) + "\n", encoding="utf-8"
    )
    return result, probes


def probe_target(
    target: dict[str, Any],
    repo_entries: Sequence[Any],
    keyrings: Sequence[Path],
    work_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = target["source"]
    version = target["source_version"]
    filename = dsc_filename(source, version)
    pool_rows = derive_pool_candidates(target, repo_entries)
    probes: list[dict[str, Any]] = []
    exact_candidates: list[dict[str, Any]] = []
    seen_body_hashes: set[str] = set()

    for row_index, row in enumerate(pool_rows):
        direct_url = url_join(row["repository_uri"], row["pool_directory"] + "/", filename)
        destination = (
            work_dir
            / "probe-objects"
            / safe(source)
            / f"direct-{row_index}-{hashlib.sha256(direct_url.encode()).hexdigest()}"
        )
        probe = download_url(direct_url, destination)
        probe.update(
            {
                "source": source,
                "version": version,
                "kind": "direct-dsc",
                "pool": row,
            }
        )
        probes.append(probe)
        if probe["ok"] and destination.is_file():
            exact, _fields = parse_exact_dsc(destination, source, version)
            probe["exact_dsc_identity"] = exact
            if exact and probe["sha256"] not in seen_body_hashes:
                seen_body_hashes.add(probe["sha256"])
                candidate, member_probes = recover_candidate(
                    source,
                    version,
                    destination,
                    direct_url,
                    keyrings,
                    work_dir,
                )
                candidate["retrieval"] = "direct"
                candidate["pool"] = row
                exact_candidates.append(candidate)
                probes.extend(member_probes)

        captures, cdx_probe = wayback_captures(direct_url, work_dir)
        cdx_probe.update(
            {
                "source": source,
                "version": version,
                "kind": "wayback-cdx-dsc",
                "pool": row,
                "original_url": direct_url,
            }
        )
        probes.append(cdx_probe)
        for capture_index, capture in enumerate(captures):
            timestamp = capture.get("timestamp", "")
            original = capture.get("original", direct_url)
            if not timestamp:
                continue
            replay_url = f"https://web.archive.org/web/{timestamp}id_/{original}"
            destination = (
                work_dir
                / "probe-objects"
                / safe(source)
                / f"wayback-{row_index}-{capture_index}-{hashlib.sha256(replay_url.encode()).hexdigest()}"
            )
            replay_probe = download_url(replay_url, destination)
            replay_probe.update(
                {
                    "source": source,
                    "version": version,
                    "kind": "wayback-replay-dsc",
                    "pool": row,
                    "capture": capture,
                    "original_url": direct_url,
                }
            )
            probes.append(replay_probe)
            if not replay_probe["ok"] or not destination.is_file():
                continue
            exact, _fields = parse_exact_dsc(destination, source, version)
            replay_probe["exact_dsc_identity"] = exact
            if not exact or replay_probe["sha256"] in seen_body_hashes:
                continue
            seen_body_hashes.add(replay_probe["sha256"])
            candidate, member_probes = recover_candidate(
                source,
                version,
                destination,
                original,
                keyrings,
                work_dir,
            )
            candidate["retrieval"] = "wayback"
            candidate["capture"] = capture
            candidate["pool"] = row
            exact_candidates.append(candidate)
            probes.extend(member_probes)

    complete = [candidate for candidate in exact_candidates if candidate["complete"]]
    promotable = [candidate for candidate in complete if candidate["promotion_allowed"]]
    complete_hashes = sorted({candidate["dsc_sha256"] for candidate in complete})
    if len(complete_hashes) > 1:
        status = "ambiguous-complete-exact-dsc-candidates"
        promotion_allowed = False
        reason = "multiple different complete exact .dsc archives were recovered"
    elif promotable:
        status = "signature-verified-exact-dsc-recovered"
        promotion_allowed = True
        reason = "exact .dsc, every member, changelog, and ISO-keyring signature verified"
    elif complete:
        status = "complete-exact-dsc-candidate-unverified-signature"
        promotion_allowed = False
        reason = "complete exact source archive recovered but signature was not verified"
    elif exact_candidates:
        status = "incomplete-exact-dsc-candidate"
        promotion_allowed = False
        reason = "exact .dsc recovered but one or more source members or checks failed"
    else:
        status = "unresolved"
        promotion_allowed = False
        reason = "no exact .dsc was recovered from deterministic official pool paths"

    result = {
        "source": source,
        "version": version,
        "dsc_filename": filename,
        "pool_candidate_count": len(pool_rows),
        "pool_candidates": pool_rows,
        "exact_dsc_candidate_count": len(exact_candidates),
        "complete_candidate_count": len(complete),
        "signature_verified_candidate_count": len(promotable),
        "distinct_complete_dsc_count": len(complete_hashes),
        "status": status,
        "promotion_allowed": promotion_allowed,
        "reason": reason,
        "candidates": exact_candidates,
    }
    return result, probes


def discover_keyrings(root: Path | None) -> list[Path]:
    if root is None or not root.exists():
        return []
    candidates: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.stat().st_size == 0:
            continue
        if path.suffix.lower() in {".gpg", ".pgp", ".kbx"} or path.name == "trusted.gpg":
            candidates.append(path.resolve())
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-evidence", type=Path, required=True)
    parser.add_argument("--higher-tier-recovery", type=Path)
    parser.add_argument("--keyring-root", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = args.reference_evidence.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    work_dir = output / "work"
    work_dir.mkdir(parents=True, exist_ok=True)

    reference_summary = json.loads((reference / "summary.json").read_text())
    if not reference_summary.get("iso", {}).get("verified"):
        raise SystemExit("reference ISO evidence is not verified")
    targets: list[dict[str, Any]] = json.loads(
        (reference / "target-findings.json").read_text()
    )
    if len(targets) != 7:
        raise SystemExit(f"expected 7 targets, found {len(targets)}")

    higher_tier: dict[str, Any] = {}
    if args.higher_tier_recovery and (args.higher_tier_recovery / "summary.json").is_file():
        higher_tier = json.loads(
            (args.higher_tier_recovery / "summary.json").read_text()
        )
    already_promotable = set(higher_tier.get("promotion_allowed_targets", []))

    repo_entries = load_repo_entries(reference)
    keyrings = discover_keyrings(args.keyring_root)
    target_results: list[dict[str, Any]] = []
    probes: list[dict[str, Any]] = []
    for target in targets:
        if target["source"] in already_promotable:
            target_results.append(
                {
                    "source": target["source"],
                    "version": target["source_version"],
                    "status": "already-authorized-by-historical-sources-index",
                    "promotion_allowed": True,
                    "reason": "higher-tier recovery already verified the complete historical checksum chain",
                    "candidates": [],
                }
            )
            continue
        result, target_probes = probe_target(
            target,
            repo_entries,
            keyrings,
            work_dir,
        )
        target_results.append(result)
        probes.extend(target_probes)

    promotable = [row for row in target_results if row.get("promotion_allowed")]
    complete_unverified = [
        row
        for row in target_results
        if row.get("status") == "complete-exact-dsc-candidate-unverified-signature"
    ]
    incomplete = [
        row for row in target_results if row.get("status") == "incomplete-exact-dsc-candidate"
    ]
    ambiguous = [
        row for row in target_results if row.get("status", "").startswith("ambiguous")
    ]
    unresolved = [row for row in target_results if row.get("status") == "unresolved"]
    already = [
        row
        for row in target_results
        if row.get("status") == "already-authorized-by-historical-sources-index"
    ]

    summary = {
        "schema": SCHEMA,
        "policy": "exact-reference-binary-pool-path-to-dsc-members-changelog-and-iso-keyring-signature",
        "reference_iso": reference_summary["iso"],
        "target_count": len(targets),
        "repository_entry_count": len(repo_entries),
        "iso_keyring_count": len(keyrings),
        "network_probe_count": len(probes),
        "already_authorized_by_higher_tier_count": len(already),
        "signature_verified_exact_dsc_count": len(
            [row for row in promotable if row.get("status") == "signature-verified-exact-dsc-recovered"]
        ),
        "complete_unverified_signature_count": len(complete_unverified),
        "incomplete_exact_dsc_count": len(incomplete),
        "ambiguous_target_count": len(ambiguous),
        "unresolved_target_count": len(unresolved),
        "promotion_allowed_target_count": len(promotable),
        "promotion_allowed_targets": [row["source"] for row in promotable],
        "automatic_promotion_performed": False,
    }
    write_json(output / "summary.json", summary)
    write_json(output / "target-results.json", target_results)
    write_json(output / "network-probes.json", probes)
    write_json(
        output / "keyrings.json",
        [
            {
                "path": str(path),
                "size": path.stat().st_size,
                "sha256": hash_file(path),
            }
            for path in keyrings
        ],
    )

    lines = [
        "# Exact `.dsc` pool-path probe",
        "",
        f"- Targets: **{len(targets)}**",
        f"- Reference-ISO keyrings: **{len(keyrings)}**",
        f"- Higher-tier authorized: **{len(already)}**",
        f"- Signature-verified exact archives: **{summary['signature_verified_exact_dsc_count']}**",
        f"- Complete but signature-unverified: **{len(complete_unverified)}**",
        f"- Incomplete exact `.dsc`: **{len(incomplete)}**",
        f"- Ambiguous: **{len(ambiguous)}**",
        f"- Unresolved: **{len(unresolved)}**",
        "",
        "| Source | Version | Result | Promotion |",
        "|---|---|---|---:|",
    ]
    for row in target_results:
        lines.append(
            f"| `{row['source']}` | `{row['version']}` | {row['status']} | "
            f"{'yes' if row.get('promotion_allowed') else 'no'} |"
        )
    lines.extend(
        [
            "",
            "A complete archive with an unverified signature is retained as a candidate, not promoted.",
            "Its next authority gate is an AMD64 reference-binary reconstruction comparison.",
            "",
        ]
    )
    (output / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")

    shutil.rmtree(work_dir / "probe-objects", ignore_errors=True)
    shutil.rmtree(work_dir / "objects", ignore_errors=True)
    shutil.rmtree(work_dir / "cdx", ignore_errors=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
