#!/usr/bin/env python3
"""Bounded exact-source recovery pass for the Hancom Gooroom 3.3 blockers.

This is a network-efficient controller around recover_exact_source_archives.py.
It queries each canonical APT source-index stem once in Wayback, prioritises
snapshots around the 2023 reference release, and then falls back to exact .dsc
filenames. Acceptance remains identical: exact Source/Version plus every member
listed in Checksums-Sha256 must be downloaded and verified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Iterable, Sequence

import recover_exact_source_archives as core

LIVE_TIMEOUT = 18
CDX_TIMEOUT = 25
INDEX_SUFFIXES = (".xz", ".gz", ".bz2", "")
MAX_ARCHIVED_INDEX_SNAPSHOTS = 12
MAX_ARCHIVED_DSC_SNAPSHOTS = 8


def write_json(path: Path, value: Any) -> None:
    core.write_json(path, value)


def canonical_repositories(reference: Path) -> list[core.Repository]:
    parsed = core.parse_sources_lists(reference)
    merged: dict[tuple[str, str], set[str]] = {}
    origins: dict[tuple[str, str], set[str]] = {}
    for repository in parsed:
        parts = urllib.parse.urlsplit(repository.base_url)
        hostname = (parts.hostname or "").lower()
        path = parts.path.rstrip("/")
        if hostname != "update.hancomgooroom.com":
            continue
        if path not in {"/gooroom", "/hancom"}:
            continue
        # HTTP is the literal reference-ISO authority. HTTPS is tried later as
        # a transport fallback without multiplying repository identities.
        base = f"http://update.hancomgooroom.com{path}"
        key = (base, repository.suite)
        merged.setdefault(key, set()).update(repository.components or ("main",))
        origins.setdefault(key, set()).add(repository.origin)

    defaults = {
        ("http://update.hancomgooroom.com/gooroom", "gooroom-3.0"): {"main"},
        ("http://update.hancomgooroom.com/hancom", "hancom-3.0"): {"main"},
    }
    for key, components in defaults.items():
        merged.setdefault(key, set()).update(components)
        origins.setdefault(key, set()).add("reference-iso-default")

    repositories: list[core.Repository] = []
    for key in sorted(merged):
        base, suite = key
        components = sorted(merged[key])
        # Custom Gooroom/Hancom source packages have historically lived in
        # main. Preserve other components only when they were explicitly in
        # the ISO sources list, while bounding accidental token noise.
        components = [component for component in components if component][:4]
        repositories.append(
            core.Repository(
                base,
                suite,
                tuple(components or ["main"]),
                ",".join(sorted(origins[key])),
            )
        )
    return repositories


def transport_variants(url: str) -> list[str]:
    variants = [url]
    if url.startswith("http://"):
        variants.append("https://" + url[len("http://") :])
    return variants


def fast_fetch(url: str, *, max_bytes: int, timeout: int = LIVE_TIMEOUT) -> core.FetchResult:
    return core.request_bytes(
        core.quote_url_path(url),
        max_bytes=max_bytes,
        timeout=timeout,
        attempts=1,
    )


def fast_cdx_query(pattern: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    params = {
        "url": pattern,
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest,length",
        "filter": "statuscode:200",
        "collapse": "digest",
        "from": "2019",
        "to": "2026",
        "limit": "160",
    }
    query_url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
    result = core.request_bytes(
        query_url,
        max_bytes=8 * 1024 * 1024,
        timeout=CDX_TIMEOUT,
        attempts=1,
    )
    metadata = result.compact()
    metadata["pattern"] = pattern
    if not result.ok:
        return [], metadata
    try:
        document = json.loads(result.body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        metadata["parse_error"] = str(exc)
        return [], metadata
    if not isinstance(document, list) or not document or not isinstance(document[0], list):
        return [], metadata
    header = [str(item) for item in document[0]]
    rows: list[dict[str, str]] = []
    for values in document[1:]:
        if isinstance(values, list):
            rows.append({key: str(value) for key, value in zip(header, values)})
    return rows, metadata


def prioritise_snapshots(
    rows: Sequence[dict[str, str]], limit: int
) -> list[dict[str, str]]:
    """Choose distinct captures with the 2023 release period first."""

    def score(row: dict[str, str]) -> tuple[int, int, str]:
        timestamp = row.get("timestamp", "")
        year = timestamp[:4]
        # Exact reference era, adjacent years, then everything else.
        rank = {"2023": 0, "2024": 1, "2022": 2, "2021": 3, "2025": 4}.get(year, 5)
        # Within an era prefer later captures; negative integer sorts later first.
        numeric = -int(timestamp or "0")
        return rank, numeric, row.get("original", "")

    selected: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in sorted(rows, key=score):
        timestamp = row.get("timestamp", "")
        original = row.get("original", "")
        key = (timestamp, original)
        if not timestamp or not original or key in seen:
            continue
        seen.add(key)
        selected.append(row)
        if len(selected) >= limit:
            break
    return selected


def add_source_candidates(
    *,
    payload: bytes,
    logical_url: str,
    provenance: str,
    timestamp: str,
    candidates: dict[str, list[dict[str, Any]]],
    attempts: list[dict[str, Any]],
) -> bool:
    any_match = False
    for target in core.TARGETS:
        try:
            stanzas = core.exact_stanzas(payload, logical_url, target)
        except Exception as exc:  # evidence records parser failures without aborting other targets
            attempts.append(
                {
                    "phase": "sources-index-parse",
                    "source": target.source,
                    "version": target.version,
                    "provenance": provenance,
                    "requested_url": logical_url,
                    "wayback_timestamp": timestamp,
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        for stanza in stanzas:
            any_match = True
            candidates[target.source].append(
                {
                    "provenance": provenance,
                    "index_url": logical_url,
                    "timestamp": timestamp,
                    "stanza": stanza,
                }
            )
    return any_match


def deduplicate_source_candidates(
    candidates: dict[str, list[dict[str, Any]]]
) -> None:
    for source, rows in candidates.items():
        unique: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            stanza = row["stanza"]
            identity = json.dumps(
                {
                    "provenance": row["provenance"],
                    "index_url": row["index_url"],
                    "timestamp": row["timestamp"],
                    "directory": stanza.get("directory", ""),
                    "members": stanza.get("members", []),
                },
                sort_keys=True,
            )
            digest = hashlib.sha256(identity.encode()).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            unique.append(row)
        candidates[source] = unique


def direct_dsc_urls(repositories: Sequence[core.Repository], target: core.Target) -> list[str]:
    filename = core.dsc_filename(target)
    prefix = core.pool_prefix(target.source)
    urls: list[str] = []
    for repository in repositories:
        components = repository.components or ("main",)
        # main first, then any explicitly configured alternatives.
        ordered_components = sorted(components, key=lambda item: (item != "main", item))
        for component in ordered_components:
            base = (
                f"{repository.base_url}/pool/{component}/{prefix}/"
                f"{target.source}/{filename}"
            )
            urls.extend(transport_variants(base))
    return list(dict.fromkeys(urls))


def recover_direct_candidate(
    *,
    target: core.Target,
    original: str,
    provenance: str,
    timestamp: str,
    payload: bytes,
    evidence_dir: Path,
    archive_dir: Path,
    attempts: list[dict[str, Any]],
    cdx_attempts: list[dict[str, Any]],
    budget: dict[str, int],
) -> dict[str, Any]:
    return core.recover_from_dsc_url(
        target=target,
        dsc_url=original,
        provenance=provenance,
        timestamp=timestamp,
        payload=payload,
        evidence_dir=evidence_dir,
        archive_dir=archive_dir,
        attempts_log=attempts,
        cdx_log=cdx_attempts,
        budget=budget,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-evidence", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--archive-dir", type=Path, required=True)
    args = parser.parse_args()

    if not args.reference_evidence.is_dir():
        raise SystemExit(f"reference evidence is missing: {args.reference_evidence}")
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    args.archive_dir.mkdir(parents=True, exist_ok=True)

    repositories = canonical_repositories(args.reference_evidence)
    write_json(
        args.evidence_dir / "repository-candidates.json",
        [
            {
                "base_url": row.base_url,
                "suite": row.suite,
                "components": list(row.components),
                "origin": row.origin,
            }
            for row in repositories
        ],
    )

    attempts: list[dict[str, Any]] = []
    cdx_attempts: list[dict[str, Any]] = []
    source_candidates: dict[str, list[dict[str, Any]]] = {
        target.source: [] for target in core.TARGETS
    }
    budget = {"bytes": 0}

    # One live extension sweep and one CDX wildcard per canonical index stem.
    for repository in repositories:
        for component in repository.components:
            stem = (
                f"{repository.base_url}/dists/{repository.suite}/"
                f"{component}/source/Sources"
            )
            live_index_found = False
            for canonical_url in transport_variants(stem):
                for suffix in INDEX_SUFFIXES:
                    url = canonical_url + suffix
                    result = fast_fetch(url, max_bytes=core.MAX_INDEX_BYTES)
                    core.record_attempt(
                        attempts,
                        phase="sources-index",
                        target=None,
                        provenance="live",
                        result=result,
                        extra={
                            "repository_base": repository.base_url,
                            "suite": repository.suite,
                            "component": component,
                        },
                    )
                    if not result.ok:
                        continue
                    live_index_found = True
                    add_source_candidates(
                        payload=result.body,
                        logical_url=url,
                        provenance="live",
                        timestamp="",
                        candidates=source_candidates,
                        attempts=attempts,
                    )
                    break
                if live_index_found:
                    break

            pattern = stem + "*"
            rows, metadata = fast_cdx_query(pattern)
            metadata.update(
                {
                    "phase": "sources-index",
                    "repository_base": repository.base_url,
                    "suite": repository.suite,
                    "component": component,
                }
            )
            cdx_attempts.append(metadata)
            for archived_row in prioritise_snapshots(
                rows, MAX_ARCHIVED_INDEX_SNAPSHOTS
            ):
                timestamp = archived_row["timestamp"]
                original = archived_row["original"]
                archived = core.request_bytes(
                    core.wayback_url(timestamp, original),
                    max_bytes=core.MAX_INDEX_BYTES,
                    timeout=CDX_TIMEOUT,
                    attempts=1,
                )
                core.record_attempt(
                    attempts,
                    phase="sources-index",
                    target=None,
                    provenance="wayback",
                    result=archived,
                    extra={
                        "wayback_timestamp": timestamp,
                        "wayback_original": original,
                        "repository_base": repository.base_url,
                        "suite": repository.suite,
                        "component": component,
                    },
                )
                if not archived.ok:
                    continue
                add_source_candidates(
                    payload=archived.body,
                    logical_url=original,
                    provenance="wayback",
                    timestamp=timestamp,
                    candidates=source_candidates,
                    attempts=attempts,
                )

    deduplicate_source_candidates(source_candidates)
    compact_candidates: list[dict[str, Any]] = []
    for target in core.TARGETS:
        for number, candidate in enumerate(source_candidates[target.source], start=1):
            stanza = candidate["stanza"]
            stanza_file = core.save_exact_stanza(
                args.evidence_dir,
                target,
                number,
                stanza["raw_stanza"],
            )
            compact_candidates.append(
                {
                    "source": target.source,
                    "version": target.version,
                    "provenance": candidate["provenance"],
                    "index_url": candidate["index_url"],
                    "wayback_timestamp": candidate["timestamp"],
                    "directory": stanza.get("directory", ""),
                    "member_count": len(stanza.get("members", [])),
                    "stanza_file": stanza_file,
                }
            )
    write_json(args.evidence_dir / "exact-source-index-candidates.json", compact_candidates)

    target_results: list[dict[str, Any]] = []
    recovered_sources: set[str] = set()
    for target in core.TARGETS:
        row: dict[str, Any] = {
            "source": target.source,
            "version": target.version,
            "status": "unresolved",
            "reason": "no complete exact source archive recovered",
            "source_stanza_candidate_count": len(source_candidates[target.source]),
            "candidate_results": [],
        }
        for candidate in source_candidates[target.source][:8]:
            recovery = core.recover_from_source_stanza(
                target=target,
                stanza=candidate["stanza"],
                index_url=candidate["index_url"],
                provenance=candidate["provenance"],
                timestamp=candidate["timestamp"],
                evidence_dir=args.evidence_dir,
                archive_dir=args.archive_dir,
                attempts_log=attempts,
                cdx_log=cdx_attempts,
                budget=budget,
            )
            row["candidate_results"].append(recovery)
            if recovery["status"] == "exact-source-archive-recovered":
                row["status"] = recovery["status"]
                row["reason"] = recovery["reason"]
                row["selected_candidate"] = recovery
                recovered_sources.add(target.source)
                break
        target_results.append(row)

    result_by_source = {row["source"]: row for row in target_results}

    # Exact pool path, exact CDX URL, then one broad filename query per target.
    for target in core.TARGETS:
        if target.source in recovered_sources:
            continue
        row = result_by_source[target.source]
        seen_archived: set[tuple[str, str]] = set()
        for dsc_url in direct_dsc_urls(repositories, target):
            live = fast_fetch(dsc_url, max_bytes=core.MAX_DSC_BYTES)
            core.record_attempt(
                attempts,
                phase="direct-dsc",
                target=target,
                provenance="live",
                result=live,
            )
            if live.ok:
                recovery = recover_direct_candidate(
                    target=target,
                    original=dsc_url,
                    provenance="live",
                    timestamp="",
                    payload=live.body,
                    evidence_dir=args.evidence_dir,
                    archive_dir=args.archive_dir,
                    attempts=attempts,
                    cdx_attempts=cdx_attempts,
                    budget=budget,
                )
                row["candidate_results"].append(recovery)
                if recovery["status"] == "exact-source-archive-recovered":
                    row["status"] = recovery["status"]
                    row["reason"] = recovery["reason"]
                    row["selected_candidate"] = recovery
                    recovered_sources.add(target.source)
                    break

            archived_rows, metadata = fast_cdx_query(dsc_url)
            metadata.update(
                {"phase": "direct-dsc", "source": target.source, "version": target.version}
            )
            cdx_attempts.append(metadata)
            for archived_row in prioritise_snapshots(
                archived_rows, MAX_ARCHIVED_DSC_SNAPSHOTS
            ):
                timestamp = archived_row["timestamp"]
                original = archived_row["original"]
                identity = (timestamp, original)
                if identity in seen_archived:
                    continue
                seen_archived.add(identity)
                archived = core.request_bytes(
                    core.wayback_url(timestamp, original),
                    max_bytes=core.MAX_DSC_BYTES,
                    timeout=CDX_TIMEOUT,
                    attempts=1,
                )
                core.record_attempt(
                    attempts,
                    phase="direct-dsc",
                    target=target,
                    provenance="wayback",
                    result=archived,
                    extra={"wayback_timestamp": timestamp, "wayback_original": original},
                )
                if not archived.ok:
                    continue
                recovery = recover_direct_candidate(
                    target=target,
                    original=original,
                    provenance="wayback",
                    timestamp=timestamp,
                    payload=archived.body,
                    evidence_dir=args.evidence_dir,
                    archive_dir=args.archive_dir,
                    attempts=attempts,
                    cdx_attempts=cdx_attempts,
                    budget=budget,
                )
                row["candidate_results"].append(recovery)
                if recovery["status"] == "exact-source-archive-recovered":
                    row["status"] = recovery["status"]
                    row["reason"] = recovery["reason"]
                    row["selected_candidate"] = recovery
                    recovered_sources.add(target.source)
                    break
            if target.source in recovered_sources:
                break

        if target.source in recovered_sources:
            continue
        broad_pattern = (
            f"update.hancomgooroom.com/*/{core.dsc_filename(target)}"
        )
        archived_rows, metadata = fast_cdx_query(broad_pattern)
        metadata.update(
            {"phase": "broad-dsc", "source": target.source, "version": target.version}
        )
        cdx_attempts.append(metadata)
        for archived_row in prioritise_snapshots(archived_rows, 16):
            timestamp = archived_row["timestamp"]
            original = archived_row["original"]
            identity = (timestamp, original)
            if identity in seen_archived:
                continue
            seen_archived.add(identity)
            archived = core.request_bytes(
                core.wayback_url(timestamp, original),
                max_bytes=core.MAX_DSC_BYTES,
                timeout=CDX_TIMEOUT,
                attempts=1,
            )
            core.record_attempt(
                attempts,
                phase="broad-dsc",
                target=target,
                provenance="wayback",
                result=archived,
                extra={"wayback_timestamp": timestamp, "wayback_original": original},
            )
            if not archived.ok:
                continue
            recovery = recover_direct_candidate(
                target=target,
                original=original,
                provenance="wayback",
                timestamp=timestamp,
                payload=archived.body,
                evidence_dir=args.evidence_dir,
                archive_dir=args.archive_dir,
                attempts=attempts,
                cdx_attempts=cdx_attempts,
                budget=budget,
            )
            row["candidate_results"].append(recovery)
            if recovery["status"] == "exact-source-archive-recovered":
                row["status"] = recovery["status"]
                row["reason"] = recovery["reason"]
                row["selected_candidate"] = recovery
                recovered_sources.add(target.source)
                break

    recovered_manifest: list[dict[str, Any]] = []
    for target in core.TARGETS:
        directory = (
            args.archive_dir
            / core.safe_component(target.source)
            / core.safe_component(target.version)
        )
        if not directory.is_dir():
            continue
        recovered_manifest.append(
            {
                "source": target.source,
                "version": target.version,
                "files": [
                    {
                        "filename": path.name,
                        "size": path.stat().st_size,
                        "sha256": core.sha256_file(path),
                    }
                    for path in sorted(directory.iterdir())
                    if path.is_file()
                ],
            }
        )

    write_json(args.evidence_dir / "target-results.json", target_results)
    write_json(args.evidence_dir / "network-attempts.json", attempts)
    write_json(args.evidence_dir / "wayback-cdx-attempts.json", cdx_attempts)
    write_json(args.evidence_dir / "recovered-source-manifest.json", recovered_manifest)

    recovered_count = sum(
        row["status"] == "exact-source-archive-recovered" for row in target_results
    )
    exact_stanza_targets = sum(
        bool(source_candidates[target.source]) for target in core.TARGETS
    )
    summary = {
        "schema": 2,
        "policy": "exact-source-version-and-all-sha256-members-required-bounded-v2",
        "target_count": len(core.TARGETS),
        "repository_candidate_count": len(repositories),
        "exact_source_stanza_target_count": exact_stanza_targets,
        "exact_source_archive_recovered_count": recovered_count,
        "unresolved_count": len(core.TARGETS) - recovered_count,
        "network_attempt_count": len(attempts),
        "wayback_cdx_query_count": len(cdx_attempts),
        "recovered_archive_bytes": budget["bytes"],
        "source_recovery_ready": recovered_count > 0,
        "all_targets_recovered": recovered_count == len(core.TARGETS),
        "promotion_allowed": False,
    }
    write_json(args.evidence_dir / "summary.json", summary)
    (args.evidence_dir / "targets.tsv").write_text(
        "source\tversion\tstatus\tsource_stanza_candidates\tcandidate_attempts\treason\n"
        + "".join(
            "\t".join(
                [
                    row["source"],
                    row["version"],
                    row["status"],
                    str(row["source_stanza_candidate_count"]),
                    str(len(row["candidate_results"])),
                    row["reason"].replace("\t", " ").replace("\n", " "),
                ]
            )
            + "\n"
            for row in target_results
        ),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
