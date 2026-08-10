#!/usr/bin/env python3
"""Recover exact Hancom Gooroom Debian sources from Common Crawl WARC records.

The URL index is queried for canonical Sources indices and exact .dsc pool
paths. WARC response payloads are extracted byte-for-byte. A source is accepted
only when Source and Version match and every Checksums-Sha256 member is present
with the exact declared size and digest. Evidence remains non-promoting.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import gzip
import hashlib
import json
import re
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

import recover_exact_source_archives as core

COLLECTION_TIMEOUT = 25
INDEX_TIMEOUT = 22
WARC_TIMEOUT = 50
MAX_COLLECTIONS = 22
MAX_RECORDS_PER_URL = 8
MAX_WARC_RECORD_BYTES = 720 * 1024 * 1024
MAX_TOTAL_BYTES = core.MAX_TOTAL_ARCHIVE_BYTES
USER_AGENT = core.USER_AGENT


@dataclass(frozen=True)
class Collection:
    collection_id: str
    api_url: str
    data_url: str
    name: str


@dataclass
class ArchiveHit:
    collection_id: str
    requested_url: str
    url: str
    timestamp: str
    filename: str
    offset: int
    length: int
    status: str
    mime: str
    digest: str

    def compact(self) -> dict[str, Any]:
        return {
            "collection": self.collection_id,
            "requested_url": self.requested_url,
            "url": self.url,
            "timestamp": self.timestamp,
            "filename": self.filename,
            "offset": self.offset,
            "length": self.length,
            "status": self.status,
            "mime": self.mime,
            "digest": self.digest,
        }


@dataclass
class WarcPayload:
    ok: bool
    body: bytes
    warc_headers: dict[str, str]
    http_headers: dict[str, str]
    status_line: str
    error: str
    fetch: dict[str, Any]


class CommonCrawlError(RuntimeError):
    pass


def write_json(path: Path, value: Any) -> None:
    core.write_json(path, value)


def request(
    url: str,
    *,
    timeout: int,
    max_bytes: int,
    headers: dict[str, str] | None = None,
) -> core.FetchResult:
    started = time.monotonic()
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
    }
    if headers:
        request_headers.update(headers)
    req = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response_headers = {
                key.lower(): value for key, value in response.headers.items()
            }
            declared = response_headers.get("content-length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise CommonCrawlError(
                    f"declared content length {declared} exceeds {max_bytes}"
                )
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise CommonCrawlError(f"response exceeds {max_bytes}")
            status = getattr(response, "status", 200)
            return core.FetchResult(
                True,
                url,
                response.geturl(),
                int(status),
                response_headers,
                body,
                "",
                time.monotonic() - started,
            )
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        OSError,
        CommonCrawlError,
    ) as exc:
        status = exc.code if isinstance(exc, urllib.error.HTTPError) else None
        response_headers: dict[str, str] = {}
        if isinstance(exc, urllib.error.HTTPError) and exc.headers:
            response_headers = {
                key.lower(): value for key, value in exc.headers.items()
            }
        return core.FetchResult(
            False,
            url,
            getattr(exc, "url", url),
            int(status) if status is not None else None,
            response_headers,
            b"",
            f"{type(exc).__name__}: {exc}",
            time.monotonic() - started,
        )


def load_collections(attempts: list[dict[str, Any]]) -> list[Collection]:
    url = "https://index.commoncrawl.org/collinfo.json"
    result = request(
        url,
        timeout=COLLECTION_TIMEOUT,
        max_bytes=4 * 1024 * 1024,
    )
    attempts.append({"phase": "collection-list", **result.compact()})
    if not result.ok:
        return []
    try:
        rows = json.loads(result.body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        attempts.append(
            {
                "phase": "collection-list-parse",
                "ok": False,
                "error": str(exc),
            }
        )
        return []
    collections: list[Collection] = []
    for row in rows if isinstance(rows, list) else []:
        collection_id = str(row.get("id", ""))
        match = re.match(r"CC-MAIN-(20\d{2})-(\d+)$", collection_id)
        if not match:
            continue
        year = int(match.group(1))
        if year < 2021 or year > 2025:
            continue
        api_url = str(row.get("cdx-api", ""))
        if not api_url:
            continue
        collections.append(
            Collection(
                collection_id=collection_id,
                api_url=api_url,
                data_url="https://data.commoncrawl.org/",
                name=str(row.get("name", collection_id)),
            )
        )

    def priority(collection: Collection) -> tuple[int, int, str]:
        match = re.match(r"CC-MAIN-(20\d{2})-(\d+)$", collection.collection_id)
        assert match
        year = int(match.group(1))
        crawl = int(match.group(2))
        rank = {2023: 0, 2024: 1, 2022: 2, 2021: 3, 2025: 4}.get(year, 5)
        return rank, -crawl, collection.collection_id

    return sorted(collections, key=priority)[:MAX_COLLECTIONS]


def canonical_lookup_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return parsed.netloc + parsed.path


def index_query(
    collection: Collection,
    requested_url: str,
) -> tuple[list[ArchiveHit], dict[str, Any]]:
    query = urllib.parse.urlencode(
        {
            "url": canonical_lookup_url(requested_url),
            "output": "json",
            "matchType": "exact",
            "filter": "status:200",
            "collapse": "digest",
        }
    )
    url = collection.api_url + "?" + query
    result = request(url, timeout=INDEX_TIMEOUT, max_bytes=8 * 1024 * 1024)
    evidence = {
        "phase": "commoncrawl-index",
        "collection": collection.collection_id,
        "lookup_url": requested_url,
        **result.compact(),
    }
    if not result.ok:
        return [], evidence
    hits: list[ArchiveHit] = []
    parse_errors: list[str] = []
    for line_number, line in enumerate(
        result.body.decode("utf-8", errors="replace").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            filename = str(row.get("filename", ""))
            offset = int(row.get("offset", -1))
            length = int(row.get("length", -1))
            if not filename or offset < 0 or length <= 0:
                continue
            hits.append(
                ArchiveHit(
                    collection_id=collection.collection_id,
                    requested_url=requested_url,
                    url=str(row.get("url", requested_url)),
                    timestamp=str(row.get("timestamp", "")),
                    filename=filename,
                    offset=offset,
                    length=length,
                    status=str(row.get("status", "")),
                    mime=str(row.get("mime", "")),
                    digest=str(row.get("digest", "")),
                )
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            if len(parse_errors) < 10:
                parse_errors.append(f"line {line_number}: {type(exc).__name__}: {exc}")
    evidence["hit_count"] = len(hits)
    evidence["parse_errors"] = parse_errors
    return hits, evidence


def query_many(
    collections: Sequence[Collection],
    urls: Sequence[str],
    attempts: list[dict[str, Any]],
) -> dict[str, list[ArchiveHit]]:
    results: dict[str, list[ArchiveHit]] = {url: [] for url in urls}
    tasks = [(collection, url) for url in urls for collection in collections]
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
        future_map = {
            executor.submit(index_query, collection, url): (collection, url)
            for collection, url in tasks
        }
        for future in concurrent.futures.as_completed(future_map):
            collection, url = future_map[future]
            try:
                hits, evidence = future.result()
            except Exception as exc:
                attempts.append(
                    {
                        "phase": "commoncrawl-index",
                        "collection": collection.collection_id,
                        "lookup_url": url,
                        "ok": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            attempts.append(evidence)
            results[url].extend(hits)
    for url, hits in results.items():
        seen: set[tuple[str, int, int]] = set()
        unique: list[ArchiveHit] = []
        for hit in sorted(hits, key=hit_priority):
            identity = (hit.filename, hit.offset, hit.length)
            if identity in seen:
                continue
            seen.add(identity)
            unique.append(hit)
        results[url] = unique
    return results


def hit_priority(hit: ArchiveHit) -> tuple[int, int, str]:
    year = int(hit.timestamp[:4]) if len(hit.timestamp) >= 4 and hit.timestamp[:4].isdigit() else 0
    rank = {2023: 0, 2024: 1, 2022: 2, 2021: 3, 2025: 4}.get(year, 5)
    timestamp_value = -int(hit.timestamp or "0") if (hit.timestamp or "0").isdigit() else 0
    return rank, timestamp_value, hit.collection_id


def parse_header_block(block: bytes) -> tuple[str, dict[str, str]]:
    lines = block.decode("iso-8859-1", errors="replace").splitlines()
    status_line = lines[0] if lines else ""
    headers: dict[str, str] = {}
    current: str | None = None
    for line in lines[1:]:
        if line.startswith((" ", "\t")) and current is not None:
            headers[current] += " " + line.strip()
        elif ":" in line:
            key, value = line.split(":", 1)
            current = key.lower().strip()
            headers[current] = value.strip()
    return status_line, headers


def dechunk(data: bytes) -> bytes:
    output = bytearray()
    position = 0
    while True:
        line_end = data.find(b"\r\n", position)
        if line_end < 0:
            raise CommonCrawlError("invalid chunked body: missing size line")
        size_text = data[position:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise CommonCrawlError("invalid chunk size") from exc
        position = line_end + 2
        if size == 0:
            return bytes(output)
        end = position + size
        if end > len(data):
            raise CommonCrawlError("truncated chunked body")
        output.extend(data[position:end])
        position = end
        if data[position : position + 2] != b"\r\n":
            raise CommonCrawlError("invalid chunk terminator")
        position += 2


def decode_http_entity(body: bytes, headers: dict[str, str]) -> bytes:
    transfer = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer:
        body = dechunk(body)
    content_encoding = headers.get("content-encoding", "").lower()
    if content_encoding == "gzip":
        body = gzip.decompress(body)
    return body


def extract_warc_payload(hit: ArchiveHit, attempts: list[dict[str, Any]]) -> WarcPayload:
    if hit.length > MAX_WARC_RECORD_BYTES:
        return WarcPayload(
            False,
            b"",
            {},
            {},
            "",
            f"WARC record exceeds limit: {hit.length}",
            hit.compact(),
        )
    end = hit.offset + hit.length - 1
    url = "https://data.commoncrawl.org/" + hit.filename
    result = request(
        url,
        timeout=WARC_TIMEOUT,
        max_bytes=hit.length + 1024,
        headers={"Range": f"bytes={hit.offset}-{end}"},
    )
    evidence = {
        "phase": "commoncrawl-warc",
        **hit.compact(),
        **result.compact(),
    }
    attempts.append(evidence)
    if not result.ok:
        return WarcPayload(False, b"", {}, {}, "", result.error, evidence)
    try:
        uncompressed = gzip.decompress(result.body)
        warc_boundary = uncompressed.find(b"\r\n\r\n")
        if warc_boundary < 0:
            raise CommonCrawlError("missing WARC header boundary")
        warc_status, warc_headers = parse_header_block(uncompressed[:warc_boundary])
        http_start = warc_boundary + 4
        http_boundary = uncompressed.find(b"\r\n\r\n", http_start)
        if http_boundary < 0:
            raise CommonCrawlError("missing HTTP header boundary")
        http_status, http_headers = parse_header_block(
            uncompressed[http_start:http_boundary]
        )
        body = uncompressed[http_boundary + 4 :]
        body = decode_http_entity(body, http_headers)
        return WarcPayload(
            True,
            body,
            warc_headers,
            http_headers,
            http_status,
            "",
            evidence,
        )
    except (OSError, EOFError, CommonCrawlError) as exc:
        evidence["payload_error"] = f"{type(exc).__name__}: {exc}"
        return WarcPayload(
            False,
            b"",
            {},
            {},
            "",
            evidence["payload_error"],
            evidence,
        )


def source_index_urls() -> list[str]:
    urls: list[str] = []
    repositories = (
        ("gooroom", "gooroom-3.0"),
        ("hancom", "hancom-3.0"),
    )
    for repository, suite in repositories:
        stem = (
            f"http://update.hancomgooroom.com/{repository}/dists/"
            f"{suite}/main/source/Sources"
        )
        for suffix in (".xz", ".gz", ".bz2", ""):
            urls.append(stem + suffix)
    return urls


def dsc_urls(target: core.Target) -> list[str]:
    prefix = core.pool_prefix(target.source)
    filename = core.dsc_filename(target)
    return [
        (
            f"http://update.hancomgooroom.com/{repository}/pool/main/"
            f"{prefix}/{target.source}/{filename}"
        )
        for repository in ("gooroom", "hancom")
    ]


def unresolved_targets(previous_evidence: Path | None) -> list[core.Target]:
    if previous_evidence is None:
        return list(core.TARGETS)
    path = previous_evidence / "target-results.json"
    if not path.is_file():
        return list(core.TARGETS)
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return list(core.TARGETS)
    resolved = {
        str(row.get("source", ""))
        for row in rows
        if row.get("status") == "exact-source-archive-recovered"
    }
    return [target for target in core.TARGETS if target.source not in resolved]


def expected_payload(
    *,
    url: str,
    expected: dict[str, Any],
    collections: Sequence[Collection],
    query_cache: dict[str, list[ArchiveHit]],
    index_attempts: list[dict[str, Any]],
    warc_attempts: list[dict[str, Any]],
) -> tuple[bytes | None, dict[str, Any]]:
    if url not in query_cache:
        query_cache.update(query_many(collections, [url], index_attempts))
    for hit in query_cache.get(url, [])[:MAX_RECORDS_PER_URL]:
        payload = extract_warc_payload(hit, warc_attempts)
        if not payload.ok:
            continue
        valid, error = core.validate_payload(payload.body, expected)
        if valid:
            return payload.body, {
                "hit": hit.compact(),
                "body_size": len(payload.body),
                "body_sha256": hashlib.sha256(payload.body).hexdigest(),
                "verified": True,
            }
        warc_attempts.append(
            {
                "phase": "commoncrawl-member-verification",
                **hit.compact(),
                "expected_size": expected["size"],
                "expected_sha256": expected["checksum"],
                "actual_size": len(payload.body),
                "actual_sha256": hashlib.sha256(payload.body).hexdigest(),
                "verified": False,
                "error": error,
            }
        )
    return None, {"verified": False, "error": "no matching Common Crawl payload"}


def recover_from_source_stanza(
    *,
    target: core.Target,
    stanza: dict[str, Any],
    index_hit: ArchiveHit,
    collections: Sequence[Collection],
    query_cache: dict[str, list[ArchiveHit]],
    evidence_dir: Path,
    archive_dir: Path,
    index_attempts: list[dict[str, Any]],
    warc_attempts: list[dict[str, Any]],
    budget: dict[str, int],
) -> dict[str, Any]:
    directory = stanza.get("directory", "").strip("/")
    members = stanza.get("members", [])
    result: dict[str, Any] = {
        "candidate_kind": "commoncrawl-Sources-stanza",
        "index_hit": index_hit.compact(),
        "directory": directory,
        "status": "rejected",
        "reason": "",
        "files": [],
    }
    if not directory or not members:
        result["reason"] = "exact Sources stanza lacks Directory or Checksums-Sha256"
        return result
    dsc_rows = [row for row in members if row["filename"].endswith(".dsc")]
    if len(dsc_rows) != 1:
        result["reason"] = f"expected one .dsc, found {len(dsc_rows)}"
        return result
    repository_base = core.repository_base_from_index(index_hit.url)
    downloaded: dict[str, bytes] = {}
    for expected in members:
        size = int(expected["size"])
        if size > core.MAX_MEMBER_BYTES or budget["bytes"] + size > MAX_TOTAL_BYTES:
            result["reason"] = f"recovery budget exceeded by {expected['filename']}"
            return result
        url = f"{repository_base}/{directory}/{expected['filename']}"
        body, provenance = expected_payload(
            url=url,
            expected=expected,
            collections=collections,
            query_cache=query_cache,
            index_attempts=index_attempts,
            warc_attempts=warc_attempts,
        )
        result["files"].append(
            {
                "filename": expected["filename"],
                "original_url": url,
                "expected_size": expected["size"],
                "expected_sha256": expected["checksum"],
                **provenance,
            }
        )
        if body is None:
            result["reason"] = f"member unavailable or mismatched: {expected['filename']}"
            return result
        downloaded[expected["filename"]] = body

    dsc_name = dsc_rows[0]["filename"]
    try:
        fields, raw, dsc_members = core.parse_dsc(downloaded[dsc_name])
    except core.RecoveryError as exc:
        result["reason"] = str(exc)
        return result
    if fields.get("Source") != target.source or fields.get("Version") != target.version:
        result["reason"] = "recovered .dsc Source/Version mismatch"
        return result
    stanza_manifest = {
        row["filename"]: (row["size"], row["checksum"])
        for row in members
        if not row["filename"].endswith(".dsc")
    }
    dsc_manifest = {
        row["filename"]: (row["size"], row["checksum"])
        for row in dsc_members
    }
    if stanza_manifest != dsc_manifest:
        result["reason"] = "Sources and .dsc SHA-256 manifests disagree"
        return result
    return persist_recovery(
        target=target,
        downloaded=downloaded,
        dsc_name=dsc_name,
        dsc_raw=raw,
        evidence_dir=evidence_dir,
        archive_dir=archive_dir,
        budget=budget,
        result=result,
        success_reason="every Common Crawl Sources/.dsc member verified",
    )


def recover_from_direct_dsc(
    *,
    target: core.Target,
    dsc_hit: ArchiveHit,
    dsc_body: bytes,
    collections: Sequence[Collection],
    query_cache: dict[str, list[ArchiveHit]],
    evidence_dir: Path,
    archive_dir: Path,
    index_attempts: list[dict[str, Any]],
    warc_attempts: list[dict[str, Any]],
    budget: dict[str, int],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "candidate_kind": "commoncrawl-direct-dsc",
        "dsc_hit": dsc_hit.compact(),
        "status": "rejected",
        "reason": "",
        "files": [],
    }
    try:
        fields, raw, members = core.parse_dsc(dsc_body)
    except core.RecoveryError as exc:
        result["reason"] = str(exc)
        return result
    if fields.get("Source") != target.source or fields.get("Version") != target.version:
        result["reason"] = "direct Common Crawl .dsc Source/Version mismatch"
        return result
    if not members:
        result["reason"] = "direct Common Crawl .dsc lacks Checksums-Sha256"
        return result
    dsc_name = urllib.parse.unquote(
        urllib.parse.urlsplit(dsc_hit.url).path.rsplit("/", 1)[-1]
    )
    downloaded = {dsc_name: dsc_body}
    base_url = dsc_hit.url.rsplit("/", 1)[0]
    result["files"].append(
        {
            "filename": dsc_name,
            "original_url": dsc_hit.url,
            "body_size": len(dsc_body),
            "body_sha256": hashlib.sha256(dsc_body).hexdigest(),
            "verified": True,
            "hit": dsc_hit.compact(),
        }
    )
    for expected in members:
        size = int(expected["size"])
        if size > core.MAX_MEMBER_BYTES or budget["bytes"] + size > MAX_TOTAL_BYTES:
            result["reason"] = f"recovery budget exceeded by {expected['filename']}"
            return result
        url = f"{base_url}/{expected['filename']}"
        body, provenance = expected_payload(
            url=url,
            expected=expected,
            collections=collections,
            query_cache=query_cache,
            index_attempts=index_attempts,
            warc_attempts=warc_attempts,
        )
        result["files"].append(
            {
                "filename": expected["filename"],
                "original_url": url,
                "expected_size": expected["size"],
                "expected_sha256": expected["checksum"],
                **provenance,
            }
        )
        if body is None:
            result["reason"] = f"member unavailable or mismatched: {expected['filename']}"
            return result
        downloaded[expected["filename"]] = body
    return persist_recovery(
        target=target,
        downloaded=downloaded,
        dsc_name=dsc_name,
        dsc_raw=raw,
        evidence_dir=evidence_dir,
        archive_dir=archive_dir,
        budget=budget,
        result=result,
        success_reason="direct Common Crawl .dsc and every member verified",
    )


def persist_recovery(
    *,
    target: core.Target,
    downloaded: dict[str, bytes],
    dsc_name: str,
    dsc_raw: str,
    evidence_dir: Path,
    archive_dir: Path,
    budget: dict[str, int],
    result: dict[str, Any],
    success_reason: str,
) -> dict[str, Any]:
    destination = (
        archive_dir
        / core.safe_component(target.source)
        / core.safe_component(target.version)
    )
    destination.mkdir(parents=True, exist_ok=True)
    for filename, body in downloaded.items():
        output = destination / filename
        output.write_bytes(body)
        budget["bytes"] += len(body)
    dsc_path = evidence_dir / "dsc" / core.safe_component(target.source) / dsc_name
    dsc_path.parent.mkdir(parents=True, exist_ok=True)
    dsc_path.write_bytes(downloaded[dsc_name])
    raw_path = (
        evidence_dir
        / "dsc-fields"
        / core.safe_component(target.source)
        / f"{dsc_name}.txt"
    )
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(dsc_raw, encoding="utf-8")
    result["status"] = "exact-source-archive-recovered"
    result["reason"] = success_reason
    result["archive_manifest"] = [
        {
            "filename": path.name,
            "size": path.stat().st_size,
            "sha256": core.sha256_file(path),
        }
        for path in sorted(destination.iterdir())
        if path.is_file()
    ]
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--previous-evidence", type=Path)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--archive-dir", type=Path, required=True)
    args = parser.parse_args()
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    args.archive_dir.mkdir(parents=True, exist_ok=True)

    index_attempts: list[dict[str, Any]] = []
    warc_attempts: list[dict[str, Any]] = []
    collections = load_collections(index_attempts)
    write_json(
        args.evidence_dir / "commoncrawl-collections.json",
        [collection.__dict__ for collection in collections],
    )
    targets = unresolved_targets(args.previous_evidence)
    write_json(
        args.evidence_dir / "targets-input.json",
        [target.__dict__ for target in targets],
    )

    query_urls = source_index_urls()
    for target in targets:
        query_urls.extend(dsc_urls(target))
    query_urls = list(dict.fromkeys(query_urls))
    query_cache = query_many(collections, query_urls, index_attempts) if collections else {
        url: [] for url in query_urls
    }

    source_candidates: dict[str, list[tuple[dict[str, Any], ArchiveHit]]] = {
        target.source: [] for target in targets
    }
    for url in source_index_urls():
        for hit in query_cache.get(url, [])[:MAX_RECORDS_PER_URL]:
            payload = extract_warc_payload(hit, warc_attempts)
            if not payload.ok:
                continue
            for target in targets:
                try:
                    stanzas = core.exact_stanzas(payload.body, hit.url, target)
                except Exception as exc:
                    warc_attempts.append(
                        {
                            "phase": "commoncrawl-sources-parse",
                            **hit.compact(),
                            "source": target.source,
                            "version": target.version,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
                    continue
                for stanza in stanzas:
                    source_candidates[target.source].append((stanza, hit))

    compact_candidates: list[dict[str, Any]] = []
    for target in targets:
        for number, (stanza, hit) in enumerate(
            source_candidates[target.source], start=1
        ):
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
                    "stanza_file": stanza_file,
                    "directory": stanza.get("directory", ""),
                    "member_count": len(stanza.get("members", [])),
                    "hit": hit.compact(),
                }
            )
    write_json(
        args.evidence_dir / "exact-source-index-candidates.json",
        compact_candidates,
    )

    budget = {"bytes": 0}
    target_results: list[dict[str, Any]] = []
    recovered: set[str] = set()
    for target in targets:
        row: dict[str, Any] = {
            "source": target.source,
            "version": target.version,
            "status": "unresolved",
            "reason": "no complete exact source archive recovered from Common Crawl",
            "source_stanza_candidate_count": len(source_candidates[target.source]),
            "direct_dsc_hit_count": sum(
                len(query_cache.get(url, [])) for url in dsc_urls(target)
            ),
            "candidate_results": [],
        }
        for stanza, hit in source_candidates[target.source][:8]:
            recovery = recover_from_source_stanza(
                target=target,
                stanza=stanza,
                index_hit=hit,
                collections=collections,
                query_cache=query_cache,
                evidence_dir=args.evidence_dir,
                archive_dir=args.archive_dir,
                index_attempts=index_attempts,
                warc_attempts=warc_attempts,
                budget=budget,
            )
            row["candidate_results"].append(recovery)
            if recovery["status"] == "exact-source-archive-recovered":
                row["status"] = recovery["status"]
                row["reason"] = recovery["reason"]
                row["selected_candidate"] = recovery
                recovered.add(target.source)
                break
        if target.source not in recovered:
            for url in dsc_urls(target):
                for hit in query_cache.get(url, [])[:MAX_RECORDS_PER_URL]:
                    payload = extract_warc_payload(hit, warc_attempts)
                    if not payload.ok:
                        continue
                    recovery = recover_from_direct_dsc(
                        target=target,
                        dsc_hit=hit,
                        dsc_body=payload.body,
                        collections=collections,
                        query_cache=query_cache,
                        evidence_dir=args.evidence_dir,
                        archive_dir=args.archive_dir,
                        index_attempts=index_attempts,
                        warc_attempts=warc_attempts,
                        budget=budget,
                    )
                    row["candidate_results"].append(recovery)
                    if recovery["status"] == "exact-source-archive-recovered":
                        row["status"] = recovery["status"]
                        row["reason"] = recovery["reason"]
                        row["selected_candidate"] = recovery
                        recovered.add(target.source)
                        break
                if target.source in recovered:
                    break
        target_results.append(row)

    recovered_manifest: list[dict[str, Any]] = []
    for target in targets:
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
    write_json(args.evidence_dir / "commoncrawl-index-attempts.json", index_attempts)
    write_json(args.evidence_dir / "commoncrawl-warc-attempts.json", warc_attempts)
    write_json(args.evidence_dir / "recovered-source-manifest.json", recovered_manifest)

    recovered_count = sum(
        row["status"] == "exact-source-archive-recovered" for row in target_results
    )
    summary = {
        "schema": 1,
        "policy": "commoncrawl-exact-source-version-and-all-sha256-members-required",
        "input_target_count": len(targets),
        "collection_count": len(collections),
        "lookup_url_count": len(query_urls),
        "exact_source_stanza_target_count": sum(
            bool(source_candidates[target.source]) for target in targets
        ),
        "exact_source_archive_recovered_count": recovered_count,
        "unresolved_count": len(targets) - recovered_count,
        "commoncrawl_index_attempt_count": len(index_attempts),
        "commoncrawl_warc_attempt_count": len(warc_attempts),
        "recovered_archive_bytes": budget["bytes"],
        "source_recovery_ready": recovered_count > 0,
        "all_input_targets_recovered": recovered_count == len(targets),
        "promotion_allowed": False,
    }
    write_json(args.evidence_dir / "summary.json", summary)
    (args.evidence_dir / "targets.tsv").write_text(
        "source\tversion\tstatus\tsource_stanza_candidates\tdirect_dsc_hits\tcandidate_attempts\treason\n"
        + "".join(
            "\t".join(
                [
                    row["source"],
                    row["version"],
                    row["status"],
                    str(row["source_stanza_candidate_count"]),
                    str(row["direct_dsc_hit_count"]),
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
