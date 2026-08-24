#!/usr/bin/env python3
"""Recover byte-exact HTTP payloads from Common Crawl WARC records.

This module is intentionally conservative.  Common Crawl metadata is discovery
only; callers must validate the returned payload against an independent size
and cryptographic digest authority.  The helper records every index query and
WARC range request so negative evidence remains auditable.
"""

from __future__ import annotations

import gzip
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable

USER_AGENT = "hancom-gooroom-arm64-common-crawl-recovery/1"
MAX_INDEX_RESPONSE = 8 * 1024 * 1024
MAX_WARC_RECORD = 64 * 1024 * 1024

# Ordered around and after the July/August 2023 reference-repository state.
# Later crawls are retained because static repository objects sometimes remain
# addressable after the Release metadata itself changes.
DEFAULT_CRAWLS = (
    "CC-MAIN-2023-40",
    "CC-MAIN-2023-50",
    "CC-MAIN-2024-10",
    "CC-MAIN-2024-18",
    "CC-MAIN-2024-22",
    "CC-MAIN-2024-26",
    "CC-MAIN-2024-30",
    "CC-MAIN-2024-33",
    "CC-MAIN-2023-23",
)


@dataclass(frozen=True)
class PayloadCandidate:
    body: bytes
    evidence: dict[str, Any]


def _request(
    url: str,
    *,
    timeout: int,
    max_bytes: int,
    headers: dict[str, str] | None = None,
) -> tuple[bytes | None, dict[str, Any]]:
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json,application/octet-stream,*/*",
        "Accept-Encoding": "identity",
    }
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError(f"response exceeded {max_bytes} bytes")
                chunks.append(chunk)
            body = b"".join(chunks)
            return body, {
                "url": url,
                "status": int(getattr(response, "status", 200)),
                "final_url": response.geturl(),
                "content_type": response.headers.get("Content-Type"),
                "content_range": response.headers.get("Content-Range"),
                "size": len(body),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
    except urllib.error.HTTPError as error:
        return None, {
            "url": url,
            "status": int(error.code),
            "error": str(error),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    except Exception as error:
        return None, {
            "url": url,
            "status": None,
            "error": repr(error),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }


def _query_forms(original: str) -> list[str]:
    parsed = urllib.parse.urlsplit(original)
    values = [original]
    if parsed.scheme and parsed.netloc:
        values.append(parsed.netloc + parsed.path)
        other = "https" if parsed.scheme == "http" else "http"
        values.append(
            urllib.parse.urlunsplit(
                (other, parsed.netloc, parsed.path, parsed.query, parsed.fragment)
            )
        )
    return list(dict.fromkeys(value for value in values if value))


def _parse_cdxj(body: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    text = body.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            # Some deployments may return one JSON array instead of JSONL.
            try:
                aggregate = json.loads(text)
            except json.JSONDecodeError:
                break
            if isinstance(aggregate, list):
                for item in aggregate:
                    if isinstance(item, dict):
                        records.append(item)
            break
        if isinstance(value, dict):
            records.append(value)
    return records


def discover_records(
    original: str,
    *,
    timeout: int,
    crawls: Iterable[str] = DEFAULT_CRAWLS,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    queries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for crawl in crawls:
        endpoint = f"https://index.commoncrawl.org/{crawl}-index"
        for query_url in _query_forms(original):
            query = urllib.parse.urlencode(
                {
                    "url": query_url,
                    "output": "json",
                    "matchType": "exact",
                    "filter": "status:200",
                    "collapse": "digest",
                }
            )
            body, evidence = _request(
                endpoint + "?" + query,
                timeout=timeout,
                max_bytes=MAX_INDEX_RESPONSE,
            )
            evidence.update(
                {
                    "crawl": crawl,
                    "query_url": query_url,
                    "record_count": 0,
                }
            )
            discovered: list[dict[str, Any]] = []
            if body is not None:
                discovered = _parse_cdxj(body)
                evidence["record_count"] = len(discovered)
            queries.append(evidence)

            for record in discovered:
                filename = str(record.get("filename", ""))
                offset = str(record.get("offset", ""))
                length = str(record.get("length", ""))
                if not filename or not offset.isdigit() or not length.isdigit():
                    continue
                key = (filename, offset, length)
                if key in seen:
                    continue
                seen.add(key)
                copied = dict(record)
                copied["crawl"] = crawl
                copied["query_url"] = query_url
                records.append(copied)

    records.sort(
        key=lambda row: (
            str(row.get("timestamp", "")),
            str(row.get("filename", "")),
            int(str(row.get("offset", "0")) or 0),
        ),
        reverse=True,
    )
    return records, queries


def _split_header_block(data: bytes) -> tuple[bytes, bytes] | None:
    for separator in (b"\r\n\r\n", b"\n\n"):
        position = data.find(separator)
        if position >= 0:
            return data[:position], data[position + len(separator) :]
    return None


def _decode_chunked(body: bytes) -> bytes:
    output = bytearray()
    cursor = 0
    while True:
        end = body.find(b"\r\n", cursor)
        separator_size = 2
        if end < 0:
            end = body.find(b"\n", cursor)
            separator_size = 1
        if end < 0:
            raise ValueError("chunk-size line is missing")
        size_token = body[cursor:end].split(b";", 1)[0].strip()
        size = int(size_token, 16)
        cursor = end + separator_size
        if size == 0:
            return bytes(output)
        if cursor + size > len(body):
            raise ValueError("chunk exceeds body length")
        output.extend(body[cursor : cursor + size])
        cursor += size
        if body[cursor : cursor + 2] == b"\r\n":
            cursor += 2
        elif body[cursor : cursor + 1] == b"\n":
            cursor += 1
        else:
            raise ValueError("chunk terminator is missing")


def _header_map(block: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    lines = re.split(br"\r?\n", block)
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("latin-1").lower()] = value.decode(
            "latin-1", errors="replace"
        ).strip()
    return headers


def extract_payload_variants(warc_gzip_member: bytes) -> list[tuple[bytes, str]]:
    decoded = gzip.decompress(warc_gzip_member)
    warc_split = _split_header_block(decoded)
    if warc_split is None:
        raise ValueError("WARC header terminator is missing")
    _, record_content = warc_split

    http_split = _split_header_block(record_content)
    if http_split is None:
        # Revisit records or raw-resource records can omit an HTTP envelope.
        return [(record_content, "warc-record-content")]

    http_headers, body = http_split
    headers = _header_map(http_headers)
    variants: list[tuple[bytes, str]] = [(body, "http-body")]

    if "chunked" in headers.get("transfer-encoding", "").lower():
        try:
            variants.append((_decode_chunked(body), "http-body-dechunked"))
        except Exception:
            pass

    # Do not normally decode Content-Encoding: gzip for a URL that is itself a
    # .gz object.  Still expose the variant because some crawlers normalize the
    # transport encoding while retaining the original URL.
    if "gzip" in headers.get("content-encoding", "").lower():
        for candidate, label in list(variants):
            try:
                variants.append((gzip.decompress(candidate), label + "-content-gzip-decoded"))
            except Exception:
                pass

    unique: list[tuple[bytes, str]] = []
    seen: set[bytes] = set()
    for candidate, label in variants:
        marker = candidate[:64] + len(candidate).to_bytes(8, "big")
        if marker in seen:
            continue
        seen.add(marker)
        unique.append((candidate, label))
    return unique


def recover_payload_candidates(
    original: str,
    *,
    timeout: int,
    record_limit: int = 40,
    crawls: Iterable[str] = DEFAULT_CRAWLS,
) -> tuple[list[PayloadCandidate], dict[str, Any]]:
    records, query_evidence = discover_records(
        original,
        timeout=timeout,
        crawls=crawls,
    )
    candidates: list[PayloadCandidate] = []
    range_evidence: list[dict[str, Any]] = []

    for record in records[:record_limit]:
        filename = str(record["filename"])
        offset = int(str(record["offset"]))
        length = int(str(record["length"]))
        if length <= 0 or length > MAX_WARC_RECORD:
            range_evidence.append(
                {
                    "filename": filename,
                    "offset": offset,
                    "length": length,
                    "error": "record length is outside the accepted bound",
                }
            )
            continue
        end = offset + length - 1
        data_url = "https://data.commoncrawl.org/" + filename
        body, evidence = _request(
            data_url,
            timeout=timeout,
            max_bytes=MAX_WARC_RECORD,
            headers={"Range": f"bytes={offset}-{end}"},
        )
        evidence.update(
            {
                "crawl": record.get("crawl"),
                "timestamp": record.get("timestamp"),
                "captured_url": record.get("url"),
                "filename": filename,
                "offset": offset,
                "length": length,
            }
        )
        if body is None:
            range_evidence.append(evidence)
            continue

        # A compliant range response is exactly one compressed WARC record.
        if len(body) != length:
            evidence["error"] = f"range size {len(body)} != {length}"
            range_evidence.append(evidence)
            continue
        try:
            variants = extract_payload_variants(body)
        except Exception as error:
            evidence["error"] = repr(error)
            range_evidence.append(evidence)
            continue

        evidence["payload_variant_count"] = len(variants)
        range_evidence.append(evidence)
        for payload, label in variants:
            candidates.append(
                PayloadCandidate(
                    body=payload,
                    evidence={
                        "source": "common-crawl-warc",
                        "variant": label,
                        "crawl": record.get("crawl"),
                        "timestamp": record.get("timestamp"),
                        "captured_url": record.get("url"),
                        "warc_filename": filename,
                        "warc_offset": offset,
                        "warc_length": length,
                        "index_digest": record.get("digest"),
                    },
                )
            )

    return candidates, {
        "schema": 1,
        "original_url": original,
        "crawl_count": len(tuple(crawls)),
        "record_count": len(records),
        "record_limit": record_limit,
        "query_evidence": query_evidence,
        "range_evidence": range_evidence,
        "payload_candidate_count": len(candidates),
    }
