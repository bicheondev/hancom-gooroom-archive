#!/usr/bin/env python3
"""Find missing Hancom Gooroom 3.3 source revisions in Software Heritage.

Public GitHub refs no longer contain several commits named in the exact AMD64
package changelogs. Software Heritage stores historical origin visits as
snapshots, snapshots point to revision heads, and revision logs retain Git
commit identifiers. This audit accepts a revision as an exact source candidate
only when its archived debian/changelog starts with the exact source/version.
Short commit IDs from the package changelog are discovery evidence, never a
substitute for that exact changelog gate.
"""

from __future__ import annotations

import argparse
import email.utils
import hashlib
import os
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

API = "https://archive.softwareheritage.org/api/1"
USER_AGENT = "hancom-gooroom-arm64-software-heritage-archaeology/1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_CONTENT_BYTES = 8 * 1024 * 1024

DEFAULT_REQUEST_INTERVAL = 1.1
DEFAULT_MAX_RETRIES = 8
MAX_RETRY_WAIT_SECONDS = 300.0
CACHEABLE_RESPONSE_BYTES = 4 * 1024 * 1024
_REQUEST_INTERVAL = DEFAULT_REQUEST_INTERVAL
_MAX_RETRIES = DEFAULT_MAX_RETRIES
_NEXT_REQUEST_AT = 0.0
_BEARER_TOKEN = os.environ.get("SWH_BEARER_TOKEN", "").strip()
_REQUEST_CACHE: dict[tuple[str, str, str], tuple[bytes, dict[str, Any]]] = {}
_REQUEST_STATS: dict[str, int] = {
    "network_attempts": 0,
    "cache_hits": 0,
    "retries": 0,
    "rate_limited_responses": 0,
    "server_error_responses": 0,
    "transport_errors": 0,
    "retry_exhaustions": 0,
}


@dataclass(frozen=True)
class Target:
    source: str
    version: str
    repository_names: tuple[str, ...]
    change_prefixes: tuple[str, ...]
    release_date: str


TARGETS = (
    Target(
        "gnome-flashback",
        "3.38.0-2+grm3u2+han3u4",
        ("gnome-flashback",),
        ("cc88eff1", "1bf11751", "7af5a94e", "6b37d402"),
        "2023-07-28T01:08:37Z",
    ),
    Target(
        "gooroom-dockbarx-applet",
        "0.3.1+grm3u1+han3u1",
        ("gooroom-dockbarx-applet",),
        ("95268201",),
        "2023-06-30T10:21:30Z",
    ),
    Target(
        "gooroom-guide",
        "0.5.3+grm3u1+han3u1",
        ("gooroom-guide",),
        ("8f97ebbb", "8dd75aa0", "7f8fabb0"),
        "2023-07-27T00:00:00Z",
    ),
    Target(
        "gooroom-integration-applet",
        "0.3.1+grm3u1+han3u3",
        ("gooroom-integration-applet",),
        ("15d785a8", "d0a3f95d"),
        "2023-06-30T10:15:35Z",
    ),
    Target(
        "gooroom-session-manager",
        "0.3.9+grm3u1+han3u2",
        ("gooroom-session-manager",),
        ("399f4475", "b6b99835"),
        "2023-07-28T01:12:58Z",
    ),
    Target(
        "linux",
        "5.10.179-1+grm3u1",
        ("linux", "linux-signed-amd64"),
        (),
        "2023-05-21T02:43:10Z",
    ),
    Target(
        "qtbase-opensource-src",
        "5.15.2+dfsg-9+grm3u1",
        ("qtbase-opensource-src", "qtbase"),
        ("b90b36aa",),
        "2023-04-28T07:18:47Z",
    ),
)

OWNERS = ("gooroom", "hancomgooroom", "hancom-io")
EXTRA_ORIGINS = {
    "linux": (
        "https://salsa.debian.org/kernel-team/linux.git",
        "https://salsa.debian.org/kernel-team/linux",
    ),
    "qtbase-opensource-src": (
        "https://salsa.debian.org/qt-kde-team/qt/qtbase.git",
        "https://salsa.debian.org/qt-kde-team/qt/qtbase",
    ),
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def reset_request_state() -> None:
    global _NEXT_REQUEST_AT
    _NEXT_REQUEST_AT = 0.0
    _REQUEST_CACHE.clear()
    for key in _REQUEST_STATS:
        _REQUEST_STATS[key] = 0


def configure_request_policy(request_interval: float, max_retries: int) -> None:
    global _REQUEST_INTERVAL, _MAX_RETRIES
    if not 0.0 <= request_interval <= 60.0:
        raise SystemExit("--request-interval must be between 0 and 60 seconds")
    if not 0 <= max_retries <= 12:
        raise SystemExit("--max-retries must be between 0 and 12")
    _REQUEST_INTERVAL = float(request_interval)
    _MAX_RETRIES = int(max_retries)
    reset_request_state()


def _header_value(headers: Any, name: str) -> str:
    if headers is None:
        return ""
    try:
        value = headers.get(name)
    except Exception:
        return ""
    return str(value).strip() if value is not None else ""


def _rate_limit_headers(headers: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for header in (
        "Retry-After",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
    ):
        value = _header_value(headers, header)
        if value:
            result[header.lower()] = value
    return result


def _seconds_until_epoch(value: str) -> float | None:
    try:
        return max(0.0, float(value) - time.time())
    except (TypeError, ValueError):
        return None


def _retry_after_seconds(value: str) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0.0, parsed.timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            return None


def _retry_delay(headers: Any, attempt: int) -> float:
    candidates = [
        max(_REQUEST_INTERVAL, min(MAX_RETRY_WAIT_SECONDS, 2.0 ** attempt)),
    ]
    retry_after = _retry_after_seconds(_header_value(headers, "Retry-After"))
    if retry_after is not None:
        candidates.append(retry_after)
    reset_delay = _seconds_until_epoch(_header_value(headers, "X-RateLimit-Reset"))
    if reset_delay is not None:
        candidates.append(reset_delay)
    return min(MAX_RETRY_WAIT_SECONDS, max(candidates))


def _server_spacing(headers: Any) -> float:
    remaining_text = _header_value(headers, "X-RateLimit-Remaining")
    reset_text = _header_value(headers, "X-RateLimit-Reset")
    if not remaining_text or not reset_text:
        return 0.0
    try:
        remaining = int(remaining_text)
    except ValueError:
        return 0.0
    reset_delay = _seconds_until_epoch(reset_text)
    if reset_delay is None:
        return 0.0
    if remaining <= 0:
        return min(MAX_RETRY_WAIT_SECONDS, reset_delay)
    return min(60.0, reset_delay / remaining)


def _pace_request() -> None:
    global _NEXT_REQUEST_AT
    current = time.monotonic()
    if current < _NEXT_REQUEST_AT:
        time.sleep(_NEXT_REQUEST_AT - current)
        current = time.monotonic()
    _NEXT_REQUEST_AT = current + _REQUEST_INTERVAL


def _extend_next_request(headers: Any) -> None:
    global _NEXT_REQUEST_AT
    spacing = max(_REQUEST_INTERVAL, _server_spacing(headers))
    _NEXT_REQUEST_AT = max(_NEXT_REQUEST_AT, time.monotonic() + spacing)


def _request_headers(url: str, accept: str) -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": accept,
        "Accept-Encoding": "identity",
    }
    if _BEARER_TOKEN and url.startswith("https://archive.softwareheritage.org/"):
        headers["Authorization"] = f"Bearer {_BEARER_TOKEN}"
    return headers


def request_bytes(
    url: str,
    *,
    timeout: int,
    max_bytes: int,
    accept: str,
    method: str = "GET",
) -> tuple[bytes | None, dict[str, Any]]:
    cache_key = (method, url, accept)
    if method == "GET" and cache_key in _REQUEST_CACHE:
        body, cached_evidence = _REQUEST_CACHE[cache_key]
        _REQUEST_STATS["cache_hits"] += 1
        evidence = dict(cached_evidence)
        evidence.update(
            {
                "cache_hit": True,
                "elapsed_seconds": 0.0,
                "attempt_count": 0,
                "retry_history": [],
            }
        )
        return body, evidence

    retry_history: list[dict[str, Any]] = []
    for attempt in range(_MAX_RETRIES + 1):
        _pace_request()
        request = urllib.request.Request(
            url,
            method=method,
            headers=_request_headers(url, accept),
        )
        started = time.monotonic()
        _REQUEST_STATS["network_attempts"] += 1
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
                rate_headers = _rate_limit_headers(response.headers)
                _extend_next_request(response.headers)
                evidence: dict[str, Any] = {
                    "url": url,
                    "status": int(getattr(response, "status", 200)),
                    "final_url": response.geturl(),
                    "content_type": response.headers.get("Content-Type"),
                    "link": response.headers.get("Link"),
                    "size": len(body),
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "cache_hit": False,
                    "attempt_count": attempt + 1,
                    "retry_history": retry_history,
                    "rate_limit": rate_headers,
                }
                if method == "GET" and len(body) <= CACHEABLE_RESPONSE_BYTES:
                    _REQUEST_CACHE[cache_key] = (body, dict(evidence))
                return body, evidence
        except urllib.error.HTTPError as error:
            status = int(error.code)
            rate_headers = _rate_limit_headers(error.headers)
            evidence = {
                "url": url,
                "status": status,
                "error": str(error),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "attempt": attempt + 1,
                "rate_limit": rate_headers,
            }
            retryable = status == 429 or 500 <= status < 600
            if not retryable:
                evidence["attempt_count"] = attempt + 1
                evidence["retry_history"] = retry_history
                return None, evidence
            if status == 429:
                _REQUEST_STATS["rate_limited_responses"] += 1
            else:
                _REQUEST_STATS["server_error_responses"] += 1
            if attempt >= _MAX_RETRIES:
                _REQUEST_STATS["retry_exhaustions"] += 1
                raise RuntimeError(
                    f"Software Heritage request retries exhausted: status={status} url={url}"
                ) from error
            delay = _retry_delay(error.headers, attempt)
            evidence["retry_delay_seconds"] = round(delay, 3)
            retry_history.append(evidence)
            _REQUEST_STATS["retries"] += 1
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as error:
            _REQUEST_STATS["transport_errors"] += 1
            evidence = {
                "url": url,
                "status": None,
                "error": repr(error),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "attempt": attempt + 1,
            }
            if attempt >= _MAX_RETRIES:
                _REQUEST_STATS["retry_exhaustions"] += 1
                raise RuntimeError(
                    f"Software Heritage transport retries exhausted: url={url}"
                ) from error
            delay = min(
                MAX_RETRY_WAIT_SECONDS,
                max(_REQUEST_INTERVAL, 2.0 ** attempt),
            )
            evidence["retry_delay_seconds"] = round(delay, 3)
            retry_history.append(evidence)
            _REQUEST_STATS["retries"] += 1
            time.sleep(delay)
        except Exception as error:
            raise RuntimeError(f"Software Heritage request failed closed: url={url}") from error

    raise AssertionError("unreachable request retry loop")


def request_json(
    url: str,
    *,
    timeout: int,
) -> tuple[Any | None, dict[str, Any]]:
    body, evidence = request_bytes(
        url,
        timeout=timeout,
        max_bytes=MAX_JSON_BYTES,
        accept="application/json",
    )
    if body is None:
        return None, evidence
    try:
        return json.loads(body.decode("utf-8")), evidence
    except Exception as error:
        evidence["parse_error"] = repr(error)
        return None, evidence


def origin_variants(target: Target) -> list[str]:
    origins: list[str] = []
    for owner in OWNERS:
        for repository in target.repository_names:
            base = f"https://github.com/{owner}/{repository}"
            origins.extend((base, base + ".git"))
    origins.extend(EXTRA_ORIGINS.get(target.source, ()))
    return list(dict.fromkeys(origins))


def origin_api_urls(origin: str) -> list[str]:
    encoded = urllib.parse.quote(origin, safe="")
    path_encoded = urllib.parse.quote(origin, safe=":/")
    return list(
        dict.fromkeys(
            (
                f"{API}/origin/{encoded}/visits/?per_page=1000",
                f"{API}/origin/{path_encoded}/visits/?per_page=1000",
            )
        )
    )


def get_visits(origin: str, timeout: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in origin_api_urls(origin):
        value, evidence = request_json(url, timeout=timeout)
        evidence["origin"] = origin
        attempts.append(evidence)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)], attempts
        if isinstance(value, dict):
            for key in ("results", "visits"):
                rows = value.get(key)
                if isinstance(rows, list):
                    return [item for item in rows if isinstance(item, dict)], attempts
    return [], attempts


def get_snapshot(snapshot: str, timeout: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    branches: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    branches_from: str | None = None
    seen_pages: set[str] = set()
    for _ in range(50):
        query = {"branches_count": "1000"}
        if branches_from:
            query["branches_from"] = branches_from
        url = f"{API}/snapshot/{snapshot}/?" + urllib.parse.urlencode(query)
        value, evidence = request_json(url, timeout=timeout)
        evidence["snapshot"] = snapshot
        attempts.append(evidence)
        if not isinstance(value, dict):
            break
        mapping = value.get("branches")
        if isinstance(mapping, dict):
            for name, branch in mapping.items():
                if isinstance(branch, dict):
                    copied = dict(branch)
                    copied["name"] = name
                    branches.append(copied)
        next_branch = value.get("next_branch")
        if not isinstance(next_branch, str) or not next_branch:
            break
        if next_branch in seen_pages:
            break
        seen_pages.add(next_branch)
        branches_from = next_branch
    return branches, attempts


def resolve_release(release: str, timeout: int) -> tuple[str | None, dict[str, Any]]:
    value, evidence = request_json(f"{API}/release/{release}/", timeout=timeout)
    if not isinstance(value, dict):
        return None, evidence
    target = str(value.get("target", ""))
    target_type = str(value.get("target_type", ""))
    if target_type == "revision" and HEX40.fullmatch(target):
        return target, evidence
    return None, evidence


def revision_log(head: str, timeout: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    value, evidence = request_json(
        f"{API}/revision/{head}/log/?limit=1000",
        timeout=timeout,
    )
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)], evidence
    if isinstance(value, dict):
        rows = value.get("revisions") or value.get("results")
        if isinstance(rows, list):
            return [item for item in rows if isinstance(item, dict)], evidence
    return [], evidence


def revision_metadata(revision: str, timeout: int) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    value, evidence = request_json(f"{API}/revision/{revision}/", timeout=timeout)
    return (value if isinstance(value, dict) else None), evidence


def find_file_entry(value: Any, filename: str) -> dict[str, Any] | None:
    if isinstance(value, dict):
        if value.get("type") == "file" and value.get("name") in {filename, None}:
            return value
        content = value.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("name") == filename:
                    return item
        if value.get("name") == filename and value.get("target"):
            return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and item.get("name") == filename:
                return item
    return None


def fetch_changelog(
    revision: str,
    directory: str,
    timeout: int,
) -> tuple[bytes | None, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    path = urllib.parse.quote("debian/changelog", safe="/")
    candidates = (
        f"{API}/directory/{directory}/{path}/",
        f"{API}/revision/{revision}/directory/{path}/",
    )
    for url in candidates:
        value, evidence = request_json(url, timeout=timeout)
        evidence["revision"] = revision
        evidence["directory"] = directory
        attempts.append(evidence)
        entry = find_file_entry(value, "changelog")
        if entry is None:
            continue
        target = str(entry.get("target", ""))
        target_url = str(entry.get("target_url", ""))
        info: Any = entry
        if target_url:
            info, info_evidence = request_json(target_url, timeout=timeout)
            info_evidence["revision"] = revision
            info_evidence["purpose"] = "content-metadata"
            attempts.append(info_evidence)
        data_url = ""
        if isinstance(info, dict):
            data_url = str(info.get("data_url", ""))
            checksums = info.get("checksums")
            if not target and isinstance(checksums, dict):
                target = str(checksums.get("sha1_git", ""))
        if not data_url and target:
            data_url = f"{API}/content/sha1_git:{target}/raw/"
        if not data_url:
            continue
        body, body_evidence = request_bytes(
            data_url,
            timeout=timeout,
            max_bytes=MAX_CONTENT_BYTES,
            accept="application/octet-stream",
        )
        body_evidence["revision"] = revision
        body_evidence["purpose"] = "debian/changelog"
        attempts.append(body_evidence)
        if body is not None:
            return body, attempts
    return None, attempts


def exact_changelog_header(body: bytes, target: Target) -> bool:
    text = body.decode("utf-8", errors="replace")
    first = text.splitlines()[0] if text else ""
    return first == f"{target.source} ({target.version}) unstable; urgency=medium" or bool(
        re.fullmatch(
            re.escape(target.source)
            + r" \("
            + re.escape(target.version)
            + r"\) [^;]+; urgency=[^\s]+",
            first,
        )
    )


def revision_date(row: dict[str, Any]) -> datetime | None:
    for key in ("committer_date", "date"):
        value = row.get(key)
        if isinstance(value, str):
            parsed = parse_date(value)
            if parsed is not None:
                return parsed
        if isinstance(value, dict):
            timestamp = value.get("timestamp")
            if isinstance(timestamp, dict):
                seconds = timestamp.get("seconds")
                if isinstance(seconds, int):
                    return datetime.fromtimestamp(seconds, tz=timezone.utc)
    return None


def interesting_revision(
    row: dict[str, Any],
    *,
    target: Target,
    heads: set[str],
    prefix_matches: set[str],
    release: datetime,
) -> bool:
    revision = str(row.get("id", ""))
    if revision in heads or revision in prefix_matches:
        return True
    date = revision_date(row)
    if date is not None and abs((date - release).total_seconds()) <= 75 * 86400:
        return True
    message = str(row.get("message", "")).lower()
    keywords = (
        "hancom",
        "changelog",
        "release",
        "theme",
        target.version.lower(),
        target.source.lower(),
    )
    return any(keyword and keyword in message for keyword in keywords)


def audit_target(target: Target, output: Path, timeout: int) -> dict[str, Any]:
    target_dir = output / target.source
    target_dir.mkdir(parents=True, exist_ok=True)
    release = parse_date(target.release_date) or datetime(2023, 8, 1, tzinfo=timezone.utc)

    origin_rows: list[dict[str, Any]] = []
    visit_attempts: list[dict[str, Any]] = []
    snapshot_attempts: list[dict[str, Any]] = []
    release_attempts: list[dict[str, Any]] = []
    log_attempts: list[dict[str, Any]] = []
    changelog_attempts: list[dict[str, Any]] = []
    heads: set[str] = set()
    head_context: dict[str, list[dict[str, Any]]] = {}

    for origin in origin_variants(target):
        visits, attempts = get_visits(origin, timeout)
        visit_attempts.extend(attempts)
        origin_row = {
            "origin": origin,
            "visit_count": len(visits),
            "full_snapshot_count": 0,
            "snapshots": [],
        }
        for visit in visits:
            snapshot = str(visit.get("snapshot", ""))
            if not HEX40.fullmatch(snapshot):
                continue
            branches, attempts = get_snapshot(snapshot, timeout)
            snapshot_attempts.extend(attempts)
            revision_count = 0
            release_count = 0
            for branch in branches:
                target_type = str(branch.get("target_type", ""))
                branch_target = str(branch.get("target", ""))
                revision: str | None = None
                if target_type == "revision" and HEX40.fullmatch(branch_target):
                    revision = branch_target
                    revision_count += 1
                elif target_type == "release" and HEX40.fullmatch(branch_target):
                    revision, evidence = resolve_release(branch_target, timeout)
                    evidence["origin"] = origin
                    evidence["snapshot"] = snapshot
                    release_attempts.append(evidence)
                    release_count += 1
                if revision is None:
                    continue
                heads.add(revision)
                head_context.setdefault(revision, []).append(
                    {
                        "origin": origin,
                        "visit": visit.get("visit"),
                        "visit_date": visit.get("date"),
                        "snapshot": snapshot,
                        "branch": branch.get("name"),
                    }
                )
            origin_row["full_snapshot_count"] += 1
            origin_row["snapshots"].append(
                {
                    "visit": visit.get("visit"),
                    "date": visit.get("date"),
                    "snapshot": snapshot,
                    "branch_count": len(branches),
                    "revision_branch_count": revision_count,
                    "release_branch_count": release_count,
                }
            )
        origin_rows.append(origin_row)

    revisions: dict[str, dict[str, Any]] = {}
    for head in sorted(heads):
        rows, evidence = revision_log(head, timeout)
        evidence["head"] = head
        evidence["revision_count"] = len(rows)
        log_attempts.append(evidence)
        if not rows:
            metadata, metadata_evidence = revision_metadata(head, timeout)
            metadata_evidence["head"] = head
            metadata_evidence["purpose"] = "head-fallback"
            log_attempts.append(metadata_evidence)
            if metadata is not None:
                rows = [metadata]
        for row in rows:
            revision = str(row.get("id", ""))
            if HEX40.fullmatch(revision):
                revisions.setdefault(revision, row)

    prefix_matches: dict[str, list[str]] = {prefix: [] for prefix in target.change_prefixes}
    matched_revisions: set[str] = set()
    for revision in revisions:
        for prefix in target.change_prefixes:
            if revision.startswith(prefix):
                prefix_matches[prefix].append(revision)
                matched_revisions.add(revision)

    candidates_to_inspect: list[tuple[float, str]] = []
    for revision, row in revisions.items():
        if not interesting_revision(
            row,
            target=target,
            heads=heads,
            prefix_matches=matched_revisions,
            release=release,
        ):
            continue
        date = revision_date(row)
        distance = abs((date - release).total_seconds()) if date else float("inf")
        if revision in heads:
            distance -= 10_000_000
        if revision in matched_revisions:
            distance -= 20_000_000
        candidates_to_inspect.append((distance, revision))
    candidates_to_inspect.sort()

    exact_candidates: list[dict[str, Any]] = []
    inspected: list[dict[str, Any]] = []
    for _, revision in candidates_to_inspect[:500]:
        row = revisions[revision]
        directory = str(row.get("directory", ""))
        if not HEX40.fullmatch(directory):
            metadata, evidence = revision_metadata(revision, timeout)
            evidence["revision"] = revision
            evidence["purpose"] = "directory-resolution"
            changelog_attempts.append(evidence)
            if metadata is not None:
                directory = str(metadata.get("directory", ""))
        if not HEX40.fullmatch(directory):
            continue
        body, attempts = fetch_changelog(revision, directory, timeout)
        changelog_attempts.extend(attempts)
        record = {
            "revision": revision,
            "directory": directory,
            "date": row.get("date"),
            "committer_date": row.get("committer_date"),
            "message": row.get("message"),
            "head_context": head_context.get(revision, []),
            "matched_change_prefixes": [
                prefix for prefix in target.change_prefixes if revision.startswith(prefix)
            ],
            "changelog_found": body is not None,
        }
        if body is not None:
            text = body.decode("utf-8", errors="replace")
            record["changelog_first_line"] = text.splitlines()[0] if text else ""
            record["changelog_size"] = len(body)
            record["changelog_sha256"] = sha256_bytes(body)
            record["exact_source_version"] = exact_changelog_header(body, target)
        else:
            record["exact_source_version"] = False
        inspected.append(record)
        if record["exact_source_version"]:
            exact_candidates.append(record)

    exact_candidates.sort(
        key=lambda row: (
            abs(
                (
                    (parse_date(str(row.get("committer_date") or row.get("date") or "")) or release)
                    - release
                ).total_seconds()
            ),
            str(row["revision"]),
        )
    )
    selected = exact_candidates[0] if exact_candidates else None
    result = {
        "schema": 1,
        "policy": "software-heritage-revision-with-exact-debian-changelog-header",
        "source": target.source,
        "source_version": target.version,
        "release_date": target.release_date,
        "change_prefixes": list(target.change_prefixes),
        "origins_checked": origin_rows,
        "origin_count": len(origin_rows),
        "archived_origin_count": sum(row["visit_count"] > 0 for row in origin_rows),
        "unique_snapshot_head_count": len(heads),
        "reachable_revision_count": len(revisions),
        "prefix_matches": prefix_matches,
        "inspected_revision_count": len(inspected),
        "exact_candidate_count": len(exact_candidates),
        "status": "exact-revision-found" if selected else "unresolved",
        "selected": selected,
        "exact_candidates": exact_candidates,
        "promotion_allowed": False,
    }
    write_json(target_dir / "result.json", result)
    write_json(target_dir / "inspected-revisions.json", inspected)
    write_json(target_dir / "origin-visit-attempts.json", visit_attempts)
    write_json(target_dir / "snapshot-attempts.json", snapshot_attempts)
    write_json(target_dir / "release-attempts.json", release_attempts)
    write_json(target_dir / "revision-log-attempts.json", log_attempts)
    write_json(target_dir / "changelog-attempts.json", changelog_attempts)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--request-interval", type=float, default=DEFAULT_REQUEST_INTERVAL)
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    parser.add_argument("--source", action="append", default=[])
    args = parser.parse_args()

    configure_request_policy(args.request_interval, args.max_retries)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    selected_sources = set(args.source)
    targets: Iterable[Target] = (
        target for target in TARGETS if not selected_sources or target.source in selected_sources
    )
    results = [audit_target(target, args.output_dir, args.timeout) for target in targets]
    summary = {
        "schema": 1,
        "generated_at": now(),
        "policy": "software-heritage-history-discovery-exact-changelog-gate",
        "transport_complete": True,
        "request_policy": {
            "minimum_interval_seconds": _REQUEST_INTERVAL,
            "max_retries": _MAX_RETRIES,
            "authenticated": bool(_BEARER_TOKEN),
        },
        "request_stats": dict(_REQUEST_STATS),
        "target_count": len(results),
        "archived_origin_target_count": sum(result["archived_origin_count"] > 0 for result in results),
        "exact_revision_target_count": sum(result["status"] == "exact-revision-found" for result in results),
        "unresolved_target_count": sum(result["status"] != "exact-revision-found" for result in results),
        "targets": [
            {
                "source": result["source"],
                "source_version": result["source_version"],
                "status": result["status"],
                "archived_origin_count": result["archived_origin_count"],
                "unique_snapshot_head_count": result["unique_snapshot_head_count"],
                "reachable_revision_count": result["reachable_revision_count"],
                "exact_candidate_count": result["exact_candidate_count"],
                "selected_revision": (result.get("selected") or {}).get("revision"),
                "selected_directory": (result.get("selected") or {}).get("directory"),
            }
            for result in results
        ],
        "source_tree_recovery_allowed": any(result["status"] == "exact-revision-found" for result in results),
        "promotion_allowed": False,
    }
    write_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
