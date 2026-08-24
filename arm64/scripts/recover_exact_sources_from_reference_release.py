#!/usr/bin/env python3
"""Recover exact Hancom Gooroom source archives from the reference ISO release locks.

The reference ISO preserves signed InRelease files whose SHA-256 sections lock the
exact `main/source/Sources` indices used around the Hancom Gooroom 3.3 build.
This tool recovers only byte-identical indices and source members, trying the
live repository first and archival snapshots second.  Version text alone never
authorizes promotion.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.parser import Parser
from pathlib import Path
from typing import Any, Iterable, Iterator

USER_AGENT = "hancom-gooroom-arm64-exact-source-recovery/2"
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_SOURCE_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_CDX_ROWS = 200
MAX_RECORDED_ATTEMPTS = 400
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Target:
    source: str
    version: str


TARGETS: tuple[Target, ...] = (
    Target("gnome-flashback", "3.38.0-2+grm3u2+han3u4"),
    Target("gooroom-dockbarx-applet", "0.3.1+grm3u1+han3u1"),
    Target("gooroom-guide", "0.5.3+grm3u1+han3u1"),
    Target("gooroom-integration-applet", "0.3.1+grm3u1+han3u3"),
    Target("gooroom-session-manager", "0.3.9+grm3u1+han3u2"),
    Target("linux", "5.10.179-1+grm3u1"),
    Target("qtbase-opensource-src", "5.15.2+dfsg-9+grm3u1"),
)
TARGET_MAP = {(target.source, target.version): target for target in TARGETS}


@dataclass(frozen=True)
class Repository:
    key: str
    base_url: str
    suite: str
    inrelease: Path


@dataclass(frozen=True)
class LockedObject:
    path: str
    size: int
    sha256: str


class RecoveryError(RuntimeError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.+~-]+", "_", value)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def parse_inrelease(path: Path) -> tuple[dict[str, str], dict[str, LockedObject]]:
    if not path.is_file():
        raise RecoveryError(f"InRelease evidence is missing: {path}")
    text = path.read_text(encoding="utf-8", errors="strict")
    signed = text
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        marker = "\n\n"
        position = text.find(marker)
        if position < 0:
            raise RecoveryError(f"Malformed clearsigned InRelease: {path}")
        signed = text[position + len(marker) :]
        signature = signed.find("\n-----BEGIN PGP SIGNATURE-----")
        if signature >= 0:
            signed = signed[:signature]

    fields: dict[str, str] = {}
    lines = signed.splitlines()
    for line in lines:
        if line in {"MD5Sum:", "SHA1:", "SHA256:", "SHA512:"}:
            break
        if ":" in line and not line.startswith((" ", "\t")):
            key, value = line.split(":", 1)
            fields[key] = value.strip()

    locks: dict[str, LockedObject] = {}
    in_sha256 = False
    for line in lines:
        if line == "SHA256:":
            in_sha256 = True
            continue
        if in_sha256 and re.match(r"^[A-Za-z0-9-]+:$", line):
            break
        if not in_sha256:
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        digest, size, logical_path = parts
        if not HEX64_RE.fullmatch(digest):
            continue
        try:
            parsed_size = int(size)
        except ValueError:
            continue
        locks[logical_path] = LockedObject(logical_path, parsed_size, digest)

    for required in ("main/source/Sources", "main/source/Sources.gz"):
        if required not in locks:
            raise RecoveryError(f"{path} does not lock {required}")
    return fields, locks


def request_bytes(
    url: str,
    *,
    timeout: int,
    max_bytes: int,
) -> tuple[bytes | None, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/octet-stream,text/plain,*/*",
            "Accept-Encoding": "identity",
        },
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            chunks: list[bytes] = []
            total = 0
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > max_bytes:
                    raise RecoveryError(
                        f"response exceeded {max_bytes} bytes while reading {url}"
                    )
                chunks.append(block)
            body = b"".join(chunks)
            return body, {
                "url": url,
                "status": int(getattr(response, "status", 200)),
                "final_url": response.geturl(),
                "content_type": response.headers.get("Content-Type"),
                "content_length_header": response.headers.get("Content-Length"),
                "size": len(body),
                "sha256": sha256_bytes(body),
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


def verify_locked_bytes(body: bytes, lock: LockedObject) -> tuple[bool, str]:
    if len(body) != lock.size:
        return False, f"size {len(body)} != {lock.size}"
    digest = sha256_bytes(body)
    if digest != lock.sha256:
        return False, f"sha256 {digest} != {lock.sha256}"
    return True, "verified"


def scheme_variants(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        return [url]
    variants = [url]
    other_scheme = "https" if parsed.scheme == "http" else "http"
    variants.append(
        urllib.parse.urlunsplit(
            (other_scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)
        )
    )
    return list(dict.fromkeys(variants))


def release_timestamp(fields: dict[str, str]) -> datetime:
    value = fields.get("Date", "")
    try:
        from email.utils import parsedate_to_datetime

        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return datetime(2023, 8, 1, tzinfo=timezone.utc)


def wayback_timestamps(center: datetime) -> list[str]:
    # CDX results are authoritative when available. These bounded timestamps
    # are only a fallback for CDX outages.
    values: list[str] = []
    for offset in (0, -1, 1, -3, 3, -7, 7, -14, 14):
        day = center + timedelta(days=offset)
        for hour in (center.hour, 0, 12):
            stamp = day.replace(hour=hour, minute=0, second=0, microsecond=0)
            values.append(stamp.strftime("%Y%m%d%H%M%S"))
    values.append(center.strftime("%Y%m%d%H%M%S"))
    return list(dict.fromkeys(values))


def cdx_snapshots(url: str, timeout: int) -> tuple[list[dict[str, str]], dict[str, Any]]:
    params = urllib.parse.urlencode(
        {
            "url": url,
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype,digest,length",
            "filter": "statuscode:200",
            "from": "2023",
            "to": "2024",
            "collapse": "digest",
            "limit": str(MAX_CDX_ROWS),
        }
    )
    endpoint = "https://web.archive.org/cdx/search/cdx?" + params
    body, attempt = request_bytes(
        endpoint, timeout=timeout, max_bytes=8 * 1024 * 1024
    )
    rows: list[dict[str, str]] = []
    if body is None:
        return rows, attempt
    try:
        parsed = json.loads(body.decode("utf-8"))
        if not isinstance(parsed, list) or not parsed:
            attempt["parse_error"] = "CDX response is empty or not a list"
            return rows, attempt
        header = parsed[0]
        if not isinstance(header, list):
            attempt["parse_error"] = "CDX header is not a list"
            return rows, attempt
        for item in parsed[1:]:
            if not isinstance(item, list) or len(item) != len(header):
                continue
            row = {str(key): str(value) for key, value in zip(header, item)}
            if row.get("timestamp") and row.get("original"):
                rows.append(row)
    except Exception as error:
        attempt["parse_error"] = repr(error)
    return rows, attempt


def candidate_archive_urls(
    original_url: str,
    *,
    center: datetime,
    timeout: int,
    cdx_evidence: list[dict[str, Any]],
) -> list[str]:
    candidates: list[str] = []
    for variant in scheme_variants(original_url):
        rows, cdx_attempt = cdx_snapshots(variant, timeout)
        cdx_attempt["original_url"] = variant
        cdx_attempt["snapshot_count"] = len(rows)
        cdx_evidence.append(cdx_attempt)
        for row in rows:
            candidates.append(
                "https://web.archive.org/web/"
                + row["timestamp"]
                + "id_/"
                + row["original"]
            )
        for timestamp in wayback_timestamps(center):
            candidates.append(
                f"https://web.archive.org/web/{timestamp}id_/{variant}"
            )
    return list(dict.fromkeys(candidates))[:120]


def recover_locked_url(
    *,
    canonical_url: str,
    lock: LockedObject,
    center: datetime,
    timeout: int,
    max_bytes: int,
    attempts: list[dict[str, Any]],
    cdx_evidence: list[dict[str, Any]],
) -> tuple[bytes | None, dict[str, Any] | None]:
    direct: list[str] = []
    for variant in scheme_variants(canonical_url):
        direct.append(variant)
        parsed = urllib.parse.urlsplit(variant)
        by_hash_path = str(Path(parsed.path).parent) + "/by-hash/SHA256/" + lock.sha256
        direct.append(
            urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, by_hash_path, "", "")
            )
        )
    candidates = list(dict.fromkeys(direct))
    candidates.extend(
        candidate_archive_urls(
            canonical_url,
            center=center,
            timeout=timeout,
            cdx_evidence=cdx_evidence,
        )
    )

    for candidate in candidates:
        body, attempt = request_bytes(
            candidate, timeout=timeout, max_bytes=max_bytes
        )
        valid = False
        reason = "no body"
        if body is not None:
            valid, reason = verify_locked_bytes(body, lock)
        attempt["expected_size"] = lock.size
        attempt["expected_sha256"] = lock.sha256
        attempt["verification"] = reason
        if len(attempts) < MAX_RECORDED_ATTEMPTS:
            attempts.append(attempt)
        if valid:
            return body, attempt
    return None, None


def iter_stanzas(text: str) -> Iterator[tuple[dict[str, str], str]]:
    block: list[str] = []
    for line in text.splitlines():
        if line.strip():
            block.append(line)
            continue
        if block:
            yield parse_stanza(block)
            block = []
    if block:
        yield parse_stanza(block)


def parse_stanza(lines: list[str]) -> tuple[dict[str, str], str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in lines:
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields, "\n".join(lines) + "\n"


def checksum_rows(value: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        digest, size, filename = parts
        if not HEX64_RE.fullmatch(digest):
            continue
        if Path(filename).name != filename:
            raise RecoveryError(f"unsafe source member filename: {filename}")
        rows.append(
            {"filename": filename, "size": int(size), "sha256": digest}
        )
    return rows


def dsc_fields(body: bytes) -> dict[str, str]:
    text = body.decode("utf-8", errors="strict")
    message = Parser().parsestr(text)
    return {key: value for key, value in message.items()}


def recover_member(
    *,
    base_url: str,
    directory: str,
    member: dict[str, Any],
    center: datetime,
    timeout: int,
    destination: Path,
    attempts: list[dict[str, Any]],
    cdx_evidence: list[dict[str, Any]],
) -> dict[str, Any] | None:
    encoded_directory = "/".join(
        urllib.parse.quote(part, safe="+~._-")
        for part in directory.strip("/").split("/")
    )
    encoded_filename = urllib.parse.quote(member["filename"], safe="+~._-")
    canonical = (
        base_url.rstrip("/") + "/" + encoded_directory + "/" + encoded_filename
    )
    lock = LockedObject(
        path=member["filename"],
        size=int(member["size"]),
        sha256=str(member["sha256"]),
    )
    body, selected = recover_locked_url(
        canonical_url=canonical,
        lock=lock,
        center=center,
        timeout=timeout,
        max_bytes=MAX_SOURCE_MEMBER_BYTES,
        attempts=attempts,
        cdx_evidence=cdx_evidence,
    )
    if body is None or selected is None:
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(body)
    return {
        "filename": member["filename"],
        "size": len(body),
        "sha256": sha256_bytes(body),
        "canonical_url": canonical,
        "recovered_url": selected.get("final_url") or selected.get("url"),
        "status": "verified",
    }


def recover_repository(
    repository: Repository, output_dir: Path, timeout: int
) -> dict[str, Any]:
    fields, locks = parse_inrelease(repository.inrelease)
    center = release_timestamp(fields)
    repo_dir = output_dir / "repositories" / repository.key
    repo_dir.mkdir(parents=True, exist_ok=True)
    index_attempts: list[dict[str, Any]] = []
    cdx_evidence: list[dict[str, Any]] = []

    plain_lock = locks["main/source/Sources"]
    gzip_lock = locks["main/source/Sources.gz"]
    gzip_url = (
        f"{repository.base_url.rstrip('/')}/dists/{repository.suite}/"
        "main/source/Sources.gz"
    )
    plain_url = (
        f"{repository.base_url.rstrip('/')}/dists/{repository.suite}/"
        "main/source/Sources"
    )

    plain_body: bytes | None = None
    selected_index: dict[str, Any] | None = None

    gzip_body, gzip_selected = recover_locked_url(
        canonical_url=gzip_url,
        lock=gzip_lock,
        center=center,
        timeout=timeout,
        max_bytes=MAX_INDEX_BYTES,
        attempts=index_attempts,
        cdx_evidence=cdx_evidence,
    )
    if gzip_body is not None:
        try:
            decompressed = gzip.decompress(gzip_body)
            verified, reason = verify_locked_bytes(decompressed, plain_lock)
            if verified:
                plain_body = decompressed
                selected_index = {
                    "encoding": "gzip",
                    "canonical_url": gzip_url,
                    "recovered_url": (gzip_selected or {}).get("final_url")
                    or (gzip_selected or {}).get("url"),
                    "compressed_size": len(gzip_body),
                    "compressed_sha256": sha256_bytes(gzip_body),
                    "plain_size": len(decompressed),
                    "plain_sha256": sha256_bytes(decompressed),
                }
                (repo_dir / "Sources.gz").write_bytes(gzip_body)
            else:
                index_attempts.append(
                    {
                        "url": gzip_url,
                        "status": "decompression-verification-failed",
                        "verification": reason,
                    }
                )
        except Exception as error:
            index_attempts.append(
                {"url": gzip_url, "status": "decompression-failed", "error": repr(error)}
            )

    if plain_body is None:
        body, plain_selected = recover_locked_url(
            canonical_url=plain_url,
            lock=plain_lock,
            center=center,
            timeout=timeout,
            max_bytes=MAX_INDEX_BYTES,
            attempts=index_attempts,
            cdx_evidence=cdx_evidence,
        )
        if body is not None:
            plain_body = body
            selected_index = {
                "encoding": "plain",
                "canonical_url": plain_url,
                "recovered_url": (plain_selected or {}).get("final_url")
                or (plain_selected or {}).get("url"),
                "plain_size": len(body),
                "plain_sha256": sha256_bytes(body),
            }

    exact_stanzas: list[dict[str, Any]] = []
    if plain_body is not None:
        (repo_dir / "Sources").write_bytes(plain_body)
        text = plain_body.decode("utf-8", errors="strict")
        for stanza_fields, raw in iter_stanzas(text):
            key = (stanza_fields.get("Package", ""), stanza_fields.get("Version", ""))
            if key not in TARGET_MAP:
                continue
            exact_stanzas.append(
                {
                    "source": key[0],
                    "version": key[1],
                    "directory": stanza_fields.get("Directory", ""),
                    "format": stanza_fields.get("Format", ""),
                    "binary": stanza_fields.get("Binary", ""),
                    "vcs_git": stanza_fields.get("Vcs-Git", ""),
                    "vcs_browser": stanza_fields.get("Vcs-Browser", ""),
                    "checksums_sha256": checksum_rows(
                        stanza_fields.get("Checksums-Sha256", "")
                    ),
                    "raw_stanza": raw,
                }
            )

    write_json(
        repo_dir / "source-index-lock.json",
        {
            "schema": 1,
            "repository": repository.key,
            "base_url": repository.base_url,
            "suite": repository.suite,
            "release_fields": fields,
            "release_evidence_path": repository.inrelease.as_posix(),
            "release_evidence_sha256": sha256_file(repository.inrelease),
            "locked_objects": {
                name: {"path": lock.path, "size": lock.size, "sha256": lock.sha256}
                for name, lock in locks.items()
                if name.startswith("main/source/")
            },
            "status": "resolved-byte-identical" if plain_body is not None else "unresolved",
            "selected_index": selected_index,
            "exact_target_stanza_count": len(exact_stanzas),
        },
    )
    write_json(repo_dir / "index-attempts.json", index_attempts)
    write_json(repo_dir / "cdx-evidence.json", cdx_evidence)
    write_json(repo_dir / "exact-target-stanzas.json", exact_stanzas)

    return {
        "repository": repository.key,
        "base_url": repository.base_url,
        "suite": repository.suite,
        "release_date": fields.get("Date"),
        "index_status": "resolved-byte-identical" if plain_body is not None else "unresolved",
        "selected_index": selected_index,
        "exact_stanzas": exact_stanzas,
        "center": center,
        "index_attempt_count": len(index_attempts),
        "cdx_query_count": len(cdx_evidence),
    }


def recover_sources(
    repository_results: list[dict[str, Any]], output_dir: Path, timeout: int
) -> list[dict[str, Any]]:
    recovered: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for repository in repository_results:
        for stanza in repository["exact_stanzas"]:
            key = (stanza["source"], stanza["version"])
            if key in seen:
                continue
            seen.add(key)
            target_dir = (
                output_dir
                / "sources"
                / safe_name(stanza["source"])
                / safe_name(stanza["version"])
            )
            attempts: list[dict[str, Any]] = []
            cdx_evidence: list[dict[str, Any]] = []
            verified_members: list[dict[str, Any]] = []
            unresolved_members: list[dict[str, Any]] = []

            for member in stanza["checksums_sha256"]:
                result = recover_member(
                    base_url=repository["base_url"],
                    directory=stanza["directory"],
                    member=member,
                    center=repository["center"],
                    timeout=timeout,
                    destination=target_dir / member["filename"],
                    attempts=attempts,
                    cdx_evidence=cdx_evidence,
                )
                if result is None:
                    unresolved_members.append(member)
                else:
                    verified_members.append(result)

            dsc_candidates = [
                item for item in verified_members if item["filename"].endswith(".dsc")
            ]
            dsc_verified = False
            declared_fields: dict[str, str] = {}
            if len(dsc_candidates) == 1:
                dsc_path = target_dir / dsc_candidates[0]["filename"]
                declared_fields = dsc_fields(dsc_path.read_bytes())
                dsc_verified = (
                    declared_fields.get("Source", "").strip() == stanza["source"]
                    and declared_fields.get("Version", "").strip() == stanza["version"]
                )

            resolved = (
                not unresolved_members
                and len(verified_members) == len(stanza["checksums_sha256"])
                and dsc_verified
            )
            lock = {
                "schema": "hancom-gooroom-exact-reference-release-source-archive-v1",
                "generated_at": now(),
                "status": "resolved" if resolved else "unresolved",
                "source": stanza["source"],
                "version": stanza["version"],
                "repository": repository["repository"],
                "base_url": repository["base_url"],
                "suite": repository["suite"],
                "source_index": repository["selected_index"],
                "source_stanza": stanza,
                "dsc_fields": declared_fields,
                "dsc_verified": dsc_verified,
                "files": verified_members,
                "unresolved_members": unresolved_members,
                "attempt_count": len(attempts),
                "cdx_query_count": len(cdx_evidence),
                "policy": "byte-identical-signed-release-index-and-source-member-checksums",
            }
            write_json(target_dir / "source-archive-lock.json", lock)
            write_json(target_dir / "download-attempts.json", attempts)
            write_json(target_dir / "cdx-evidence.json", cdx_evidence)
            sums = []
            for path in sorted(target_dir.iterdir()):
                if not path.is_file() or path.name == "SOURCESUMS.sha256":
                    continue
                sums.append(f"{sha256_file(path)}  {path.name}")
            (target_dir / "SOURCESUMS.sha256").write_text(
                "\n".join(sums) + ("\n" if sums else ""), encoding="utf-8"
            )
            recovered.append(lock)
    return recovered


def compact_copy(output_dir: Path) -> None:
    compact = output_dir / "compact"
    if compact.exists():
        shutil.rmtree(compact)
    compact.mkdir(parents=True)
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(output_dir)
        if relative.parts and relative.parts[0] == "compact":
            continue
        if relative.parts and relative.parts[0] == "sources":
            if path.suffix not in {".json", ".dsc", ".sha256"}:
                continue
            if path.name in {"download-attempts.json", "cdx-evidence.json"}:
                continue
        destination = compact / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gooroom-inrelease", type=Path, required=True)
    parser.add_argument("--hancom-inrelease", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    repositories = (
        Repository(
            "gooroom",
            "http://update.hancomgooroom.com/gooroom",
            "gooroom-3.0",
            args.gooroom_inrelease,
        ),
        Repository(
            "hancom",
            "http://update.hancomgooroom.com/hancom",
            "hancom-3.0",
            args.hancom_inrelease,
        ),
    )

    repository_results: list[dict[str, Any]] = []
    for repository in repositories:
        repository_results.append(
            recover_repository(repository, args.output_dir, args.timeout)
        )
    source_results = recover_sources(repository_results, args.output_dir, args.timeout)

    matched = {(row["source"], row["version"]) for row in source_results}
    unresolved_without_stanza = [
        {"source": target.source, "version": target.version}
        for target in TARGETS
        if (target.source, target.version) not in matched
    ]
    summary = {
        "schema": 1,
        "generated_at": now(),
        "policy": "exact-signed-release-source-index-and-member-checksums",
        "target_count": len(TARGETS),
        "repository_count": len(repository_results),
        "resolved_index_count": sum(
            row["index_status"] == "resolved-byte-identical"
            for row in repository_results
        ),
        "exact_stanza_count": sum(
            len(row["exact_stanzas"]) for row in repository_results
        ),
        "resolved_source_count": sum(row["status"] == "resolved" for row in source_results),
        "unresolved_source_count": sum(
            row["status"] != "resolved" for row in source_results
        )
        + len(unresolved_without_stanza),
        "repositories": [
            {key: value for key, value in row.items() if key not in {"exact_stanzas", "center"}}
            for row in repository_results
        ],
        "sources": source_results,
        "unresolved_without_stanza": unresolved_without_stanza,
        "promotion_allowed": False,
    }
    write_json(args.output_dir / "summary.json", summary)
    compact_copy(args.output_dir)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["resolved_index_count"] > 0 else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as error:
        print(f"recovery error: {error}", file=sys.stderr)
        raise SystemExit(2)
