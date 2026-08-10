#!/usr/bin/env python3
"""Recover byte-identical APT Sources indices locked by the reference ISO.

The Hancom Gooroom 3.3 ISO retained clearsigned InRelease files from July/August
2023.  Their SHA-256 sections lock the exact source indices.  This tool accepts
only byte-identical index bytes and never treats matching version text alone as
source authority.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterator

USER_AGENT = "hancom-gooroom-arm64-source-index-recovery/1"
MAX_INDEX_BYTES = 16 * 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Target:
    source: str
    version: str


TARGETS = (
    Target("gnome-flashback", "3.38.0-2+grm3u2+han3u4"),
    Target("gooroom-dockbarx-applet", "0.3.1+grm3u1+han3u1"),
    Target("gooroom-guide", "0.5.3+grm3u1+han3u1"),
    Target("gooroom-integration-applet", "0.3.1+grm3u1+han3u3"),
    Target("gooroom-session-manager", "0.3.9+grm3u1+han3u2"),
    Target("linux", "5.10.179-1+grm3u1"),
    Target("qtbase-opensource-src", "5.15.2+dfsg-9+grm3u1"),
)
TARGET_KEYS = {(item.source, item.version) for item in TARGETS}


@dataclass(frozen=True)
class Repository:
    key: str
    base_url: str
    suite: str
    inrelease: Path


@dataclass(frozen=True)
class Lock:
    path: str
    size: int
    sha256: str


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def parse_inrelease(path: Path) -> tuple[dict[str, str], dict[str, Lock]]:
    text = path.read_text(encoding="utf-8", errors="strict")
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        separator = text.find("\n\n")
        if separator < 0:
            raise ValueError(f"malformed clearsigned InRelease: {path}")
        text = text[separator + 2 :]
        signature = text.find("\n-----BEGIN PGP SIGNATURE-----")
        if signature >= 0:
            text = text[:signature]

    fields: dict[str, str] = {}
    lines = text.splitlines()
    for line in lines:
        if line in {"MD5Sum:", "SHA1:", "SHA256:", "SHA512:"}:
            break
        if ":" in line and not line.startswith((" ", "\t")):
            key, value = line.split(":", 1)
            fields[key] = value.strip()

    locks: dict[str, Lock] = {}
    active = False
    for line in lines:
        if line == "SHA256:":
            active = True
            continue
        if active and re.fullmatch(r"[A-Za-z0-9-]+:", line):
            break
        if not active:
            continue
        parts = line.split()
        if len(parts) != 3 or not HEX64.fullmatch(parts[0]):
            continue
        locks[parts[2]] = Lock(parts[2], int(parts[1]), parts[0])

    for required in ("main/source/Sources", "main/source/Sources.gz"):
        if required not in locks:
            raise ValueError(f"{path} does not lock {required}")
    return fields, locks


def request_bytes(url: str, timeout: int) -> tuple[bytes | None, dict[str, Any]]:
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
            size = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_INDEX_BYTES:
                    raise ValueError(f"response exceeded {MAX_INDEX_BYTES} bytes")
                chunks.append(chunk)
            body = b"".join(chunks)
            return body, {
                "url": url,
                "status": int(getattr(response, "status", 200)),
                "final_url": response.geturl(),
                "content_type": response.headers.get("Content-Type"),
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


def verify(body: bytes, lock: Lock) -> tuple[bool, str]:
    if len(body) != lock.size:
        return False, f"size {len(body)} != {lock.size}"
    digest = sha256_bytes(body)
    if digest != lock.sha256:
        return False, f"sha256 {digest} != {lock.sha256}"
    return True, "verified"


def scheme_variants(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    variants = [url]
    if parsed.scheme in {"http", "https"}:
        other = "https" if parsed.scheme == "http" else "http"
        variants.append(urllib.parse.urlunsplit((other, parsed.netloc, parsed.path, parsed.query, parsed.fragment)))
    return list(dict.fromkeys(variants))


def cdx_urls(original: str, timeout: int) -> tuple[list[str], dict[str, Any]]:
    query = urllib.parse.urlencode(
        {
            "url": original,
            "output": "json",
            "fl": "timestamp,original,statuscode,digest,length",
            "filter": "statuscode:200",
            "from": "2023",
            "to": "2024",
            "collapse": "digest",
            "limit": "200",
        }
    )
    endpoint = "https://web.archive.org/cdx/search/cdx?" + query
    body, evidence = request_bytes(endpoint, timeout)
    urls: list[str] = []
    if body is None:
        evidence["snapshot_count"] = 0
        return urls, evidence
    try:
        rows = json.loads(body.decode("utf-8"))
        if isinstance(rows, list) and rows and isinstance(rows[0], list):
            header = rows[0]
            for row in rows[1:]:
                if not isinstance(row, list) or len(row) != len(header):
                    continue
                item = dict(zip(header, row))
                timestamp = str(item.get("timestamp", ""))
                archived_original = str(item.get("original", ""))
                if timestamp and archived_original:
                    urls.append(f"https://web.archive.org/web/{timestamp}id_/{archived_original}")
    except Exception as error:
        evidence["parse_error"] = repr(error)
    evidence["snapshot_count"] = len(urls)
    return urls, evidence


def archive_guesses(original: str, release_date: datetime) -> list[str]:
    guesses: list[str] = []
    for offset in range(-1, 2):
        day = release_date + timedelta(days=offset)
        for hour in (0, 12, release_date.hour):
            stamp = day.replace(hour=hour, minute=0, second=0, microsecond=0).strftime("%Y%m%d%H%M%S")
            guesses.append(f"https://web.archive.org/web/{stamp}id_/{original}")
    return list(dict.fromkeys(guesses))


def candidate_urls(canonical: str, lock: Lock, release_date: datetime, timeout: int) -> tuple[list[str], list[dict[str, Any]]]:
    direct: list[str] = []
    cdx_evidence: list[dict[str, Any]] = []
    archive: list[str] = []
    for variant in scheme_variants(canonical):
        direct.append(variant)
        parsed = urllib.parse.urlsplit(variant)
        by_hash = str(Path(parsed.path).parent) + "/by-hash/SHA256/" + lock.sha256
        direct.append(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, by_hash, "", "")))
        discovered, evidence = cdx_urls(variant, timeout)
        evidence["original_url"] = variant
        cdx_evidence.append(evidence)
        archive.extend(discovered)
        archive.extend(archive_guesses(variant, release_date))
    return list(dict.fromkeys(direct + archive)), cdx_evidence


def recover(canonical: str, lock: Lock, release_date: datetime, timeout: int) -> tuple[bytes | None, dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]]]:
    candidates, cdx_evidence = candidate_urls(canonical, lock, release_date, timeout)
    attempts: list[dict[str, Any]] = []
    for candidate in candidates:
        body, attempt = request_bytes(candidate, timeout)
        valid = False
        reason = "no body"
        if body is not None:
            valid, reason = verify(body, lock)
        attempt.update({"expected_size": lock.size, "expected_sha256": lock.sha256, "verification": reason})
        attempts.append(attempt)
        if valid:
            return body, attempt, attempts, cdx_evidence
    return None, None, attempts, cdx_evidence


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


def iter_stanzas(text: str) -> Iterator[tuple[dict[str, str], str]]:
    block: list[str] = []
    for line in text.splitlines():
        if line.strip():
            block.append(line)
        elif block:
            yield parse_stanza(block)
            block = []
    if block:
        yield parse_stanza(block)


def recover_repository(repository: Repository, output: Path, timeout: int) -> dict[str, Any]:
    fields, locks = parse_inrelease(repository.inrelease)
    try:
        release_date = parsedate_to_datetime(fields.get("Date", ""))
        if release_date.tzinfo is None:
            release_date = release_date.replace(tzinfo=timezone.utc)
        release_date = release_date.astimezone(timezone.utc)
    except Exception:
        release_date = datetime(2023, 8, 1, tzinfo=timezone.utc)

    repo_dir = output / repository.key
    repo_dir.mkdir(parents=True, exist_ok=True)
    gzip_url = f"{repository.base_url}/dists/{repository.suite}/main/source/Sources.gz"
    plain_url = f"{repository.base_url}/dists/{repository.suite}/main/source/Sources"

    all_attempts: list[dict[str, Any]] = []
    all_cdx: list[dict[str, Any]] = []
    selected: dict[str, Any] | None = None
    plain: bytes | None = None

    compressed, compressed_selected, attempts, cdx = recover(gzip_url, locks["main/source/Sources.gz"], release_date, timeout)
    all_attempts.extend(attempts)
    all_cdx.extend(cdx)
    if compressed is not None:
        try:
            candidate_plain = gzip.decompress(compressed)
            valid, reason = verify(candidate_plain, locks["main/source/Sources"])
            if valid:
                plain = candidate_plain
                selected = {
                    "encoding": "gzip",
                    "url": (compressed_selected or {}).get("final_url") or (compressed_selected or {}).get("url"),
                    "compressed_size": len(compressed),
                    "compressed_sha256": sha256_bytes(compressed),
                    "plain_size": len(candidate_plain),
                    "plain_sha256": sha256_bytes(candidate_plain),
                }
                (repo_dir / "Sources.gz").write_bytes(compressed)
            else:
                all_attempts.append({"url": gzip_url, "verification": "decompressed " + reason})
        except Exception as error:
            all_attempts.append({"url": gzip_url, "verification": "decompression failed", "error": repr(error)})

    if plain is None:
        body, plain_selected, attempts, cdx = recover(plain_url, locks["main/source/Sources"], release_date, timeout)
        all_attempts.extend(attempts)
        all_cdx.extend(cdx)
        if body is not None:
            plain = body
            selected = {
                "encoding": "plain",
                "url": (plain_selected or {}).get("final_url") or (plain_selected or {}).get("url"),
                "plain_size": len(body),
                "plain_sha256": sha256_bytes(body),
            }

    stanzas: list[dict[str, Any]] = []
    if plain is not None:
        (repo_dir / "Sources").write_bytes(plain)
        for stanza_fields, raw in iter_stanzas(plain.decode("utf-8", errors="strict")):
            key = (stanza_fields.get("Package", ""), stanza_fields.get("Version", ""))
            if key not in TARGET_KEYS:
                continue
            stanzas.append(
                {
                    "source": key[0],
                    "version": key[1],
                    "directory": stanza_fields.get("Directory", ""),
                    "format": stanza_fields.get("Format", ""),
                    "binary": stanza_fields.get("Binary", ""),
                    "vcs_git": stanza_fields.get("Vcs-Git", ""),
                    "vcs_browser": stanza_fields.get("Vcs-Browser", ""),
                    "files": stanza_fields.get("Files", ""),
                    "checksums_sha1": stanza_fields.get("Checksums-Sha1", ""),
                    "checksums_sha256": stanza_fields.get("Checksums-Sha256", ""),
                    "raw_stanza": raw,
                }
            )

    result = {
        "schema": 1,
        "repository": repository.key,
        "base_url": repository.base_url,
        "suite": repository.suite,
        "inrelease_path": repository.inrelease.as_posix(),
        "inrelease_sha256": sha256_file(repository.inrelease),
        "release_fields": fields,
        "locked_indices": {
            key: {"path": value.path, "size": value.size, "sha256": value.sha256}
            for key, value in locks.items()
            if key.startswith("main/source/")
        },
        "status": "resolved-byte-identical" if plain is not None else "unresolved",
        "selected": selected,
        "exact_target_stanza_count": len(stanzas),
        "exact_target_stanzas": stanzas,
        "attempt_count": len(all_attempts),
        "cdx_query_count": len(all_cdx),
        "promotion_allowed": False,
    }
    write_json(repo_dir / "result.json", result)
    write_json(repo_dir / "attempts.json", all_attempts)
    write_json(repo_dir / "cdx-evidence.json", all_cdx)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gooroom-inrelease", type=Path, required=True)
    parser.add_argument("--hancom-inrelease", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=35)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    repositories = (
        Repository("gooroom", "http://update.hancomgooroom.com/gooroom", "gooroom-3.0", args.gooroom_inrelease),
        Repository("hancom", "http://update.hancomgooroom.com/hancom", "hancom-3.0", args.hancom_inrelease),
    )
    results = [recover_repository(repository, args.output_dir, args.timeout) for repository in repositories]
    found = {(item["source"], item["version"]) for result in results for item in result["exact_target_stanzas"]}
    summary = {
        "schema": 1,
        "generated_at": now(),
        "policy": "byte-identical-InRelease-locked-source-indices-only",
        "target_count": len(TARGETS),
        "resolved_index_count": sum(result["status"] == "resolved-byte-identical" for result in results),
        "exact_target_stanza_count": len(found),
        "unresolved_targets": [
            {"source": target.source, "version": target.version}
            for target in TARGETS
            if (target.source, target.version) not in found
        ],
        "repositories": results,
        "source_archive_recovery_allowed": bool(found),
        "promotion_allowed": False,
    }
    write_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
