#!/usr/bin/env python3
"""Recover exact Debian source archives for unresolved Hancom Gooroom sources.

The crawler is deliberately fail-closed:

* exact Source and Version must match;
* a Sources stanza or .dsc text hit alone is never promoted;
* every member named by Checksums-Sha256 must be downloaded and verified;
* live repository and Internet Archive provenance are recorded separately;
* generated evidence never sets promotion_allowed=true.

Large recovered source members are written below --archive-dir for a workflow
artifact. Compact manifests, exact stanzas, and .dsc files are written below
--evidence-dir and may be committed as immutable authority.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

USER_AGENT = (
    "hancom-gooroom-arm64-source-recovery/1 "
    "(+https://github.com/bicheondev/hancom-gooroom-archive)"
)
MAX_INDEX_BYTES = 96 * 1024 * 1024
MAX_DSC_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 700 * 1024 * 1024
MAX_TOTAL_ARCHIVE_BYTES = 2_000 * 1024 * 1024
MAX_CDX_ROWS = 120
TIMEOUT_SECONDS = 45

SOURCE_FIELD_RE = re.compile(r"^\s*([^\s(]+)(?:\s*\(([^)]+)\))?\s*$")
PGP_BEGIN = "-----BEGIN PGP SIGNED MESSAGE-----"
PGP_SIGNATURE = "-----BEGIN PGP SIGNATURE-----"


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


@dataclass(frozen=True)
class Repository:
    base_url: str
    suite: str
    components: tuple[str, ...]
    origin: str


@dataclass
class FetchResult:
    ok: bool
    requested_url: str
    final_url: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    error: str
    elapsed_seconds: float

    def compact(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status": self.status,
            "content_type": self.headers.get("content-type", ""),
            "content_length": self.headers.get("content-length", ""),
            "last_modified": self.headers.get("last-modified", ""),
            "etag": self.headers.get("etag", ""),
            "body_size": len(self.body),
            "body_sha256": hashlib.sha256(self.body).hexdigest() if self.body else "",
            "error": self.error,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


class RecoveryError(RuntimeError):
    pass


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def safe_component(value: str) -> str:
    value = value.replace("/", "__")
    return re.sub(r"[^A-Za-z0-9.+_~=-]", "_", value)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def request_bytes(
    url: str,
    *,
    max_bytes: int,
    timeout: int = TIMEOUT_SECONDS,
    attempts: int = 2,
) -> FetchResult:
    last: FetchResult | None = None
    for attempt in range(1, attempts + 1):
        started = time.monotonic()
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Encoding": "identity",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = getattr(response, "status", None)
                final_url = response.geturl()
                headers = {key.lower(): value for key, value in response.headers.items()}
                declared = headers.get("content-length", "")
                if declared.isdigit() and int(declared) > max_bytes:
                    raise RecoveryError(
                        f"declared content length {declared} exceeds limit {max_bytes}"
                    )
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise RecoveryError(f"response exceeds limit {max_bytes}")
                return FetchResult(
                    True,
                    url,
                    final_url,
                    int(status) if status is not None else 200,
                    headers,
                    body,
                    "",
                    time.monotonic() - started,
                )
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, RecoveryError) as exc:
            status = exc.code if isinstance(exc, urllib.error.HTTPError) else None
            headers: dict[str, str] = {}
            if isinstance(exc, urllib.error.HTTPError) and exc.headers:
                headers = {key.lower(): value for key, value in exc.headers.items()}
            last = FetchResult(
                False,
                url,
                getattr(exc, "url", url),
                int(status) if status is not None else None,
                headers,
                b"",
                f"{type(exc).__name__}: {exc}",
                time.monotonic() - started,
            )
            if attempt < attempts:
                time.sleep(attempt * 1.5)
    assert last is not None
    return last


def decompress_payload(data: bytes, name: str) -> bytes:
    lower = name.lower()
    if data.startswith(b"\x1f\x8b") or lower.endswith(".gz"):
        return gzip.decompress(data)
    if data.startswith(b"\xfd7zXZ\x00") or lower.endswith((".xz", ".lzma")):
        return lzma.decompress(data)
    if data.startswith(b"BZh") or lower.endswith(".bz2"):
        return bz2.decompress(data)
    if data.startswith(b"\x04\x22\x4d\x18") or lower.endswith(".lz4"):
        return external_decompress(data, "lz4")
    if data.startswith(b"\x28\xb5\x2f\xfd") or lower.endswith((".zst", ".zstd")):
        return external_decompress(data, "zstd")
    return data


def external_decompress(data: bytes, kind: str) -> bytes:
    command = ["lz4", "-dc"] if kind == "lz4" else ["zstd", "-dc", "--quiet"]
    process = subprocess.run(
        command,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode:
        raise RecoveryError(
            f"{kind} decompressor failed ({process.returncode}): "
            + process.stderr.decode("utf-8", errors="replace")[-1000:]
        )
    return process.stdout


def parse_deb822(text: str) -> Iterator[tuple[dict[str, str], str]]:
    block: list[str] = []
    for line in text.splitlines():
        if line.strip():
            block.append(line)
            continue
        if block:
            yield parse_deb822_block(block)
            block = []
    if block:
        yield parse_deb822_block(block)


def parse_deb822_block(block: Sequence[str]) -> tuple[dict[str, str], str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in block:
        if line.startswith((" ", "\t")) and current is not None:
            fields[current] += "\n" + line
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields, "\n".join(block) + "\n"


def strip_clearsign(text: str) -> str:
    if not text.startswith(PGP_BEGIN):
        return text
    lines = text.splitlines()
    body_start = None
    for index, line in enumerate(lines):
        if index > 0 and not line.strip():
            body_start = index + 1
            break
    if body_start is None:
        return text
    body: list[str] = []
    for line in lines[body_start:]:
        if line == PGP_SIGNATURE:
            break
        if line.startswith("- "):
            line = line[2:]
        body.append(line)
    return "\n".join(body) + "\n"


def parse_checksum_field(value: str, kind: str = "sha256") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        checksum, size, filename = parts
        try:
            parsed_size = int(size)
        except ValueError:
            continue
        rows.append(
            {
                "kind": kind,
                "checksum": checksum.lower(),
                "size": parsed_size,
                "filename": filename,
            }
        )
    return rows


def exact_stanzas(payload: bytes, url: str, target: Target) -> list[dict[str, Any]]:
    text = decompress_payload(payload, url).decode("utf-8", errors="replace")
    found: list[dict[str, Any]] = []
    for fields, raw in parse_deb822(text):
        if fields.get("Package", "") != target.source:
            continue
        if fields.get("Version", "") != target.version:
            continue
        members = parse_checksum_field(fields.get("Checksums-Sha256", ""))
        found.append(
            {
                "package": fields.get("Package", ""),
                "version": fields.get("Version", ""),
                "directory": fields.get("Directory", ""),
                "format": fields.get("Format", ""),
                "architecture": fields.get("Architecture", ""),
                "binary": fields.get("Binary", ""),
                "vcs_git": fields.get("Vcs-Git", ""),
                "vcs_browser": fields.get("Vcs-Browser", ""),
                "members": members,
                "raw_stanza": raw,
            }
        )
    return found


def parse_dsc(payload: bytes) -> tuple[dict[str, str], str, list[dict[str, Any]]]:
    text = payload.decode("utf-8", errors="replace")
    unsigned = strip_clearsign(text)
    parsed = list(parse_deb822(unsigned))
    if not parsed:
        raise RecoveryError(".dsc did not contain a deb822 stanza")
    fields, raw = parsed[0]
    members = parse_checksum_field(fields.get("Checksums-Sha256", ""))
    return fields, raw, members


def version_without_epoch(version: str) -> str:
    return version.split(":", 1)[-1]


def pool_prefix(source: str) -> str:
    return source[:4] if source.startswith("lib") and len(source) >= 4 else source[0]


def dsc_filename(target: Target) -> str:
    return f"{target.source}_{version_without_epoch(target.version)}.dsc"


def quote_url_path(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    path = urllib.parse.quote(urllib.parse.unquote(parsed.path), safe="/+._~=-")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))


def normalize_base(url: str) -> str:
    return url.rstrip("/")


def parse_sources_lists(evidence_root: Path) -> list[Repository]:
    repositories: list[Repository] = []
    patterns = (
        "selected-text/*sources.list*.txt",
        "selected-text/*repositories.list*.txt",
    )
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for pattern in patterns:
        for path in sorted(evidence_root.glob(pattern)):
            for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line or not line.startswith(("deb ", "deb-src ")):
                    continue
                tokens = line.split()
                kind = tokens.pop(0)
                if tokens and tokens[0].startswith("["):
                    while tokens and not tokens[0].endswith("]"):
                        tokens.pop(0)
                    if tokens:
                        tokens.pop(0)
                if len(tokens) < 3:
                    continue
                base_url, suite, *components = tokens
                if base_url.startswith(("file:", "cdrom:")):
                    continue
                if not base_url.startswith(("http://", "https://")):
                    continue
                key = (normalize_base(base_url), suite, tuple(components))
                if key in seen:
                    continue
                seen.add(key)
                repositories.append(
                    Repository(key[0], suite, key[2], f"{path.name}:{kind}")
                )

    defaults = (
        Repository(
            "http://update.hancomgooroom.com/gooroom",
            "gooroom-3.0",
            ("main",),
            "reference-iso-inrelease-default",
        ),
        Repository(
            "https://update.hancomgooroom.com/gooroom",
            "gooroom-3.0",
            ("main",),
            "https-variant",
        ),
        Repository(
            "http://update.hancomgooroom.com/hancom",
            "hancom-3.0",
            ("main",),
            "reference-iso-inrelease-default",
        ),
        Repository(
            "https://update.hancomgooroom.com/hancom",
            "hancom-3.0",
            ("main",),
            "https-variant",
        ),
    )
    for repository in defaults:
        key = (repository.base_url, repository.suite, repository.components)
        if key not in seen:
            seen.add(key)
            repositories.append(repository)
    return repositories


def index_urls(repository: Repository) -> Iterator[str]:
    suffixes = (".xz", ".gz", ".bz2", ".lz4", ".zst", "")
    for component in repository.components:
        stem = (
            f"{normalize_base(repository.base_url)}/dists/{repository.suite}/"
            f"{component}/source/Sources"
        )
        for suffix in suffixes:
            yield stem + suffix


def cdx_query(pattern: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    params = {
        "url": pattern,
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest,length",
        "filter": "statuscode:200",
        "collapse": "digest",
        "from": "2019",
        "to": "2026",
        "limit": str(MAX_CDX_ROWS),
    }
    query_url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
    result = request_bytes(query_url, max_bytes=8 * 1024 * 1024, attempts=2)
    metadata = result.compact()
    metadata["pattern"] = pattern
    if not result.ok:
        return [], metadata
    try:
        document = json.loads(result.body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        metadata["parse_error"] = str(exc)
        return [], metadata
    if not isinstance(document, list) or not document:
        return [], metadata
    header = document[0]
    if not isinstance(header, list):
        return [], metadata
    rows: list[dict[str, str]] = []
    for values in document[1:]:
        if not isinstance(values, list):
            continue
        row = {str(key): str(value) for key, value in zip(header, values)}
        rows.append(row)
    rows.sort(key=lambda row: row.get("timestamp", ""), reverse=True)
    return rows, metadata


def wayback_url(timestamp: str, original: str) -> str:
    return f"https://web.archive.org/web/{timestamp}id_/{original}"


def repository_base_from_index(index_url: str) -> str:
    marker = "/dists/"
    position = index_url.find(marker)
    if position < 0:
        raise RecoveryError(f"cannot derive repository base from {index_url}")
    return index_url[:position]


def save_exact_stanza(
    evidence_dir: Path,
    target: Target,
    candidate_number: int,
    raw_stanza: str,
) -> str:
    relative = Path("exact-source-stanzas") / safe_component(target.source) / (
        f"{candidate_number:03d}.txt"
    )
    path = evidence_dir / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw_stanza, encoding="utf-8")
    return relative.as_posix()


def record_attempt(
    attempts: list[dict[str, Any]],
    *,
    phase: str,
    target: Target | None,
    provenance: str,
    result: FetchResult,
    extra: dict[str, Any] | None = None,
) -> None:
    row: dict[str, Any] = {
        "phase": phase,
        "source": target.source if target else "",
        "version": target.version if target else "",
        "provenance": provenance,
        **result.compact(),
    }
    if extra:
        row.update(extra)
    attempts.append(row)


def fetch_member_live(
    url: str,
    *,
    max_bytes: int,
    attempts_log: list[dict[str, Any]],
    target: Target,
    phase: str,
) -> FetchResult:
    result = request_bytes(quote_url_path(url), max_bytes=max_bytes, attempts=2)
    record_attempt(
        attempts_log,
        phase=phase,
        target=target,
        provenance="live",
        result=result,
    )
    return result


def fetch_member_wayback(
    original_url: str,
    preferred_timestamp: str,
    *,
    max_bytes: int,
    attempts_log: list[dict[str, Any]],
    cdx_log: list[dict[str, Any]],
    target: Target,
    phase: str,
) -> tuple[FetchResult | None, str]:
    candidates: list[dict[str, str]] = []
    if preferred_timestamp:
        candidates.append({"timestamp": preferred_timestamp, "original": original_url})
    rows, cdx_meta = cdx_query(original_url)
    cdx_meta.update({"phase": phase, "source": target.source, "version": target.version})
    cdx_log.append(cdx_meta)
    seen: set[tuple[str, str]] = set()
    for row in candidates + rows:
        timestamp = row.get("timestamp", "")
        original = row.get("original", original_url)
        key = (timestamp, original)
        if not timestamp or key in seen:
            continue
        seen.add(key)
        result = request_bytes(
            wayback_url(timestamp, original),
            max_bytes=max_bytes,
            attempts=2,
        )
        record_attempt(
            attempts_log,
            phase=phase,
            target=target,
            provenance="wayback",
            result=result,
            extra={"wayback_timestamp": timestamp, "wayback_original": original},
        )
        if result.ok:
            return result, timestamp
    return None, ""


def validate_payload(payload: bytes, expected: dict[str, Any]) -> tuple[bool, str]:
    if len(payload) != int(expected["size"]):
        return False, f"size mismatch {len(payload)} != {expected['size']}"
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected["checksum"].lower():
        return False, f"sha256 mismatch {actual} != {expected['checksum']}"
    return True, ""


def recover_from_source_stanza(
    *,
    target: Target,
    stanza: dict[str, Any],
    index_url: str,
    provenance: str,
    timestamp: str,
    evidence_dir: Path,
    archive_dir: Path,
    attempts_log: list[dict[str, Any]],
    cdx_log: list[dict[str, Any]],
    budget: dict[str, int],
) -> dict[str, Any]:
    directory = stanza.get("directory", "").strip("/")
    members = stanza.get("members", [])
    record: dict[str, Any] = {
        "candidate_kind": "Sources-stanza",
        "index_url": index_url,
        "provenance": provenance,
        "wayback_timestamp": timestamp,
        "directory": directory,
        "source_stanza_members": members,
        "status": "rejected",
        "reason": "",
        "files": [],
    }
    if not directory:
        record["reason"] = "exact stanza has no Directory field"
        return record
    if not members:
        record["reason"] = "exact stanza has no Checksums-Sha256 members"
        return record
    dsc_rows = [row for row in members if row["filename"].endswith(".dsc")]
    if len(dsc_rows) != 1:
        record["reason"] = f"expected one .dsc member, found {len(dsc_rows)}"
        return record

    repository_base = repository_base_from_index(index_url)
    downloaded: dict[str, bytes] = {}
    effective_timestamp = timestamp
    for expected in members:
        filename = expected["filename"]
        size = int(expected["size"])
        if size > MAX_MEMBER_BYTES:
            record["reason"] = f"member exceeds per-file limit: {filename} ({size})"
            return record
        if budget["bytes"] + size > MAX_TOTAL_ARCHIVE_BYTES:
            record["reason"] = "global archive recovery byte budget exceeded"
            return record
        original_url = f"{repository_base}/{directory}/{filename}"
        if provenance == "live":
            result = fetch_member_live(
                original_url,
                max_bytes=MAX_MEMBER_BYTES,
                attempts_log=attempts_log,
                target=target,
                phase="source-stanza-member",
            )
            member_timestamp = ""
        else:
            found, member_timestamp = fetch_member_wayback(
                original_url,
                timestamp,
                max_bytes=MAX_MEMBER_BYTES,
                attempts_log=attempts_log,
                cdx_log=cdx_log,
                target=target,
                phase="source-stanza-member",
            )
            result = found if found is not None else FetchResult(
                False,
                original_url,
                original_url,
                None,
                {},
                b"",
                "no archived member response",
                0.0,
            )
        file_record = {
            "filename": filename,
            "original_url": original_url,
            "expected_size": size,
            "expected_sha256": expected["checksum"],
            "retrieved": result.ok,
            "retrieval": result.compact(),
            "wayback_timestamp": member_timestamp,
            "verified": False,
            "verification_error": "",
        }
        if not result.ok:
            file_record["verification_error"] = result.error
            record["files"].append(file_record)
            record["reason"] = f"member retrieval failed: {filename}"
            return record
        valid, error = validate_payload(result.body, expected)
        file_record["verified"] = valid
        file_record["verification_error"] = error
        record["files"].append(file_record)
        if not valid:
            record["reason"] = f"member verification failed: {filename}: {error}"
            return record
        downloaded[filename] = result.body
        effective_timestamp = member_timestamp or effective_timestamp

    dsc_name = dsc_rows[0]["filename"]
    try:
        dsc_fields, dsc_raw, dsc_members = parse_dsc(downloaded[dsc_name])
    except RecoveryError as exc:
        record["reason"] = str(exc)
        return record
    record["dsc_source"] = dsc_fields.get("Source", "")
    record["dsc_version"] = dsc_fields.get("Version", "")
    record["dsc_members"] = dsc_members
    if dsc_fields.get("Source", "") != target.source:
        record["reason"] = "downloaded .dsc Source does not match target"
        return record
    if dsc_fields.get("Version", "") != target.version:
        record["reason"] = "downloaded .dsc Version does not match target"
        return record
    if not dsc_members:
        record["reason"] = "downloaded .dsc has no Checksums-Sha256 field"
        return record

    source_members_without_dsc = {
        row["filename"]: (row["size"], row["checksum"]) for row in members
        if not row["filename"].endswith(".dsc")
    }
    dsc_member_map = {
        row["filename"]: (row["size"], row["checksum"]) for row in dsc_members
    }
    if source_members_without_dsc != dsc_member_map:
        record["reason"] = "Sources stanza and .dsc member manifests disagree"
        return record

    destination = archive_dir / safe_component(target.source) / safe_component(target.version)
    destination.mkdir(parents=True, exist_ok=True)
    for filename, payload in downloaded.items():
        output = destination / filename
        output.write_bytes(payload)
        budget["bytes"] += len(payload)
    dsc_evidence = evidence_dir / "dsc" / safe_component(target.source) / dsc_name
    dsc_evidence.parent.mkdir(parents=True, exist_ok=True)
    dsc_evidence.write_bytes(downloaded[dsc_name])
    dsc_text = evidence_dir / "dsc-fields" / safe_component(target.source) / f"{dsc_name}.txt"
    dsc_text.parent.mkdir(parents=True, exist_ok=True)
    dsc_text.write_text(dsc_raw, encoding="utf-8")

    record["status"] = "exact-source-archive-recovered"
    record["reason"] = "all Sources and .dsc SHA-256 members verified"
    record["archive_directory"] = destination.as_posix()
    record["effective_wayback_timestamp"] = effective_timestamp
    record["archive_manifest"] = [
        {
            "filename": path.name,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(destination.iterdir())
        if path.is_file()
    ]
    return record


def recover_from_dsc_url(
    *,
    target: Target,
    dsc_url: str,
    provenance: str,
    timestamp: str,
    payload: bytes,
    evidence_dir: Path,
    archive_dir: Path,
    attempts_log: list[dict[str, Any]],
    cdx_log: list[dict[str, Any]],
    budget: dict[str, int],
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "candidate_kind": "direct-dsc",
        "dsc_url": dsc_url,
        "provenance": provenance,
        "wayback_timestamp": timestamp,
        "status": "rejected",
        "reason": "",
        "files": [],
    }
    try:
        fields, dsc_raw, members = parse_dsc(payload)
    except RecoveryError as exc:
        record["reason"] = str(exc)
        return record
    record["dsc_source"] = fields.get("Source", "")
    record["dsc_version"] = fields.get("Version", "")
    record["dsc_members"] = members
    if fields.get("Source", "") != target.source or fields.get("Version", "") != target.version:
        record["reason"] = "direct .dsc Source/Version mismatch"
        return record
    if not members:
        record["reason"] = "direct .dsc has no Checksums-Sha256 members"
        return record

    dsc_name = urllib.parse.unquote(urllib.parse.urlsplit(dsc_url).path.rsplit("/", 1)[-1])
    dsc_expected = {
        "filename": dsc_name,
        "size": len(payload),
        "checksum": hashlib.sha256(payload).hexdigest(),
    }
    all_expected = [dsc_expected, *members]
    downloaded = {dsc_name: payload}
    base_url = dsc_url.rsplit("/", 1)[0]
    for expected in members:
        filename = expected["filename"]
        size = int(expected["size"])
        if size > MAX_MEMBER_BYTES or budget["bytes"] + size > MAX_TOTAL_ARCHIVE_BYTES:
            record["reason"] = f"member exceeds recovery budget: {filename}"
            return record
        original_url = f"{base_url}/{filename}"
        if provenance == "live":
            result = fetch_member_live(
                original_url,
                max_bytes=MAX_MEMBER_BYTES,
                attempts_log=attempts_log,
                target=target,
                phase="direct-dsc-member",
            )
            member_timestamp = ""
        else:
            found, member_timestamp = fetch_member_wayback(
                original_url,
                timestamp,
                max_bytes=MAX_MEMBER_BYTES,
                attempts_log=attempts_log,
                cdx_log=cdx_log,
                target=target,
                phase="direct-dsc-member",
            )
            result = found if found is not None else FetchResult(
                False,
                original_url,
                original_url,
                None,
                {},
                b"",
                "no archived member response",
                0.0,
            )
        file_record = {
            "filename": filename,
            "original_url": original_url,
            "expected_size": size,
            "expected_sha256": expected["checksum"],
            "retrieved": result.ok,
            "retrieval": result.compact(),
            "wayback_timestamp": member_timestamp,
            "verified": False,
            "verification_error": "",
        }
        if not result.ok:
            file_record["verification_error"] = result.error
            record["files"].append(file_record)
            record["reason"] = f"member retrieval failed: {filename}"
            return record
        valid, error = validate_payload(result.body, expected)
        file_record["verified"] = valid
        file_record["verification_error"] = error
        record["files"].append(file_record)
        if not valid:
            record["reason"] = f"member verification failed: {filename}: {error}"
            return record
        downloaded[filename] = result.body

    destination = archive_dir / safe_component(target.source) / safe_component(target.version)
    destination.mkdir(parents=True, exist_ok=True)
    for filename, member_payload in downloaded.items():
        output = destination / filename
        output.write_bytes(member_payload)
        budget["bytes"] += len(member_payload)
    dsc_evidence = evidence_dir / "dsc" / safe_component(target.source) / dsc_name
    dsc_evidence.parent.mkdir(parents=True, exist_ok=True)
    dsc_evidence.write_bytes(payload)
    dsc_text = evidence_dir / "dsc-fields" / safe_component(target.source) / f"{dsc_name}.txt"
    dsc_text.parent.mkdir(parents=True, exist_ok=True)
    dsc_text.write_text(dsc_raw, encoding="utf-8")

    record["status"] = "exact-source-archive-recovered"
    record["reason"] = "direct .dsc and every SHA-256 member verified"
    record["archive_directory"] = destination.as_posix()
    record["archive_manifest"] = [
        {
            "filename": path.name,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(destination.iterdir())
        if path.is_file()
    ]
    record["files"].insert(
        0,
        {
            "filename": dsc_name,
            "original_url": dsc_url,
            "expected_size": len(payload),
            "expected_sha256": hashlib.sha256(payload).hexdigest(),
            "retrieved": True,
            "verified": True,
            "wayback_timestamp": timestamp,
        },
    )
    return record


def direct_dsc_urls(repositories: Sequence[Repository], target: Target) -> list[str]:
    filename = dsc_filename(target)
    prefix = pool_prefix(target.source)
    urls: list[str] = []
    for repository in repositories:
        for component in repository.components or ("main",):
            urls.append(
                f"{normalize_base(repository.base_url)}/pool/{component}/"
                f"{prefix}/{target.source}/{filename}"
            )
    return list(dict.fromkeys(urls))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-evidence", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--archive-dir", type=Path, required=True)
    args = parser.parse_args()

    if not args.reference_evidence.is_dir():
        raise SystemExit(f"reference evidence directory is missing: {args.reference_evidence}")
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    args.archive_dir.mkdir(parents=True, exist_ok=True)

    repositories = parse_sources_lists(args.reference_evidence)
    write_json(
        args.evidence_dir / "repository-candidates.json",
        [
            {
                "base_url": repository.base_url,
                "suite": repository.suite,
                "components": list(repository.components),
                "origin": repository.origin,
            }
            for repository in repositories
        ],
    )

    attempts_log: list[dict[str, Any]] = []
    cdx_log: list[dict[str, Any]] = []
    source_candidates: dict[str, list[dict[str, Any]]] = {
        target.source: [] for target in TARGETS
    }
    target_results: list[dict[str, Any]] = []
    budget = {"bytes": 0}

    # Phase 1: exact Sources indices from the live repositories and Wayback.
    for repository in repositories:
        if "hancomgooroom" not in repository.base_url.lower():
            continue
        for index_url in index_urls(repository):
            live = request_bytes(quote_url_path(index_url), max_bytes=MAX_INDEX_BYTES, attempts=2)
            record_attempt(
                attempts_log,
                phase="sources-index",
                target=None,
                provenance="live",
                result=live,
                extra={
                    "repository_base": repository.base_url,
                    "suite": repository.suite,
                },
            )
            if live.ok:
                for target in TARGETS:
                    try:
                        stanzas = exact_stanzas(live.body, live.final_url or index_url, target)
                    except (OSError, EOFError, lzma.LZMAError, RecoveryError) as exc:
                        attempts_log.append(
                            {
                                "phase": "sources-index-parse",
                                "source": target.source,
                                "version": target.version,
                                "provenance": "live",
                                "requested_url": index_url,
                                "ok": False,
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        )
                        stanzas = []
                    for stanza in stanzas:
                        source_candidates[target.source].append(
                            {
                                "provenance": "live",
                                "index_url": index_url,
                                "timestamp": "",
                                "stanza": stanza,
                            }
                        )

            rows, cdx_meta = cdx_query(index_url)
            cdx_meta.update(
                {
                    "phase": "sources-index",
                    "repository_base": repository.base_url,
                    "suite": repository.suite,
                }
            )
            cdx_log.append(cdx_meta)
            for row in rows[:24]:
                timestamp = row.get("timestamp", "")
                original = row.get("original", index_url)
                if not timestamp:
                    continue
                archived = request_bytes(
                    wayback_url(timestamp, original),
                    max_bytes=MAX_INDEX_BYTES,
                    attempts=2,
                )
                record_attempt(
                    attempts_log,
                    phase="sources-index",
                    target=None,
                    provenance="wayback",
                    result=archived,
                    extra={
                        "wayback_timestamp": timestamp,
                        "wayback_original": original,
                        "repository_base": repository.base_url,
                        "suite": repository.suite,
                    },
                )
                if not archived.ok:
                    continue
                any_match = False
                for target in TARGETS:
                    try:
                        stanzas = exact_stanzas(archived.body, original, target)
                    except (OSError, EOFError, lzma.LZMAError, RecoveryError) as exc:
                        attempts_log.append(
                            {
                                "phase": "sources-index-parse",
                                "source": target.source,
                                "version": target.version,
                                "provenance": "wayback",
                                "requested_url": original,
                                "wayback_timestamp": timestamp,
                                "ok": False,
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        )
                        stanzas = []
                    for stanza in stanzas:
                        any_match = True
                        source_candidates[target.source].append(
                            {
                                "provenance": "wayback",
                                "index_url": original,
                                "timestamp": timestamp,
                                "stanza": stanza,
                            }
                        )
                # Older snapshots of the same digest are redundant for exact lookup.
                if any_match:
                    break

    # Persist exact stanzas before attempting large downloads.
    compact_candidates: list[dict[str, Any]] = []
    for target in TARGETS:
        for number, candidate in enumerate(source_candidates[target.source], start=1):
            stanza = candidate["stanza"]
            stanza_file = save_exact_stanza(
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

    # Phase 2: recover complete source sets from exact Sources stanzas.
    recovered_sources: set[str] = set()
    for target in TARGETS:
        result_row: dict[str, Any] = {
            "source": target.source,
            "version": target.version,
            "status": "unresolved",
            "reason": "no exact source archive was recovered",
            "source_stanza_candidate_count": len(source_candidates[target.source]),
            "candidate_results": [],
        }
        for candidate in source_candidates[target.source][:12]:
            recovery = recover_from_source_stanza(
                target=target,
                stanza=candidate["stanza"],
                index_url=candidate["index_url"],
                provenance=candidate["provenance"],
                timestamp=candidate["timestamp"],
                evidence_dir=args.evidence_dir,
                archive_dir=args.archive_dir,
                attempts_log=attempts_log,
                cdx_log=cdx_log,
                budget=budget,
            )
            result_row["candidate_results"].append(recovery)
            if recovery["status"] == "exact-source-archive-recovered":
                result_row["status"] = recovery["status"]
                result_row["reason"] = recovery["reason"]
                result_row["selected_candidate"] = recovery
                recovered_sources.add(target.source)
                break
        target_results.append(result_row)

    # Phase 3: direct .dsc URL and broad Wayback filename recovery fallback.
    result_by_source = {row["source"]: row for row in target_results}
    for target in TARGETS:
        if target.source in recovered_sources:
            continue
        row = result_by_source[target.source]
        candidates = direct_dsc_urls(repositories, target)
        seen_dsc: set[tuple[str, str]] = set()
        for dsc_url in candidates:
            live = request_bytes(quote_url_path(dsc_url), max_bytes=MAX_DSC_BYTES, attempts=2)
            record_attempt(
                attempts_log,
                phase="direct-dsc",
                target=target,
                provenance="live",
                result=live,
            )
            if live.ok:
                recovery = recover_from_dsc_url(
                    target=target,
                    dsc_url=dsc_url,
                    provenance="live",
                    timestamp="",
                    payload=live.body,
                    evidence_dir=args.evidence_dir,
                    archive_dir=args.archive_dir,
                    attempts_log=attempts_log,
                    cdx_log=cdx_log,
                    budget=budget,
                )
                row["candidate_results"].append(recovery)
                if recovery["status"] == "exact-source-archive-recovered":
                    row["status"] = recovery["status"]
                    row["reason"] = recovery["reason"]
                    row["selected_candidate"] = recovery
                    recovered_sources.add(target.source)
                    break

            archived_rows, cdx_meta = cdx_query(dsc_url)
            cdx_meta.update(
                {"phase": "direct-dsc", "source": target.source, "version": target.version}
            )
            cdx_log.append(cdx_meta)
            for archived_row in archived_rows[:20]:
                timestamp = archived_row.get("timestamp", "")
                original = archived_row.get("original", dsc_url)
                key = (timestamp, original)
                if not timestamp or key in seen_dsc:
                    continue
                seen_dsc.add(key)
                archived = request_bytes(
                    wayback_url(timestamp, original),
                    max_bytes=MAX_DSC_BYTES,
                    attempts=2,
                )
                record_attempt(
                    attempts_log,
                    phase="direct-dsc",
                    target=target,
                    provenance="wayback",
                    result=archived,
                    extra={"wayback_timestamp": timestamp, "wayback_original": original},
                )
                if not archived.ok:
                    continue
                recovery = recover_from_dsc_url(
                    target=target,
                    dsc_url=original,
                    provenance="wayback",
                    timestamp=timestamp,
                    payload=archived.body,
                    evidence_dir=args.evidence_dir,
                    archive_dir=args.archive_dir,
                    attempts_log=attempts_log,
                    cdx_log=cdx_log,
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
        # Broad filename query catches historical pool layouts not represented by
        # the ISO's current sources.list.
        broad_patterns = (
            f"update.hancomgooroom.com/*/{dsc_filename(target)}",
            f"*.hancomgooroom.com/*/{dsc_filename(target)}",
        )
        for pattern in broad_patterns:
            archived_rows, cdx_meta = cdx_query(pattern)
            cdx_meta.update(
                {"phase": "broad-dsc", "source": target.source, "version": target.version}
            )
            cdx_log.append(cdx_meta)
            for archived_row in archived_rows[:40]:
                timestamp = archived_row.get("timestamp", "")
                original = archived_row.get("original", "")
                key = (timestamp, original)
                if not timestamp or not original or key in seen_dsc:
                    continue
                seen_dsc.add(key)
                archived = request_bytes(
                    wayback_url(timestamp, original),
                    max_bytes=MAX_DSC_BYTES,
                    attempts=2,
                )
                record_attempt(
                    attempts_log,
                    phase="broad-dsc",
                    target=target,
                    provenance="wayback",
                    result=archived,
                    extra={"wayback_timestamp": timestamp, "wayback_original": original},
                )
                if not archived.ok:
                    continue
                recovery = recover_from_dsc_url(
                    target=target,
                    dsc_url=original,
                    provenance="wayback",
                    timestamp=timestamp,
                    payload=archived.body,
                    evidence_dir=args.evidence_dir,
                    archive_dir=args.archive_dir,
                    attempts_log=attempts_log,
                    cdx_log=cdx_log,
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

    recovered_manifest: list[dict[str, Any]] = []
    for target in TARGETS:
        directory = args.archive_dir / safe_component(target.source) / safe_component(target.version)
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
                        "sha256": sha256_file(path),
                    }
                    for path in sorted(directory.iterdir())
                    if path.is_file()
                ],
            }
        )

    write_json(args.evidence_dir / "target-results.json", target_results)
    write_json(args.evidence_dir / "network-attempts.json", attempts_log)
    write_json(args.evidence_dir / "wayback-cdx-attempts.json", cdx_log)
    write_json(args.evidence_dir / "recovered-source-manifest.json", recovered_manifest)

    recovered_count = sum(
        row["status"] == "exact-source-archive-recovered" for row in target_results
    )
    exact_stanza_target_count = sum(
        bool(source_candidates[target.source]) for target in TARGETS
    )
    summary = {
        "schema": 1,
        "policy": "exact-source-version-and-all-sha256-members-required",
        "target_count": len(TARGETS),
        "repository_candidate_count": len(repositories),
        "exact_source_stanza_target_count": exact_stanza_target_count,
        "exact_source_archive_recovered_count": recovered_count,
        "unresolved_count": len(TARGETS) - recovered_count,
        "network_attempt_count": len(attempts_log),
        "wayback_cdx_query_count": len(cdx_log),
        "recovered_archive_bytes": budget["bytes"],
        "source_recovery_ready": recovered_count > 0,
        "all_targets_recovered": recovered_count == len(TARGETS),
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
