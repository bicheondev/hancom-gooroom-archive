#!/usr/bin/env python3
"""Recover exact Debian source packages from the reference ISO's APT history.

Trust model
===========
The archived Hancom Gooroom 3.3 ISO is already locked by size and SHA-256.  Its
cached custom-repository InRelease files therefore act as immutable historical
metadata.  This resolver only marks a source archive as recoverable when all of
these conditions hold:

* a Sources index byte stream matches the SHA-256 and size recorded in a cached
  InRelease file from the locked ISO;
* that index contains the exact source name and exact Debian version;
* the .dsc and every source member match the SHA-256 values in the exact Sources
  stanza;
* the .dsc itself names the exact source/version and its member checksums also
  match the downloaded files; and
* no conflicting exact stanza is found.

Current repository files, guessed pool paths, changelogs, version strings, and
Wayback captures are useful discovery evidence, but none is promotable unless
it is anchored to the historical InRelease checksum chain above.
"""

from __future__ import annotations

import argparse
import bz2
import datetime as dt
import email.utils
import gzip
import hashlib
import json
import lzma
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

SCHEMA = 1
MAX_DOWNLOAD = 256 * 1024 * 1024
HTTP_TIMEOUT = 45
WAYBACK_CAPTURE_LIMIT = 24
USER_AGENT = (
    "hancom-gooroom-arm64-exact-source-recovery/1.0 "
    "(+https://github.com/bicheondev/hancom-gooroom-archive)"
)
SOURCE_INDEX_RE = re.compile(
    r"(?:^|/)source/Sources(?:\.(?:gz|xz|bz2|lz4|zst|zstd))?$", re.I
)
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]+)\s+(\d+)\s+(.+)$")
SAFE_RE = re.compile(r"[^A-Za-z0-9._+~-]")


@dataclass(frozen=True)
class RepoEntry:
    uri: str
    suite: str
    components: tuple[str, ...]
    source_file: str

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.uri).netloc.lower()

    @property
    def path(self) -> str:
        return urllib.parse.urlsplit(self.uri).path.rstrip("/")


class RecoveryError(RuntimeError):
    pass


def safe(value: str) -> str:
    return SAFE_RE.sub("_", value)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def variant_uris(uri: str) -> list[str]:
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme not in {"http", "https"}:
        return [uri.rstrip("/")]
    variants = [uri.rstrip("/")]
    alternate = "https" if parsed.scheme == "http" else "http"
    variants.append(
        urllib.parse.urlunsplit(
            (alternate, parsed.netloc, parsed.path.rstrip("/"), "", "")
        )
    )
    return list(dict.fromkeys(variants))


def parse_one_line_sources(path: Path) -> list[RepoEntry]:
    entries: list[RepoEntry] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError:
            continue
        if not tokens or tokens[0] not in {"deb", "deb-src"}:
            continue
        index = 1
        if index < len(tokens) and tokens[index].startswith("["):
            while index < len(tokens) and not tokens[index].endswith("]"):
                index += 1
            index += 1
        if len(tokens) - index < 2:
            continue
        uri = tokens[index].rstrip("/")
        suite = tokens[index + 1]
        components = tuple(tokens[index + 2 :])
        if not uri.startswith(("http://", "https://")):
            continue
        entries.append(
            RepoEntry(
                uri=uri,
                suite=suite,
                components=components,
                source_file=path.name,
            )
        )
    return entries


def load_repo_entries(evidence_dir: Path) -> list[RepoEntry]:
    selected = evidence_dir / "selected-text"
    entries: list[RepoEntry] = []
    for path in sorted(selected.glob("*sources.list*.txt")):
        entries.extend(parse_one_line_sources(path))

    # The exact custom repositories are also visible in cached APT-list names.
    # Keep these deterministic fallbacks so a cosmetically edited .list file
    # cannot hide the historical repository roots from the audit.
    entries.extend(
        [
            RepoEntry(
                "http://update.hancomgooroom.com/gooroom",
                "gooroom-3.0",
                ("main",),
                "inferred-from-cached-inrelease",
            ),
            RepoEntry(
                "http://update.hancomgooroom.com/hancom",
                "hancom-3.0",
                ("main",),
                "inferred-from-cached-inrelease",
            ),
        ]
    )

    expanded: list[RepoEntry] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for entry in entries:
        if "hancomgooroom" not in entry.host and "gooroom" not in entry.host:
            continue
        for uri in variant_uris(entry.uri):
            key = (uri, entry.suite, entry.components)
            if key in seen:
                continue
            seen.add(key)
            expanded.append(
                RepoEntry(uri, entry.suite, entry.components, entry.source_file)
            )
    return expanded


def unarmor_clearsigned(text: str) -> str:
    if "-----BEGIN PGP SIGNED MESSAGE-----" not in text:
        return text
    lines = text.splitlines()
    start = 0
    for index, line in enumerate(lines):
        if line == "-----BEGIN PGP SIGNED MESSAGE-----":
            start = index + 1
            break
    while start < len(lines) and lines[start].strip():
        start += 1
    if start < len(lines):
        start += 1
    payload: list[str] = []
    for line in lines[start:]:
        if line == "-----BEGIN PGP SIGNATURE-----":
            break
        payload.append(line[2:] if line.startswith("- ") else line)
    return "\n".join(payload) + "\n"


def parse_deb822_block(lines: Sequence[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in lines:
        if line.startswith((" ", "\t")) and current is not None:
            fields[current] += "\n" + line
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields


def iter_deb822(text: str) -> Iterator[tuple[dict[str, str], str]]:
    block: list[str] = []
    for line in text.splitlines():
        if line.strip():
            block.append(line)
        elif block:
            yield parse_deb822_block(block), "\n".join(block) + "\n"
            block = []
    if block:
        yield parse_deb822_block(block), "\n".join(block) + "\n"


def parse_release(text: str) -> dict[str, str]:
    payload = unarmor_clearsigned(text)
    first = next(iter_deb822(payload), None)
    return first[0] if first else {}


def checksum_rows(value: str, algorithm: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in value.splitlines():
        match = CHECKSUM_RE.match(line.strip())
        if not match:
            continue
        rows.append(
            {
                "algorithm": algorithm,
                "checksum": match.group(1).lower(),
                "size": int(match.group(2)),
                "path": match.group(3),
            }
        )
    return rows


def normalize_for_apt_list(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.+-]", "_", value.strip("/"))


def map_release_to_entries(
    release_file: Path, fields: dict[str, str], entries: Sequence[RepoEntry]
) -> list[RepoEntry]:
    name = release_file.name.lower()
    suite_candidates = {
        fields.get("Suite", ""),
        fields.get("Codename", ""),
    }
    suite_candidates.discard("")
    matched: list[RepoEntry] = []
    for entry in entries:
        host_token = normalize_for_apt_list(entry.host).lower()
        path_token = normalize_for_apt_list(entry.path).lower()
        suite_match = not suite_candidates or entry.suite in suite_candidates
        if host_token in name and (not path_token or path_token in name) and suite_match:
            matched.append(entry)
    if matched:
        return matched

    # Conservative filename fallback for the two locked custom origins.
    for family, suite in (("gooroom", "gooroom-3.0"), ("hancom", "hancom-3.0")):
        if f"update.hancomgooroom.com_{family}_dists_{suite}" not in name:
            continue
        for entry in entries:
            if entry.path.endswith("/" + family) and entry.suite == suite:
                matched.append(entry)
    return matched


def parse_historical_releases(
    evidence_dir: Path, entries: Sequence[RepoEntry]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    releases: list[dict[str, Any]] = []
    expectations: list[dict[str, Any]] = []
    selected = evidence_dir / "selected-text"
    for path in sorted(selected.glob("*InRelease.txt")):
        if "hancomgooroom" not in path.name.lower():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        fields = parse_release(text)
        mapped_entries = map_release_to_entries(path, fields, entries)
        sha256_entries = checksum_rows(fields.get("SHA256", ""), "sha256")
        source_rows = [row for row in sha256_entries if SOURCE_INDEX_RE.search(row["path"])]
        release = {
            "file": path.name,
            "sha256": sha256_bytes(path.read_bytes()),
            "origin": fields.get("Origin", ""),
            "label": fields.get("Label", ""),
            "suite": fields.get("Suite", ""),
            "codename": fields.get("Codename", ""),
            "date": fields.get("Date", ""),
            "valid_until": fields.get("Valid-Until", ""),
            "acquire_by_hash": fields.get("Acquire-By-Hash", ""),
            "architectures": fields.get("Architectures", ""),
            "components": fields.get("Components", ""),
            "repository_entries": [entry.__dict__ for entry in mapped_entries],
            "source_index_rows": source_rows,
        }
        releases.append(release)
        for row in source_rows:
            for entry in mapped_entries:
                expectations.append(
                    {
                        "release_file": path.name,
                        "release_date": fields.get("Date", ""),
                        "repository_uri": entry.uri,
                        "suite": entry.suite,
                        "path": row["path"],
                        "size": row["size"],
                        "sha256": row["checksum"],
                        "acquire_by_hash": fields.get("Acquire-By-Hash", ""),
                    }
                )
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for row in expectations:
        key = (row["repository_uri"], row["suite"], row["path"], row["sha256"])
        if key not in seen:
            seen.add(key)
            deduped.append(row)
    return releases, deduped


def url_join(base: str, *parts: str) -> str:
    value = base.rstrip("/") + "/"
    for part in parts:
        value = urllib.parse.urljoin(value, part.lstrip("/"))
        if not value.endswith("/") and part.endswith("/"):
            value += "/"
    return value


def download_url(url: str, destination: Path) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        },
    )
    started = dt.datetime.now(dt.timezone.utc)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            status = getattr(response, "status", 200)
            final_url = response.geturl()
            data = response.read(MAX_DOWNLOAD + 1)
            if len(data) > MAX_DOWNLOAD:
                raise RecoveryError(f"download exceeds {MAX_DOWNLOAD} bytes")
            destination.write_bytes(data)
            return {
                "url": url,
                "final_url": final_url,
                "status": status,
                "ok": 200 <= status < 300,
                "size": len(data),
                "sha256": sha256_bytes(data),
                "elapsed_seconds": round(
                    (dt.datetime.now(dt.timezone.utc) - started).total_seconds(), 3
                ),
                "error": "",
            }
    except Exception as exc:  # network evidence must be recorded, not hidden
        destination.unlink(missing_ok=True)
        status = getattr(exc, "code", None)
        return {
            "url": url,
            "final_url": "",
            "status": status,
            "ok": False,
            "size": 0,
            "sha256": "",
            "elapsed_seconds": round(
                (dt.datetime.now(dt.timezone.utc) - started).total_seconds(), 3
            ),
            "error": f"{type(exc).__name__}: {exc}",
        }


def decompressed_bytes(path: Path, source_url: str = "") -> bytes:
    data = path.read_bytes()
    lower = source_url.lower()
    if data.startswith(b"\x1f\x8b") or lower.endswith(".gz"):
        return gzip.decompress(data)
    if data.startswith(b"\xfd7zXZ\x00") or lower.endswith((".xz", ".lzma")):
        return lzma.decompress(data)
    if data.startswith(b"BZh") or lower.endswith(".bz2"):
        return bz2.decompress(data)
    if data.startswith(b"\x04\x22\x4d\x18") or lower.endswith(".lz4"):
        process = subprocess.run(
            ["lz4", "-dc", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode:
            raise RecoveryError(process.stderr.decode("utf-8", "replace")[-2000:])
        return process.stdout
    if data.startswith(b"\x28\xb5\x2f\xfd") or lower.endswith((".zst", ".zstd")):
        process = subprocess.run(
            ["zstd", "-dc", "--", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode:
            raise RecoveryError(process.stderr.decode("utf-8", "replace")[-2000:])
        return process.stdout
    return data


def by_hash_url(expectation: dict[str, Any]) -> str:
    index_path = expectation["path"]
    directory = index_path.rsplit("/", 1)[0]
    return url_join(
        expectation["repository_uri"],
        "dists/",
        expectation["suite"] + "/",
        directory + "/by-hash/SHA256/",
        expectation["sha256"],
    )


def direct_index_url(expectation: dict[str, Any]) -> str:
    return url_join(
        expectation["repository_uri"],
        "dists/",
        expectation["suite"] + "/",
        expectation["path"],
    )


def wayback_captures(url: str, work_dir: Path) -> tuple[list[dict[str, str]], dict[str, Any]]:
    query = urllib.parse.urlencode(
        {
            "url": url,
            "output": "json",
            "fl": "timestamp,original,statuscode,digest,length,mimetype",
            "filter": "statuscode:200",
            "collapse": "digest",
            "limit": str(WAYBACK_CAPTURE_LIMIT),
            "from": "2019",
            "to": "2026",
        }
    )
    cdx_url = "https://web.archive.org/cdx/search/cdx?" + query
    destination = work_dir / "cdx" / (hashlib.sha256(url.encode()).hexdigest() + ".json")
    probe = download_url(cdx_url, destination)
    rows: list[dict[str, str]] = []
    if not probe["ok"] or not destination.is_file():
        return rows, probe
    try:
        value = json.loads(destination.read_text(encoding="utf-8"))
        if not isinstance(value, list) or len(value) < 2:
            return rows, probe
        header = value[0]
        for item in value[1:]:
            if isinstance(item, list) and len(item) == len(header):
                rows.append(dict(zip(header, item)))
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return rows, probe


def fetch_matching_bytes(
    urls: Sequence[str],
    expected_sha256: str,
    expected_size: int,
    work_dir: Path,
    label: str,
    allow_wayback: bool = True,
) -> tuple[Path | None, list[dict[str, Any]]]:
    probes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)
        destination = work_dir / "objects" / safe(label) / hashlib.sha256(url.encode()).hexdigest()
        probe = download_url(url, destination)
        probe.update(
            {
                "expected_sha256": expected_sha256,
                "expected_size": expected_size,
                "checksum_match": probe["sha256"] == expected_sha256,
                "size_match": probe["size"] == expected_size,
                "retrieval": "direct",
            }
        )
        probes.append(probe)
        if probe["ok"] and probe["checksum_match"] and probe["size_match"]:
            return destination, probes

    if not allow_wayback:
        return None, probes

    for original_url in list(seen):
        captures, cdx_probe = wayback_captures(original_url, work_dir)
        cdx_probe.update(
            {
                "expected_sha256": "",
                "expected_size": 0,
                "checksum_match": False,
                "size_match": False,
                "retrieval": "wayback-cdx",
                "original_url": original_url,
            }
        )
        probes.append(cdx_probe)
        for capture in captures:
            timestamp = capture.get("timestamp", "")
            original = capture.get("original", original_url)
            if not timestamp:
                continue
            replay = f"https://web.archive.org/web/{timestamp}id_/{original}"
            destination = (
                work_dir
                / "objects"
                / safe(label)
                / hashlib.sha256(replay.encode()).hexdigest()
            )
            probe = download_url(replay, destination)
            probe.update(
                {
                    "expected_sha256": expected_sha256,
                    "expected_size": expected_size,
                    "checksum_match": probe["sha256"] == expected_sha256,
                    "size_match": probe["size"] == expected_size,
                    "retrieval": "wayback-replay",
                    "capture": capture,
                    "original_url": original_url,
                }
            )
            probes.append(probe)
            if probe["ok"] and probe["checksum_match"] and probe["size_match"]:
                return destination, probes
    return None, probes


def source_members(fields: dict[str, str]) -> list[dict[str, Any]]:
    sha_rows = checksum_rows(fields.get("Checksums-Sha256", ""), "sha256")
    if sha_rows:
        return [
            {
                "filename": row["path"],
                "size": row["size"],
                "sha256": row["checksum"],
            }
            for row in sha_rows
        ]
    return []


def dsc_payload_fields(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    payload = unarmor_clearsigned(text)
    first = next(iter_deb822(payload), None)
    return first[0] if first else {}


def normalized_source_from_dsc(fields: dict[str, str]) -> str:
    return fields.get("Source", fields.get("Package", "")).strip()


def target_manifest_key(fields: dict[str, str]) -> str:
    members = source_members(fields)
    canonical = json.dumps(
        {
            "package": fields.get("Package", ""),
            "version": fields.get("Version", ""),
            "directory": fields.get("Directory", ""),
            "members": sorted(members, key=lambda row: row["filename"]),
        },
        sort_keys=True,
    ).encode()
    return sha256_bytes(canonical)


def repository_candidates_for_stanza(
    expectation: dict[str, Any], fields: dict[str, str]
) -> list[str]:
    directory = fields.get("Directory", "").strip("/")
    if not directory:
        return []
    return [
        url_join(uri, directory + "/")
        for uri in variant_uris(expectation["repository_uri"])
    ]


def recover_stanza_members(
    target: dict[str, Any],
    fields: dict[str, str],
    expectation: dict[str, Any],
    work_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = target["source"]
    version = target["source_version"]
    members = source_members(fields)
    result: dict[str, Any] = {
        "source": source,
        "version": version,
        "directory": fields.get("Directory", ""),
        "member_count": len(members),
        "members": [],
        "dsc_validation": {},
        "complete": False,
        "reason": "",
    }
    probes: list[dict[str, Any]] = []
    if not members:
        result["reason"] = "exact Sources stanza has no SHA-256 member list"
        return result, probes

    bases = repository_candidates_for_stanza(expectation, fields)
    archive_dir = work_dir / "source-archives" / safe(source) / safe(version)
    archive_dir.mkdir(parents=True, exist_ok=True)
    downloaded_by_name: dict[str, Path] = {}
    for member in members:
        urls = [url_join(base, member["filename"]) for base in bases]
        found, member_probes = fetch_matching_bytes(
            urls,
            member["sha256"],
            member["size"],
            work_dir,
            f"source-member-{source}-{member['filename']}",
        )
        probes.extend(member_probes)
        member_result = dict(member)
        member_result["urls"] = urls
        member_result["recovered"] = found is not None
        if found is not None:
            destination = archive_dir / member["filename"]
            shutil.copy2(found, destination)
            downloaded_by_name[member["filename"]] = destination
            member_result["artifact_path"] = str(destination.relative_to(work_dir))
            member_result["verified_sha256"] = hash_file(destination)
        result["members"].append(member_result)

    dsc_rows = [row for row in members if row["filename"].endswith(".dsc")]
    if len(dsc_rows) != 1:
        result["reason"] = f"expected exactly one .dsc member, found {len(dsc_rows)}"
        return result, probes
    dsc_name = dsc_rows[0]["filename"]
    dsc_path = downloaded_by_name.get(dsc_name)
    if dsc_path is None:
        result["reason"] = "exact .dsc was not recovered"
        return result, probes

    dsc_fields = dsc_payload_fields(dsc_path)
    dsc_source = normalized_source_from_dsc(dsc_fields)
    dsc_version = dsc_fields.get("Version", "")
    dsc_members = source_members(dsc_fields)
    dsc_validation = {
        "source": dsc_source,
        "version": dsc_version,
        "source_match": dsc_source == source,
        "version_match": dsc_version == version,
        "member_count": len(dsc_members),
        "members": [],
    }
    source_index_by_name = {row["filename"]: row for row in members}
    all_dsc_members_valid = True
    for row in dsc_members:
        expected = source_index_by_name.get(row["filename"])
        path = downloaded_by_name.get(row["filename"])
        valid = bool(
            expected
            and path
            and expected["sha256"] == row["sha256"]
            and expected["size"] == row["size"]
            and hash_file(path) == row["sha256"]
            and path.stat().st_size == row["size"]
        )
        all_dsc_members_valid = all_dsc_members_valid and valid
        dsc_validation["members"].append(
            {
                **row,
                "present_in_sources_stanza": expected is not None,
                "downloaded": path is not None,
                "valid": valid,
            }
        )
    dsc_validation["all_members_valid"] = all_dsc_members_valid
    result["dsc_validation"] = dsc_validation

    every_sources_member = all(row["recovered"] for row in result["members"])
    result["complete"] = bool(
        every_sources_member
        and dsc_validation["source_match"]
        and dsc_validation["version_match"]
        and dsc_members
        and all_dsc_members_valid
    )
    result["reason"] = (
        "exact source archive and all checksum chains verified"
        if result["complete"]
        else "source archive checksum chain is incomplete"
    )
    if result["complete"]:
        manifest_path = archive_dir / "RECOVERY-MANIFEST.json"
        write_json(manifest_path, result)
        lock_lines = []
        for path in sorted(archive_dir.iterdir()):
            if path.is_file() and path.name not in {"LOCKSUMS.sha256"}:
                lock_lines.append(f"{hash_file(path)}  {path.name}")
        (archive_dir / "LOCKSUMS.sha256").write_text(
            "\n".join(lock_lines) + "\n", encoding="utf-8"
        )
    return result, probes


def parse_date(value: str) -> str:
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        return ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    evidence_dir = args.evidence_dir.resolve()
    output_dir = args.output_dir.resolve()
    if not (evidence_dir / "summary.json").is_file():
        raise SystemExit(f"reference ISO evidence is missing: {evidence_dir}")
    reference_summary = json.loads(
        (evidence_dir / "summary.json").read_text(encoding="utf-8")
    )
    if not reference_summary.get("iso", {}).get("verified"):
        raise SystemExit("reference ISO evidence is not verified")
    if reference_summary.get("promotion_allowed") is not False:
        raise SystemExit("unexpected reference evidence policy state")

    target_path = evidence_dir / "target-findings.json"
    targets: list[dict[str, Any]] = json.loads(target_path.read_text(encoding="utf-8"))
    if len(targets) != 7:
        raise SystemExit(f"expected 7 source blockers, found {len(targets)}")

    output_dir.mkdir(parents=True, exist_ok=True)
    work_dir = output_dir / "work"
    work_dir.mkdir(parents=True, exist_ok=True)

    entries = load_repo_entries(evidence_dir)
    releases, expectations = parse_historical_releases(evidence_dir, entries)
    for release in releases:
        release["date_utc"] = parse_date(release.get("date", ""))

    all_probes: list[dict[str, Any]] = []
    verified_indexes: list[dict[str, Any]] = []
    exact_stanzas: dict[str, list[dict[str, Any]]] = {
        target["source"]: [] for target in targets
    }

    for expectation_index, expectation in enumerate(expectations):
        direct_urls = [direct_index_url(expectation), by_hash_url(expectation)]
        found, probes = fetch_matching_bytes(
            direct_urls,
            expectation["sha256"],
            expectation["size"],
            work_dir,
            f"historical-source-index-{expectation_index}",
        )
        all_probes.extend(probes)
        index_record = dict(expectation)
        index_record["direct_urls"] = direct_urls
        index_record["recovered"] = found is not None
        index_record["exact_stanzas"] = []
        if found is None:
            verified_indexes.append(index_record)
            continue
        try:
            plain = decompressed_bytes(found, direct_urls[0])
            text = plain.decode("utf-8", "replace")
        except Exception as exc:
            index_record["parse_error"] = f"{type(exc).__name__}: {exc}"
            verified_indexes.append(index_record)
            continue
        index_record["decompressed_size"] = len(plain)
        index_copy = output_dir / "verified-indexes" / (
            f"{expectation_index:02d}-{safe(Path(expectation['path']).name)}.txt"
        )
        index_copy.parent.mkdir(parents=True, exist_ok=True)
        index_copy.write_bytes(plain)
        index_record["verified_index_path"] = str(index_copy.relative_to(output_dir))
        for fields, raw in iter_deb822(text):
            package = fields.get("Package", "")
            version = fields.get("Version", "")
            for target in targets:
                if package != target["source"] or version != target["source_version"]:
                    continue
                record = {
                    "expectation": expectation,
                    "fields": fields,
                    "raw_stanza": raw,
                    "manifest_key": target_manifest_key(fields),
                }
                exact_stanzas[target["source"]].append(record)
                index_record["exact_stanzas"].append(
                    {
                        "source": package,
                        "version": version,
                        "manifest_key": record["manifest_key"],
                    }
                )
        verified_indexes.append(index_record)

    target_results: list[dict[str, Any]] = []
    download_manifest: list[dict[str, Any]] = []
    for target in targets:
        source = target["source"]
        candidates = exact_stanzas[source]
        manifest_keys = sorted({candidate["manifest_key"] for candidate in candidates})
        result: dict[str, Any] = {
            "source": source,
            "version": target["source_version"],
            "historically_verified_exact_stanza_count": len(candidates),
            "distinct_exact_manifest_count": len(manifest_keys),
            "status": "unresolved",
            "promotion_allowed": False,
            "reason": "no exact stanza was recovered from a historically verified Sources index",
            "recovery": None,
        }
        if len(manifest_keys) > 1:
            result["status"] = "ambiguous-exact-source-stanzas"
            result["reason"] = "conflicting exact source manifests were recovered"
            target_results.append(result)
            continue
        if not candidates:
            target_results.append(result)
            continue

        # Identical stanzas from HTTP/HTTPS or duplicate release metadata are
        # equivalent. Use the first and retain every occurrence as evidence.
        candidate = candidates[0]
        recovery, member_probes = recover_stanza_members(
            target,
            candidate["fields"],
            candidate["expectation"],
            work_dir,
        )
        all_probes.extend(member_probes)
        result["recovery"] = recovery
        if recovery["complete"]:
            result["status"] = "exact-source-archive-recovered"
            result["promotion_allowed"] = True
            result["reason"] = recovery["reason"]
            download_manifest.append(recovery)
        else:
            result["status"] = "exact-source-stanza-recovered"
            result["reason"] = recovery["reason"]
        target_results.append(result)

    promotable = [row for row in target_results if row["promotion_allowed"]]
    ambiguous = [row for row in target_results if row["status"].startswith("ambiguous")]
    stanza_only = [
        row for row in target_results if row["status"] == "exact-source-stanza-recovered"
    ]
    unresolved = [row for row in target_results if row["status"] == "unresolved"]
    recovered_indexes = [row for row in verified_indexes if row.get("recovered")]

    summary = {
        "schema": SCHEMA,
        "policy": "locked-iso-cached-inrelease-sha256-to-exact-sources-to-dsc-member-chain",
        "reference_iso": reference_summary["iso"],
        "target_count": len(targets),
        "repository_entry_count": len(entries),
        "historical_release_count": len(releases),
        "historical_source_index_expectation_count": len(expectations),
        "historically_verified_source_index_count": len(recovered_indexes),
        "network_probe_count": len(all_probes),
        "exact_source_archive_recovered_count": len(promotable),
        "exact_source_stanza_only_count": len(stanza_only),
        "ambiguous_target_count": len(ambiguous),
        "unresolved_target_count": len(unresolved),
        "promotion_allowed_target_count": len(promotable),
        "promotion_allowed_targets": [row["source"] for row in promotable],
        "automatic_promotion_performed": False,
        "all_targets_recovered": len(promotable) == len(targets),
    }

    write_json(output_dir / "summary.json", summary)
    write_json(output_dir / "repository-entries.json", [entry.__dict__ for entry in entries])
    write_json(output_dir / "historical-releases.json", releases)
    write_json(output_dir / "historical-source-index-expectations.json", expectations)
    write_json(output_dir / "verified-source-indexes.json", verified_indexes)
    write_json(output_dir / "network-probes.json", all_probes)
    write_json(output_dir / "target-results.json", target_results)
    write_json(output_dir / "download-manifest.json", download_manifest)

    lines = [
        "# Reference APT exact-source recovery",
        "",
        f"- Locked targets: **{len(targets)}**",
        f"- Cached historical InRelease files: **{len(releases)}**",
        f"- Historical source-index expectations: **{len(expectations)}**",
        f"- Source indexes recovered with exact historical SHA-256: **{len(recovered_indexes)}**",
        f"- Fully recovered exact source archives: **{len(promotable)}**",
        f"- Exact stanza only: **{len(stanza_only)}**",
        f"- Ambiguous: **{len(ambiguous)}**",
        f"- Unresolved: **{len(unresolved)}**",
        "",
        "| Source | Exact version | Result | Promotion |",
        "|---|---|---|---:|",
    ]
    for row in target_results:
        lines.append(
            f"| `{row['source']}` | `{row['version']}` | {row['status']} | "
            f"{'yes' if row['promotion_allowed'] else 'no'} |"
        )
    lines.extend(
        [
            "",
            "No source is promoted merely because a current URL, changelog, or guessed `.dsc` exists.",
            "Promotion requires the complete historical InRelease → Sources → `.dsc` → member SHA-256 chain.",
            "",
        ]
    )
    (output_dir / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")

    # Remove transient duplicate object cache. Verified indexes, manifests and
    # recovered source archives remain in the output tree/artifact.
    shutil.rmtree(work_dir / "objects", ignore_errors=True)
    shutil.rmtree(work_dir / "cdx", ignore_errors=True)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as exc:
        print(f"recovery error: {exc}", file=sys.stderr)
        raise SystemExit(2)
