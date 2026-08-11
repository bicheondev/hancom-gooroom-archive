#!/usr/bin/env python3
"""Recover exact Debian source archives from byte-locked APT Sources indices.

Input indices must already have been accepted by
``recover_locked_apt_source_indices.py`` against the SHA-256 values embedded in
the reference ISO's clearsigned InRelease files. This stage accepts a source
archive member only when its byte length and SHA-256 match the exact Sources
stanza. It emits both compact authority evidence and a user handoff manifest
for anything that cannot be reached from CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

USER_AGENT = "hancom-gooroom-arm64-source-archive-recovery/1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_MEMBER_BYTES = 1024 * 1024 * 1024


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
TARGETS_BY_KEY = {(target.source, target.version): target for target in TARGETS}


@dataclass(frozen=True)
class Member:
    filename: str
    size: int
    sha256: str


class RecoveryError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+~-]", "_", value)


def parse_block(lines: list[str]) -> tuple[dict[str, str], str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in lines:
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields, "\n".join(lines) + "\n"


def iter_deb822(text: str) -> Iterator[tuple[dict[str, str], str]]:
    block: list[str] = []
    for line in text.splitlines():
        if line.strip():
            block.append(line)
        elif block:
            yield parse_block(block)
            block = []
    if block:
        yield parse_block(block)


def strip_clearsign(text: str) -> str:
    if not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        return text
    separator = text.find("\n\n")
    if separator < 0:
        raise RecoveryError("malformed clearsigned document")
    text = text[separator + 2 :]
    signature = text.find("\n-----BEGIN PGP SIGNATURE-----")
    if signature >= 0:
        text = text[:signature]
    return text.replace("\n- -", "\n-")


def parse_members(value: str) -> list[Member]:
    members: list[Member] = []
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        digest, size_text, filename = parts
        if not HEX64.fullmatch(digest):
            continue
        try:
            size = int(size_text)
        except ValueError:
            continue
        members.append(Member(filename=filename, size=size, sha256=digest))
    return members


def repository_results(index_root: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    for result_path in sorted(index_root.glob("*/result.json")):
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result.get("status") != "resolved-byte-identical":
            continue
        sources_path = result_path.parent / "Sources"
        if not sources_path.is_file():
            raise RecoveryError(f"resolved result lacks Sources: {result_path}")
        yield sources_path, result


def release_date(result: dict[str, Any]) -> datetime:
    value = str((result.get("release_fields") or {}).get("Date", ""))
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return datetime(2023, 8, 1, tzinfo=timezone.utc)


def scheme_variants(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    variants = [url]
    if parsed.scheme in {"http", "https"}:
        other = "https" if parsed.scheme == "http" else "http"
        variants.append(
            urllib.parse.urlunsplit(
                (other, parsed.netloc, parsed.path, parsed.query, parsed.fragment)
            )
        )
    return list(dict.fromkeys(variants))


def request_json(url: str, timeout: int) -> tuple[Any | None, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json,text/plain,*/*",
            "Accept-Encoding": "identity",
        },
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(8 * 1024 * 1024 + 1)
            if len(body) > 8 * 1024 * 1024:
                raise RecoveryError("JSON response exceeded limit")
            value = json.loads(body.decode("utf-8"))
            return value, {
                "url": url,
                "status": int(getattr(response, "status", 200)),
                "final_url": response.geturl(),
                "size": len(body),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
    except Exception as error:
        status = error.code if isinstance(error, urllib.error.HTTPError) else None
        return None, {
            "url": url,
            "status": status,
            "error": repr(error),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }


def cdx_candidates(original: str, timeout: int) -> tuple[list[str], dict[str, Any]]:
    query = urllib.parse.urlencode(
        {
            "url": original,
            "output": "json",
            "fl": "timestamp,original,statuscode,digest,length",
            "filter": "statuscode:200",
            "from": "2022",
            "to": "2024",
            "collapse": "digest",
            "limit": "120",
        }
    )
    endpoint = "https://web.archive.org/cdx/search/cdx?" + query
    value, evidence = request_json(endpoint, timeout)
    candidates: list[str] = []
    if isinstance(value, list) and value and isinstance(value[0], list):
        header = value[0]
        for row in value[1:]:
            if not isinstance(row, list) or len(row) != len(header):
                continue
            item = dict(zip(header, row))
            timestamp = str(item.get("timestamp", ""))
            archived = str(item.get("original", ""))
            if timestamp and archived:
                candidates.append(
                    f"https://web.archive.org/web/{timestamp}id_/{archived}"
                )
    evidence["candidate_count"] = len(candidates)
    evidence["original_url"] = original
    return candidates, evidence


def timestamp_guesses(original: str, date: datetime) -> list[str]:
    candidates: list[str] = []
    for day_offset in range(-2, 3):
        day = date + timedelta(days=day_offset)
        for hour in (0, 6, 12, 18, date.hour):
            stamp = day.replace(
                hour=hour, minute=0, second=0, microsecond=0
            ).strftime("%Y%m%d%H%M%S")
            candidates.append(
                f"https://web.archive.org/web/{stamp}id_/{original}"
            )
    return list(dict.fromkeys(candidates))


def download_candidate(
    url: str, destination: Path, member: Member, timeout: int
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/octet-stream,*/*",
            "Accept-Encoding": "identity",
        },
    )
    started = time.monotonic()
    temporary = destination.with_suffix(destination.suffix + ".part")
    temporary.parent.mkdir(parents=True, exist_ok=True)
    temporary.unlink(missing_ok=True)
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            with temporary.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > member.size or size > MAX_MEMBER_BYTES:
                        raise RecoveryError(
                            f"response too large: {size} > expected {member.size}"
                        )
                    digest.update(chunk)
                    output.write(chunk)
            actual = digest.hexdigest()
            verified = size == member.size and actual == member.sha256
            if verified:
                os.replace(temporary, destination)
            else:
                temporary.unlink(missing_ok=True)
            return {
                "url": url,
                "status": int(getattr(response, "status", 200)),
                "final_url": response.geturl(),
                "size": size,
                "sha256": actual,
                "expected_size": member.size,
                "expected_sha256": member.sha256,
                "verified": verified,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
    except Exception as error:
        temporary.unlink(missing_ok=True)
        status = error.code if isinstance(error, urllib.error.HTTPError) else None
        return {
            "url": url,
            "status": status,
            "error": repr(error),
            "expected_size": member.size,
            "expected_sha256": member.sha256,
            "verified": False,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }


def recover_member(
    canonical_url: str,
    destination: Path,
    member: Member,
    date: datetime,
    timeout: int,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[str] = []
    cdx_evidence: list[dict[str, Any]] = []
    for variant in scheme_variants(canonical_url):
        candidates.append(variant)
        discovered, evidence = cdx_candidates(variant, timeout)
        cdx_evidence.append(evidence)
        candidates.extend(discovered)
        candidates.extend(timestamp_guesses(variant, date))
    attempts: list[dict[str, Any]] = []
    for candidate in dict.fromkeys(candidates):
        attempt = download_candidate(candidate, destination, member, timeout)
        attempts.append(attempt)
        if attempt.get("verified") is True:
            return attempt, attempts, cdx_evidence
    return None, attempts, cdx_evidence


def dsc_fields(path: Path) -> tuple[dict[str, str], str]:
    text = strip_clearsign(path.read_text(encoding="utf-8", errors="strict"))
    fields, raw = parse_block(text.splitlines())
    return fields, raw


def validate_dsc(
    dsc: Path,
    source: str,
    version: str,
    members: list[Member],
) -> dict[str, Any]:
    fields, raw = dsc_fields(dsc)
    if fields.get("Source") != source:
        raise RecoveryError(
            f"DSC Source mismatch: {fields.get('Source')!r} != {source!r}"
        )
    if fields.get("Version") != version:
        raise RecoveryError(
            f"DSC Version mismatch: {fields.get('Version')!r} != {version!r}"
        )
    dsc_members = {item.filename: item for item in parse_members(fields.get("Checksums-Sha256", ""))}
    expected_non_dsc = {item.filename: item for item in members if item.filename != dsc.name}
    if set(dsc_members) != set(expected_non_dsc):
        raise RecoveryError(
            f"DSC member set mismatch: {sorted(dsc_members)} != {sorted(expected_non_dsc)}"
        )
    for filename, expected in expected_non_dsc.items():
        actual = dsc_members[filename]
        if actual.size != expected.size or actual.sha256 != expected.sha256:
            raise RecoveryError(f"DSC checksum mismatch for {filename}")
    return {
        "source": fields.get("Source"),
        "version": fields.get("Version"),
        "format": fields.get("Format"),
        "maintainer": fields.get("Maintainer"),
        "binary": fields.get("Binary"),
        "architecture": fields.get("Architecture"),
        "vcs_git": fields.get("Vcs-Git"),
        "vcs_browser": fields.get("Vcs-Browser"),
        "raw_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "member_count": len(dsc_members),
    }


def extract_source(dsc: Path, destination: Path) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(destination, ignore_errors=True)
    process = subprocess.run(
        ["dpkg-source", "-x", str(dsc), str(destination)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    result: dict[str, Any] = {
        "exit_code": process.returncode,
        "stdout_tail": process.stdout[-8000:],
        "stderr_tail": process.stderr[-8000:],
        "extracted": process.returncode == 0 and destination.is_dir(),
    }
    if result["extracted"]:
        changelog = destination / "debian/changelog"
        result["changelog_head"] = (
            changelog.read_text(encoding="utf-8", errors="replace").splitlines()[0]
            if changelog.is_file()
            else ""
        )
        result["source_tree_file_count"] = sum(
            path.is_file() for path in destination.rglob("*")
        )
    return result


def compact_result(value: dict[str, Any]) -> dict[str, Any]:
    copy = dict(value)
    copy.pop("attempts", None)
    copy.pop("cdx_evidence", None)
    return copy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()

    if not args.index_root.is_dir():
        raise SystemExit(f"source-index recovery root is missing: {args.index_root}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archives_root = args.output_dir / "archives"
    compact_root = args.output_dir / "compact"
    detail_root = args.output_dir / "details"
    extracted_root = args.output_dir / "extracted"

    index_summary_path = args.index_root / "summary.json"
    index_summary = (
        json.loads(index_summary_path.read_text(encoding="utf-8"))
        if index_summary_path.is_file()
        else {}
    )

    stanzas: dict[tuple[str, str], dict[str, Any]] = {}
    origins: dict[tuple[str, str], dict[str, Any]] = {}
    for sources_path, repository in repository_results(args.index_root):
        text = sources_path.read_text(encoding="utf-8", errors="strict")
        for fields, raw in iter_deb822(text):
            key = (fields.get("Package", ""), fields.get("Version", ""))
            if key not in TARGETS_BY_KEY:
                continue
            if key in stanzas:
                raise RecoveryError(f"duplicate exact source stanza: {key}")
            members = parse_members(fields.get("Checksums-Sha256", ""))
            if not members or not any(member.filename.endswith(".dsc") for member in members):
                raise RecoveryError(f"exact source stanza lacks DSC: {key}")
            stanzas[key] = {
                "fields": fields,
                "raw": raw,
                "members": members,
            }
            origins[key] = {
                "repository": repository.get("repository"),
                "base_url": repository.get("base_url"),
                "suite": repository.get("suite"),
                "inrelease_path": repository.get("inrelease_path"),
                "inrelease_sha256": repository.get("inrelease_sha256"),
                "selected_index": repository.get("selected"),
                "release_fields": repository.get("release_fields"),
            }

    results: list[dict[str, Any]] = []
    handoff_needed: list[dict[str, Any]] = []
    recovered_count = 0

    for target in TARGETS:
        key = (target.source, target.version)
        stanza = stanzas.get(key)
        if stanza is None:
            result = {
                "source": target.source,
                "version": target.version,
                "status": "blocked-missing-exact-source-stanza",
                "authority": None,
                "members": [],
                "promotion_allowed": False,
            }
            results.append(result)
            handoff_needed.append(
                {
                    "kind": "exact-source-index",
                    "source": target.source,
                    "version": target.version,
                    "reason": "No byte-identical InRelease-locked Sources stanza was recovered in CI.",
                }
            )
            continue

        fields = stanza["fields"]
        members: list[Member] = stanza["members"]
        origin = origins[key]
        base_url = str(origin["base_url"]).rstrip("/")
        directory = str(fields.get("Directory", "")).strip("/")
        if not base_url or not directory:
            raise RecoveryError(f"source stanza lacks repository location: {key}")

        target_dir = archives_root / safe_component(target.source) / safe_component(target.version)
        target_dir.mkdir(parents=True, exist_ok=True)
        member_rows: list[dict[str, Any]] = []
        all_members = True
        for member in members:
            canonical = f"{base_url}/{directory}/{member.filename}"
            destination = target_dir / member.filename
            selected, attempts, cdx = recover_member(
                canonical,
                destination,
                member,
                release_date(origin),
                args.timeout,
            )
            row = {
                "filename": member.filename,
                "size": member.size,
                "sha256": member.sha256,
                "canonical_url": canonical,
                "status": "recovered-and-verified" if selected else "unresolved",
                "selected": selected,
                "attempts": attempts,
                "cdx_evidence": cdx,
            }
            member_rows.append(row)
            if selected is None:
                all_members = False
                handoff_needed.append(
                    {
                        "kind": "source-archive-member",
                        "source": target.source,
                        "version": target.version,
                        "filename": member.filename,
                        "size": member.size,
                        "sha256": member.sha256,
                        "canonical_url": canonical,
                        "reason": "No byte-identical copy was reachable from GitHub Actions.",
                    }
                )

        result: dict[str, Any] = {
            "source": target.source,
            "version": target.version,
            "status": "blocked-unresolved-source-members",
            "origin": origin,
            "directory": directory,
            "source_stanza_sha256": hashlib.sha256(
                stanza["raw"].encode("utf-8")
            ).hexdigest(),
            "members": member_rows,
            "dsc": None,
            "extraction": None,
            "promotion_allowed": False,
        }

        if all_members:
            dsc_candidates = [member for member in members if member.filename.endswith(".dsc")]
            if len(dsc_candidates) != 1:
                raise RecoveryError(f"exactly one DSC is required: {key}")
            dsc_path = target_dir / dsc_candidates[0].filename
            dsc = validate_dsc(dsc_path, target.source, target.version, members)
            extraction = extract_source(
                dsc_path,
                extracted_root / safe_component(target.source) / safe_component(target.version),
            )
            result["dsc"] = dsc
            result["extraction"] = extraction
            if extraction.get("extracted") is True:
                result["status"] = "recovered-exact-source-archive"
                result["promotion_allowed"] = True
                recovered_count += 1
            else:
                result["status"] = "blocked-dpkg-source-extraction-failed"
                handoff_needed.append(
                    {
                        "kind": "source-validation",
                        "source": target.source,
                        "version": target.version,
                        "reason": "All exact members were recovered but dpkg-source extraction failed.",
                    }
                )

        detail_path = detail_root / safe_component(target.source) / safe_component(target.version) / "result.json"
        write_json(detail_path, result)
        results.append(result)

    index_handoff: list[dict[str, Any]] = []
    for repository in index_summary.get("repositories", []):
        if repository.get("status") == "resolved-byte-identical":
            continue
        base_url = str(repository.get("base_url", "")).rstrip("/")
        suite = str(repository.get("suite", ""))
        for relative, lock in (repository.get("locked_indices") or {}).items():
            if not relative.endswith("Sources.gz"):
                continue
            index_handoff.append(
                {
                    "kind": "locked-source-index",
                    "repository": repository.get("repository"),
                    "url": f"{base_url}/dists/{suite}/{relative}",
                    "filename": f"{repository.get('repository')}-Sources.gz",
                    "size": lock.get("size"),
                    "sha256": lock.get("sha256"),
                }
            )

    handoff = {
        "schema": 1,
        "generated_at": utc_now(),
        "policy": "user-may-supply-bytes-only-when-size-and-sha256-match-locked-authority",
        "instructions": [
            "Do not rename or modify downloaded source members before hashing.",
            "A version string alone is not accepted; byte size and SHA-256 must both match.",
            "Return all recovered files together with `sha256sum` and byte-size output.",
        ],
        "locked_source_indices_needed": index_handoff,
        "items_needed": handoff_needed,
    }
    summary = {
        "schema": 1,
        "generated_at": utc_now(),
        "policy": "exact-InRelease-index-plus-exact-Sources-member-checksums",
        "target_count": len(TARGETS),
        "exact_source_stanza_count": len(stanzas),
        "recovered_exact_source_archive_count": recovered_count,
        "blocked_target_count": len(TARGETS) - recovered_count,
        "handoff_item_count": len(index_handoff) + len(handoff_needed),
        "source_archive_build_ready": recovered_count > 0,
        "all_source_archives_ready": recovered_count == len(TARGETS),
        "results": [compact_result(result) for result in results],
    }

    write_json(args.output_dir / "summary.json", summary)
    write_json(args.output_dir / "user-handoff.json", handoff)
    write_json(compact_root / "summary.json", summary)
    write_json(compact_root / "user-handoff.json", handoff)
    for result in results:
        compact_path = (
            compact_root
            / safe_component(result["source"])
            / safe_component(result["version"])
            / "authority.json"
        )
        write_json(compact_path, compact_result(result))

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
