#!/usr/bin/env python3
"""Recover exact Debian source archives from byte-locked APT Sources indices.

Input authority is produced by recover_locked_apt_source_indices.py.  A target is
build-ready only when its exact Source/Version stanza came from a Sources index
whose bytes matched the preserved signed InRelease lock, every stanza member
matches filename/size/SHA-256, and the .dsc metadata agrees with that stanza.
No source is promoted merely because a version string or changelog matches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterator

HEX64 = re.compile(r"^[0-9a-f]{64}$")
USER_AGENT = "hancom-gooroom-arm64-exact-source-archive-recovery/1"
MAX_MEMBER_BYTES = 3 * 1024 * 1024 * 1024
TARGETS = (
    ("gnome-flashback", "3.38.0-2+grm3u2+han3u4"),
    ("gooroom-dockbarx-applet", "0.3.1+grm3u1+han3u1"),
    ("gooroom-guide", "0.5.3+grm3u1+han3u1"),
    ("gooroom-integration-applet", "0.3.1+grm3u1+han3u3"),
    ("gooroom-session-manager", "0.3.9+grm3u1+han3u2"),
    ("linux", "5.10.179-1+grm3u1"),
    ("qtbase-opensource-src", "5.15.2+dfsg-9+grm3u1"),
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON document is not an object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]", "_", value)


def strip_clearsign(text: str) -> str:
    if not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        return text
    separator = text.find("\n\n")
    if separator < 0:
        raise ValueError("malformed clear-signed document")
    body = text[separator + 2 :]
    signature = body.find("\n-----BEGIN PGP SIGNATURE-----")
    if signature >= 0:
        body = body[:signature]
    return "\n".join(
        line[2:] if line.startswith("- ") else line
        for line in body.splitlines()
    ) + "\n"


def parse_deb822(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields


def parse_sha256_members(value: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3 or not HEX64.fullmatch(parts[0]):
            continue
        try:
            size = int(parts[1])
        except ValueError:
            continue
        rows.append(
            {"sha256": parts[0], "size": size, "filename": parts[2]}
        )
    return rows


def scheme_variants(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    values = [url]
    if parsed.scheme in {"http", "https"}:
        other = "https" if parsed.scheme == "http" else "http"
        values.append(
            urllib.parse.urlunsplit(
                (other, parsed.netloc, parsed.path, parsed.query, parsed.fragment)
            )
        )
    return list(dict.fromkeys(values))


def request_small(url: str, timeout: int) -> tuple[bytes | None, dict[str, Any]]:
    started = time.monotonic()
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json,text/plain,*/*",
            "Accept-Encoding": "identity",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(8 * 1024 * 1024 + 1)
            if len(body) > 8 * 1024 * 1024:
                raise ValueError("small response exceeded 8 MiB")
            return body, {
                "url": url,
                "status": int(getattr(response, "status", 200)),
                "final_url": response.geturl(),
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


def cdx_snapshots(url: str, timeout: int) -> tuple[list[str], dict[str, Any]]:
    endpoint = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(
        {
            "url": url,
            "output": "json",
            "fl": "timestamp,original,statuscode,digest,length",
            "filter": "statuscode:200",
            "from": "2022",
            "to": "2026",
            "collapse": "digest",
            "limit": "200",
        }
    )
    body, evidence = request_small(endpoint, timeout)
    snapshots: list[str] = []
    if body is not None:
        try:
            rows = json.loads(body.decode("utf-8"))
            if isinstance(rows, list) and rows and isinstance(rows[0], list):
                header = rows[0]
                for row in rows[1:]:
                    if not isinstance(row, list) or len(row) != len(header):
                        continue
                    item = dict(zip(header, row))
                    timestamp = str(item.get("timestamp", ""))
                    original = str(item.get("original", ""))
                    if timestamp and original:
                        snapshots.append(
                            f"https://web.archive.org/web/{timestamp}id_/{original}"
                        )
        except Exception as error:
            evidence["parse_error"] = repr(error)
    evidence["snapshot_count"] = len(snapshots)
    return list(dict.fromkeys(snapshots)), evidence


def archive_guesses(url: str, release_date: datetime) -> list[str]:
    values: list[str] = []
    for offset in (-2, -1, 0, 1, 2, 7, 30, 180):
        day = release_date + timedelta(days=offset)
        for hour in (0, 12, 23):
            stamp = day.replace(
                hour=hour, minute=0, second=0, microsecond=0
            ).strftime("%Y%m%d%H%M%S")
            values.append(f"https://web.archive.org/web/{stamp}id_/{url}")
    return list(dict.fromkeys(values))


def parse_release_date(repository: dict[str, Any]) -> datetime:
    fields = repository.get("release_fields")
    if isinstance(fields, dict):
        try:
            value = parsedate_to_datetime(str(fields.get("Date", "")))
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        except Exception:
            pass
    return datetime(2023, 8, 1, tzinfo=timezone.utc)


def download_candidate(
    url: str,
    destination: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    timeout: int,
) -> dict[str, Any]:
    started = time.monotonic()
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/octet-stream,*/*",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-cache",
        },
    )
    temporary = destination.with_name(destination.name + ".part")
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
                    if size > MAX_MEMBER_BYTES or size > expected_size:
                        raise ValueError(
                            f"response exceeds expected size: {size} > {expected_size}"
                        )
                    digest.update(chunk)
                    output.write(chunk)
            actual_sha256 = digest.hexdigest()
            if size != expected_size:
                raise ValueError(f"size {size} != {expected_size}")
            if actual_sha256 != expected_sha256:
                raise ValueError(
                    f"sha256 {actual_sha256} != {expected_sha256}"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(temporary, destination)
            return {
                "url": url,
                "status": int(getattr(response, "status", 200)),
                "final_url": response.geturl(),
                "size": size,
                "sha256": actual_sha256,
                "verification": "verified",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
    except urllib.error.HTTPError as error:
        temporary.unlink(missing_ok=True)
        return {
            "url": url,
            "status": int(error.code),
            "error": str(error),
            "verification": "unresolved",
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError, ValueError) as error:
        temporary.unlink(missing_ok=True)
        return {
            "url": url,
            "status": None,
            "error": repr(error),
            "verification": "unresolved",
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }


def recover_member(
    canonical_url: str,
    destination: Path,
    member: dict[str, Any],
    *,
    release_date: datetime,
    timeout: int,
) -> tuple[bool, list[dict[str, Any]], list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    cdx_evidence: list[dict[str, Any]] = []
    direct = scheme_variants(canonical_url)
    for candidate in direct:
        attempt = download_candidate(
            candidate,
            destination,
            expected_size=int(member["size"]),
            expected_sha256=str(member["sha256"]),
            timeout=timeout,
        )
        attempts.append(attempt)
        if attempt["verification"] == "verified":
            return True, attempts, cdx_evidence

    archived: list[str] = []
    for candidate in direct:
        snapshots, evidence = cdx_snapshots(candidate, timeout)
        evidence["original_url"] = candidate
        cdx_evidence.append(evidence)
        archived.extend(snapshots)
        archived.extend(archive_guesses(candidate, release_date))

    for candidate in list(dict.fromkeys(archived)):
        attempt = download_candidate(
            candidate,
            destination,
            expected_size=int(member["size"]),
            expected_sha256=str(member["sha256"]),
            timeout=timeout,
        )
        attempts.append(attempt)
        if attempt["verification"] == "verified":
            return True, attempts, cdx_evidence
    return False, attempts, cdx_evidence


def verify_dsc(
    path: Path,
    *,
    source: str,
    version: str,
    index_members: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    fields = parse_deb822(
        strip_clearsign(path.read_text(encoding="utf-8", errors="strict"))
    )
    if fields.get("Source") != source:
        raise ValueError(f".dsc Source mismatch: {fields.get('Source')} != {source}")
    if fields.get("Version") != version:
        raise ValueError(f".dsc Version mismatch: {fields.get('Version')} != {version}")
    members = parse_sha256_members(fields.get("Checksums-Sha256", ""))
    if not members:
        raise ValueError(".dsc has no Checksums-Sha256")
    for member in members:
        indexed = index_members.get(member["filename"])
        if indexed is None:
            raise ValueError(
                f".dsc member is absent from signed Sources stanza: {member['filename']}"
            )
        if (
            int(indexed["size"]) != int(member["size"])
            or indexed["sha256"] != member["sha256"]
        ):
            raise ValueError(
                f".dsc and signed Sources disagree: {member['filename']}"
            )
    return {
        "source": fields.get("Source"),
        "version": fields.get("Version"),
        "format": fields.get("Format"),
        "members": members,
        "verified_against_signed_sources_stanza": True,
    }


def build_stanza_map(index_summary: dict[str, Any]) -> tuple[dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]], list[dict[str, Any]]]:
    found: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    ambiguities: list[dict[str, Any]] = []
    repositories = index_summary.get("repositories")
    if not isinstance(repositories, list):
        return found, ambiguities
    for repository in repositories:
        if not isinstance(repository, dict):
            continue
        stanzas = repository.get("exact_target_stanzas")
        if not isinstance(stanzas, list):
            continue
        for stanza in stanzas:
            if not isinstance(stanza, dict):
                continue
            key = (str(stanza.get("source", "")), str(stanza.get("version", "")))
            if key not in TARGETS:
                continue
            previous = found.get(key)
            if previous is None:
                found[key] = (repository, stanza)
                continue
            previous_stanza = previous[1]
            if (
                previous_stanza.get("directory") != stanza.get("directory")
                or previous_stanza.get("checksums_sha256") != stanza.get("checksums_sha256")
            ):
                ambiguities.append(
                    {
                        "source": key[0],
                        "version": key[1],
                        "repositories": [previous[0].get("repository"), repository.get("repository")],
                    }
                )
    return found, ambiguities


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=18)
    args = parser.parse_args()

    summary_path = args.index_root / "summary.json"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not summary_path.is_file():
        summary = {
            "schema": 1,
            "generated_at": now(),
            "status": "waiting-for-byte-identical-source-index-recovery",
            "target_count": len(TARGETS),
            "recovered_target_count": 0,
            "unresolved_target_count": len(TARGETS),
            "source_build_ready": False,
            "promotion_allowed": False,
        }
        write_json(args.output_dir / "summary.json", summary)
        write_json(
            args.output_dir / "USER_ACTION_REQUIRED.json",
            {
                "schema": 1,
                "required": True,
                "reason": "The exact signed Sources indices are not present yet.",
                "accepted_evidence": "Byte-identical Sources/Sources.gz or exact source members matching signed filename, size, and SHA-256.",
            },
        )
        print(json.dumps(summary, indent=2))
        return 0

    index_summary = load_json(summary_path)
    stanza_map, ambiguities = build_stanza_map(index_summary)
    compact_results: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []

    for source, version in TARGETS:
        target_dir = args.output_dir / "targets" / safe(source) / safe(version)
        files_dir = target_dir / "files"
        target_dir.mkdir(parents=True, exist_ok=True)
        authority = stanza_map.get((source, version))
        if authority is None:
            result = {
                "schema": 1,
                "source": source,
                "source_version": version,
                "status": "exact-signed-source-stanza-unavailable",
                "recovered": False,
                "source_build_ready": False,
                "promotion_allowed": False,
            }
            write_json(target_dir / "result.json", result)
            compact_results.append(result)
            unresolved.append(result)
            continue

        repository, stanza = authority
        members = parse_sha256_members(str(stanza.get("checksums_sha256", "")))
        dsc_members = [row for row in members if row["filename"].endswith(".dsc")]
        if not members or len(dsc_members) != 1:
            result = {
                "schema": 1,
                "source": source,
                "source_version": version,
                "repository": repository.get("repository"),
                "status": "signed-source-stanza-has-no-unique-dsc",
                "member_count": len(members),
                "dsc_count": len(dsc_members),
                "recovered": False,
                "source_build_ready": False,
                "promotion_allowed": False,
            }
            write_json(target_dir / "result.json", result)
            compact_results.append(result)
            unresolved.append(result)
            continue

        base_url = str(repository.get("base_url", "")).rstrip("/")
        directory = str(stanza.get("directory", "")).strip("/")
        release_date = parse_release_date(repository)
        member_results: list[dict[str, Any]] = []
        complete = True
        for member in members:
            filename = member["filename"]
            quoted = urllib.parse.quote(f"{directory}/{filename}", safe="/+~._-")
            canonical = f"{base_url}/{quoted}"
            destination = files_dir / filename
            recovered, attempts, cdx = recover_member(
                canonical,
                destination,
                member,
                release_date=release_date,
                timeout=args.timeout,
            )
            write_json(target_dir / f"{safe(filename)}.attempts.json", attempts)
            write_json(target_dir / f"{safe(filename)}.cdx-evidence.json", cdx)
            row = {
                "filename": filename,
                "size": int(member["size"]),
                "sha256": member["sha256"],
                "canonical_url": canonical,
                "status": "recovered-byte-identical" if recovered else "unresolved",
            }
            if recovered:
                row["local_path"] = destination.relative_to(args.output_dir).as_posix()
            else:
                complete = False
            member_results.append(row)

        dsc_verification: dict[str, Any]
        if complete:
            try:
                dsc_verification = verify_dsc(
                    files_dir / dsc_members[0]["filename"],
                    source=source,
                    version=version,
                    index_members={row["filename"]: row for row in members},
                )
            except Exception as error:
                complete = False
                dsc_verification = {"verified": False, "error": repr(error)}
        else:
            dsc_verification = {"verified": False, "reason": "one or more source members are missing"}

        result = {
            "schema": 1,
            "source": source,
            "source_version": version,
            "repository": repository.get("repository"),
            "base_url": base_url,
            "suite": repository.get("suite"),
            "directory": directory,
            "signed_source_stanza_sha256": hashlib.sha256(
                str(stanza.get("raw_stanza", "")).encode("utf-8")
            ).hexdigest(),
            "status": "recovered-byte-identical-source-archive-set" if complete else "incomplete",
            "recovered": complete,
            "source_build_ready": complete,
            "member_count": len(members),
            "members": member_results,
            "dsc_verification": dsc_verification,
            "promotion_allowed": False,
        }
        write_json(target_dir / "result.json", result)
        compact_results.append(result)
        if not complete:
            unresolved.append(result)

    recovered_count = sum(bool(row.get("recovered")) for row in compact_results)
    summary = {
        "schema": 1,
        "generated_at": now(),
        "policy": "byte-identical-signed-Sources-stanza-and-SHA256-locked-source-members",
        "index_authority_path": summary_path.as_posix(),
        "index_authority_sha256": sha256_file(summary_path),
        "target_count": len(TARGETS),
        "exact_stanza_count": len(stanza_map),
        "ambiguity_count": len(ambiguities),
        "recovered_target_count": recovered_count,
        "unresolved_target_count": len(TARGETS) - recovered_count,
        "results": compact_results,
        "ambiguities": ambiguities,
        "source_build_ready": recovered_count == len(TARGETS) and not ambiguities,
        "promotion_allowed": False,
    }
    write_json(args.output_dir / "summary.json", summary)
    write_json(
        args.output_dir / "USER_ACTION_REQUIRED.json",
        {
            "schema": 1,
            "required": summary["unresolved_target_count"] > 0,
            "reason": "One or more exact source archives were unavailable from the GitHub-hosted runner network.",
            "unresolved": unresolved,
            "accepted_evidence": "Only files matching the signed Sources filename, byte size, and SHA-256 are accepted.",
        },
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
