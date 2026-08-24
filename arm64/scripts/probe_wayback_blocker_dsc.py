#!/usr/bin/env python3
"""Probe Internet Archive for exact missing vendor .dsc files.

This is a discovery-only gate. A capture is interesting only when its signed
payload declares the exact Source and Version from the AMD64 ISO. It is never
promoted to build authority here; a later verifier must validate the OpenPGP
signature and every Checksums-Sha256 component.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


HEADER_RE = re.compile(r"^Source:\s*(\S+)\s*$", re.MULTILINE)
VERSION_RE = re.compile(r"^Version:\s*(\S+)\s*$", re.MULTILINE)
BEGIN_SIGNATURE = "-----BEGIN PGP SIGNATURE-----"
USER_AGENT = "hancom-gooroom-arm64-wayback-probe/1"


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def request_bytes(url: str, timeout: int = 90) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def request_json(url: str, timeout: int = 90) -> Any:
    return json.loads(request_bytes(url, timeout).decode("utf-8", "replace"))


def retry_json(url: str) -> tuple[Any | None, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for attempt in range(1, 6):
        try:
            value = request_json(url)
            attempts.append({"attempt": attempt, "status": "success"})
            return value, attempts
        except urllib.error.HTTPError as error:
            attempts.append(
                {"attempt": attempt, "status": f"http-{error.code}"}
            )
            if error.code in {400, 404}:
                break
        except Exception as error:
            attempts.append(
                {
                    "attempt": attempt,
                    "status": f"{type(error).__name__}: {error}",
                }
            )
        if attempt < 5:
            time.sleep(min(30, 2**attempt))
    return None, attempts


def signed_payload(text: str) -> str:
    if not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        return text
    start = text.find("\n\n")
    end = text.find(BEGIN_SIGNATURE)
    if start < 0 or end < 0:
        return text
    lines = text[start + 2 : end].rstrip("\n").splitlines()
    return "\n".join(line[2:] if line.startswith("- ") else line for line in lines) + "\n"


def exact_identity(data: bytes, source: str, version: str) -> dict[str, Any]:
    text = data.decode("utf-8", "replace")
    payload = signed_payload(text)
    source_match = HEADER_RE.search(payload)
    version_match = VERSION_RE.search(payload)
    declared_source = source_match.group(1) if source_match else None
    declared_version = version_match.group(1) if version_match else None
    return {
        "declared_source": declared_source,
        "declared_version": declared_version,
        "clearsigned": text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"),
        "exact": declared_source == source and declared_version == version,
    }


def dsc_urls(row: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for attempt in row.get("attempts", []):
        url = attempt.get("url")
        if isinstance(url, str) and url.endswith(".dsc"):
            urls.append(url)
    for key in ("candidate_dsc_urls", "dsc_urls"):
        for url in row.get(key, []):
            if isinstance(url, str) and url.endswith(".dsc"):
                urls.append(url)
    expanded: list[str] = []
    seen = set()
    for url in urls:
        variants = {
            url,
            url.replace("https://", "http://", 1),
            url.replace("http://", "https://", 1),
            urllib.parse.unquote(url),
        }
        for variant in variants:
            if variant not in seen:
                seen.add(variant)
                expanded.append(variant)
    return expanded


def cdx_url(original: str) -> str:
    parameters = {
        "url": original,
        "matchType": "exact",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest,length",
        "filter": "statuscode:200",
        "collapse": "digest",
        "from": "2021",
        "to": "2026",
    }
    return "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(parameters)


def parse_cdx(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) < 2:
        return []
    header = value[0]
    if not isinstance(header, list):
        return []
    records = []
    for raw in value[1:]:
        if not isinstance(raw, list) or len(raw) != len(header):
            continue
        records.append(dict(zip(header, raw)))
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unresolved", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    rows = load(args.unresolved)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    exact_capture_count = 0

    for row in rows:
        source = row["source"]
        version = row["source_version"]
        probes = []
        exact_captures = []
        for original in dsc_urls(row):
            query = cdx_url(original)
            value, attempts = retry_json(query)
            captures = parse_cdx(value)
            probe = {
                "original": original,
                "cdx_query": query,
                "query_attempts": attempts,
                "capture_count": len(captures),
                "captures": captures,
            }
            probes.append(probe)
            for capture in captures:
                timestamp = capture.get("timestamp")
                captured_original = capture.get("original") or original
                if not timestamp:
                    continue
                replay = (
                    f"https://web.archive.org/web/{timestamp}id_/"
                    f"{captured_original}"
                )
                try:
                    data = request_bytes(replay, timeout=120)
                    identity = exact_identity(data, source, version)
                    record = {
                        **capture,
                        "replay_url": replay,
                        "bytes": len(data),
                        **identity,
                    }
                    if identity["exact"]:
                        safe = re.sub(r"[^A-Za-z0-9_.+-]+", "_", source)
                        name = f"{safe}-{timestamp}.dsc"
                        path = args.output_dir / name
                        path.write_bytes(data)
                        record["saved_path"] = name
                        exact_captures.append(record)
                        exact_capture_count += 1
                except Exception as error:
                    exact_captures.append(
                        {
                            **capture,
                            "replay_url": replay,
                            "download_error": f"{type(error).__name__}: {error}",
                            "exact": False,
                        }
                    )
        results.append(
            {
                "source": source,
                "source_version": version,
                "probe_count": len(probes),
                "probes": probes,
                "exact_captures": exact_captures,
                "exact_capture_count": sum(
                    capture.get("exact") is True for capture in exact_captures
                ),
                "status": (
                    "exact-dsc-capture-found"
                    if any(capture.get("exact") is True for capture in exact_captures)
                    else "no-exact-dsc-capture"
                ),
            }
        )

    summary = {
        "schema": 1,
        "policy": "discovery-only-exact-source-version-not-build-authority",
        "target_count": len(rows),
        "targets_with_exact_capture": sum(
            row["status"] == "exact-dsc-capture-found" for row in results
        ),
        "exact_capture_count": exact_capture_count,
        "targets_without_exact_capture": sum(
            row["status"] == "no-exact-dsc-capture" for row in results
        ),
    }
    (args.output_dir / "wayback-dsc-probe.json").write_text(
        json.dumps({"summary": summary, "sources": results}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
