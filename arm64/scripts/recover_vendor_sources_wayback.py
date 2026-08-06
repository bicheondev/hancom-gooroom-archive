#!/usr/bin/env python3
"""Recover exact official vendor source packages from Internet Archive captures.

Only the original Hancom/Gooroom pool URL inferred from the ISO-preserved
binary index is queried. A source is accepted when a captured .dsc has a valid
signature under an ISO-extracted Gooroom keyring, declares the exact Source and
Version, and every source file downloads with the signed size and SHA-256.
Conflicting valid captures fail closed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import re
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
REPLAY_PREFIX = "https://web.archive.org/web"
USER_AGENT = "hancom-gooroom-arm64-source-recovery/1 (+exact-version-audit)"
PRINT_LOCK = threading.Lock()


def parse_deb822(text: str) -> Iterable[dict[str, str]]:
    stanza: dict[str, str] = {}
    key: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if stanza:
                yield stanza
                stanza = {}
                key = None
            continue
        if line[0].isspace():
            if key is not None:
                stanza[key] += "\n" + line[1:]
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stanza[key] = value.lstrip()
    if stanza:
        yield stanza


def clearsigned_payload(text: str) -> str:
    marker = "-----BEGIN PGP SIGNED MESSAGE-----"
    signature = "-----BEGIN PGP SIGNATURE-----"
    if not text.startswith(marker):
        return text
    body_start = text.find("\n\n")
    body_end = text.find(signature)
    if body_start < 0 or body_end < 0:
        return text
    lines = text[body_start + 2 : body_end].rstrip("\n").splitlines()
    return "\n".join(line[2:] if line.startswith("- ") else line for line in lines) + "\n"


def parse_checksums(value: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not value:
        return rows
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        digest, size, filename = parts
        if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            continue
        try:
            parsed_size = int(size)
        except ValueError:
            continue
        rows.append(
            {
                "sha256": digest.lower(),
                "size": parsed_size,
                "name": filename,
            }
        )
    return rows


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request_bytes(url: str, *, timeout: int = 120, attempts: int = 5) -> bytes:
    error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(request, timeout=timeout) as response:
                return response.read()
        except HTTPError as exception:
            error = exception
            if exception.code in {400, 401, 403, 404}:
                raise
        except URLError as exception:
            error = exception
        if attempt < attempts:
            time.sleep(min(30, 2 ** (attempt - 1)))
    assert error is not None
    raise error


def scheme_variants(url: str) -> list[str]:
    split = urlsplit(url)
    variants = []
    for scheme in (split.scheme, "http", "https"):
        candidate = urlunsplit((scheme, split.netloc, split.path, split.query, ""))
        if candidate not in variants:
            variants.append(candidate)
    return variants


def cdx_captures(url: str, *, limit: int = 50) -> tuple[list[dict[str, str]], str | None]:
    params = {
        "url": url,
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest,length",
        "filter": "statuscode:200",
        "collapse": "digest",
        "limit": str(limit),
        "from": "2000",
    }
    endpoint = CDX_ENDPOINT + "?" + urlencode(params)
    try:
        data = request_bytes(endpoint, timeout=120, attempts=4)
    except Exception as exception:
        return [], f"{type(exception).__name__}: {exception}"
    try:
        document = json.loads(data.decode("utf-8", "replace"))
    except Exception as exception:
        return [], f"invalid CDX JSON: {type(exception).__name__}: {exception}"
    if not isinstance(document, list) or not document:
        return [], None
    header = document[0]
    if not isinstance(header, list):
        return [], "invalid CDX header"
    rows = []
    for values in document[1:]:
        if not isinstance(values, list):
            continue
        padded = values + [""] * (len(header) - len(values))
        row = dict(zip(header, padded))
        timestamp = row.get("timestamp", "")
        if re.fullmatch(r"[0-9]{14}", timestamp):
            rows.append(row)
    rows.sort(key=lambda row: row["timestamp"], reverse=True)
    return rows, None


def replay_url(timestamp: str, original: str) -> str:
    return f"{REPLAY_PREFIX}/{timestamp}id_/{original}"


def verify_signature(data: bytes, keyrings: list[Path]) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile(suffix=".dsc") as handle:
        handle.write(data)
        handle.flush()
        command = ["gpgv"]
        for keyring in keyrings:
            command.extend(["--keyring", str(keyring)])
        command.append(handle.name)
        process = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    diagnostic = (process.stdout + "\n" + process.stderr).strip()
    return process.returncode == 0, diagnostic


def fetch_file_for_capture(
    original_candidates: list[str], timestamp: str, expected: dict[str, Any]
) -> tuple[bytes | None, dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    for original in original_candidates:
        direct = replay_url(timestamp, original)
        try:
            data = request_bytes(direct, timeout=240, attempts=4)
        except Exception as exception:
            attempts.append(
                {
                    "url": direct,
                    "error": f"{type(exception).__name__}: {exception}",
                }
            )
        else:
            actual = {"size": len(data), "sha256": sha256_bytes(data)}
            attempts.append({"url": direct, **actual})
            if actual == {
                "size": int(expected["size"]),
                "sha256": expected["sha256"],
            }:
                return data, {"method": "same-timestamp-replay", "url": direct, "attempts": attempts}

    # The .dsc and source payload may have been captured on different crawls.
    # Query exact source file URLs and accept only a hash-identical capture.
    for original in original_candidates:
        captures, error = cdx_captures(original, limit=30)
        if error:
            attempts.append({"url": original, "cdx_error": error})
        for capture in captures:
            url = replay_url(capture["timestamp"], capture.get("original") or original)
            try:
                data = request_bytes(url, timeout=240, attempts=4)
            except Exception as exception:
                attempts.append(
                    {"url": url, "error": f"{type(exception).__name__}: {exception}"}
                )
                continue
            actual = {"size": len(data), "sha256": sha256_bytes(data)}
            attempts.append({"url": url, **actual})
            if actual == {
                "size": int(expected["size"]),
                "sha256": expected["sha256"],
            }:
                return data, {
                    "method": "independent-cdx-capture",
                    "url": url,
                    "timestamp": capture["timestamp"],
                    "attempts": attempts,
                }
    return None, {"method": "not-found", "attempts": attempts}


def source_identity(candidate: dict[str, Any]) -> tuple[Any, ...]:
    return (
        candidate["dsc_sha256"],
        tuple(
            sorted(
                (row["name"], int(row["size"]), row["sha256"])
                for row in candidate["files"]
            )
        ),
    )


def recover_row(
    row: dict[str, Any], keyrings: list[Path], sources_dir: Path
) -> dict[str, Any]:
    result = {
        **row,
        "wayback_status": "missing-exact-archive-source",
        "wayback_candidates": [],
        "wayback_errors": [],
        "wayback_selected": None,
    }
    valid: list[dict[str, Any]] = []
    for pool in row.get("pool_candidates", []):
        base = str(pool.get("base_url", "")).rstrip("/")
        directory = str(pool.get("directory", "")).strip("/")
        dsc_name = row.get("dsc_name")
        if not base or not directory or not dsc_name:
            continue
        original_dsc_urls: list[str] = []
        for base_variant in scheme_variants(base):
            original = f"{base_variant}/{directory}/{quote(dsc_name, safe='+~._-')}"
            if original not in original_dsc_urls:
                original_dsc_urls.append(original)

        captures: list[dict[str, str]] = []
        for original in original_dsc_urls:
            found, error = cdx_captures(original)
            if error:
                result["wayback_errors"].append(
                    {"url": original, "stage": "dsc-cdx", "error": error}
                )
            captures.extend(found)
        unique_captures: dict[tuple[str, str], dict[str, str]] = {}
        for capture in captures:
            key = (capture["timestamp"], capture.get("original", ""))
            unique_captures[key] = capture

        for capture in sorted(
            unique_captures.values(), key=lambda item: item["timestamp"], reverse=True
        ):
            original = capture.get("original") or original_dsc_urls[0]
            url = replay_url(capture["timestamp"], original)
            try:
                dsc_data = request_bytes(url, timeout=180, attempts=4)
            except Exception as exception:
                result["wayback_errors"].append(
                    {
                        "url": url,
                        "stage": "dsc-download",
                        "error": f"{type(exception).__name__}: {exception}",
                    }
                )
                continue
            signature_valid, signature_diagnostic = verify_signature(
                dsc_data, keyrings
            )
            text = dsc_data.decode("utf-8", "replace")
            stanzas = list(parse_deb822(clearsigned_payload(text)))
            descriptor = stanzas[0] if stanzas else {}
            files = parse_checksums(descriptor.get("Checksums-Sha256"))
            candidate: dict[str, Any] = {
                "repository": pool.get("repository"),
                "suite": pool.get("suite"),
                "directory": directory,
                "capture_timestamp": capture["timestamp"],
                "capture_original": original,
                "capture_url": url,
                "dsc_name": dsc_name,
                "dsc_size": len(dsc_data),
                "dsc_sha256": sha256_bytes(dsc_data),
                "signature_valid": signature_valid,
                "signature_diagnostic": signature_diagnostic,
                "signed_source": descriptor.get("Source", ""),
                "signed_version": descriptor.get("Version", ""),
                "files": files,
                "file_captures": [],
                "complete": False,
            }
            if not (
                signature_valid
                and candidate["signed_source"] == row.get("source")
                and candidate["signed_version"] == row.get("source_version")
                and files
            ):
                result["wayback_candidates"].append(candidate)
                continue

            recovered_files: list[tuple[dict[str, Any], bytes, dict[str, Any]]] = []
            complete = True
            for expected in files:
                original_candidates: list[str] = []
                for base_variant in scheme_variants(base):
                    source_url = (
                        f"{base_variant}/{directory}/"
                        f"{quote(expected['name'], safe='+~._-')}"
                    )
                    if source_url not in original_candidates:
                        original_candidates.append(source_url)
                data, capture_evidence = fetch_file_for_capture(
                    original_candidates, capture["timestamp"], expected
                )
                candidate["file_captures"].append(
                    {"expected": expected, "capture": capture_evidence}
                )
                if data is None:
                    complete = False
                    break
                recovered_files.append((expected, data, capture_evidence))
            candidate["complete"] = complete
            result["wayback_candidates"].append(candidate)
            if not complete:
                continue

            destination = sources_dir / (
                re.sub(r"[^A-Za-z0-9_.+-]+", "_", row["source"])
                + "__"
                + candidate["dsc_sha256"][:16]
            )
            destination.mkdir(parents=True, exist_ok=True)
            (destination / dsc_name).write_bytes(dsc_data)
            for expected, data, _ in recovered_files:
                (destination / expected["name"]).write_bytes(data)
            candidate["saved_directory"] = str(destination.relative_to(sources_dir.parent))
            candidate["saved_files"] = [dsc_name] + [
                expected["name"] for expected, _, _ in recovered_files
            ]
            valid.append(candidate)

    if not valid:
        return result
    identities = {source_identity(candidate) for candidate in valid}
    if len(identities) != 1:
        result["wayback_status"] = "ambiguous-exact-archive-source"
        return result
    valid.sort(
        key=lambda candidate: (
            candidate.get("capture_timestamp", ""),
            candidate.get("capture_url", ""),
        ),
        reverse=True,
    )
    result["wayback_selected"] = valid[0]
    result["wayback_status"] = "resolved"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor-pool-lock", type=Path, required=True)
    parser.add_argument("--keyring", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    document = json.loads(args.vendor_pool_lock.read_text(encoding="utf-8"))
    rows = document.get("sources", [])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    sources_dir = args.output_dir / "sources"
    sources_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any] | None] = [None] * len(rows)

    def worker(item: tuple[int, dict[str, Any]]) -> tuple[int, dict[str, Any]]:
        index, row = item
        with PRINT_LOCK:
            print(
                f"[{index + 1}/{len(rows)}] Wayback probe "
                f"{row.get('source')} {row.get('source_version')}",
                flush=True,
            )
        recovered = recover_row(row, args.keyring, sources_dir)
        with PRINT_LOCK:
            print(
                f"[{index + 1}/{len(rows)}] {recovered['wayback_status']} "
                f"{row.get('source')}",
                flush=True,
            )
        return index, recovered

    workers = max(1, min(args.workers, len(rows) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(worker, item): item[0] for item in enumerate(rows)
        }
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            try:
                resolved_index, row = future.result()
            except Exception as exception:
                original = rows[index]
                row = {
                    **original,
                    "wayback_status": "recovery-exception",
                    "wayback_candidates": [],
                    "wayback_errors": [
                        {
                            "stage": "worker",
                            "error": f"{type(exception).__name__}: {exception}",
                        }
                    ],
                    "wayback_selected": None,
                }
                resolved_index = index
            results[resolved_index] = row

    complete_rows = [row for row in results if row is not None]
    resolved = [row for row in complete_rows if row["wayback_status"] == "resolved"]
    unresolved = [row for row in complete_rows if row["wayback_status"] != "resolved"]
    rebuild_unresolved = [
        row
        for row in unresolved
        if row.get("role") == "rebuild-arm64"
        and row.get("source") != "linux-signed-amd64"
    ]
    summary = {
        "schema": 1,
        "policy": "exact-signed-official-pool-source-from-wayback",
        "source_target_count": len(complete_rows),
        "resolved_count": len(resolved),
        "unresolved_count": len(unresolved),
        "rebuild_unresolved_count": len(rebuild_unresolved),
    }
    output = {"summary": summary, "sources": complete_rows}
    (args.output_dir / "wayback-source-lock.json").write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "resolved.json").write_text(
        json.dumps(resolved, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "unresolved.json").write_text(
        json.dumps(unresolved, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "rebuild-blockers.json").write_text(
        json.dumps(rebuild_unresolved, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not rebuild_unresolved else 2


if __name__ == "__main__":
    raise SystemExit(main())
