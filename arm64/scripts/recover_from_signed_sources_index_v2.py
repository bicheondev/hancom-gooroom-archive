#!/usr/bin/env python3
"""Wayback-capable exact signed Sources-index recovery.

This version keeps the v1 trust and output schema, while adding two narrowly
scoped compatibility layers:

* Some Gooroom InRelease files omit Suite but retain an exact Codename. After
  the original bytes pass gpgv, Codename is mirrored into the in-memory Suite
  field only for validation.
* When the original APT URL is gone, Internet Archive CDX captures are tried.
  A capture is accepted only when its bytes exactly match the size and SHA-256
  authenticated by the signed InRelease or signed Sources stanza.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, Iterator


def load_module(name: str, path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


SCRIPT_DIR = Path(__file__).resolve().parent
v1 = load_module(
    "hancom_gooroom_signed_sources_index_v1",
    SCRIPT_DIR / "recover_from_signed_sources_index_v1.py",
)
wayback = load_module(
    "hancom_gooroom_wayback_helpers",
    SCRIPT_DIR / "recover_vendor_sources_wayback.py",
)

ORIGINAL_PARSE_DEB822_BLOCKS = v1.parse_deb822_blocks
ORIGINAL_DOWNLOAD_EXACT = v1.download_exact


def compatible_deb822_blocks(text: str) -> Iterator[tuple[dict[str, str], str]]:
    for fields, raw in ORIGINAL_PARSE_DEB822_BLOCKS(text):
        if fields.get("Codename") and not fields.get("Suite"):
            fields = dict(fields)
            fields["Suite"] = fields["Codename"]
        yield fields, raw


def attempt_wayback_exact(
    url: str,
    destination: Path,
    expected_size: int,
    expected_sha256: str,
    capture: dict[str, str],
    *,
    attempts: int = 3,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    evidence: list[dict[str, Any]] = []
    expected_sha256 = expected_sha256.lower()
    for attempt in range(1, attempts + 1):
        temporary = destination.with_name(destination.name + f".wayback-{os.getpid()}.part")
        temporary.unlink(missing_ok=True)
        digest = hashlib.sha256()
        size = 0
        final_url = ""
        status_code: int | None = None
        content_type = ""
        try:
            request = urllib.request.Request(url, headers={"User-Agent": v1.USER_AGENT})
            with urllib.request.urlopen(request, timeout=300) as response, temporary.open("wb") as handle:
                status_code = getattr(response, "status", None)
                final_url = response.geturl()
                content_type = response.headers.get("Content-Type", "")
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > expected_size:
                        raise v1.RecoveryError(
                            f"Wayback replay exceeded exact expected size {expected_size}"
                        )
                    digest.update(chunk)
                    handle.write(chunk)
            actual_sha256 = digest.hexdigest()
            if size != expected_size:
                raise v1.RecoveryError(f"size {size} != {expected_size}")
            if actual_sha256 != expected_sha256:
                raise v1.RecoveryError(
                    f"sha256 {actual_sha256} != {expected_sha256}"
                )
            temporary.replace(destination)
            selected = {
                "method": "wayback-cdx-exact-hash",
                "url": url,
                "final_url": final_url or url,
                "status_code": status_code,
                "content_type": content_type,
                "attempt": attempt,
                "size": size,
                "sha256": actual_sha256,
                "verified": True,
                "capture": capture,
            }
            evidence.append(selected)
            return selected, evidence
        except urllib.error.HTTPError as error:
            temporary.unlink(missing_ok=True)
            evidence.append(
                {
                    "method": "wayback-cdx-exact-hash",
                    "url": url,
                    "attempt": attempt,
                    "status": "http-error",
                    "status_code": error.code,
                    "error": str(error),
                    "verified": False,
                    "capture": capture,
                }
            )
            if error.code in {400, 401, 403, 404}:
                break
        except Exception as error:
            temporary.unlink(missing_ok=True)
            evidence.append(
                {
                    "method": "wayback-cdx-exact-hash",
                    "url": url,
                    "attempt": attempt,
                    "status": "download-or-verification-error",
                    "actual_size": size,
                    "actual_sha256": digest.hexdigest(),
                    "error": f"{type(error).__name__}: {error}",
                    "verified": False,
                    "capture": capture,
                }
            )
        if attempt < attempts:
            time.sleep(min(16, 2 ** (attempt - 1)))
    destination.unlink(missing_ok=True)
    return None, evidence


def download_exact_with_wayback(
    urls: Iterable[str],
    destination: Path,
    expected_size: int,
    expected_sha256: str,
    *,
    attempts_per_url: int = 4,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    original_urls = list(dict.fromkeys(urls))
    selected, evidence = ORIGINAL_DOWNLOAD_EXACT(
        original_urls,
        destination,
        expected_size,
        expected_sha256,
        attempts_per_url=attempts_per_url,
    )
    if selected is not None:
        selected = dict(selected)
        selected.setdefault("method", "direct")
        return selected, evidence

    seen: set[tuple[str, str]] = set()
    for original in original_urls:
        captures, cdx_error = wayback.cdx_captures(original, limit=100)
        evidence.append(
            {
                "method": "wayback-cdx",
                "original_url": original,
                "capture_count": len(captures),
                "error": cdx_error,
            }
        )
        for capture in captures:
            timestamp = capture.get("timestamp", "")
            captured_original = capture.get("original") or original
            identity = (timestamp, captured_original)
            if identity in seen or not re.fullmatch(r"[0-9]{14}", timestamp):
                continue
            seen.add(identity)
            replay = wayback.replay_url(timestamp, captured_original)
            selected, replay_evidence = attempt_wayback_exact(
                replay,
                destination,
                expected_size,
                expected_sha256,
                capture,
            )
            evidence.extend(replay_evidence)
            if selected is not None:
                selected["original_url"] = original
                return selected, evidence

    destination.unlink(missing_ok=True)
    return None, evidence


v1.parse_deb822_blocks = compatible_deb822_blocks
v1.download_exact = download_exact_with_wayback


if __name__ == "__main__":
    try:
        raise SystemExit(v1.main())
    except v1.RecoveryError as error:
        print(f"recovery error: {error}", file=sys.stderr)
        raise SystemExit(2)
