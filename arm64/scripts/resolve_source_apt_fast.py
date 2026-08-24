#!/usr/bin/env python3
"""Run the exact APT source resolver with bounded index-probe latency.

Dead historical repositories can otherwise consume minutes per nonexistent
Sources variant.  Index probes use one short attempt, while source payloads
retain long retries because they may legitimately be large.  All acceptance
rules remain those of ``resolve_source_apt``: exact source/version, per-file
SHA-256 and size, successful .dsc extraction, and matching changelog identity.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request

import resolve_source_apt as resolver

USER_AGENT = "hancom-gooroom-arm64-source-lock-fast/1"


def bounded_request(url: str, retries: int = 3) -> bytes:
    path = urllib.parse.urlsplit(url).path
    is_index = path.endswith(("/Sources", "/Sources.xz", "/Sources.gz", "/Sources.bz2"))
    attempts = 1 if is_index else max(1, retries)
    timeout = 15 if is_index else 900
    error: Exception | None = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT},
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = exc
            if attempt + 1 < attempts:
                time.sleep(min(8, 2**attempt))
    assert error is not None
    raise error


def main() -> int:
    resolver.request_bytes = bounded_request
    return resolver.main()


if __name__ == "__main__":
    raise SystemExit(main())
