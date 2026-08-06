#!/usr/bin/env python3
"""Fast fail-closed front-end for exact Wayback source recovery.

This wrapper changes only transport breadth and retry duration. Acceptance still
uses the base resolver's ISO keyring signature gate, exact Source/Version gate,
and signed payload size/SHA-256 gate. It is intended for the small current
rebuild-blocker set while the exhaustive recovery continues independently.
"""

from __future__ import annotations

import recover_vendor_sources_wayback as base


_original_request_bytes = base.request_bytes
_original_cdx_captures = base.cdx_captures


def bounded_request_bytes(
    url: str, *, timeout: int = 120, attempts: int = 5
) -> bytes:
    return _original_request_bytes(
        url,
        timeout=min(timeout, 75),
        attempts=min(attempts, 2),
    )


def bounded_cdx_captures(
    url: str, *, limit: int = 50
) -> tuple[list[dict[str, str]], str | None]:
    return _original_cdx_captures(url, limit=min(limit, 12))


base.request_bytes = bounded_request_bytes
base.cdx_captures = bounded_cdx_captures


if __name__ == "__main__":
    raise SystemExit(base.main())
