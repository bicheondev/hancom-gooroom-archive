#!/usr/bin/env python3
"""Bounded-latency archival candidate resolver.

This composes the short APT index probes from ``resolve_source_apt_fast`` with
the non-promoting Internet Archive fallback from
``resolve_source_apt_archival``.  Acceptance remains an archival candidate when
any capture is used.
"""

from __future__ import annotations

import resolve_source_apt as direct
import resolve_source_apt_archival as archival
import resolve_source_apt_fast as fast


def main() -> int:
    archival.ORIGINAL_REQUEST = fast.bounded_request
    direct.request_bytes = archival.request_with_archival_fallback
    result = direct.main()
    archival.rewrite_as_candidates(archival.output_dir_from_argv())
    return result


if __name__ == "__main__":
    raise SystemExit(main())
