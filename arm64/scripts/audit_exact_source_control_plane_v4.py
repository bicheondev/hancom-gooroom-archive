#!/usr/bin/env python3
"""Exception-safe entry point for exact-source control-plane audit v3."""

from __future__ import annotations

from typing import Any

import audit_exact_source_control_plane_v3 as base


def safe_error(
    errors: list[dict[str, Any]], path: Any, reason: str, **details: Any
) -> None:
    details.pop("path", None)
    errors.append({"path": str(path), "reason": reason, **details})


if __name__ == "__main__":
    base.error = safe_error
    raise SystemExit(base.main())
