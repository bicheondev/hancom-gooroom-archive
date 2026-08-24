#!/usr/bin/env python3
"""Persistent-release-aware exact package materializer."""

from __future__ import annotations

import materialize_package_acquisition_plan as base


base.DIRECT_METHODS.add("download-release-exact")


if __name__ == "__main__":
    raise SystemExit(base.main())
