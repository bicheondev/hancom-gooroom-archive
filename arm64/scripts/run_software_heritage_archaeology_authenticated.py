#!/usr/bin/env python3
"""Run exact-source archaeology with an authenticated, retrying SWH client.

The bearer token is read only from ``SWH_BEARER_TOKEN`` and is never written to
logs or evidence. The wrapped program continues to perform all source/version
validation; this file only adds Authorization, request pacing, and 429 retry
handling around the standard-library HTTP client it already uses.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime
from pathlib import Path
from types import ModuleType
from typing import Any

TOKEN_ENV = "SWH_BEARER_TOKEN"
DEFAULT_INTERVAL = 0.75
MAX_RETRIES = 12


class AuthenticatedRateLimitedUrlopen:
    def __init__(self, original: Any, token: str) -> None:
        self.original = original
        self.token = token
        self.lock = threading.Lock()
        self.last_request = 0.0

    def _pace(self) -> None:
        with self.lock:
            delay = DEFAULT_INTERVAL - (time.monotonic() - self.last_request)
            if delay > 0:
                time.sleep(delay)
            self.last_request = time.monotonic()

    @staticmethod
    def _retry_delay(error: urllib.error.HTTPError, attempt: int) -> float:
        retry_after = error.headers.get("Retry-After") if error.headers else None
        if retry_after:
            try:
                return max(1.0, min(float(retry_after), 900.0))
            except ValueError:
                try:
                    retry_date = parsedate_to_datetime(retry_after)
                    return max(1.0, min(retry_date.timestamp() - time.time(), 900.0))
                except Exception:
                    pass
        reset = error.headers.get("X-RateLimit-Reset") if error.headers else None
        if reset:
            try:
                return max(1.0, min(float(reset) - time.time() + 2.0, 900.0))
            except ValueError:
                pass
        return min(15.0 * (2 ** attempt), 900.0)

    def __call__(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(request, str):
            request = urllib.request.Request(request)
        request.add_unredirected_header("Authorization", f"Bearer {self.token}")
        for attempt in range(MAX_RETRIES + 1):
            self._pace()
            try:
                return self.original(request, *args, **kwargs)
            except urllib.error.HTTPError as error:
                if error.code != 429 or attempt >= MAX_RETRIES:
                    raise
                delay = self._retry_delay(error, attempt)
                print(
                    f"Software Heritage rate limit reached; retrying after {delay:.1f}s "
                    f"(attempt {attempt + 1}/{MAX_RETRIES}).",
                    file=sys.stderr,
                    flush=True,
                )
                time.sleep(delay)
        raise RuntimeError("unreachable")


def load_program(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("swh_exact_source_archaeology", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"unable to load archaeology program: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        print(
            f"{TOKEN_ENV} is missing; authenticated Software Heritage archaeology was not run.",
            file=sys.stderr,
        )
        return 78

    program = Path(__file__).with_name(
        "archaeology_software_heritage_exact_sources.py"
    )
    module = load_program(program)
    original = urllib.request.urlopen
    wrapped = AuthenticatedRateLimitedUrlopen(original, token)
    urllib.request.urlopen = wrapped  # type: ignore[assignment]
    try:
        return int(module.main())
    finally:
        urllib.request.urlopen = original  # type: ignore[assignment]


if __name__ == "__main__":
    raise SystemExit(main())
