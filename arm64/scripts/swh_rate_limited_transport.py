#!/usr/bin/env python3
"""Rate-aware urllib transport for Software Heritage API archaeology."""

from __future__ import annotations

import email.utils
import time
import urllib.error
import urllib.request
from typing import Any, Callable

TRANSIENT_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})
DEFAULT_MIN_INTERVAL = 1.1
DEFAULT_MAX_RETRIES = 10
DEFAULT_MAX_RETRY_DELAY = 300.0
MAX_RECORDED_ATTEMPTS = 32


def _header(headers: Any, *names: str) -> str | None:
    if headers is None:
        return None
    for name in names:
        try:
            value = headers.get(name)
        except Exception:
            value = None
        if value is not None:
            return str(value)
    return None


def _headers_evidence(headers: Any) -> dict[str, str]:
    names = (
        "Retry-After",
        "RateLimit-Limit",
        "RateLimit-Remaining",
        "RateLimit-Reset",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "Content-Type",
    )
    return {
        name: value
        for name in names
        if (value := _header(headers, name)) is not None
    }


def _nonnegative_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _nonnegative_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


class RateAwareTransport:
    """Small urllib transport following Software Heritage rate-limit signals."""

    def __init__(
        self,
        *,
        min_interval: float = DEFAULT_MIN_INTERVAL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        max_retry_delay: float = DEFAULT_MAX_RETRY_DELAY,
        bearer_token: str | None = None,
        opener: Callable[..., Any] = urllib.request.urlopen,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ) -> None:
        if min_interval < 0:
            raise ValueError("min_interval must be non-negative")
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if max_retry_delay <= 0:
            raise ValueError("max_retry_delay must be positive")
        self.min_interval = float(min_interval)
        self.max_retries = int(max_retries)
        self.max_retry_delay = float(max_retry_delay)
        self.bearer_token = (bearer_token or "").strip() or None
        self._opener = opener
        self._sleep = sleep
        self._monotonic = monotonic
        self._wall_time = wall_time
        self._next_request_at = 0.0

        self.logical_request_count = 0
        self.http_attempt_count = 0
        self.retry_count = 0
        self.rate_limit_retry_count = 0
        self.transient_server_retry_count = 0
        self.network_retry_count = 0
        self.terminal_transient_error_count = 0
        self.total_sleep_seconds = 0.0
        self.max_observed_retry_delay_seconds = 0.0

    def _sleep_until_slot(self) -> None:
        delay = self._next_request_at - self._monotonic()
        if delay <= 0:
            return
        self._sleep(delay)
        self.total_sleep_seconds += delay

    def _reserve_interval(self, delay: float) -> None:
        delay = max(0.0, min(float(delay), self.max_retry_delay))
        self._next_request_at = max(
            self._next_request_at,
            self._monotonic() + delay,
        )
        self.max_observed_retry_delay_seconds = max(
            self.max_observed_retry_delay_seconds,
            delay,
        )

    def _retry_after_seconds(self, headers: Any) -> float | None:
        raw = _header(headers, "Retry-After")
        seconds = _nonnegative_float(raw)
        if seconds is not None:
            return seconds
        if not raw:
            return None
        try:
            parsed = email.utils.parsedate_to_datetime(raw)
        except (TypeError, ValueError, OverflowError):
            return None
        if parsed.tzinfo is None:
            return None
        return max(0.0, parsed.timestamp() - self._wall_time())

    def _reset_seconds(self, headers: Any) -> float | None:
        raw = _header(
            headers,
            "RateLimit-Reset",
            "X-RateLimit-Reset",
        )
        reset = _nonnegative_float(raw)
        if reset is None:
            return None
        return max(0.0, reset - self._wall_time())

    def _learn_success_pace(self, headers: Any) -> None:
        remaining = _nonnegative_int(
            _header(
                headers,
                "RateLimit-Remaining",
                "X-RateLimit-Remaining",
            )
        )
        reset_seconds = self._reset_seconds(headers)
        pace = self.min_interval
        if remaining == 0 and reset_seconds is not None:
            pace = max(pace, reset_seconds)
        elif remaining is not None and reset_seconds is not None:
            pace = max(pace, reset_seconds / remaining)
        self._reserve_interval(pace)

    def _retry_delay(self, headers: Any, attempt_index: int) -> float:
        signaled = [
            value
            for value in (
                self._retry_after_seconds(headers),
                self._reset_seconds(headers),
            )
            if value is not None
        ]
        exponential = max(self.min_interval, min(2.0**attempt_index, 60.0))
        return min(
            self.max_retry_delay,
            max([exponential, *signaled]),
        )

    def _request_headers(self, accept: str) -> dict[str, str]:
        headers = {
            "User-Agent": (
                "hancom-gooroom-arm64-software-heritage-archaeology/"
                "2-rate-aware"
            ),
            "Accept": accept,
            "Accept-Encoding": "identity",
        }
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers

    def _final_evidence(
        self,
        attempts: list[dict[str, Any]],
        *,
        started: float,
        terminal_transient: bool,
    ) -> dict[str, Any]:
        final = dict(attempts[-1])
        final["attempt_count"] = len(attempts)
        final["retry_count"] = len(attempts) - 1
        final["terminal_transient"] = terminal_transient
        final["retry_exhausted"] = (
            terminal_transient and len(attempts) > self.max_retries
        )
        final["total_elapsed_seconds"] = round(
            self._monotonic() - started,
            3,
        )
        final["attempts"] = attempts[-MAX_RECORDED_ATTEMPTS:]
        return final

    def request_bytes(
        self,
        url: str,
        *,
        timeout: int,
        max_bytes: int,
        accept: str,
        method: str = "GET",
    ) -> tuple[bytes | None, dict[str, Any]]:
        self.logical_request_count += 1
        logical_started = self._monotonic()
        attempts: list[dict[str, Any]] = []

        for attempt_index in range(self.max_retries + 1):
            self._sleep_until_slot()
            attempt_started = self._monotonic()
            request = urllib.request.Request(
                url,
                method=method,
                headers=self._request_headers(accept),
            )
            self.http_attempt_count += 1
            try:
                with self._opener(request, timeout=timeout) as response:
                    chunks: list[bytes] = []
                    size = 0
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > max_bytes:
                            raise ValueError(
                                f"response exceeded {max_bytes} bytes"
                            )
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    headers = getattr(response, "headers", None)
                    status = int(getattr(response, "status", 200))
                    attempt = {
                        "attempt": attempt_index + 1,
                        "url": url,
                        "status": status,
                        "final_url": response.geturl(),
                        "content_type": _header(headers, "Content-Type"),
                        "link": _header(headers, "Link"),
                        "size": len(body),
                        "headers": _headers_evidence(headers),
                        "elapsed_seconds": round(
                            self._monotonic() - attempt_started,
                            3,
                        ),
                    }
                    attempts.append(attempt)
                    self._learn_success_pace(headers)
                    return body, self._final_evidence(
                        attempts,
                        started=logical_started,
                        terminal_transient=False,
                    )
            except urllib.error.HTTPError as error:
                status = int(error.code)
                headers = getattr(error, "headers", None)
                attempt = {
                    "attempt": attempt_index + 1,
                    "url": url,
                    "status": status,
                    "error": str(error),
                    "headers": _headers_evidence(headers),
                    "elapsed_seconds": round(
                        self._monotonic() - attempt_started,
                        3,
                    ),
                }
                attempts.append(attempt)
                transient = status in TRANSIENT_HTTP_STATUSES
                if transient and attempt_index < self.max_retries:
                    delay = self._retry_delay(headers, attempt_index)
                    self._reserve_interval(delay)
                    self.retry_count += 1
                    if status == 429:
                        self.rate_limit_retry_count += 1
                    else:
                        self.transient_server_retry_count += 1
                    continue
                if transient:
                    self.terminal_transient_error_count += 1
                else:
                    self._reserve_interval(self.min_interval)
                return None, self._final_evidence(
                    attempts,
                    started=logical_started,
                    terminal_transient=transient,
                )
            except Exception as error:
                attempt = {
                    "attempt": attempt_index + 1,
                    "url": url,
                    "status": None,
                    "error": repr(error),
                    "elapsed_seconds": round(
                        self._monotonic() - attempt_started,
                        3,
                    ),
                }
                attempts.append(attempt)
                if attempt_index < self.max_retries:
                    delay = min(
                        self.max_retry_delay,
                        max(self.min_interval, min(2.0**attempt_index, 60.0)),
                    )
                    self._reserve_interval(delay)
                    self.retry_count += 1
                    self.network_retry_count += 1
                    continue
                self.terminal_transient_error_count += 1
                return None, self._final_evidence(
                    attempts,
                    started=logical_started,
                    terminal_transient=True,
                )

        raise AssertionError("bounded retry loop terminated unexpectedly")

    def summary(self) -> dict[str, Any]:
        return {
            "policy": (
                "paced-rate-limit-headers-bounded-transient-retry-"
                "fail-closed"
            ),
            "authenticated": self.bearer_token is not None,
            "min_interval_seconds": self.min_interval,
            "max_retries": self.max_retries,
            "max_retry_delay_seconds": self.max_retry_delay,
            "logical_request_count": self.logical_request_count,
            "http_attempt_count": self.http_attempt_count,
            "retry_count": self.retry_count,
            "rate_limit_retry_count": self.rate_limit_retry_count,
            "transient_server_retry_count": (
                self.transient_server_retry_count
            ),
            "network_retry_count": self.network_retry_count,
            "terminal_transient_error_count": (
                self.terminal_transient_error_count
            ),
            "total_sleep_seconds": round(self.total_sleep_seconds, 3),
            "max_observed_retry_delay_seconds": round(
                self.max_observed_retry_delay_seconds,
                3,
            ),
        }
