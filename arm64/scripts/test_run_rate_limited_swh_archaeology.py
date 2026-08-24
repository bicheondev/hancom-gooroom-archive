#!/usr/bin/env python3
"""Regression tests for the rate-aware Software Heritage archaeology launcher."""

from __future__ import annotations

import email.message
import importlib.util
import io
import json
import sys
import tempfile
import urllib.error
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).with_name(
    "run_rate_limited_swh_archaeology.py"
)
SPEC = importlib.util.spec_from_file_location(
    "run_rate_limited_swh_archaeology",
    SCRIPT,
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"could not load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class Clock:
    def __init__(self) -> None:
        self.value = 100.0
        self.wall = 1_700_000_000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.value

    def wall_time(self) -> float:
        return self.wall + (self.value - 100.0)

    def sleep(self, seconds: float) -> None:
        assert seconds >= 0
        self.sleeps.append(seconds)
        self.value += seconds


class Response:
    def __init__(
        self,
        body: bytes,
        *,
        url: str,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._stream = io.BytesIO(body)
        self._url = url
        self.status = status
        self.headers = email.message.Message()
        for name, value in (headers or {}).items():
            self.headers[name] = value

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def geturl(self) -> str:
        return self._url


class SequenceOpener:
    def __init__(self, values: list[Any]) -> None:
        self.values = list(values)
        self.requests: list[Any] = []

    def __call__(self, request: Any, timeout: int) -> Any:
        assert timeout > 0
        self.requests.append(request)
        if not self.values:
            raise AssertionError("opener sequence exhausted")
        value = self.values.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def headers(**values: str) -> email.message.Message:
    message = email.message.Message()
    for name, value in values.items():
        message[name.replace("_", "-")] = value
    return message


def http_error(
    url: str,
    status: int,
    **header_values: str,
) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url,
        status,
        f"HTTP {status}",
        headers(**header_values),
        io.BytesIO(b""),
    )


def test_429_is_retried_with_retry_after() -> None:
    clock = Clock()
    url = "https://archive.softwareheritage.org/api/1/revision/a/log/"
    opener = SequenceOpener(
        [
            http_error(url, 429, Retry_After="2"),
            Response(
                b"[]",
                url=url,
                headers={
                    "RateLimit-Limit": "60",
                    "RateLimit-Remaining": "59",
                    "RateLimit-Reset": str(int(clock.wall_time() + 60)),
                    "Content-Type": "application/json",
                },
            ),
        ]
    )
    transport = MODULE.RateAwareTransport(
        min_interval=0.0,
        max_retries=2,
        max_retry_delay=30.0,
        opener=opener,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
    )
    body, evidence = transport.request_bytes(
        url,
        timeout=10,
        max_bytes=1024,
        accept="application/json",
    )
    assert body == b"[]"
    assert evidence["status"] == 200
    assert evidence["attempt_count"] == 2
    assert evidence["terminal_transient"] is False
    assert transport.rate_limit_retry_count == 1
    assert clock.sleeps == [2.0]


def test_rate_headers_pace_following_request() -> None:
    clock = Clock()
    first = "https://archive.softwareheritage.org/api/1/first/"
    second = "https://archive.softwareheritage.org/api/1/second/"
    opener = SequenceOpener(
        [
            Response(
                b"{}",
                url=first,
                headers={
                    "RateLimit-Remaining": "30",
                    "RateLimit-Reset": str(int(clock.wall_time() + 30)),
                },
            ),
            Response(b"{}", url=second),
        ]
    )
    transport = MODULE.RateAwareTransport(
        min_interval=0.0,
        max_retries=0,
        max_retry_delay=30.0,
        opener=opener,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
    )
    transport.request_bytes(
        first,
        timeout=10,
        max_bytes=1024,
        accept="application/json",
    )
    transport.request_bytes(
        second,
        timeout=10,
        max_bytes=1024,
        accept="application/json",
    )
    assert clock.sleeps == [1.0]


def test_zero_remaining_waits_until_reset() -> None:
    clock = Clock()
    first = "https://archive.softwareheritage.org/api/1/zero/"
    second = "https://archive.softwareheritage.org/api/1/after-reset/"
    opener = SequenceOpener(
        [
            Response(
                b"{}",
                url=first,
                headers={
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(clock.wall_time() + 12)),
                },
            ),
            Response(b"{}", url=second),
        ]
    )
    transport = MODULE.RateAwareTransport(
        min_interval=0.0,
        max_retries=0,
        max_retry_delay=30.0,
        opener=opener,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
    )
    transport.request_bytes(
        first,
        timeout=10,
        max_bytes=1024,
        accept="application/json",
    )
    transport.request_bytes(
        second,
        timeout=10,
        max_bytes=1024,
        accept="application/json",
    )
    assert clock.sleeps == [12.0]


def test_exhausted_429_is_terminal_and_fail_closed() -> None:
    clock = Clock()
    url = "https://archive.softwareheritage.org/api/1/exhausted/"
    opener = SequenceOpener(
        [
            http_error(url, 429, Retry_After="1"),
            http_error(url, 429, Retry_After="1"),
        ]
    )
    transport = MODULE.RateAwareTransport(
        min_interval=0.0,
        max_retries=1,
        max_retry_delay=30.0,
        opener=opener,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
    )
    body, evidence = transport.request_bytes(
        url,
        timeout=10,
        max_bytes=1024,
        accept="application/json",
    )
    assert body is None
    assert evidence["status"] == 429
    assert evidence["terminal_transient"] is True
    assert evidence["retry_exhausted"] is True
    assert transport.terminal_transient_error_count == 1


def test_optional_bearer_token_is_sent() -> None:
    clock = Clock()
    url = "https://archive.softwareheritage.org/api/1/auth/"
    opener = SequenceOpener([Response(b"{}", url=url)])
    transport = MODULE.RateAwareTransport(
        min_interval=0.0,
        max_retries=0,
        max_retry_delay=30.0,
        bearer_token="token-value",
        opener=opener,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
    )
    transport.request_bytes(
        url,
        timeout=10,
        max_bytes=1024,
        accept="application/json",
    )
    request = opener.requests[0]
    assert request.get_header("Authorization") == "Bearer token-value"


def test_output_annotation_marks_terminal_errors_incomplete() -> None:
    clock = Clock()
    transport = MODULE.RateAwareTransport(
        min_interval=0.0,
        max_retries=0,
        max_retry_delay=30.0,
        opener=SequenceOpener([]),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
    )
    transport.terminal_transient_error_count = 1
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary)
        target = output / "sample"
        target.mkdir()
        (output / "summary.json").write_text(
            json.dumps({"schema": 1}) + "\n",
            encoding="utf-8",
        )
        (target / "result.json").write_text(
            json.dumps(
                {
                    "status": "unresolved",
                    "promotion_allowed": False,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (target / "revision-log-attempts.json").write_text(
            json.dumps(
                [
                    {
                        "status": 429,
                        "terminal_transient": True,
                    }
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        assert MODULE.annotate_output(output, transport) is False
        summary = json.loads(
            (output / "summary.json").read_text(encoding="utf-8")
        )
        result = json.loads(
            (target / "result.json").read_text(encoding="utf-8")
        )
        assert summary["evidence_complete"] is False
        assert summary["terminal_transport_error_count"] == 1
        assert summary["transport_incomplete_target_count"] == 1
        assert result["status"] == "incomplete-transport"
        assert result["evidence_complete"] is False


def test_clean_output_is_complete() -> None:
    clock = Clock()
    transport = MODULE.RateAwareTransport(
        min_interval=0.0,
        max_retries=0,
        max_retry_delay=30.0,
        opener=SequenceOpener([]),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
    )
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary)
        target = output / "sample"
        target.mkdir()
        (output / "summary.json").write_text(
            json.dumps({"schema": 1}) + "\n",
            encoding="utf-8",
        )
        (target / "result.json").write_text(
            json.dumps(
                {
                    "status": "unresolved",
                    "promotion_allowed": False,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (target / "revision-log-attempts.json").write_text(
            json.dumps(
                [
                    {
                        "status": 404,
                        "terminal_transient": False,
                    }
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        assert MODULE.annotate_output(output, transport) is True
        summary = json.loads(
            (output / "summary.json").read_text(encoding="utf-8")
        )
        assert summary["evidence_complete"] is True
        assert summary["terminal_transport_error_count"] == 0


def main() -> int:
    test_429_is_retried_with_retry_after()
    test_rate_headers_pace_following_request()
    test_zero_remaining_waits_until_reset()
    test_exhausted_429_is_terminal_and_fail_closed()
    test_optional_bearer_token_is_sent()
    test_output_annotation_marks_terminal_errors_incomplete()
    test_clean_output_is_complete()
    print("rate-limited Software Heritage archaeology tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
