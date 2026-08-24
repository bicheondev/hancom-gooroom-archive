#!/usr/bin/env python3
"""Regression tests for fail-closed Software Heritage API pacing."""

from __future__ import annotations

import importlib.util
import io
import sys
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "arm64" / "scripts" / "archaeology_software_heritage_exact_sources.py"
SPEC = importlib.util.spec_from_file_location("swh_archaeology_request_policy", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class Response:
    status = 200

    def __init__(self, body: bytes = b"{}", headers: Message | None = None) -> None:
        self._body = io.BytesIO(body)
        self.headers = headers or Message()
        if not self.headers.get("Content-Type"):
            self.headers["Content-Type"] = "application/json"

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def geturl(self) -> str:
        return "https://archive.softwareheritage.org/api/1/test/"


def http_error(status: int, *, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError(
        "https://archive.softwareheritage.org/api/1/test/",
        status,
        f"HTTP {status}",
        headers,
        None,
    )


class SoftwareHeritageRequestPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        MODULE.configure_request_policy(0.0, 2)

    def request(self, url: str = "https://archive.softwareheritage.org/api/1/test/"):
        return MODULE.request_bytes(
            url,
            timeout=1,
            max_bytes=1024,
            accept="application/json",
        )

    def test_429_is_retried_and_recorded(self) -> None:
        limited = http_error(429, retry_after="0")
        with patch.object(MODULE.urllib.request, "urlopen", side_effect=[limited, Response()]) as opener, \
             patch.object(MODULE.time, "sleep", return_value=None) as sleeper:
            body, evidence = self.request()
        self.assertEqual(body, b"{}")
        self.assertEqual(evidence["attempt_count"], 2)
        self.assertEqual(len(evidence["retry_history"]), 1)
        self.assertEqual(evidence["retry_history"][0]["status"], 429)
        self.assertEqual(MODULE._REQUEST_STATS["rate_limited_responses"], 1)
        self.assertEqual(MODULE._REQUEST_STATS["retries"], 1)
        self.assertEqual(opener.call_count, 2)
        sleeper.assert_called_once()

    def test_429_exhaustion_fails_closed(self) -> None:
        MODULE.configure_request_policy(0.0, 0)
        with patch.object(MODULE.urllib.request, "urlopen", side_effect=http_error(429, retry_after="0")), \
             patch.object(MODULE.time, "sleep", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "retries exhausted"):
                self.request("https://archive.softwareheritage.org/api/1/exhaust/")
        self.assertEqual(MODULE._REQUEST_STATS["retry_exhaustions"], 1)

    def test_server_errors_are_retried(self) -> None:
        with patch.object(MODULE.urllib.request, "urlopen", side_effect=[http_error(503), Response()]), \
             patch.object(MODULE.time, "sleep", return_value=None):
            body, evidence = self.request("https://archive.softwareheritage.org/api/1/server-error/")
        self.assertEqual(body, b"{}")
        self.assertEqual(evidence["attempt_count"], 2)
        self.assertEqual(MODULE._REQUEST_STATS["server_error_responses"], 1)

    def test_404_remains_a_legitimate_negative_result(self) -> None:
        with patch.object(MODULE.urllib.request, "urlopen", side_effect=http_error(404)) as opener:
            body, evidence = self.request("https://archive.softwareheritage.org/api/1/missing/")
        self.assertIsNone(body)
        self.assertEqual(evidence["status"], 404)
        self.assertEqual(evidence["attempt_count"], 1)
        self.assertEqual(evidence["retry_history"], [])
        opener.assert_called_once()

    def test_successful_get_is_cached(self) -> None:
        with patch.object(MODULE.urllib.request, "urlopen", return_value=Response()) as opener:
            first_body, first_evidence = self.request("https://archive.softwareheritage.org/api/1/cache/")
            second_body, second_evidence = self.request("https://archive.softwareheritage.org/api/1/cache/")
        self.assertEqual(first_body, second_body)
        self.assertFalse(first_evidence["cache_hit"])
        self.assertTrue(second_evidence["cache_hit"])
        self.assertEqual(second_evidence["attempt_count"], 0)
        self.assertEqual(MODULE._REQUEST_STATS["cache_hits"], 1)
        opener.assert_called_once()

    def test_bearer_token_is_not_sent_to_external_urls(self) -> None:
        original = MODULE._BEARER_TOKEN
        MODULE._BEARER_TOKEN = "secret-test-token"
        self.addCleanup(setattr, MODULE, "_BEARER_TOKEN", original)
        archive_headers = MODULE._request_headers(
            "https://archive.softwareheritage.org/api/1/test/", "application/json"
        )
        external_headers = MODULE._request_headers(
            "https://example.invalid/metadata", "application/json"
        )
        self.assertEqual(archive_headers.get("Authorization"), "Bearer secret-test-token")
        self.assertNotIn("Authorization", external_headers)


if __name__ == "__main__":
    unittest.main()
