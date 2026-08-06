#!/usr/bin/env python3
"""Hardened front-end for historical ARM64 artifact reauditing.

GitHub's artifact archive endpoint redirects to a short-lived Azure object URL.
The v2 downloader allowed urllib to forward the GitHub Authorization header to
that different origin, which Azure rejects with HTTP 401. This wrapper performs
the authenticated GitHub request without automatic redirects, then downloads
the temporary object without GitHub credentials.

It also prioritizes artifacts for currently unresolved package-layer sources so
an audit limit does not spend its entire budget on newer unrelated retries.
All package/source/version/ELF acceptance rules remain those of the v2 auditor.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import import_historical_arm64_artifacts_v2 as auditor


PRIORITY_NAMES = (
    "gnome-control-center",
    "gnome-settings-daemon",
    "nautilus",
    "policykit-1",
    "yelp",
    "p7zip",
    "gooroom-browser",
    "gooroom-libsecurity-extensions",
    "gooroom-security-status-tools",
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def copy_response(response: Any, destination: Path, max_bytes: int) -> None:
    content_length = response.headers.get("Content-Length")
    if content_length and int(content_length) > max_bytes:
        raise RuntimeError(
            f"artifact is larger than limit: {content_length} > {max_bytes}"
        )
    total = 0
    with destination.open("wb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError(
                    f"artifact exceeded size limit: {total} > {max_bytes}"
                )
            output.write(chunk)


def redirected_artifact_download(
    url: str, token: str, destination: Path, max_bytes: int
) -> None:
    opener = urllib.request.build_opener(NoRedirect())
    error_text = ""
    for attempt in range(5):
        temporary = destination.with_suffix(destination.suffix + ".partial")
        temporary.unlink(missing_ok=True)
        try:
            api_request = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "hancom-gooroom-arm64-artifact-import-v3/1",
                },
            )
            redirect_url = ""
            try:
                with opener.open(api_request, timeout=90) as response:
                    if response.getcode() == 200:
                        copy_response(response, temporary, max_bytes)
                    else:
                        raise RuntimeError(
                            f"unexpected GitHub artifact response {response.getcode()}"
                        )
            except urllib.error.HTTPError as error:
                if error.code not in {301, 302, 303, 307, 308}:
                    raise
                redirect_url = error.headers.get("Location", "")
                if not redirect_url:
                    raise RuntimeError("artifact redirect has no Location header")

            if redirect_url:
                object_request = urllib.request.Request(
                    redirect_url,
                    headers={
                        "Accept": "application/octet-stream",
                        "User-Agent": "hancom-gooroom-arm64-artifact-import-v3/1",
                    },
                )
                with urllib.request.urlopen(object_request, timeout=300) as response:
                    copy_response(response, temporary, max_bytes)

            if not temporary.exists() or temporary.stat().st_size == 0:
                raise RuntimeError("artifact download produced an empty file")
            temporary.replace(destination)
            return
        except Exception as error:
            error_text = f"{type(error).__name__}: {error}"
            temporary.unlink(missing_ok=True)
            if attempt < 4:
                time.sleep(2**attempt)
    raise RuntimeError(error_text)


_original_candidates = auditor.artifact_candidates


def prioritized_candidates(repository: str, token: str, branch: str) -> list[dict[str, Any]]:
    rows = _original_candidates(repository, token, branch)

    def priority(row: dict[str, Any]) -> tuple[int, str, int]:
        name = str(row.get("name", "")).lower()
        targeted = any(source in name for source in PRIORITY_NAMES)
        return (
            1 if targeted else 0,
            str(row.get("created_at", "")),
            int(row.get("id", 0)),
        )

    rows.sort(key=priority, reverse=True)
    return rows


def successful_partial_audit() -> bool:
    """Accept a bounded scan only when it produced verified exact evidence.

    The v2 auditor returns a nonzero code when `--max-artifacts` truncates the
    candidate set, even though every imported row has already passed package,
    source authority, version, architecture, and ELF checks. A bounded scan is
    therefore usable as an incremental import, but an empty or malformed result
    remains a hard failure.
    """

    try:
        index = sys.argv.index("--output-dir")
        output_dir = Path(sys.argv[index + 1])
        summary = json.loads((output_dir / "summary.json").read_text())
        document = json.loads(
            (output_dir / "historical-rebuild-import.json").read_text()
        )
    except (ValueError, IndexError, OSError, json.JSONDecodeError):
        return False
    sources = document.get("sources", [])
    return (
        summary.get("verified_artifact_count", 0) > 0
        and summary.get("imported_source_count", 0) > 0
        and summary.get("imported_binary_package_count", 0) > 0
        and len(sources) == summary.get("imported_source_count")
        and all(row.get("packages") for row in sources)
    )


auditor.download = redirected_artifact_download
auditor.artifact_candidates = prioritized_candidates

if __name__ == "__main__":
    return_code = auditor.main()
    if return_code and successful_partial_audit():
        return_code = 0
    raise SystemExit(return_code)
