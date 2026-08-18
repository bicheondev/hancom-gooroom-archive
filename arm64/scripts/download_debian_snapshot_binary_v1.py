#!/usr/bin/env python3
"""Download and verify one exact Debian binary package from snapshot.debian.org.

The snapshot machine-readable API occasionally returns more than one file hash for
one binary/version pair.  This tool downloads candidates fail-closed and accepts
only a DEB whose Package, Version, and Architecture fields exactly match the
requested tuple.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

USER_AGENT = "hancom-gooroom-arm64-port/1.0 (+https://github.com/bicheondev/hancom-gooroom-archive)"
SNAPSHOT_ROOT = "https://snapshot.debian.org"


def request_bytes(url: str, *, attempts: int = 8, timeout: int = 120) -> bytes:
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
            if attempt == attempts:
                break
            time.sleep(min(3 * attempt, 20))
    raise RuntimeError(f"unable to download {url}: {last_error}")


def request_json(url: str) -> Any:
    payload = request_bytes(url)
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"snapshot API returned invalid JSON for {url}: {error}") from error


def iter_hashes(value: Any) -> Iterable[str]:
    """Yield unique SHA-256-like snapshot file hashes from arbitrary API JSON."""

    seen: set[str] = set()

    def walk(item: Any) -> Iterable[str]:
        if isinstance(item, dict):
            preferred = item.get("hash")
            if isinstance(preferred, str):
                candidate = preferred.lower()
                if len(candidate) == 64 and all(character in "0123456789abcdef" for character in candidate):
                    yield candidate
            for nested in item.values():
                yield from walk(nested)
        elif isinstance(item, list):
            for nested in item:
                yield from walk(nested)
        elif isinstance(item, str):
            candidate = item.lower()
            if len(candidate) == 64 and all(character in "0123456789abcdef" for character in candidate):
                yield candidate

    for candidate in walk(value):
        if candidate not in seen:
            seen.add(candidate)
            yield candidate


def deb_field(path: Path, field: str) -> str:
    result = subprocess.run(
        ["dpkg-deb", "-f", str(path), field],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"dpkg-deb could not inspect {path}: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--metadata-output", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    package = arguments.package.strip()
    version = arguments.version.strip()
    architecture = arguments.architecture.strip()
    output: Path = arguments.output
    metadata_output: Path = arguments.metadata_output or output.with_suffix(output.suffix + ".snapshot.json")

    if not package or not version or not architecture:
        raise RuntimeError("package, version, and architecture must be non-empty")

    api_url = (
        f"{SNAPSHOT_ROOT}/mr/binary/"
        f"{urllib.parse.quote(package, safe='')}/"
        f"{urllib.parse.quote(version, safe='')}/binfiles"
    )
    api_response = request_json(api_url)
    hashes = list(iter_hashes(api_response))
    if not hashes:
        raise RuntimeError(f"snapshot API returned no file hashes for {package}={version}")

    attempts: list[dict[str, Any]] = []
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata_output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="snapshot-binary-") as temporary_directory:
        temporary = Path(temporary_directory)
        for index, snapshot_hash in enumerate(hashes, start=1):
            candidate = temporary / f"candidate-{index}.deb"
            file_url = f"{SNAPSHOT_ROOT}/file/{snapshot_hash}"
            record: dict[str, Any] = {
                "snapshot_hash": snapshot_hash,
                "url": file_url,
            }
            try:
                candidate.write_bytes(request_bytes(file_url))
                record["size"] = candidate.stat().st_size
                record["download_sha256"] = sha256_file(candidate)
                record["package"] = deb_field(candidate, "Package")
                record["version"] = deb_field(candidate, "Version")
                record["architecture"] = deb_field(candidate, "Architecture")
            except BaseException as error:  # keep all rejected-candidate evidence
                record["accepted"] = False
                record["error"] = f"{type(error).__name__}: {error}"
                attempts.append(record)
                continue

            accepted = (
                record["package"] == package
                and record["version"] == version
                and record["architecture"] == architecture
            )
            record["accepted"] = accepted
            attempts.append(record)
            if not accepted:
                continue

            shutil.copyfile(candidate, output)
            os.chmod(output, 0o644)
            metadata = {
                "schema": 1,
                "requested": {
                    "package": package,
                    "version": version,
                    "architecture": architecture,
                },
                "snapshot_api_url": api_url,
                "selected": record,
                "attempts": attempts,
                "output": {
                    "path": str(output),
                    "size": output.stat().st_size,
                    "sha256": sha256_file(output),
                },
            }
            metadata_output.write_text(
                json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(json.dumps(metadata, sort_keys=True))
            return 0

    metadata_output.write_text(
        json.dumps(
            {
                "schema": 1,
                "requested": {
                    "package": package,
                    "version": version,
                    "architecture": architecture,
                },
                "snapshot_api_url": api_url,
                "attempts": attempts,
                "error": "no candidate matched the exact Package/Version/Architecture tuple",
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise
    except BaseException as error:
        print(f"fatal: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
