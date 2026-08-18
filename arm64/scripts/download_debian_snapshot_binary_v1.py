#!/usr/bin/env python3
"""Download and verify one exact Debian binary package from snapshot.debian.org.

Snapshot currently identifies archived files with SHA-1 hashes.  Its published
machine-readable API also documents that SHA-256 migration is planned while old
SHA-1 URLs remain valid, so this downloader accepts both 40-character SHA-1 and
64-character SHA-256 file identities.  Every downloaded candidate is verified
against its snapshot identity and then accepted only when Package, Version, and
Architecture exactly match the requested tuple.
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
from typing import Any

USER_AGENT = "hancom-gooroom-arm64-port/1.0 (+https://github.com/bicheondev/hancom-gooroom-archive)"
SNAPSHOT_ROOT = "https://snapshot.debian.org"
HASH_ALGORITHMS_BY_LENGTH = {40: "sha1", 64: "sha256"}


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


def valid_snapshot_hash(value: Any) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    algorithm = HASH_ALGORITHMS_BY_LENGTH.get(len(candidate))
    if algorithm is None or any(character not in "0123456789abcdef" for character in candidate):
        return None
    return candidate, algorithm


def extract_candidates(api_response: Any, architecture: str) -> list[dict[str, Any]]:
    """Return unique API result rows, preferring the requested architecture."""

    if not isinstance(api_response, dict) or not isinstance(api_response.get("result"), list):
        raise RuntimeError("snapshot API response has no result list")

    seen: set[str] = set()
    exact_architecture: list[dict[str, Any]] = []
    unspecified_architecture: list[dict[str, Any]] = []
    other_architectures: list[dict[str, Any]] = []

    for raw_row in api_response["result"]:
        if not isinstance(raw_row, dict):
            continue
        parsed_hash = valid_snapshot_hash(raw_row.get("hash"))
        if parsed_hash is None:
            continue
        snapshot_hash, hash_algorithm = parsed_hash
        if snapshot_hash in seen:
            continue
        seen.add(snapshot_hash)
        row = {
            "snapshot_hash": snapshot_hash,
            "snapshot_hash_algorithm": hash_algorithm,
            "api_architecture": raw_row.get("architecture"),
            "api_row": raw_row,
        }
        api_architecture = raw_row.get("architecture")
        if api_architecture == architecture:
            exact_architecture.append(row)
        elif api_architecture in (None, ""):
            unspecified_architecture.append(row)
        else:
            other_architectures.append(row)

    # The API normally supplies Architecture.  Keep unspecified and other rows as
    # fail-closed fallbacks because dpkg-deb performs the final exact tuple check.
    return exact_architecture + unspecified_architecture + other_architectures


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


def digest_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    return digest_file(path, "sha256")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--metadata-output", type=Path)
    return parser.parse_args()


def write_metadata(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


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
    requested = {
        "package": package,
        "version": version,
        "architecture": architecture,
    }
    api_response = request_json(api_url)
    candidates = extract_candidates(api_response, architecture)
    if not candidates:
        write_metadata(
            metadata_output,
            {
                "schema": 2,
                "requested": requested,
                "snapshot_api_url": api_url,
                "snapshot_api_result_count": len(api_response.get("result", []))
                if isinstance(api_response, dict)
                else None,
                "attempts": [],
                "error": "snapshot API returned no valid SHA-1 or SHA-256 file identities",
            },
        )
        raise RuntimeError(f"snapshot API returned no valid file identities for {package}={version}")

    attempts: list[dict[str, Any]] = []
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata_output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="snapshot-binary-") as temporary_directory:
        temporary = Path(temporary_directory)
        for index, candidate_row in enumerate(candidates, start=1):
            candidate = temporary / f"candidate-{index}.deb"
            snapshot_hash = candidate_row["snapshot_hash"]
            hash_algorithm = candidate_row["snapshot_hash_algorithm"]
            file_url = f"{SNAPSHOT_ROOT}/file/{snapshot_hash}"
            record: dict[str, Any] = {
                **candidate_row,
                "url": file_url,
            }
            try:
                candidate.write_bytes(request_bytes(file_url))
                record["size"] = candidate.stat().st_size
                record["download_sha256"] = sha256_file(candidate)
                observed_identity = digest_file(candidate, hash_algorithm)
                record["observed_snapshot_identity"] = observed_identity
                record["snapshot_identity_verified"] = observed_identity == snapshot_hash
                if not record["snapshot_identity_verified"]:
                    raise RuntimeError(
                        f"snapshot {hash_algorithm} mismatch: expected {snapshot_hash}, observed {observed_identity}"
                    )
                record["package"] = deb_field(candidate, "Package")
                record["version"] = deb_field(candidate, "Version")
                record["architecture"] = deb_field(candidate, "Architecture")
            except BaseException as error:  # preserve every rejected-candidate reason
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
                "schema": 2,
                "requested": requested,
                "snapshot_api_url": api_url,
                "snapshot_api_result_count": len(api_response.get("result", [])),
                "valid_snapshot_identity_count": len(candidates),
                "selected": record,
                "attempts": attempts,
                "output": {
                    "path": str(output),
                    "size": output.stat().st_size,
                    "sha256": sha256_file(output),
                },
            }
            write_metadata(metadata_output, metadata)
            print(json.dumps(metadata, sort_keys=True))
            return 0

    write_metadata(
        metadata_output,
        {
            "schema": 2,
            "requested": requested,
            "snapshot_api_url": api_url,
            "snapshot_api_result_count": len(api_response.get("result", [])),
            "valid_snapshot_identity_count": len(candidates),
            "attempts": attempts,
            "error": "no candidate matched the exact Package/Version/Architecture tuple",
        },
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
