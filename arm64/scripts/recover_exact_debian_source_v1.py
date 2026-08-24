#!/usr/bin/env python3
"""Recover an exact Debian source package from explicit pool base URLs.

Every file referenced by the .dsc is size- and SHA-256-verified before
`dpkg-source -x` is allowed to run.  A source/version mismatch is fatal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

USER_AGENT = "hancom-gooroom-arm64-port/1.0 (+https://github.com/bicheondev/hancom-gooroom-archive)"


def download(url: str, destination: Path, *, attempts: int = 6) -> None:
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                if getattr(response, "status", 200) != 200:
                    raise RuntimeError(f"HTTP {response.status}")
                destination.write_bytes(response.read())
            return
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
            last_error = error
            if attempt == attempts:
                break
            time.sleep(min(3 * attempt, 18))
    raise RuntimeError(f"download failed for {url}: {last_error}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line[1:]
            continue
        if ":" not in line:
            current = None
            continue
        key, value = line.split(":", 1)
        current = key.strip()
        fields[current] = value.strip()
    return fields


def parse_sha256_entries(fields: dict[str, str]) -> list[dict[str, Any]]:
    value = fields.get("Checksums-Sha256", "")
    entries: list[dict[str, Any]] = []
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        digest, size_text, filename = parts
        if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            continue
        entries.append(
            {
                "sha256": digest.lower(),
                "size": int(size_text),
                "filename": filename,
            }
        )
    if not entries:
        raise RuntimeError(".dsc has no usable Checksums-Sha256 entries")
    return entries


def run(arguments: list[str]) -> str:
    result = subprocess.run(
        arguments,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(arguments)}\n{result.stdout}")
    return result.stdout.strip()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--metadata-output", required=True, type=Path)
    parser.add_argument("--base-url", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    source = arguments.source.strip()
    version = arguments.version.strip()
    output = arguments.output_directory
    metadata_output = arguments.metadata_output
    output.mkdir(parents=True, exist_ok=True)
    metadata_output.parent.mkdir(parents=True, exist_ok=True)

    escaped_version = version.replace(":", "%3a")
    dsc_filename = f"{source}_{escaped_version}.dsc"
    attempts: list[dict[str, Any]] = []

    for raw_base_url in arguments.base_url:
        base_url = raw_base_url.rstrip("/") + "/"
        dsc_url = urllib.parse.urljoin(base_url, dsc_filename)
        attempt: dict[str, Any] = {"base_url": base_url, "dsc_url": dsc_url}
        work = output / "archive"
        if work.exists():
            for path in sorted(work.iterdir()):
                if path.is_dir():
                    import shutil
                    shutil.rmtree(path)
                else:
                    path.unlink()
        work.mkdir(parents=True, exist_ok=True)
        dsc = work / dsc_filename
        try:
            download(dsc_url, dsc)
            fields = parse_fields(dsc.read_text(encoding="utf-8", errors="replace"))
            observed_source = fields.get("Source") or fields.get("Format")
            observed_version = fields.get("Version")
            if fields.get("Source") != source:
                raise RuntimeError(f"Source mismatch: {fields.get('Source')!r}")
            if observed_version != version:
                raise RuntimeError(f"Version mismatch: {observed_version!r}")
            files = parse_sha256_entries(fields)
            downloaded: list[dict[str, Any]] = []
            for entry in files:
                path = work / entry["filename"]
                url = urllib.parse.urljoin(base_url, urllib.parse.quote(entry["filename"]))
                download(url, path)
                actual_size = path.stat().st_size
                actual_sha256 = sha256_file(path)
                if actual_size != entry["size"]:
                    raise RuntimeError(
                        f"size mismatch for {entry['filename']}: {actual_size} != {entry['size']}"
                    )
                if actual_sha256 != entry["sha256"]:
                    raise RuntimeError(
                        f"SHA-256 mismatch for {entry['filename']}: {actual_sha256} != {entry['sha256']}"
                    )
                downloaded.append(
                    {
                        **entry,
                        "url": url,
                        "actual_size": actual_size,
                        "actual_sha256": actual_sha256,
                    }
                )

            extracted = output / "source"
            if extracted.exists():
                import shutil
                shutil.rmtree(extracted)
            run(["dpkg-source", "-x", str(dsc), str(extracted)])
            changelog_source = run(["dpkg-parsechangelog", f"-l{extracted / 'debian' / 'changelog'}", "-SSource"])
            changelog_version = run(["dpkg-parsechangelog", f"-l{extracted / 'debian' / 'changelog'}", "-SVersion"])
            if changelog_source != source or changelog_version != version:
                raise RuntimeError(
                    f"extracted source mismatch: {changelog_source} {changelog_version}"
                )
            attempt.update(
                {
                    "accepted": True,
                    "dsc_sha256": sha256_file(dsc),
                    "files": downloaded,
                    "extracted_source": str(extracted),
                }
            )
            attempts.append(attempt)
            metadata = {
                "schema": 1,
                "source": source,
                "version": version,
                "status": "recovered-exact-source-archive",
                "selected_base_url": base_url,
                "selected_dsc_url": dsc_url,
                "dsc_sha256": sha256_file(dsc),
                "files": downloaded,
                "attempts": attempts,
            }
            metadata_output.write_text(
                json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(json.dumps(metadata, sort_keys=True))
            return 0
        except BaseException as error:
            attempt["accepted"] = False
            attempt["error"] = f"{type(error).__name__}: {error}"
            attempts.append(attempt)

    metadata = {
        "schema": 1,
        "source": source,
        "version": version,
        "status": "not-recovered",
        "attempts": attempts,
    }
    metadata_output.write_text(
        json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, sort_keys=True))
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise
    except BaseException as error:
        print(f"fatal: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
