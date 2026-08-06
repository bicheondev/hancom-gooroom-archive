#!/usr/bin/env python3
"""Recover an exact Debian source package from URLs preserved in lock evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path
from typing import Any, Iterable

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
POOL_RE = re.compile(r"^(https?://.+?/pool/)([^/]+)/([^/]+)/([^/]+)/")
DEB_LINE_RE = re.compile(
    r"^\s*deb(?:-src)?\s+(?:\[[^]]+\]\s+)?(https?://\S+)\s+\S+\s+(.+)$"
)
DEFAULT_COMPONENTS = ("main", "contrib", "non-free", "non-free-firmware")
TEXT_SUFFIXES = {
    ".json",
    ".txt",
    ".tsv",
    ".list",
    ".sources",
    ".log",
    ".md",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.+-]+", "_", value)


def iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)


def evidence_strings(roots: list[Path]) -> list[str]:
    values: list[str] = []
    seen: set[Path] = set()
    for root in roots:
        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            if path.stat().st_size > 32 * 1024 * 1024:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if path.suffix.lower() == ".json":
                try:
                    values.extend(iter_strings(json.loads(text)))
                except json.JSONDecodeError:
                    values.append(text)
            else:
                values.append(text)
    return values


def clean_url(value: str) -> str:
    return value.rstrip("),.;]}")


def discover_urls(strings: list[str]) -> tuple[list[str], list[str], list[str]]:
    urls: set[str] = set()
    apt_roots: set[str] = set()
    components: set[str] = set(DEFAULT_COMPONENTS)
    for value in strings:
        for match in URL_RE.findall(value):
            url = clean_url(match)
            urls.add(url)
            if "/dists/" in url:
                apt_roots.add(url.split("/dists/", 1)[0].rstrip("/"))
            pool = POOL_RE.match(url)
            if pool:
                apt_roots.add(pool.group(1)[:-6].rstrip("/"))
                components.add(pool.group(2))
        for line in value.splitlines():
            match = DEB_LINE_RE.match(line)
            if not match:
                continue
            apt_roots.add(match.group(1).rstrip("/"))
            components.update(match.group(2).split())
    return sorted(urls), sorted(apt_roots), sorted(components)


def version_filename(version: str) -> str:
    # Debian pool filenames omit an epoch even though the control Version keeps it.
    return version.split(":", 1)[-1]


def candidate_urls(
    source: str,
    version: str,
    urls: list[str],
    apt_roots: list[str],
    components: list[str],
    extra_bases: list[str],
) -> list[str]:
    filename = f"{source}_{version_filename(version)}.dsc"
    encoded = urllib.parse.quote(filename, safe="+~._-")
    first_letter = source[0].lower()
    candidates: set[str] = set()

    for url in urls:
        pool = POOL_RE.match(url)
        if pool:
            pool_root, component, letter, package = pool.groups()
            if package == source or source in url:
                directory = f"{pool_root}{component}/{letter}/{package}/"
                candidates.add(urllib.parse.urljoin(directory, encoded))
            candidates.add(
                f"{pool_root}{component}/{first_letter}/{source}/{encoded}"
            )
        if url.endswith(".dsc") and source in url:
            candidates.add(url)

    bases = set(apt_roots)
    bases.update(base.rstrip("/") for base in extra_bases)
    for base in bases:
        if base.endswith("/pool"):
            pool_root = base.rstrip("/") + "/"
        else:
            pool_root = base.rstrip("/") + "/pool/"
        for component in components:
            candidates.add(
                f"{pool_root}{component}/{first_letter}/{source}/{encoded}"
            )

    # Source-specific evidence is most likely to be correct, then use a stable URL order.
    return sorted(candidates, key=lambda url: (source not in url, len(url), url))[:600]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def request_bytes(url: str, timeout: int) -> tuple[bytes | None, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "hancom-gooroom-arm64-source-lock/1",
            "Accept": "text/plain,application/octet-stream,*/*",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            return body, {
                "url": url,
                "status": int(response.status),
                "final_url": response.geturl(),
                "content_type": response.headers.get("Content-Type"),
                "content_length": len(body),
            }
    except urllib.error.HTTPError as error:
        return None, {
            "url": url,
            "status": int(error.code),
            "error": str(error),
        }
    except Exception as error:
        return None, {"url": url, "status": None, "error": repr(error)}


def deb822(text: str) -> dict[str, str]:
    message = Parser().parsestr(text)
    return {key: value for key, value in message.items()}


def checksum_rows(value: str) -> list[dict[str, Any]]:
    rows = []
    for line in value.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        digest, size, filename = fields
        if Path(filename).name != filename:
            raise ValueError(f"unsafe source filename: {filename}")
        rows.append(
            {"sha256": digest.lower(), "size": int(size), "filename": filename}
        )
    return rows


def download_file(
    url: str,
    destination: Path,
    expected_sha256: str,
    expected_size: int,
    timeout: int,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "hancom-gooroom-arm64-source-lock/1"},
    )
    temporary = destination.with_suffix(destination.suffix + ".part")
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response, temporary.open(
            "wb"
        ) as output:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                output.write(block)
                digest.update(block)
                size += len(block)
        actual_sha256 = digest.hexdigest()
        if size != expected_size:
            raise ValueError(f"size {size} != {expected_size}")
        if actual_sha256 != expected_sha256:
            raise ValueError(f"sha256 {actual_sha256} != {expected_sha256}")
        temporary.replace(destination)
        return {
            "filename": destination.name,
            "url": url,
            "size": size,
            "sha256": actual_sha256,
            "status": "verified",
        }
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--search-root", type=Path, action="append", default=[])
    parser.add_argument("--extra-base-url", action="append", default=[])
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    roots = args.search_root or [Path("arm64/locks")]
    strings = evidence_strings(roots)
    urls, apt_roots, components = discover_urls(strings)
    candidates = candidate_urls(
        args.source,
        args.version,
        urls,
        apt_roots,
        components,
        args.extra_base_url,
    )
    attempts: list[dict[str, Any]] = []
    resolved: dict[str, Any] | None = None

    for url in candidates:
        body, attempt = request_bytes(url, args.timeout)
        attempts.append(attempt)
        if body is None or attempt.get("status") != 200:
            continue
        try:
            text = body.decode("utf-8")
            fields = deb822(text)
            declared_source = fields.get("Source", "").strip()
            declared_version = fields.get("Version", "").strip()
            if declared_source != args.source or declared_version != args.version:
                attempt["rejected"] = {
                    "declared_source": declared_source,
                    "declared_version": declared_version,
                }
                continue
            checksums = checksum_rows(fields.get("Checksums-Sha256", ""))
            if not checksums:
                attempt["rejected"] = "Checksums-Sha256 is absent"
                continue
            dsc_name = Path(urllib.parse.urlparse(attempt["final_url"]).path).name
            dsc_path = args.output_dir / dsc_name
            dsc_path.write_bytes(body)
            base_url = attempt["final_url"].rsplit("/", 1)[0] + "/"
            verified_files = []
            for item in checksums:
                source_url = urllib.parse.urljoin(
                    base_url,
                    urllib.parse.quote(item["filename"], safe="+~._-"),
                )
                verified_files.append(
                    download_file(
                        source_url,
                        args.output_dir / item["filename"],
                        item["sha256"],
                        item["size"],
                        args.timeout,
                    )
                )
            resolved = {
                "schema": "hancom-gooroom-exact-vendor-source-archive-v1",
                "generated_at": now(),
                "status": "resolved",
                "source": args.source,
                "version": args.version,
                "dsc": {
                    "filename": dsc_name,
                    "url": attempt["final_url"],
                    "size": len(body),
                    "sha256": sha256_bytes(body),
                    "fields": fields,
                },
                "files": verified_files,
                "discovery": {
                    "search_roots": [str(path) for path in roots],
                    "apt_roots": apt_roots,
                    "components": components,
                    "candidate_count": len(candidates),
                    "attempts": attempts,
                },
            }
            break
        except Exception as error:
            attempt["rejected"] = repr(error)
            for path in args.output_dir.iterdir():
                if path.is_file() and path.name not in {
                    "source-archive-probe.json",
                    "source-archive-lock.json",
                }:
                    path.unlink(missing_ok=True)

    if resolved is None:
        result = {
            "schema": "hancom-gooroom-exact-vendor-source-archive-probe-v1",
            "generated_at": now(),
            "status": "unresolved",
            "source": args.source,
            "version": args.version,
            "search_roots": [str(path) for path in roots],
            "discovered_url_count": len(urls),
            "apt_roots": apt_roots,
            "components": components,
            "candidate_count": len(candidates),
            "attempts": attempts,
        }
        (args.output_dir / "source-archive-probe.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2

    (args.output_dir / "source-archive-lock.json").write_text(
        json.dumps(resolved, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    checksum_lines = []
    for path in sorted(args.output_dir.iterdir()):
        if not path.is_file() or path.name == "SOURCESUMS.sha256":
            continue
        checksum_lines.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        )
    (args.output_dir / "SOURCESUMS.sha256").write_text(
        "\n".join(checksum_lines) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(resolved, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
