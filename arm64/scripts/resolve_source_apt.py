#!/usr/bin/env python3
"""Resolve exact Hancom Gooroom source packages from historical APT metadata.

Git is the preferred lock source, but some vendor revisions were published only
through an APT repository. This resolver discovers source indexes exclusively
from URLs already recorded in the immutable port evidence, matches the exact
AMD64 ISO source version, verifies every source-file SHA-256 from the Sources
stanza, extracts the .dsc, and rechecks debian/changelog before accepting it.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import json
import lzma
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

USER_AGENT = "hancom-gooroom-arm64-source-lock/1"
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
DEB_LINE_RE = re.compile(
    r"^\s*deb(?:-src)?\s+(?:\[[^]]+\]\s+)?(https?://\S+)\s+(\S+)\s+(.+?)\s*$"
)
SOURCE_HEAD_RE = re.compile(r"^([^\s(]+)\s+\(([^)]+)\)")


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def all_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from all_strings(item)


def evidence_text(paths: list[Path]) -> str:
    chunks: list[str] = []
    for path in paths:
        if path.is_dir():
            candidates = sorted(
                item
                for item in path.rglob("*")
                if item.is_file() and item.suffix.lower()
                in {".json", ".txt", ".list", ".sources", ".tsv", ".md"}
            )
        else:
            candidates = [path]
        for candidate in candidates:
            try:
                if candidate.stat().st_size > 64 * 1024 * 1024:
                    continue
                chunks.append(candidate.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    return "\n".join(chunks)


def source_index_variants(base: str) -> list[str]:
    base = base.rstrip("/")
    return [base + suffix for suffix in (".xz", ".gz", ".bz2", "")]


def discover_indexes(text: str) -> list[str]:
    candidates: set[str] = set()
    for raw in URL_RE.findall(text):
        url = raw.rstrip("),.;]}")
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path
        if "/dists/" in path:
            prefix, rest = path.split("/dists/", 1)
            parts = [part for part in rest.split("/") if part]
            if len(parts) >= 3:
                suite, component = parts[0], parts[1]
                base = urllib.parse.urlunsplit(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        f"{prefix}/dists/{suite}/{component}/source/Sources",
                        "",
                        "",
                    )
                )
                candidates.update(source_index_variants(base))
        replacements = (
            ("/binary-amd64/Packages", "/source/Sources"),
            ("/binary-arm64/Packages", "/source/Sources"),
            ("/binary-all/Packages", "/source/Sources"),
        )
        for old, new in replacements:
            if old in url:
                base = url.replace(old, new)
                base = re.sub(r"\.(?:xz|gz|bz2)$", "", base)
                candidates.update(source_index_variants(base))

    for line in text.splitlines():
        match = DEB_LINE_RE.match(line)
        if not match:
            continue
        root, suite, component_text = match.groups()
        for component in component_text.split():
            base = f"{root.rstrip('/')}/dists/{suite}/{component}/source/Sources"
            candidates.update(source_index_variants(base))

    return sorted(
        candidates, key=lambda url: (0 if url.startswith("https://") else 1, url)
    )


def request_bytes(url: str, retries: int = 3) -> bytes:
    error: Exception | None = None
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=45) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = exc
            if attempt + 1 < retries:
                time.sleep(2**attempt)
    assert error is not None
    raise error


def decompress(url: str, payload: bytes) -> str:
    path = urllib.parse.urlsplit(url).path
    if path.endswith(".xz"):
        payload = lzma.decompress(payload)
    elif path.endswith(".gz"):
        payload = gzip.decompress(payload)
    elif path.endswith(".bz2"):
        payload = bz2.decompress(payload)
    return payload.decode("utf-8", errors="strict")


def parse_control(text: str) -> list[dict[str, str]]:
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] = {}
    field: str | None = None
    for raw in text.splitlines() + [""]:
        if not raw.strip():
            if current:
                stanzas.append(current)
            current = {}
            field = None
            continue
        if raw[0].isspace() and field:
            current[field] += "\n" + raw[1:]
            continue
        if ":" not in raw:
            field = None
            continue
        field, value = raw.split(":", 1)
        current[field] = value.lstrip()
    return stanzas


def checksum_entries(stanza: dict[str, str]) -> list[dict[str, Any]]:
    field = stanza.get("Checksums-Sha256", "")
    entries: list[dict[str, Any]] = []
    for line in field.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        digest, size, filename = parts
        if re.fullmatch(r"[0-9a-fA-F]{64}", digest) and size.isdigit():
            entries.append(
                {"sha256": digest.lower(), "size": int(size), "filename": filename}
            )
    return entries


def changelog_head(source_root: Path) -> tuple[str, str] | None:
    changelog = source_root / "debian" / "changelog"
    if not changelog.is_file():
        return None
    first = changelog.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    match = SOURCE_HEAD_RE.match(first)
    return match.groups() if match else None


def download_source_candidate(
    stanza: dict[str, str],
    index_url: str,
    target: dict[str, Any],
    output_root: Path,
) -> dict[str, Any]:
    directory = stanza.get("Directory", "").strip("/")
    if not directory:
        raise RuntimeError("Sources stanza has no Directory")
    parsed = urllib.parse.urlsplit(index_url)
    marker = "/dists/"
    if marker not in parsed.path:
        raise RuntimeError("cannot derive repository root from Sources URL")
    repository_path = parsed.path.split(marker, 1)[0].rstrip("/")
    repository_root = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, repository_path + "/", "", "")
    )
    files = checksum_entries(stanza)
    if not files or not any(item["filename"].endswith(".dsc") for item in files):
        raise RuntimeError("Sources stanza lacks SHA-256-locked .dsc files")

    destination = (
        output_root
        / safe_component(target["source"])
        / safe_component(target["source_version"])
    )
    destination.mkdir(parents=True, exist_ok=True)
    downloaded: list[dict[str, Any]] = []
    for item in files:
        url = urllib.parse.urljoin(
            repository_root, directory + "/" + item["filename"]
        )
        path = destination / item["filename"]
        payload = request_bytes(url)
        path.write_bytes(payload)
        actual = sha256_file(path)
        if actual != item["sha256"] or len(payload) != item["size"]:
            raise RuntimeError(f"source file checksum/size mismatch: {url}")
        downloaded.append(
            {**item, "url": url, "local_path": str(path), "actual_sha256": actual}
        )

    dsc = next(
        destination / item["filename"]
        for item in files
        if item["filename"].endswith(".dsc")
    )
    extract_root = destination / "extracted"
    shutil.rmtree(extract_root, ignore_errors=True)
    extract_root.mkdir()
    subprocess.run(
        ["dpkg-source", "-x", str(dsc), str(extract_root / "source")],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    declared = changelog_head(extract_root / "source")
    if declared != (target["source"], target["source_version"]):
        raise RuntimeError(
            "extracted changelog mismatch: "
            f"expected {(target['source'], target['source_version'])}, got {declared}"
        )

    return {
        "type": "apt-source",
        "source_index_url": index_url,
        "repository_root": repository_root,
        "directory": directory,
        "declared_source": declared[0],
        "declared_version": declared[1],
        "files": downloaded,
        "dsc": str(dsc),
    }


def target_rows(seed: dict[str, Any]) -> list[dict[str, Any]]:
    rows = seed.get("sources")
    if not isinstance(rows, list):
        raise SystemExit("seed source lock has no sources list")
    result = []
    for row in rows:
        if row.get("status") == "resolved" and row.get("selected"):
            continue
        source = row.get("source")
        version = row.get("source_version")
        if source and version:
            result.append(dict(row))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed-lock", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, nargs="+", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-indexes", type=int, default=120)
    args = parser.parse_args()

    if shutil.which("dpkg-source") is None:
        raise SystemExit("dpkg-source is required")

    seed = json.loads(args.seed_lock.read_text(encoding="utf-8"))
    targets = target_rows(seed)
    text = evidence_text(args.evidence)
    indexes = discover_indexes(text)[: args.max_indexes]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    source_payload_dir = args.output_dir / "source-files"

    fetched_indexes: list[dict[str, Any]] = []
    matches: dict[tuple[str, str], list[tuple[str, dict[str, str]]]] = {
        (row["source"], row["source_version"]): [] for row in targets
    }
    for index, url in enumerate(indexes, 1):
        try:
            payload = request_bytes(url)
            text_index = decompress(url, payload)
            stanzas = parse_control(text_index)
            fetched_indexes.append(
                {
                    "url": url,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "compressed_size": len(payload),
                    "stanza_count": len(stanzas),
                    "status": "fetched",
                }
            )
        except Exception as error:
            fetched_indexes.append(
                {"url": url, "status": "error", "error": repr(error)}
            )
            continue
        for stanza in stanzas:
            candidate = (stanza.get("Package", ""), stanza.get("Version", ""))
            if candidate in matches:
                matches[candidate].append((url, stanza))
        print(f"[{index}/{len(indexes)}] {url}", file=sys.stderr, flush=True)

    rows: list[dict[str, Any]] = []
    for target in targets:
        candidate_rows = matches[(target["source"], target["source_version"])]
        successes: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for index_url, stanza in candidate_rows:
            try:
                selected = download_source_candidate(
                    stanza, index_url, target, source_payload_dir
                )
                successes.append(selected)
            except Exception as error:
                errors.append(
                    {"source_index_url": index_url, "error": repr(error)}
                )
        identities = {
            tuple(
                (item["filename"], item["sha256"])
                for item in selected["files"]
            )
            for selected in successes
        }
        if len(identities) == 1 and successes:
            selected = sorted(
                successes, key=lambda item: item["source_index_url"]
            )[0]
            rows.append(
                {
                    **target,
                    "status": "resolved",
                    "reason": "exact source version and all source file SHA-256 values verified from historical APT Sources metadata",
                    "selected": selected,
                    "apt_candidates": successes,
                    "errors": errors,
                }
            )
        elif len(identities) > 1:
            rows.append(
                {
                    **target,
                    "status": "ambiguous-apt-source",
                    "reason": "multiple exact-version APT source payload identities were found",
                    "selected": None,
                    "apt_candidates": successes,
                    "errors": errors,
                }
            )
        else:
            rows.append(
                {
                    **target,
                    "status": "unresolved",
                    "reason": "no fully SHA-256-verified exact source payload was recovered from discovered APT Sources indexes",
                    "selected": None,
                    "apt_candidates": [],
                    "errors": errors,
                }
            )

    resolved = [row for row in rows if row["status"] == "resolved"]
    unresolved = [row for row in rows if row["status"] != "resolved"]
    summary = {
        "seed_lock": str(args.seed_lock),
        "target_count": len(targets),
        "discovered_index_count": len(indexes),
        "fetched_index_count": sum(
            item["status"] == "fetched" for item in fetched_indexes
        ),
        "resolved_count": len(resolved),
        "unresolved_count": len(unresolved),
        "resolved_sources": [row["source"] for row in resolved],
        "unresolved_sources": [row["source"] for row in unresolved],
    }
    document = {
        "summary": summary,
        "sources": rows,
        "source_indexes": fetched_indexes,
    }
    (args.output_dir / "apt-source-lock.json").write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "apt-source-lock-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "unresolved-apt-sources.json").write_text(
        json.dumps(unresolved, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
