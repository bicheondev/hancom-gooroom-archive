#!/usr/bin/env python3
"""Extract provenance clues from exact AMD64 blocker packages.

For source versions whose public Git commit or signed .dsc is unavailable, the
original ISO-preserved vendor Packages indexes are still authoritative for the
exact AMD64 binary. This tool downloads one small native binary per blocked
source, verifies size/SHA-256/control identity, and extracts only compact
provenance evidence: Debian changelogs, control metadata, file lists, ELF build
IDs and package copyright. It does not treat the binary as source and never
changes the requested version.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


MAX_TEXT_BYTES = 2 * 1024 * 1024
COMMIT_TOKEN_RE = re.compile(r"(?<![0-9a-f])([0-9a-f]{7,40})(?![0-9a-f])", re.I)


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        **kwargs,
    )


def deb_field(path: Path, field: str) -> str:
    process = run(["dpkg-deb", "-f", str(path), field])
    if process.returncode:
        raise RuntimeError(
            f"dpkg-deb -f {path.name} {field} failed: {process.stderr.strip()}"
        )
    return process.stdout.strip()


def source_field(value: str, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, version
    match = re.fullmatch(r"\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*", value)
    if not match:
        return value.strip(), version
    return match.group(1), match.group(2) or version


def candidate_urls(record: dict[str, Any]) -> list[str]:
    filename = str(record["binary_filename"]).lstrip("/")
    bases = [str(record.get("base_url", "")).rstrip("/")]
    repository = str(record.get("repository", ""))
    for scheme in ("https", "http"):
        if repository:
            bases.append(f"{scheme}://update.hancomgooroom.com/{repository}")
        bases.append(f"{scheme}://update.hancomgooroom.com/gooroom")
        bases.append(f"{scheme}://update.hancomgooroom.com/hancom")
    urls = []
    seen = set()
    for base in bases:
        if not base:
            continue
        base = re.sub(r"^http://", "https://", base) if base.startswith("http://") else base
        url = f"{base}/{urllib.parse.quote(filename, safe='/+~._-:%')}"
        if url not in seen:
            seen.add(url)
            urls.append(url)
        if url.startswith("https://"):
            alternate = "http://" + url.removeprefix("https://")
            if alternate not in seen:
                seen.add(alternate)
                urls.append(alternate)
    return urls


def download(urls: list[str], destination: Path) -> tuple[str, list[dict[str, str]]]:
    attempts: list[dict[str, str]] = []
    headers = {"User-Agent": "hancom-gooroom-arm64-blocker-evidence/1"}
    for url in urls:
        for attempt in range(1, 4):
            partial = destination.with_suffix(destination.suffix + ".partial")
            try:
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=180) as response, partial.open(
                    "wb"
                ) as output:
                    shutil.copyfileobj(response, output, length=1024 * 1024)
                partial.replace(destination)
                attempts.append({"url": url, "status": "downloaded", "attempt": str(attempt)})
                return url, attempts
            except urllib.error.HTTPError as error:
                attempts.append(
                    {
                        "url": url,
                        "status": f"http-{error.code}",
                        "attempt": str(attempt),
                    }
                )
                partial.unlink(missing_ok=True)
                if error.code == 404:
                    break
            except Exception as error:
                attempts.append(
                    {
                        "url": url,
                        "status": f"{type(error).__name__}: {error}",
                        "attempt": str(attempt),
                    }
                )
                partial.unlink(missing_ok=True)
            if attempt < 3:
                time.sleep(2**attempt)
    raise RuntimeError(f"all exact binary URLs failed: {attempts[-8:]}")


def read_text_file(path: Path) -> tuple[str, bool]:
    data = path.read_bytes()
    if path.suffix == ".gz":
        try:
            data = gzip.decompress(data)
        except OSError:
            pass
    truncated = len(data) > MAX_TEXT_BYTES
    if truncated:
        data = data[:MAX_TEXT_BYTES]
    return data.decode("utf-8", "replace"), truncated


def extract_text_evidence(root: Path, output: Path) -> list[dict[str, Any]]:
    patterns = (
        "usr/share/doc/*/changelog.Debian.gz",
        "usr/share/doc/*/changelog.gz",
        "usr/share/doc/*/changelog.Debian",
        "usr/share/doc/*/copyright",
    )
    records: list[dict[str, Any]] = []
    for pattern in patterns:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            text, truncated = read_text_file(path)
            relative = str(path.relative_to(root))
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", relative)
            target = output / f"{safe_name}.txt"
            target.write_text(text, encoding="utf-8")
            tokens = sorted(
                {
                    match.group(1).lower()
                    for match in COMMIT_TOKEN_RE.finditer(text)
                    if len(match.group(1)) >= 7
                },
                key=lambda value: (len(value), value),
            )
            records.append(
                {
                    "source_path": relative,
                    "saved_path": target.name,
                    "sha256": sha256(target),
                    "bytes": target.stat().st_size,
                    "truncated": truncated,
                    "commit_tokens": tokens,
                }
            )
    return records


def elf_build_ids(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for directory, _, files in os.walk(root):
        for filename in files:
            path = Path(directory) / filename
            if path.is_symlink() or not path.is_file():
                continue
            try:
                with path.open("rb") as handle:
                    if handle.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue
            process = run(["readelf", "-n", str(path)])
            build_ids = re.findall(r"Build ID:\s*([0-9a-f]+)", process.stdout, re.I)
            records.append(
                {
                    "path": str(path.relative_to(root)),
                    "size": path.stat().st_size,
                    "sha256": sha256(path),
                    "build_ids": [value.lower() for value in build_ids],
                    "readelf_returncode": process.returncode,
                }
            )
    return records


def choose_record(source: dict[str, Any]) -> dict[str, Any] | None:
    native = [
        record
        for record in source.get("binary_index_records", [])
        if record.get("binary_architecture") == "amd64"
        and not str(record.get("binary_package", "")).endswith("-dbgsym")
    ]
    if not native:
        native = [
            record
            for record in source.get("binary_index_records", [])
            if record.get("binary_architecture") == "amd64"
        ]
    if not native:
        return None
    return min(native, key=lambda record: int(record.get("binary_size", 1 << 62)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unresolved", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    sources = load(args.unresolved)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="hancom-blocker-binary-") as temporary:
        work = Path(temporary)
        for source in sources:
            source_name = source["source"]
            source_version = source["source_version"]
            record = choose_record(source)
            if record is None:
                failures.append(
                    {
                        "source": source_name,
                        "source_version": source_version,
                        "reason": "no-native-amd64-binary-index-record",
                    }
                )
                continue
            package = record["binary_package"]
            version = record["binary_version"]
            architecture = record["binary_architecture"]
            source_dir = args.output_dir / re.sub(r"[^A-Za-z0-9_.+-]+", "_", source_name)
            source_dir.mkdir(parents=True, exist_ok=True)
            deb = work / Path(record["binary_filename"]).name
            try:
                selected_url, attempts = download(candidate_urls(record), deb)
                actual_size = deb.stat().st_size
                actual_sha256 = sha256(deb)
                if actual_size != int(record["binary_size"]):
                    raise RuntimeError(
                        f"size mismatch: {actual_size} != {record['binary_size']}"
                    )
                if actual_sha256 != str(record["binary_sha256"]).lower():
                    raise RuntimeError(
                        f"sha256 mismatch: {actual_sha256} != {record['binary_sha256']}"
                    )
                control_package = deb_field(deb, "Package")
                control_version = deb_field(deb, "Version")
                control_architecture = deb_field(deb, "Architecture")
                control_source_field = deb_field(deb, "Source")
                control_source, control_source_version = source_field(
                    control_source_field, control_package, control_version
                )
                checks = {
                    "package": (control_package, package),
                    "version": (control_version, version),
                    "architecture": (control_architecture, architecture),
                    "source": (control_source, source_name),
                    "source_version": (control_source_version, source_version),
                }
                mismatches = {
                    key: {"actual": actual, "expected": expected}
                    for key, (actual, expected) in checks.items()
                    if actual != expected
                }
                if mismatches:
                    raise RuntimeError(f"control identity mismatch: {mismatches}")

                extract_root = work / f"extract-{source_name}"
                control_root = work / f"control-{source_name}"
                extract_root.mkdir()
                control_root.mkdir()
                extract_process = run(["dpkg-deb", "-x", str(deb), str(extract_root)])
                control_process = run(["dpkg-deb", "-e", str(deb), str(control_root)])
                if extract_process.returncode or control_process.returncode:
                    raise RuntimeError(
                        f"dpkg-deb extraction failed: {extract_process.stderr} {control_process.stderr}"
                    )
                control_texts = []
                for path in sorted(control_root.iterdir()):
                    if path.is_file() and path.stat().st_size <= MAX_TEXT_BYTES:
                        target = source_dir / f"control-{path.name}.txt"
                        target.write_bytes(path.read_bytes())
                        control_texts.append(
                            {
                                "name": path.name,
                                "saved_path": target.name,
                                "sha256": sha256(target),
                                "bytes": target.stat().st_size,
                            }
                        )
                file_list = source_dir / "payload-files.txt"
                file_list.write_text(
                    "".join(
                        f"{path.relative_to(extract_root)}\n"
                        for path in sorted(extract_root.rglob("*"))
                    ),
                    encoding="utf-8",
                )
                text_records = extract_text_evidence(extract_root, source_dir)
                elf_records = elf_build_ids(extract_root)
                manifest = {
                    "schema": 1,
                    "policy": "exact-amd64-binary-provenance-clues-only-not-source",
                    "source": source_name,
                    "source_version": source_version,
                    "selected_binary": {
                        "package": package,
                        "version": version,
                        "architecture": architecture,
                        "filename": deb.name,
                        "url": selected_url,
                        "size": actual_size,
                        "sha256": actual_sha256,
                    },
                    "download_attempts": attempts,
                    "control": {
                        "package": control_package,
                        "version": control_version,
                        "architecture": control_architecture,
                        "source_field": control_source_field,
                        "parsed_source": control_source,
                        "parsed_source_version": control_source_version,
                    },
                    "control_files": control_texts,
                    "text_evidence": text_records,
                    "elf_build_ids": elf_records,
                    "payload_file_list": file_list.name,
                    "passed": True,
                }
                (source_dir / "evidence.json").write_text(
                    json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                results.append(manifest)
            except Exception as error:
                failure = {
                    "source": source_name,
                    "source_version": source_version,
                    "selected_record": record,
                    "reason": f"{type(error).__name__}: {error}",
                }
                failures.append(failure)
                (source_dir / "failure.json").write_text(
                    json.dumps(failure, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )

    summary = {
        "schema": 1,
        "target_count": len(sources),
        "passed_count": len(results),
        "failed_count": len(failures),
        "sources_with_commit_tokens": sum(
            any(record.get("commit_tokens") for record in result["text_evidence"])
            for result in results
        ),
        "complete": len(results) == len(sources) and not failures,
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "failures.json").write_text(
        json.dumps(failures, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
