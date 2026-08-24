#!/usr/bin/env python3
"""Recover exact signed source descriptors from the original vendor APT pool.

The Gooroom/Hancom repositories published binary indexes but no `Sources`
index. The AMD64 ISO preserves the exact 2023 binary `Packages` records. Their
`Filename` fields reveal the source pool directory. This tool constructs only
the exact `.dsc` filename implied by the ISO source version, downloads it,
checks its OpenPGP signature against keyrings extracted from the same ISO, and
accepts it only when the signed Source and Version fields are exact.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import tempfile
import time
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


SOURCE_RE = re.compile(r"^\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*$")


def parse_deb822(text: str) -> Iterable[dict[str, str]]:
    stanza: dict[str, str] = {}
    key: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if stanza:
                yield stanza
                stanza = {}
                key = None
            continue
        if line[0].isspace():
            if key is not None:
                stanza[key] += "\n" + line[1:]
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stanza[key] = value.lstrip()
    if stanza:
        yield stanza


def clearsigned_payload(text: str) -> str:
    marker = "-----BEGIN PGP SIGNED MESSAGE-----"
    signature = "-----BEGIN PGP SIGNATURE-----"
    if not text.startswith(marker):
        return text
    body_start = text.find("\n\n")
    body_end = text.find(signature)
    if body_start < 0 or body_end < 0:
        return text
    lines = text[body_start + 2 : body_end].rstrip("\n").splitlines()
    return "\n".join(line[2:] if line.startswith("- ") else line for line in lines) + "\n"


def parse_source_field(value: str | None, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, version
    match = SOURCE_RE.fullmatch(value)
    if not match:
        return value.strip(), version
    return match.group(1), match.group(2) or version


def parse_checksums(value: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not value:
        return rows
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        digest, size, filename = parts
        rows.append({"sha256": digest, "size": int(size), "name": filename})
    return rows


def target_sources(reference_path: Path) -> list[dict[str, Any]]:
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    packages: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for package in reference["packages"]:
        packages[(package["source"], package["source_version"])].append(package)

    rows: list[dict[str, Any]] = []
    for source in reference["sources"]:
        if not source.get("custom_candidate"):
            continue
        members = packages[(source["source"], source["source_version"])]
        architectures = sorted({member["architecture"] for member in members})
        rows.append(
            {
                "source": source["source"],
                "source_version": source["source_version"],
                "role": "reuse-all" if architectures == ["all"] else "rebuild-arm64",
                "binary_packages": sorted(member["package"] for member in members),
                "binary_versions": {
                    member["package"]: member["version"] for member in members
                },
                "binary_architectures": architectures,
            }
        )
    return sorted(rows, key=lambda row: row["source"])


def download(url: str, *, timeout: int = 60) -> bytes | None:
    headers = {"User-Agent": "hancom-gooroom-arm64-source-recovery/1"}
    for attempt in range(4):
        try:
            with urlopen(Request(url, headers=headers), timeout=timeout) as response:
                return response.read()
        except HTTPError as error:
            if error.code == 404:
                return None
            if error.code not in {429, 500, 502, 503, 504} or attempt == 3:
                raise
        except URLError:
            if attempt == 3:
                raise
        time.sleep(2**attempt)
    return None


def verify_signature(data: bytes, keyrings: list[Path]) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile(suffix=".dsc") as handle:
        handle.write(data)
        handle.flush()
        command = ["gpgv"]
        for keyring in keyrings:
            command.extend(["--keyring", str(keyring)])
        command.append(handle.name)
        process = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    diagnostic = (process.stdout + "\n" + process.stderr).strip()
    return process.returncode == 0, diagnostic


def source_version_filename(version: str) -> str:
    return version.split(":", 1)[-1]


def repository_preference(version: str) -> tuple[str, ...]:
    if "+han" in version.lower():
        return ("hancom", "gooroom")
    return ("gooroom", "hancom")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--packages", action="append", type=Path, required=True)
    parser.add_argument("--packages-metadata", action="append", required=True)
    parser.add_argument("--keyring", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    if len(args.packages) != len(args.packages_metadata):
        parser.error("--packages and --packages-metadata counts must match")

    binary_records: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    index_evidence: list[dict[str, Any]] = []
    for path, metadata_text in zip(args.packages, args.packages_metadata):
        metadata = json.loads(metadata_text)
        count = 0
        for stanza in parse_deb822(path.read_text(encoding="utf-8", errors="replace")):
            package = stanza.get("Package", "")
            version = stanza.get("Version", "")
            filename = stanza.get("Filename", "")
            if not package or not version or not filename:
                continue
            source, source_version = parse_source_field(
                stanza.get("Source"), package, version
            )
            binary_records[(package, version)].append(
                {
                    **metadata,
                    "package": package,
                    "version": version,
                    "source": source,
                    "source_version": source_version,
                    "filename": filename,
                    "sha256": stanza.get("SHA256", ""),
                    "size": int(stanza.get("Size", "0") or 0),
                }
            )
            count += 1
        index_evidence.append({**metadata, "path": str(path), "record_count": count})

    output_dsc = args.output_dir / "dsc"
    output_dsc.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []

    for target in target_sources(args.reference):
        pool_candidates: dict[tuple[str, str], dict[str, Any]] = {}
        evidence: list[dict[str, Any]] = []
        for package in target["binary_packages"]:
            binary_version = target["binary_versions"][package]
            for record in binary_records.get((package, binary_version), []):
                evidence.append(record)
                if (record["source"], record["source_version"]) != (
                    target["source"],
                    target["source_version"],
                ):
                    continue
                directory = str(PurePosixPath(record["filename"]).parent)
                pool_candidates[(record["repository"], directory)] = {
                    "repository": record["repository"],
                    "suite": record["suite"],
                    "base_url": record["base_url"].rstrip("/"),
                    "directory": directory,
                }

        dsc_name = (
            f"{target['source']}_{source_version_filename(target['source_version'])}.dsc"
        )
        exact_candidates: list[dict[str, Any]] = []
        probe_errors: list[dict[str, str]] = []
        for pool in pool_candidates.values():
            for scheme in ("https", "http"):
                base = re.sub(r"^https?", scheme, pool["base_url"])
                url = f"{base}/{pool['directory']}/{quote(dsc_name, safe='+~._-')}"
                try:
                    data = download(url)
                except Exception as error:
                    probe_errors.append({"url": url, "error": repr(error)})
                    continue
                if data is None:
                    continue

                text = data.decode("utf-8", "replace")
                payload = clearsigned_payload(text)
                stanzas = list(parse_deb822(payload))
                descriptor = stanzas[0] if stanzas else {}
                signed_source = descriptor.get("Source", "")
                signed_version = descriptor.get("Version", "")
                signature_valid, signature_diagnostic = verify_signature(
                    data, args.keyring
                )
                files = parse_checksums(descriptor.get("Checksums-Sha256"))
                candidate = {
                    **pool,
                    "url": url,
                    "dsc_name": dsc_name,
                    "dsc_sha256": hashlib.sha256(data).hexdigest(),
                    "dsc_size": len(data),
                    "signed_source": signed_source,
                    "signed_version": signed_version,
                    "signature_valid": signature_valid,
                    "signature_diagnostic": signature_diagnostic,
                    "files": files,
                    "source_urls": [
                        f"{base}/{pool['directory']}/{quote(file['name'], safe='+~._-')}"
                        for file in files
                    ],
                }
                if (
                    signed_source == target["source"]
                    and signed_version == target["source_version"]
                    and signature_valid
                    and files
                ):
                    local_name = (
                        f"{target['source']}__"
                        f"{hashlib.sha256(data).hexdigest()[:16]}.dsc"
                    )
                    (output_dsc / local_name).write_bytes(data)
                    candidate["saved_dsc"] = f"dsc/{local_name}"
                    exact_candidates.append(candidate)
                else:
                    probe_errors.append(
                        {
                            "url": url,
                            "error": "descriptor failed exact Source/Version/signature/files gate",
                        }
                    )
                break

        row: dict[str, Any] = {
            **target,
            "dsc_name": dsc_name,
            "binary_index_evidence": evidence,
            "pool_candidates": sorted(
                pool_candidates.values(),
                key=lambda candidate: (candidate["repository"], candidate["directory"]),
            ),
            "exact_candidates": exact_candidates,
            "probe_errors": probe_errors,
            "status": "missing-exact-signed-dsc",
            "selected": None,
        }
        if exact_candidates:
            rank = {
                repository: index
                for index, repository in enumerate(
                    repository_preference(target["source_version"])
                )
            }
            best_rank = min(
                rank.get(candidate["repository"], 99)
                for candidate in exact_candidates
            )
            authoritative = [
                candidate
                for candidate in exact_candidates
                if rank.get(candidate["repository"], 99) == best_rank
            ]
            identities = {
                (
                    candidate["dsc_sha256"],
                    tuple(
                        sorted(
                            (file["name"], file["size"], file["sha256"])
                            for file in candidate["files"]
                        )
                    ),
                )
                for candidate in authoritative
            }
            if len(identities) == 1:
                authoritative.sort(key=lambda candidate: candidate["url"])
                row["selected"] = authoritative[0]
                row["status"] = "resolved"
            else:
                row["status"] = "ambiguous-exact-signed-dsc"
        rows.append(row)

    unresolved = [row for row in rows if row["status"] != "resolved"]
    rebuild_unresolved = [
        row
        for row in unresolved
        if row["role"] == "rebuild-arm64"
        and row["source"] != "linux-signed-amd64"
    ]
    summary = {
        "schema": 1,
        "policy": "exact-signed-dsc-from-iso-preserved-binary-index",
        "index_evidence": index_evidence,
        "source_target_count": len(rows),
        "resolved_count": sum(row["status"] == "resolved" for row in rows),
        "unresolved_count": len(unresolved),
        "rebuild_unresolved_count": len(rebuild_unresolved),
    }

    (args.output_dir / "vendor-pool-source-lock.json").write_text(
        json.dumps({"summary": summary, "sources": rows}, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "vendor-pool-source-lock-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output_dir / "vendor-pool-source-unresolved.json").write_text(
        json.dumps(unresolved, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output_dir / "vendor-pool-rebuild-blockers.json").write_text(
        json.dumps(rebuild_unresolved, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    fields = [
        "source",
        "source_version",
        "role",
        "status",
        "repository",
        "directory",
        "dsc_name",
        "dsc_sha256",
        "url",
    ]
    with (args.output_dir / "vendor-pool-source-lock.tsv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in rows:
            selected = row.get("selected") or {}
            writer.writerow(
                {
                    "source": row["source"],
                    "source_version": row["source_version"],
                    "role": row["role"],
                    "status": row["status"],
                    "repository": selected.get("repository", ""),
                    "directory": selected.get("directory", ""),
                    "dsc_name": row["dsc_name"],
                    "dsc_sha256": selected.get("dsc_sha256", ""),
                    "url": selected.get("url", ""),
                }
            )

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 2 if rebuild_unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main())
