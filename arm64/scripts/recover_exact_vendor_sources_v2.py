#!/usr/bin/env python3
"""Recover exact vendor source packages from ISO-preserved APT metadata.

GitHub is preferred, but some Hancom/Gooroom 3.3 source versions are absent
from the public Git history. The AMD64 ISO preserves the exact binary Packages
records and vendor keyrings. For each unresolved native source this tool:

* requires an exact Source and source Version match in those Packages records;
* derives the source pool directory from the exact binary Filename field;
* downloads only the exact Debian .dsc filename implied by that version;
* verifies the clear-signature with keyrings extracted from the same ISO;
* requires exact Source/Version inside the signed descriptor;
* downloads every referenced source component and verifies SHA-256 and size;
* rejects conflicting exact descriptors instead of choosing one silently.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


BINNMU_RE = re.compile(r"\+b\d+$")
SOURCE_RE = re.compile(r"^\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*$")


def parse_deb822(text: str) -> Iterable[dict[str, str]]:
    stanza: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if stanza:
                yield stanza
                stanza = {}
                current = None
            continue
        if line[0].isspace():
            if current:
                stanza[current] += "\n" + line[1:]
            continue
        if ":" not in line:
            continue
        current, value = line.split(":", 1)
        stanza[current] = value.lstrip()
    if stanza:
        yield stanza


def parse_source(value: str | None, package: str, binary_version: str) -> tuple[str, str]:
    if not value:
        return package, BINNMU_RE.sub("", binary_version)
    match = SOURCE_RE.fullmatch(value)
    if not match:
        return value.strip(), BINNMU_RE.sub("", binary_version)
    return match.group(1), match.group(2) or BINNMU_RE.sub("", binary_version)


def clearsigned_payload(text: str) -> str:
    if not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        return text
    start = text.find("\n\n")
    end = text.find("-----BEGIN PGP SIGNATURE-----")
    if start < 0 or end < 0:
        return text
    lines = text[start + 2 : end].rstrip("\n").splitlines()
    return "\n".join(line[2:] if line.startswith("- ") else line for line in lines) + "\n"


def checksum_rows(value: str | None, algorithm: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not value:
        return rows
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        digest, raw_size, filename = parts
        try:
            size = int(raw_size)
        except ValueError:
            continue
        rows.append({algorithm: digest.lower(), "size": size, "name": filename})
    return rows


def source_filename_version(version: str) -> str:
    return version.split(":", 1)[-1]


def quote_path(path: str) -> str:
    return "/".join(
        urllib.parse.quote(part, safe="+~._-:") for part in path.split("/")
    )


def fetch_bytes(url: str, limit: int = 16 * 1024 * 1024) -> bytes | None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "hancom-gooroom-arm64-source-recovery-v2/1"},
    )
    for attempt in range(5):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > limit:
                    raise RuntimeError(f"descriptor exceeds size limit: {content_length}")
                data = response.read(limit + 1)
                if len(data) > limit:
                    raise RuntimeError("descriptor exceeds size limit")
                return data
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            if error.code not in {408, 429, 500, 502, 503, 504} or attempt == 4:
                raise
        except urllib.error.URLError:
            if attempt == 4:
                raise
        time.sleep(2**attempt)
    return None


def stream_verify(url: str, expected_size: int, expected_sha256: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "hancom-gooroom-arm64-source-recovery-v2/1"},
    )
    error_text = ""
    for attempt in range(1, 6):
        digest = hashlib.sha256()
        size = 0
        try:
            with urllib.request.urlopen(request, timeout=240) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
            actual_sha256 = digest.hexdigest()
            if size != expected_size:
                raise RuntimeError(f"size {size} != {expected_size}")
            if actual_sha256 != expected_sha256.lower():
                raise RuntimeError(
                    f"sha256 {actual_sha256} != {expected_sha256.lower()}"
                )
            return {
                "url": url,
                "size": size,
                "sha256": actual_sha256,
                "verified": True,
                "attempts": attempt,
            }
        except Exception as error:  # retained as evidence on final attempt
            error_text = f"{type(error).__name__}: {error}"
            if attempt < 5:
                time.sleep(2 ** (attempt - 1))
    return {
        "url": url,
        "size": size,
        "sha256": digest.hexdigest(),
        "verified": False,
        "attempts": 5,
        "error": error_text,
    }


def verify_signature(data: bytes, keyrings: list[Path]) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile(suffix=".dsc") as handle:
        handle.write(data)
        handle.flush()
        command = ["gpgv", "--status-fd", "1"]
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


def target_sources(reference: dict[str, Any], existing: dict[str, Any]) -> list[dict[str, Any]]:
    packages: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for package in reference.get("packages", []):
        packages[(package["source"], package["source_version"])].append(package)

    resolved = {
        (row.get("source"), row.get("source_version"))
        for row in existing.get("sources", [])
        if row.get("status") in {"resolved", "arch-replace"}
    }
    rows: list[dict[str, Any]] = []
    for source in reference.get("sources", []):
        key = (source["source"], source["source_version"])
        if not source.get("custom_candidate") or key in resolved:
            continue
        members = packages.get(key, [])
        native = sorted(
            {member["package"] for member in members if member["architecture"] == "amd64"}
        )
        if not native:
            continue
        if source["source"] == "linux-signed-amd64":
            continue
        rows.append(
            {
                "source": source["source"],
                "source_version": source["source_version"],
                "binary_packages": sorted(member["package"] for member in members),
                "native_binary_packages": native,
                "role": "rebuild-arm64",
            }
        )
    return sorted(rows, key=lambda row: (row["source"], row["source_version"]))


def load_binary_records(specifications: list[str]) -> tuple[dict[tuple[str, str], list[dict[str, Any]]], list[dict[str, Any]]]:
    records: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    evidence: list[dict[str, Any]] = []
    for specification in specifications:
        metadata_text, raw_path = specification.split("::", 1)
        metadata = json.loads(metadata_text)
        path = Path(raw_path)
        count = 0
        for stanza in parse_deb822(path.read_text(encoding="utf-8", errors="replace")):
            package = stanza.get("Package", "")
            version = stanza.get("Version", "")
            filename = stanza.get("Filename", "")
            if not package or not version or not filename:
                continue
            source, source_version = parse_source(stanza.get("Source"), package, version)
            records[(source, source_version)].append(
                {
                    **metadata,
                    "binary_package": package,
                    "binary_version": version,
                    "binary_architecture": stanza.get("Architecture", ""),
                    "binary_filename": filename,
                    "binary_sha256": stanza.get("SHA256", "").lower(),
                    "binary_size": int(stanza.get("Size", "0") or 0),
                    "source": source,
                    "source_version": source_version,
                }
            )
            count += 1
        evidence.append({**metadata, "path": str(path), "record_count": count})
    return records, evidence


def candidate_urls(target: dict[str, Any], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dsc_name = f"{target['source']}_{source_filename_version(target['source_version'])}.dsc"
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        directory = str(Path(record["binary_filename"]).parent).replace(os.sep, "/")
        bases = [record["base_url"]]
        # An exact +han version normally lives in hancom, while +grm normally
        # lives in gooroom. Trying the sibling archive is discovery only; the
        # signed descriptor remains the version authority.
        if "/hancom" in record["base_url"]:
            bases.append(record["base_url"].replace("/hancom", "/gooroom"))
        elif "/gooroom" in record["base_url"]:
            bases.append(record["base_url"].replace("/gooroom", "/hancom"))
        for base in bases:
            for scheme in ("https", "http"):
                normalized = re.sub(r"^https?", scheme, base.rstrip("/"))
                url = f"{normalized}/{quote_path(directory)}/{quote_path(dsc_name)}"
                candidates[(url, directory)] = {
                    "repository": record["repository"],
                    "suite": record["suite"],
                    "base_url": normalized,
                    "directory": directory,
                    "dsc_name": dsc_name,
                    "url": url,
                }
    return sorted(candidates.values(), key=lambda row: row["url"])


def resolve_target(
    target: dict[str, Any],
    records: list[dict[str, Any]],
    keyrings: list[Path],
    dsc_output: Path,
    component_workers: int,
) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    exact: list[dict[str, Any]] = []
    for candidate in candidate_urls(target, records):
        attempt = dict(candidate)
        try:
            data = fetch_bytes(candidate["url"])
        except Exception as error:
            attempt.update(status="download-error", error=f"{type(error).__name__}: {error}")
            attempts.append(attempt)
            continue
        if data is None:
            attempt["status"] = "not-found"
            attempts.append(attempt)
            continue

        attempt["dsc_size"] = len(data)
        attempt["dsc_sha256"] = hashlib.sha256(data).hexdigest()
        signature_valid, signature_diagnostic = verify_signature(data, keyrings)
        attempt["signature_valid"] = signature_valid
        attempt["signature_diagnostic"] = signature_diagnostic
        payload = clearsigned_payload(data.decode("utf-8", "replace"))
        stanzas = list(parse_deb822(payload))
        descriptor = stanzas[0] if stanzas else {}
        attempt["declared_source"] = descriptor.get("Source", "")
        attempt["declared_version"] = descriptor.get("Version", "")
        components = checksum_rows(descriptor.get("Checksums-Sha256"), "sha256")
        attempt["components"] = components

        if not signature_valid:
            attempt["status"] = "bad-signature"
            attempts.append(attempt)
            continue
        if (
            descriptor.get("Source") != target["source"]
            or descriptor.get("Version") != target["source_version"]
        ):
            attempt["status"] = "source-version-mismatch"
            attempts.append(attempt)
            continue
        if not components:
            attempt["status"] = "missing-sha256-components"
            attempts.append(attempt)
            continue

        component_jobs = []
        for component in components:
            component_url = (
                f"{candidate['base_url'].rstrip('/')}/"
                f"{quote_path(candidate['directory'])}/{quote_path(component['name'])}"
            )
            component_jobs.append((component, component_url))
        component_results: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, component_workers)
        ) as executor:
            futures = {
                executor.submit(
                    stream_verify,
                    url,
                    component["size"],
                    component["sha256"],
                ): (component, url)
                for component, url in component_jobs
            }
            for future in concurrent.futures.as_completed(futures):
                component, url = futures[future]
                result = future.result()
                component_results.append({**component, **result})
        component_results.sort(key=lambda row: row["name"])
        attempt["component_results"] = component_results
        if not all(result.get("verified") is True for result in component_results):
            attempt["status"] = "component-verification-failed"
            attempts.append(attempt)
            continue

        saved_name = (
            f"{target['source']}__{source_filename_version(target['source_version'])}__"
            f"{attempt['dsc_sha256'][:16]}.dsc"
        )
        dsc_output.mkdir(parents=True, exist_ok=True)
        (dsc_output / saved_name).write_bytes(data)
        attempt["saved_dsc"] = f"dsc/{saved_name}"
        attempt["status"] = "exact-signed-source-verified"
        attempts.append(attempt)
        exact.append(attempt)

    row: dict[str, Any] = {
        **target,
        "status": "unresolved",
        "selected": None,
        "binary_index_records": records,
        "attempts": attempts,
    }
    if not exact:
        return row

    identities = {
        (
            candidate["dsc_sha256"],
            tuple(
                (component["name"], component["size"], component["sha256"])
                for component in candidate["component_results"]
            ),
        )
        for candidate in exact
    }
    if len(identities) != 1:
        row["status"] = "ambiguous-exact-source"
        return row

    repository_order = (
        ("hancom", "gooroom")
        if "+han" in target["source_version"].lower()
        else ("gooroom", "hancom")
    )
    rank = {repository: index for index, repository in enumerate(repository_order)}
    exact.sort(key=lambda candidate: (rank.get(candidate["repository"], 99), candidate["url"]))
    selected = exact[0]
    row["status"] = "resolved"
    row["selected"] = {
        "type": "dsc",
        "provenance": "iso-preserved-vendor-binary-index",
        "repository": selected["repository"],
        "suite": selected["suite"],
        "base_url": selected["base_url"],
        "directory": selected["directory"],
        "url": selected["url"],
        "dsc_name": selected["dsc_name"],
        "dsc_sha256": selected["dsc_sha256"],
        "dsc_size": selected["dsc_size"],
        "signature_valid": True,
        "declared_source": selected["declared_source"],
        "declared_version": selected["declared_version"],
        "components": selected["component_results"],
        "saved_dsc": selected["saved_dsc"],
    }
    return row


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--existing-lock", type=Path, required=True)
    parser.add_argument("--packages-index", action="append", required=True)
    parser.add_argument("--keyring", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--component-workers", type=int, default=3)
    args = parser.parse_args()

    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    existing = json.loads(args.existing_lock.read_text(encoding="utf-8"))
    records, index_evidence = load_binary_records(args.packages_index)
    targets = target_sources(reference, existing)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any] | None] = [None] * len(targets)

    def work(item: tuple[int, dict[str, Any]]) -> tuple[int, dict[str, Any]]:
        index, target = item
        row = resolve_target(
            target,
            records.get((target["source"], target["source_version"]), []),
            args.keyring,
            args.output_dir / "dsc",
            args.component_workers,
        )
        return index, row

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, args.workers)
    ) as executor:
        futures = {executor.submit(work, item): item for item in enumerate(targets)}
        for future in concurrent.futures.as_completed(futures):
            index, target = futures[future]
            try:
                resolved_index, row = future.result()
            except Exception as error:
                resolved_index = index
                row = {
                    **target,
                    "status": "resolver-exception",
                    "selected": None,
                    "error": f"{type(error).__name__}: {error}",
                }
            rows[resolved_index] = row
            print(
                f"{row['source']} {row['source_version']}: {row['status']}",
                flush=True,
            )

    complete = [row for row in rows if row is not None]
    unresolved = [row for row in complete if row["status"] != "resolved"]
    summary = {
        "schema": 2,
        "policy": "exact-signed-dsc-and-all-component-sha256",
        "index_evidence": index_evidence,
        "target_count": len(complete),
        "resolved_count": sum(row["status"] == "resolved" for row in complete),
        "unresolved_count": len(unresolved),
        "all_blocking_sources_recovered": not unresolved,
    }
    (args.output_dir / "apt-source-fallback-lock.json").write_text(
        json.dumps({"summary": summary, "sources": complete}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "unresolved.json").write_text(
        json.dumps(unresolved, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    with (args.output_dir / "lock.tsv").open("w", encoding="utf-8", newline="") as handle:
        fields = [
            "source",
            "source_version",
            "status",
            "repository",
            "url",
            "dsc_sha256",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in complete:
            selected = row.get("selected") or {}
            writer.writerow(
                {
                    "source": row["source"],
                    "source_version": row["source_version"],
                    "status": row["status"],
                    "repository": selected.get("repository", ""),
                    "url": selected.get("url", ""),
                    "dsc_sha256": selected.get("dsc_sha256", ""),
                }
            )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not unresolved else 2


if __name__ == "__main__":
    raise SystemExit(main())
