#!/usr/bin/env python3
"""Recover exact vendor source packages through the ISO-preserved signed Sources index.

Trust chain (fail closed):

1. The Hancom Gooroom 3.3 reference ISO is hash-locked by the workflow.
2. Vendor InRelease files and archive keyrings are extracted from that ISO.
3. gpgv must validate each InRelease with those ISO-preserved keyrings.
4. Sources.gz and its decompressed Sources bytes must match the size and
   SHA-256 recorded in the signed InRelease payload.
5. A target Source/Version must occur exactly in that authenticated Sources
   index. Its exact Directory and Checksums-Sha256 fields are authoritative.
6. The .dsc and every source component are downloaded from that Directory and
   verified against the authenticated source stanza.
7. The .dsc must independently declare the exact Source/Version, and every
   component checksum in it must agree with the authenticated source stanza.

No path is guessed from binary package filenames, and no version string alone
can promote a source lock.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

USER_AGENT = "hancom-gooroom-arm64-signed-sources-index-recovery-v1/1"
RETRYABLE_HTTP = {408, 425, 429, 500, 502, 503, 504}
MAX_DSC_BYTES = 8 * 1024 * 1024


class RecoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class Target:
    source: str
    version: str
    binary_packages: tuple[str, ...]
    native_binary_packages: tuple[str, ...]
    reused_all_packages: tuple[str, ...]


@dataclass(frozen=True)
class RepositorySpec:
    repository: str
    suite: str
    base_url: str
    inrelease: Path


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+~-]", "_", value)


def quote_path(path: str) -> str:
    return "/".join(
        urllib.parse.quote(part, safe="+~._-:") for part in path.split("/")
    )


def clearsigned_payload(text: str) -> str:
    if not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        return text
    start = text.find("\n\n")
    end = text.find("-----BEGIN PGP SIGNATURE-----")
    if start < 0 or end < 0 or end <= start:
        raise RecoveryError("malformed clearsigned document")
    lines = text[start + 2 : end].rstrip("\n").splitlines()
    return "\n".join(line[2:] if line.startswith("- ") else line for line in lines) + "\n"


def parse_deb822_blocks(text: str) -> Iterator[tuple[dict[str, str], str]]:
    block: list[str] = []
    for line in text.splitlines():
        if line.strip():
            block.append(line)
            continue
        if block:
            yield parse_deb822_block(block)
            block = []
    if block:
        yield parse_deb822_block(block)


def parse_deb822_block(block: list[str]) -> tuple[dict[str, str], str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in block:
        if line.startswith((" ", "\t")):
            if current is not None:
                fields[current] += "\n" + line[1:]
            continue
        if ":" not in line:
            continue
        current, value = line.split(":", 1)
        fields[current] = value.lstrip()
    return fields, "\n".join(block) + "\n"


def parse_checksum_rows(value: str | None, algorithm: str = "sha256") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not value:
        return rows
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        checksum, raw_size, name = parts
        try:
            size = int(raw_size)
        except ValueError:
            continue
        rows.append(
            {
                "name": name,
                "size": size,
                algorithm: checksum.lower(),
            }
        )
    return rows


def verify_signature(path: Path, keyrings: list[Path]) -> dict[str, Any]:
    command = ["gpgv", "--status-fd", "1"]
    for keyring in keyrings:
        command.extend(["--keyring", str(keyring)])
    command.append(str(path))
    process = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    diagnostic = (process.stdout + "\n" + process.stderr).strip()
    return {
        "valid": process.returncode == 0,
        "exit_code": process.returncode,
        "diagnostic": diagnostic,
        "keyrings": [str(path) for path in keyrings],
    }


def repository_spec(raw: str) -> RepositorySpec:
    value = json.loads(raw)
    required = ("repository", "suite", "base_url", "inrelease")
    missing = [key for key in required if not value.get(key)]
    if missing:
        raise RecoveryError(f"repository specification missing: {', '.join(missing)}")
    return RepositorySpec(
        repository=str(value["repository"]),
        suite=str(value["suite"]),
        base_url=str(value["base_url"]).rstrip("/"),
        inrelease=Path(value["inrelease"]),
    )


def scheme_variants(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        return [url]
    schemes = [parsed.scheme, "http" if parsed.scheme == "https" else "https"]
    rows: list[str] = []
    for scheme in schemes:
        candidate = urllib.parse.urlunsplit(
            (scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)
        )
        if candidate not in rows:
            rows.append(candidate)
    return rows


def download_exact(
    urls: Iterable[str],
    destination: Path,
    expected_size: int,
    expected_sha256: str,
    *,
    attempts_per_url: int = 4,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    expected_sha256 = expected_sha256.lower()
    evidence: list[dict[str, Any]] = []
    for url in urls:
        for attempt in range(1, attempts_per_url + 1):
            temporary = destination.with_name(destination.name + f".part-{os.getpid()}")
            temporary.unlink(missing_ok=True)
            digest = hashlib.sha256()
            size = 0
            final_url = ""
            status_code: int | None = None
            content_type = ""
            try:
                request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(request, timeout=240) as response, temporary.open("wb") as handle:
                    status_code = getattr(response, "status", None)
                    final_url = response.geturl()
                    content_type = response.headers.get("Content-Type", "")
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > expected_size:
                            raise RecoveryError(
                                f"download exceeded exact expected size {expected_size}"
                            )
                        digest.update(chunk)
                        handle.write(chunk)
                actual_sha256 = digest.hexdigest()
                if size != expected_size:
                    raise RecoveryError(f"size {size} != {expected_size}")
                if actual_sha256 != expected_sha256:
                    raise RecoveryError(
                        f"sha256 {actual_sha256} != {expected_sha256}"
                    )
                temporary.replace(destination)
                selected = {
                    "url": url,
                    "final_url": final_url or url,
                    "status_code": status_code,
                    "content_type": content_type,
                    "attempt": attempt,
                    "size": size,
                    "sha256": actual_sha256,
                    "verified": True,
                }
                evidence.append(selected)
                return selected, evidence
            except urllib.error.HTTPError as error:
                temporary.unlink(missing_ok=True)
                row = {
                    "url": url,
                    "attempt": attempt,
                    "status": "http-error",
                    "status_code": error.code,
                    "error": str(error),
                    "verified": False,
                }
                evidence.append(row)
                if error.code == 404:
                    break
                if error.code not in RETRYABLE_HTTP or attempt == attempts_per_url:
                    break
            except Exception as error:
                temporary.unlink(missing_ok=True)
                evidence.append(
                    {
                        "url": url,
                        "attempt": attempt,
                        "status": "download-or-verification-error",
                        "actual_size": size,
                        "actual_sha256": digest.hexdigest(),
                        "error": f"{type(error).__name__}: {error}",
                        "verified": False,
                    }
                )
                if attempt == attempts_per_url:
                    break
            time.sleep(min(16, 2 ** (attempt - 1)))
    destination.unlink(missing_ok=True)
    return None, evidence


def load_targets(reference_path: Path, targets_path: Path) -> list[Target]:
    reference = load_json(reference_path)
    requested = load_json(targets_path)
    if not isinstance(requested, list):
        raise RecoveryError("target file must contain a JSON array")

    known_sources = {
        (row.get("source"), row.get("source_version"))
        for row in reference.get("sources", [])
    }
    packages: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for package in reference.get("packages", []):
        packages[(package.get("source"), package.get("source_version"))].append(package)

    targets: list[Target] = []
    seen: set[tuple[str, str]] = set()
    for row in requested:
        source = str(row.get("source", ""))
        version = str(row.get("source_version", ""))
        key = (source, version)
        if not source or not version:
            raise RecoveryError(f"invalid target row: {row!r}")
        if key in seen:
            continue
        seen.add(key)
        if key not in known_sources:
            raise RecoveryError(f"target is absent from reference: {source} {version}")
        members = packages.get(key, [])
        if not members:
            raise RecoveryError(f"target has no binary members: {source} {version}")
        native = sorted(
            {
                str(member["package"])
                for member in members
                if member.get("architecture") == "amd64"
            }
        )
        reused = sorted(
            {
                str(member["package"])
                for member in members
                if member.get("architecture") == "all"
            }
        )
        if not native:
            raise RecoveryError(f"target is not a native rebuild: {source} {version}")
        targets.append(
            Target(
                source=source,
                version=version,
                binary_packages=tuple(
                    sorted({str(member["package"]) for member in members})
                ),
                native_binary_packages=tuple(native),
                reused_all_packages=tuple(reused),
            )
        )
    return sorted(targets, key=lambda item: (item.source, item.version))


def release_entry(fields: dict[str, str], path: str) -> dict[str, Any]:
    for row in parse_checksum_rows(fields.get("SHA256"), "sha256"):
        if row["name"] == path:
            return row
    raise RecoveryError(f"signed InRelease has no SHA256 entry for {path}")


def source_index_url(base_url: str, suite: str, relative_path: str) -> str:
    return (
        f"{base_url.rstrip('/')}/dists/{quote_path(suite)}/"
        f"{quote_path(relative_path)}"
    )


def authenticate_source_index(
    spec: RepositorySpec,
    keyrings: list[Path],
    output_dir: Path,
) -> dict[str, Any]:
    if not spec.inrelease.is_file():
        return {
            "repository": spec.repository,
            "suite": spec.suite,
            "base_url": spec.base_url,
            "status": "missing-inrelease",
            "inrelease": str(spec.inrelease),
            "usable": False,
        }

    signature = verify_signature(spec.inrelease, keyrings)
    inrelease_bytes = spec.inrelease.read_bytes()
    evidence: dict[str, Any] = {
        "repository": spec.repository,
        "suite": spec.suite,
        "base_url": spec.base_url,
        "inrelease": str(spec.inrelease),
        "inrelease_size": len(inrelease_bytes),
        "inrelease_sha256": sha256_bytes(inrelease_bytes),
        "inrelease_signature": signature,
        "usable": False,
    }
    if not signature["valid"]:
        evidence["status"] = "invalid-inrelease-signature"
        return evidence

    try:
        payload = clearsigned_payload(inrelease_bytes.decode("utf-8", "replace"))
        stanzas = list(parse_deb822_blocks(payload))
        if len(stanzas) != 1:
            raise RecoveryError(f"InRelease payload has {len(stanzas)} stanzas")
        fields, _raw = stanzas[0]
        if fields.get("Suite") != spec.suite or fields.get("Codename") != spec.suite:
            raise RecoveryError(
                f"suite/codename mismatch: {fields.get('Suite')} / {fields.get('Codename')}"
            )
        compressed = release_entry(fields, "main/source/Sources.gz")
        uncompressed = release_entry(fields, "main/source/Sources")
    except Exception as error:
        evidence.update(
            status="invalid-inrelease-payload",
            error=f"{type(error).__name__}: {error}",
        )
        return evidence

    index_root = output_dir / "indexes" / safe_name(spec.repository)
    compressed_path = index_root / "Sources.gz"
    uncompressed_path = index_root / "Sources"
    candidate_urls: list[str] = []
    for base in scheme_variants(spec.base_url):
        candidate = source_index_url(base, spec.suite, "main/source/Sources.gz")
        if candidate not in candidate_urls:
            candidate_urls.append(candidate)
    selected, attempts = download_exact(
        candidate_urls,
        compressed_path,
        int(compressed["size"]),
        str(compressed["sha256"]),
    )
    evidence.update(
        signed_release={
            "origin": fields.get("Origin", ""),
            "label": fields.get("Label", ""),
            "suite": fields.get("Suite", ""),
            "codename": fields.get("Codename", ""),
            "date": fields.get("Date", ""),
            "architectures": fields.get("Architectures", ""),
            "components": fields.get("Components", ""),
        },
        compressed_index_expected=compressed,
        uncompressed_index_expected=uncompressed,
        index_download_attempts=attempts,
    )
    if selected is None:
        evidence["status"] = "exact-sources-index-unavailable"
        return evidence

    try:
        decompressed = gzip.decompress(compressed_path.read_bytes())
    except Exception as error:
        evidence.update(
            status="sources-index-decompression-failed",
            error=f"{type(error).__name__}: {error}",
        )
        return evidence
    actual_uncompressed_sha256 = sha256_bytes(decompressed)
    if len(decompressed) != int(uncompressed["size"]):
        evidence.update(
            status="uncompressed-sources-size-mismatch",
            actual_uncompressed_size=len(decompressed),
            actual_uncompressed_sha256=actual_uncompressed_sha256,
        )
        return evidence
    if actual_uncompressed_sha256 != str(uncompressed["sha256"]).lower():
        evidence.update(
            status="uncompressed-sources-sha256-mismatch",
            actual_uncompressed_size=len(decompressed),
            actual_uncompressed_sha256=actual_uncompressed_sha256,
        )
        return evidence

    uncompressed_path.write_bytes(decompressed)
    source_stanzas = list(
        parse_deb822_blocks(decompressed.decode("utf-8", errors="replace"))
    )
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for source_fields, raw in source_stanzas:
        package = source_fields.get("Package", "")
        version = source_fields.get("Version", "")
        if package and version:
            by_key[(package, version)].append(
                {
                    "fields": source_fields,
                    "raw": raw,
                    "raw_sha256": sha256_bytes(raw.encode("utf-8")),
                }
            )

    evidence.update(
        status="exact-signed-sources-index-verified",
        usable=True,
        selected_index_download=selected,
        compressed_index_path=str(compressed_path),
        uncompressed_index_path=str(uncompressed_path),
        actual_uncompressed_size=len(decompressed),
        actual_uncompressed_sha256=actual_uncompressed_sha256,
        source_stanza_count=len(source_stanzas),
        exact_stanzas=by_key,
    )
    return evidence


def file_url_candidates(base_url: str, directory: str, filename: str) -> list[str]:
    rows: list[str] = []
    for base in scheme_variants(base_url):
        url = f"{base.rstrip('/')}/{quote_path(directory)}/{quote_path(filename)}"
        if url not in rows:
            rows.append(url)
    return rows


def verify_descriptor(
    dsc_path: Path,
    target: Target,
    source_index_files: dict[str, dict[str, Any]],
    keyrings: list[Path],
) -> tuple[dict[str, Any] | None, str | None]:
    data = dsc_path.read_bytes()
    if len(data) > MAX_DSC_BYTES:
        return None, f"descriptor exceeds limit: {len(data)}"
    text = data.decode("utf-8", "replace")
    is_clearsigned = text.startswith("-----BEGIN PGP SIGNED MESSAGE-----")
    signature = verify_signature(dsc_path, keyrings) if is_clearsigned else {
        "valid": False,
        "exit_code": None,
        "diagnostic": "descriptor is not clearsigned",
        "keyrings": [str(path) for path in keyrings],
    }
    try:
        payload = clearsigned_payload(text) if is_clearsigned else text
        stanzas = list(parse_deb822_blocks(payload))
        if len(stanzas) != 1:
            raise RecoveryError(f"descriptor has {len(stanzas)} stanzas")
        fields, _raw = stanzas[0]
        if fields.get("Source") != target.source:
            raise RecoveryError(
                f"descriptor source {fields.get('Source')} != {target.source}"
            )
        if fields.get("Version") != target.version:
            raise RecoveryError(
                f"descriptor version {fields.get('Version')} != {target.version}"
            )
        component_rows = parse_checksum_rows(fields.get("Checksums-Sha256"), "sha256")
        if not component_rows:
            raise RecoveryError("descriptor has no Checksums-Sha256 components")
        names: set[str] = set()
        for component in component_rows:
            name = component["name"]
            if name in names:
                raise RecoveryError(f"duplicate descriptor component: {name}")
            names.add(name)
            source_row = source_index_files.get(name)
            if source_row is None:
                raise RecoveryError(
                    f"descriptor component absent from signed source stanza: {name}"
                )
            if (
                int(source_row["size"]) != int(component["size"])
                or str(source_row["sha256"]).lower()
                != str(component["sha256"]).lower()
            ):
                raise RecoveryError(
                    f"descriptor/source-index checksum disagreement: {name}"
                )
        return {
            "declared_source": fields.get("Source"),
            "declared_version": fields.get("Version"),
            "format": fields.get("Format", ""),
            "architecture": fields.get("Architecture", ""),
            "binary": fields.get("Binary", ""),
            "maintainer": fields.get("Maintainer", ""),
            "dsc_clearsigned": is_clearsigned,
            "dsc_signature": signature,
            "components": component_rows,
        }, None
    except Exception as error:
        return None, f"{type(error).__name__}: {error}"


def recover_candidate(
    target: Target,
    repository: dict[str, Any],
    stanza_record: dict[str, Any],
    keyrings: list[Path],
    compact_output: Path,
    vault_output: Path,
    component_workers: int,
) -> dict[str, Any]:
    fields = stanza_record["fields"]
    raw_stanza = stanza_record["raw"]
    directory = fields.get("Directory", "")
    source_files = parse_checksum_rows(fields.get("Checksums-Sha256"), "sha256")
    row: dict[str, Any] = {
        "repository": repository["repository"],
        "suite": repository["suite"],
        "base_url": repository["base_url"],
        "source_index_url": repository.get("selected_index_download", {}).get(
            "final_url", ""
        ),
        "source_index_sha256": repository.get("selected_index_download", {}).get(
            "sha256", ""
        ),
        "source_index_signature_valid": repository.get("inrelease_signature", {}).get(
            "valid"
        )
        is True,
        "source_stanza_sha256": stanza_record["raw_sha256"],
        "directory": directory,
        "status": "unresolved",
    }
    if not directory:
        row.update(status="missing-directory")
        return row
    if not source_files:
        row.update(status="missing-source-sha256-files")
        return row
    by_name: dict[str, dict[str, Any]] = {}
    for item in source_files:
        if item["name"] in by_name:
            row.update(status="duplicate-source-file", duplicate=item["name"])
            return row
        by_name[item["name"]] = item
    dsc_items = [item for item in source_files if item["name"].endswith(".dsc")]
    if len(dsc_items) != 1:
        row.update(status="invalid-dsc-count", dsc_count=len(dsc_items))
        return row
    dsc_item = dsc_items[0]

    safe_source = safe_name(target.source)
    safe_version = safe_name(target.version)
    vault_dir = vault_output / safe_source / safe_version / repository["repository"]
    vault_dir.mkdir(parents=True, exist_ok=True)

    def fetch_item(item: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None, list[dict[str, Any]]]:
        destination = vault_dir / Path(item["name"]).name
        urls = file_url_candidates(repository["base_url"], directory, item["name"])
        selected, attempts = download_exact(
            urls,
            destination,
            int(item["size"]),
            str(item["sha256"]),
        )
        return item, selected, attempts

    downloads: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, component_workers)
    ) as executor:
        futures = [executor.submit(fetch_item, item) for item in source_files]
        for future in concurrent.futures.as_completed(futures):
            item, selected, attempts = future.result()
            downloads.append(
                {
                    **item,
                    "selected": selected,
                    "attempts": attempts,
                    "verified": selected is not None,
                }
            )
    downloads.sort(key=lambda item: item["name"])
    row["downloads"] = downloads
    if not all(item["verified"] for item in downloads):
        row.update(status="source-file-download-or-verification-failed")
        return row

    dsc_path = vault_dir / Path(dsc_item["name"]).name
    descriptor, descriptor_error = verify_descriptor(
        dsc_path,
        target,
        by_name,
        keyrings,
    )
    if descriptor is None:
        row.update(status="invalid-descriptor", error=descriptor_error)
        return row

    selected_downloads = {
        item["name"]: item["selected"] for item in downloads if item["selected"]
    }
    dsc_download = selected_downloads[dsc_item["name"]]
    components: list[dict[str, Any]] = []
    for component in descriptor["components"]:
        download = selected_downloads[component["name"]]
        components.append(
            {
                "name": component["name"],
                "size": int(component["size"]),
                "sha256": str(component["sha256"]).lower(),
                "url": download["final_url"],
                "requested_url": download["url"],
                "verified": True,
            }
        )
    components.sort(key=lambda item: item["name"])

    compact_dsc_dir = compact_output / "dsc"
    compact_dsc_dir.mkdir(parents=True, exist_ok=True)
    saved_dsc = (
        f"{safe_source}__{safe_version}__{str(dsc_item['sha256'])[:16]}.dsc"
    )
    shutil.copy2(dsc_path, compact_dsc_dir / saved_dsc)
    stanza_dir = compact_output / "source-stanzas"
    stanza_dir.mkdir(parents=True, exist_ok=True)
    stanza_name = f"{safe_source}__{safe_version}__{repository['repository']}.txt"
    (stanza_dir / stanza_name).write_text(raw_stanza, encoding="utf-8")

    dsc_signature_valid = descriptor["dsc_signature"]["valid"] is True
    selected = {
        "type": "dsc",
        "repository": repository["repository"],
        "suite": repository["suite"],
        "base_url": repository["base_url"],
        "directory": directory,
        "url": dsc_download["final_url"],
        "requested_url": dsc_download["url"],
        "dsc_name": dsc_item["name"],
        "dsc_size": int(dsc_item["size"]),
        "dsc_sha256": str(dsc_item["sha256"]).lower(),
        "saved_dsc": f"dsc/{saved_dsc}",
        "declared_source": descriptor["declared_source"],
        "declared_version": descriptor["declared_version"],
        "format": descriptor["format"],
        "architecture": descriptor["architecture"],
        "binary": descriptor["binary"],
        "signature_valid": True,
        "signature_basis": (
            "iso-keyring-verified-inrelease-plus-dsc-signature"
            if dsc_signature_valid
            else "iso-keyring-verified-inrelease-and-signed-source-index-checksum-chain"
        ),
        "source_index_signature_valid": True,
        "dsc_clearsigned": descriptor["dsc_clearsigned"],
        "dsc_signature_valid": dsc_signature_valid,
        "dsc_signature_diagnostic": descriptor["dsc_signature"]["diagnostic"],
        "source_index_url": row["source_index_url"],
        "source_index_sha256": row["source_index_sha256"],
        "source_stanza_sha256": row["source_stanza_sha256"],
        "components": components,
    }
    row.update(status="resolved", selected=selected)
    return row


def candidate_identity(candidate: dict[str, Any]) -> tuple[Any, ...]:
    selected = candidate["selected"]
    return (
        selected["dsc_sha256"],
        tuple(
            (component["name"], component["size"], component["sha256"])
            for component in selected["components"]
        ),
    )


def select_candidate(target: Target, candidates: list[dict[str, Any]]) -> tuple[str, dict[str, Any] | None]:
    resolved = [candidate for candidate in candidates if candidate.get("status") == "resolved"]
    if not resolved:
        return "unresolved", None
    identities = {candidate_identity(candidate) for candidate in resolved}
    if len(identities) != 1:
        return "ambiguous-exact-source", None
    preferred = "hancom" if "+han" in target.version.lower() else "gooroom"
    resolved.sort(
        key=lambda candidate: (
            0 if candidate["repository"] == preferred else 1,
            candidate["repository"],
            candidate["selected"]["url"],
        )
    )
    return "resolved", resolved[0]["selected"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--repository-spec", action="append", required=True)
    parser.add_argument("--keyring", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--vault-dir", type=Path, required=True)
    parser.add_argument("--component-workers", type=int, default=4)
    args = parser.parse_args()

    targets = load_targets(args.reference, args.targets)
    specs = [repository_spec(raw) for raw in args.repository_spec]
    keyrings = sorted({path.resolve() for path in args.keyring if path.is_file()})
    if not keyrings:
        raise RecoveryError("no readable keyrings")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.vault_dir.mkdir(parents=True, exist_ok=True)

    repository_rows: list[dict[str, Any]] = []
    for spec in specs:
        repository_rows.append(
            authenticate_source_index(spec, keyrings, args.output_dir)
        )

    sources: list[dict[str, Any]] = []
    for target in targets:
        candidates: list[dict[str, Any]] = []
        exact_stanza_count = 0
        for repository in repository_rows:
            if repository.get("usable") is not True:
                continue
            stanzas = repository["exact_stanzas"].get(
                (target.source, target.version), []
            )
            exact_stanza_count += len(stanzas)
            for stanza in stanzas:
                candidates.append(
                    recover_candidate(
                        target,
                        repository,
                        stanza,
                        keyrings,
                        args.output_dir,
                        args.vault_dir,
                        args.component_workers,
                    )
                )
        status, selected = select_candidate(target, candidates)
        sources.append(
            {
                "source": target.source,
                "source_version": target.version,
                "binary_packages": list(target.binary_packages),
                "native_binary_packages": list(target.native_binary_packages),
                "reused_all_packages": list(target.reused_all_packages),
                "role": "rebuild-arm64",
                "status": status,
                "selected": selected,
                "exact_source_stanza_count": exact_stanza_count,
                "candidates": candidates,
            }
        )

    compact_repositories: list[dict[str, Any]] = []
    for repository in repository_rows:
        compact = {key: value for key, value in repository.items() if key != "exact_stanzas"}
        compact_repositories.append(compact)

    resolved = [row for row in sources if row["status"] == "resolved"]
    ambiguous = [row for row in sources if row["status"].startswith("ambiguous-")]
    unresolved = [row for row in sources if row["status"] != "resolved"]
    vault_files = sorted(path for path in args.vault_dir.rglob("*") if path.is_file())
    summary = {
        "schema": 3,
        "policy": "iso-keyring-verified-inrelease-exact-sources-index-and-all-source-file-sha256",
        "repository_count": len(compact_repositories),
        "usable_repository_count": sum(
            row.get("usable") is True for row in compact_repositories
        ),
        "target_count": len(sources),
        "resolved_count": len(resolved),
        "unresolved_count": len(unresolved),
        "ambiguous_count": len(ambiguous),
        "all_blocking_sources_recovered": len(unresolved) == 0,
        "source_file_count": len(vault_files),
        "source_file_bytes": sum(path.stat().st_size for path in vault_files),
        "promotion_basis": "signed-source-index-checksum-chain",
        "version_text_alone_allowed": False,
        "index_evidence": compact_repositories,
    }
    lock = {"summary": summary, "sources": sources}
    write_json(args.output_dir / "summary.json", summary)
    write_json(args.output_dir / "apt-source-fallback-lock.json", lock)
    write_json(args.output_dir / "resolved.json", resolved)
    write_json(args.output_dir / "unresolved.json", unresolved)
    write_json(args.output_dir / "repository-evidence.json", compact_repositories)

    with (args.output_dir / "sources.tsv").open("w", encoding="utf-8") as handle:
        handle.write(
            "source\tsource_version\tstatus\texact_source_stanzas\trepository\tdsc_sha256\n"
        )
        for row in sources:
            selected = row.get("selected") or {}
            handle.write(
                "\t".join(
                    [
                        row["source"],
                        row["source_version"],
                        row["status"],
                        str(row["exact_source_stanza_count"]),
                        str(selected.get("repository", "")),
                        str(selected.get("dsc_sha256", "")),
                    ]
                )
                + "\n"
            )

    vault_manifest = args.vault_dir / "SOURCEFILES.sha256"
    with vault_manifest.open("w", encoding="utf-8") as handle:
        for path in vault_files:
            if path == vault_manifest:
                continue
            handle.write(
                f"{sha256_file(path)}  {path.relative_to(args.vault_dir).as_posix()}\n"
            )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["all_blocking_sources_recovered"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as error:
        print(f"recovery error: {error}", file=sys.stderr)
        raise SystemExit(2)
