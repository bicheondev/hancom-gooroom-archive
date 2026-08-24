#!/usr/bin/env python3
"""Reaudit historical Actions artifacts and import exact ARM64 package evidence.

Artifact names are discovery hints only. Every accepted artifact must contain:

* ARM64 DEBs whose package/version match the immutable AMD64 reference;
* the complete architecture-dependent binary set for one exact source version;
* Git commit/tree or signed-DSC SHA evidence matching the effective source lock;
* no x86 or unsupported foreign ELF payload in any accepted DEB.

The script commits only hashes and provenance. The DEBs remain in their original
GitHub Actions artifact and are downloaded later by exact run/artifact identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


SOURCE_RE = re.compile(r"^\s*([^\s(]+)\s*(?:\(([^)]+)\))?\s*$")
ARTIFACT_HINT_RE = re.compile(
    r"(?:exact.*arm64|arm64.*(?:rebuild|wave|package|passed)|"
    r"(?:accountsservice|cups-pk-helper|file-roller|mousetweaks|"
    r"gnome-screenshot|security-status-tools).*arm64)",
    re.IGNORECASE,
)
ARTIFACT_EXCLUDE_RE = re.compile(
    r"(?:iso|stage0|rootfs|source-lock|coverage|audit|lint|plan|"
    r"repository|evidence|workflow|selfcheck|manifest)",
    re.IGNORECASE,
)
ELF_NAMES = {3: "x86", 40: "arm32", 62: "x86_64", 183: "aarch64", 247: "bpf"}


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def request_json(url: str, token: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hancom-gooroom-arm64-artifact-import-v2/1",
        },
    )
    for attempt in range(5):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code not in {408, 429, 500, 502, 503, 504} or attempt == 4:
                raise
        time.sleep(2**attempt)
    raise RuntimeError(f"failed to request {url}")


def download(url: str, token: str, destination: Path, max_bytes: int) -> None:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hancom-gooroom-arm64-artifact-import-v2/1",
        },
    )
    error_text = ""
    for attempt in range(5):
        temporary = destination.with_suffix(destination.suffix + ".partial")
        try:
            digest_size = 0
            with urllib.request.urlopen(request, timeout=300) as response, temporary.open(
                "wb"
            ) as output:
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > max_bytes:
                    raise RuntimeError(
                        f"artifact is larger than limit: {content_length} > {max_bytes}"
                    )
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    digest_size += len(chunk)
                    if digest_size > max_bytes:
                        raise RuntimeError(
                            f"artifact exceeded size limit: {digest_size} > {max_bytes}"
                        )
                    output.write(chunk)
            temporary.replace(destination)
            return
        except Exception as error:
            error_text = f"{type(error).__name__}: {error}"
            temporary.unlink(missing_ok=True)
            if attempt < 4:
                time.sleep(2**attempt)
    raise RuntimeError(error_text)


def safe_extract(archive: Path, destination: Path) -> None:
    destination_resolved = destination.resolve()
    with zipfile.ZipFile(archive) as handle:
        for member in handle.infolist():
            path = (destination / member.filename).resolve()
            if path != destination_resolved and destination_resolved not in path.parents:
                raise RuntimeError(f"unsafe artifact path: {member.filename}")
            if member.file_size > 2 * 1024 * 1024 * 1024:
                raise RuntimeError(f"oversized artifact member: {member.filename}")
        handle.extractall(destination)


def deb_field(path: Path, field: str) -> str:
    process = subprocess.run(
        ["dpkg-deb", "-f", str(path), field],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return process.stdout.strip() if process.returncode == 0 else ""


def parse_source(value: str, package: str, version: str) -> tuple[str, str]:
    if not value:
        return package, version
    match = SOURCE_RE.fullmatch(value)
    if not match:
        return value, version
    return match.group(1), match.group(2) or version


def elf_machine(path: Path) -> int | None:
    try:
        with path.open("rb") as handle:
            header = handle.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    if header[5] == 1:
        return struct.unpack("<H", header[18:20])[0]
    if header[5] == 2:
        return struct.unpack(">H", header[18:20])[0]
    return -1


def scan_deb(path: Path, temporary_root: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    extraction = temporary_root / hashlib.sha1(str(path).encode()).hexdigest()
    extraction.mkdir(parents=True)
    process = subprocess.run(
        ["dpkg-deb", "-x", str(path), str(extraction)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(f"dpkg-deb extraction failed: {path.name}")
    x86: list[dict[str, str]] = []
    foreign: list[dict[str, str]] = []
    for root, _, files in os.walk(extraction):
        for filename in files:
            file_path = Path(root) / filename
            if file_path.is_symlink():
                continue
            machine = elf_machine(file_path)
            if machine is None:
                continue
            relative = str(file_path.relative_to(extraction))
            name = ELF_NAMES.get(machine, f"machine-{machine}")
            if machine in {3, 62}:
                x86.append({"path": relative, "machine": name})
            elif machine not in {0, 183, 247}:
                foreign.append({"path": relative, "machine": name})
    return x86, foreign


def all_json(root: Path) -> Iterable[tuple[Path, dict[str, Any]]]:
    for path in root.rglob("*.json"):
        try:
            value = load(path)
        except Exception:
            continue
        if isinstance(value, dict):
            yield path, value


def evidence_for_source(
    documents: list[tuple[Path, dict[str, Any]]], source: str, version: str
) -> list[dict[str, Any]]:
    result = []
    for path, document in documents:
        if document.get("source") == source and document.get("source_version") == version:
            result.append({"path": str(path), "document": document})
    return result


def authority_rows(document: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    rows: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in document.get("sources", []):
        source = row.get("source")
        version = row.get("source_version")
        if source and version:
            rows[(source, version)].append(row)
    return rows


def exact_authority(
    authorities: dict[tuple[str, str], list[dict[str, Any]]],
    source: str,
    version: str,
) -> dict[str, Any] | None:
    matches = [
        row
        for row in authorities.get((source, version), [])
        if row.get("status") == "resolved" and isinstance(row.get("selected"), dict)
    ]
    identities = set()
    for row in matches:
        selected = row["selected"]
        if selected.get("type") in (None, "git"):
            identities.add(
                (
                    "git",
                    selected.get("repository_full_name"),
                    selected.get("commit_sha"),
                    selected.get("tree_sha"),
                )
            )
        elif selected.get("type") == "dsc":
            identities.add(("dsc", selected.get("dsc_sha256")))
    identities.discard(("git", None, None, None))
    identities.discard(("dsc", None))
    if len(identities) != 1:
        return None
    selected_type = next(iter(identities))[0]
    for row in matches:
        if (row["selected"].get("type") or "git") == selected_type:
            return row
    return None


def evidence_matches(
    authority: dict[str, Any], evidence: list[dict[str, Any]]
) -> tuple[bool, dict[str, Any] | None, str]:
    selected = authority["selected"]
    selected_type = selected.get("type") or "git"
    for item in evidence:
        document = item["document"]
        if selected_type == "git":
            commit = document.get("commit_sha") or document.get("verified_commit_sha")
            tree = document.get("tree_sha") or document.get("verified_tree_sha")
            if (
                commit == selected.get("commit_sha")
                and tree == selected.get("tree_sha")
            ):
                return True, item, "git-commit-tree"
        else:
            dsc_sha256 = document.get("dsc_sha256")
            if dsc_sha256 == selected.get("dsc_sha256"):
                return True, item, "signed-dsc-sha256"
    return False, None, f"no evidence matched {selected_type} authority"


def artifact_candidates(repository: str, token: str, branch: str) -> list[dict[str, Any]]:
    rows = []
    for page in range(1, 30):
        document = request_json(
            f"https://api.github.com/repos/{repository}/actions/artifacts?per_page=100&page={page}",
            token,
        )
        artifacts = document.get("artifacts", [])
        for artifact in artifacts:
            run = artifact.get("workflow_run") or {}
            name = artifact.get("name", "")
            if artifact.get("expired") or run.get("head_branch") != branch:
                continue
            if not ARTIFACT_HINT_RE.search(name) or ARTIFACT_EXCLUDE_RE.search(name):
                continue
            rows.append(artifact)
        if len(artifacts) < 100:
            break
    rows.sort(key=lambda artifact: (artifact.get("created_at", ""), artifact["id"]), reverse=True)
    return rows


def audit_artifact(
    artifact: dict[str, Any],
    repository: str,
    token: str,
    reference_by_package: dict[tuple[str, str], dict[str, Any]],
    reference_by_source: dict[tuple[str, str], list[dict[str, Any]]],
    authorities: dict[tuple[str, str], list[dict[str, Any]]],
    maximum_bytes: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "artifact_id": artifact["id"],
        "artifact_name": artifact["name"],
        "artifact_size": artifact.get("size_in_bytes"),
        "artifact_digest": artifact.get("digest"),
        "created_at": artifact.get("created_at"),
        "actions_run_id": str((artifact.get("workflow_run") or {}).get("id", "")),
        "status": "rejected",
        "sources": [],
        "errors": [],
    }
    if int(artifact.get("size_in_bytes") or 0) > maximum_bytes:
        result["errors"].append("artifact-size-limit")
        return result

    with tempfile.TemporaryDirectory(prefix="arm64-artifact-audit-") as temporary:
        root = Path(temporary)
        archive = root / "artifact.zip"
        extracted = root / "extracted"
        extracted.mkdir()
        try:
            download(
                artifact["archive_download_url"], token, archive, maximum_bytes
            )
            digest_label = artifact.get("digest") or ""
            if digest_label.startswith("sha256:"):
                expected = digest_label.split(":", 1)[1].lower()
                actual = sha256(archive)
                if actual != expected:
                    raise RuntimeError(f"artifact zip digest {actual} != {expected}")
            safe_extract(archive, extracted)
        except Exception as error:
            result["errors"].append(f"artifact-download-or-extract: {type(error).__name__}: {error}")
            return result

        debs = sorted(extracted.rglob("*.deb"))
        if not debs:
            result["errors"].append("artifact-has-no-deb")
            return result
        documents = list(all_json(extracted))
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        with tempfile.TemporaryDirectory(prefix="arm64-deb-elf-") as elf_temp:
            elf_root = Path(elf_temp)
            for deb in debs:
                package = deb_field(deb, "Package")
                version = deb_field(deb, "Version")
                architecture = deb_field(deb, "Architecture")
                source, source_version = parse_source(
                    deb_field(deb, "Source"), package, version
                )
                reference = reference_by_package.get((package, version))
                # Debug and other non-reference outputs are retained only as
                # diagnostics and never enter the package authority.
                if reference is None:
                    continue
                if reference.get("source") != source or reference.get("source_version") != source_version:
                    result["errors"].append(
                        f"{deb.name}: source identity differs from reference"
                    )
                    continue
                if reference.get("architecture") != "amd64":
                    continue
                if architecture != "arm64":
                    result["errors"].append(
                        f"{deb.name}: required native package architecture is {architecture}"
                    )
                    continue
                try:
                    x86, foreign = scan_deb(deb, elf_root)
                except Exception as error:
                    result["errors"].append(
                        f"{deb.name}: ELF scan failed: {type(error).__name__}: {error}"
                    )
                    continue
                if x86 or foreign:
                    result["errors"].append(
                        f"{deb.name}: x86={len(x86)} foreign={len(foreign)}"
                    )
                    continue
                grouped[(source, source_version)].append(
                    {
                        "package": package,
                        "version": version,
                        "architecture": architecture,
                        "filename": deb.name,
                        "size": deb.stat().st_size,
                        "sha256": sha256(deb),
                        "source": source,
                        "source_version": source_version,
                        "x86_payload_count": 0,
                        "foreign_payload_count": 0,
                    }
                )

        for (source, source_version), packages in sorted(grouped.items()):
            authority = exact_authority(authorities, source, source_version)
            record: dict[str, Any] = {
                "source": source,
                "source_version": source_version,
                "status": "rejected",
                "packages": sorted(packages, key=lambda package: package["package"]),
                "errors": [],
            }
            if authority is None:
                record["errors"].append("no-unambiguous-exact-source-authority")
                result["sources"].append(record)
                continue
            expected = {
                row["package"]
                for row in reference_by_source.get((source, source_version), [])
                if row.get("architecture") == "amd64"
            }
            produced = {package["package"] for package in packages}
            missing = sorted(expected - produced)
            if missing:
                record["errors"].append(
                    "missing-reference-native-packages:" + ",".join(missing)
                )
                result["sources"].append(record)
                continue
            evidence = evidence_for_source(documents, source, source_version)
            matched, matched_evidence, mode = evidence_matches(authority, evidence)
            if not matched:
                record["errors"].append(mode)
                result["sources"].append(record)
                continue
            selected = authority["selected"]
            record.update(
                status="verified",
                provenance=(
                    "github-exact-commit"
                    if (selected.get("type") or "git") == "git"
                    else "vendor-apt-exact-signed-dsc"
                ),
                repository=selected.get("repository_full_name")
                or selected.get("repository"),
                commit_sha=selected.get("commit_sha"),
                tree_sha=selected.get("tree_sha"),
                dsc_sha256=selected.get("dsc_sha256"),
                evidence_mode=mode,
                evidence_path=(matched_evidence or {}).get("path"),
            )
            result["sources"].append(record)

        verified_sources = [source for source in result["sources"] if source["status"] == "verified"]
        if verified_sources:
            result["status"] = "verified"
        elif not result["errors"]:
            result["errors"].append("no-reference-native-source-was-verified")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--branch", default="arm64-port")
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--source-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-artifacts", type=int, default=100)
    parser.add_argument("--max-artifact-bytes", type=int, default=800 * 1024 * 1024)
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN is required")
    reference = load(args.reference)
    source_lock = load(args.source_lock)
    reference_by_package = {
        (row["package"], row["version"]): row
        for row in reference.get("packages", [])
    }
    reference_by_source: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in reference.get("packages", []):
        reference_by_source[(row["source"], row["source_version"])].append(row)
    authorities = authority_rows(source_lock)

    artifacts = artifact_candidates(args.repository, token, args.branch)
    selected_artifacts = artifacts[: max(0, args.max_artifacts)]
    results = []
    for index, artifact in enumerate(selected_artifacts, 1):
        print(
            f"[{index}/{len(selected_artifacts)}] {artifact['name']} "
            f"run={(artifact.get('workflow_run') or {}).get('id')}",
            flush=True,
        )
        try:
            result = audit_artifact(
                artifact,
                args.repository,
                token,
                reference_by_package,
                reference_by_source,
                authorities,
                args.max_artifact_bytes,
            )
        except Exception as error:
            result = {
                "artifact_id": artifact["id"],
                "artifact_name": artifact["name"],
                "actions_run_id": str((artifact.get("workflow_run") or {}).get("id", "")),
                "status": "exception",
                "sources": [],
                "errors": [f"{type(error).__name__}: {error}"],
            }
        results.append(result)
        print(f"  -> {result['status']}", flush=True)

    source_candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for artifact in results:
        for source in artifact.get("sources", []):
            if source.get("status") != "verified":
                continue
            source_candidates[(source["source"], source["source_version"])].append(
                {
                    **source,
                    "actions_run_id": artifact["actions_run_id"],
                    "actions_run_url": (
                        f"https://github.com/{args.repository}/actions/runs/"
                        f"{artifact['actions_run_id']}"
                    ),
                    "artifact_id": artifact["artifact_id"],
                    "artifact_name": artifact["artifact_name"],
                    "artifact_created_at": artifact.get("created_at"),
                }
            )

    imported = []
    for key, candidates in sorted(source_candidates.items()):
        candidates.sort(
            key=lambda row: (
                row.get("artifact_created_at") or "",
                int(row.get("actions_run_id") or 0),
                row["artifact_id"],
            ),
            reverse=True,
        )
        imported.append(candidates[0])

    summary = {
        "schema": 2,
        "policy": "reaudited-reference-version-source-authority-and-no-x86-elf",
        "candidate_artifact_count": len(artifacts),
        "audited_artifact_count": len(results),
        "verified_artifact_count": sum(result["status"] == "verified" for result in results),
        "imported_source_count": len(imported),
        "imported_binary_package_count": sum(len(row["packages"]) for row in imported),
        "truncated_by_max_artifacts": len(artifacts) > len(selected_artifacts),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "historical-rebuild-import.json").write_text(
        json.dumps({"summary": summary, "sources": imported}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "artifact-audit.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
