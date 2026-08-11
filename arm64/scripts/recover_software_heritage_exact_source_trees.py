#!/usr/bin/env python3
"""Recover exact source trees selected by Software Heritage archaeology.

An input candidate must already have an archived Git revision whose root
`debian/changelog` begins with the exact AMD64 source/version. This program asks
Software Heritage Vault for the immutable root directory, downloads the cooked
flat archive, extracts it safely, repeats the changelog check, and seals every
file and symlink. It does not claim byte identity with an unavailable Debian
`.dsc` source archive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API = "https://archive.softwareheritage.org/api/1"
USER_AGENT = "hancom-gooroom-arm64-software-heritage-tree-recovery/1"
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
HEX40 = set("0123456789abcdef")
TARGETS = {
    "gnome-flashback": "3.38.0-2+grm3u2+han3u4",
    "gooroom-dockbarx-applet": "0.3.1+grm3u1+han3u1",
    "gooroom-guide": "0.5.3+grm3u1+han3u1",
    "gooroom-integration-applet": "0.3.1+grm3u1+han3u3",
    "gooroom-session-manager": "0.3.9+grm3u1+han3u2",
    "linux": "5.10.179-1+grm3u1",
    "qtbase-opensource-src": "5.15.2+dfsg-9+grm3u1",
}


def valid_hex40(value: str) -> bool:
    return len(value) == 40 and all(character in HEX40 for character in value)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON document is not an object: {path}")
    return value


def request_json(
    url: str,
    *,
    timeout: int,
    method: str = "GET",
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        method=method,
        data=b"" if method == "POST" else None,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(8 * 1024 * 1024 + 1)
            if len(body) > 8 * 1024 * 1024:
                raise ValueError("JSON response exceeded 8 MiB")
            value = json.loads(body.decode("utf-8"))
            return (value if isinstance(value, dict) else None), {
                "url": url,
                "method": method,
                "status": int(getattr(response, "status", 200)),
                "final_url": response.geturl(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
    except urllib.error.HTTPError as error:
        body = error.read(64 * 1024).decode("utf-8", errors="replace")
        return None, {
            "url": url,
            "method": method,
            "status": int(error.code),
            "error": str(error),
            "body": body,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    except Exception as error:
        return None, {
            "url": url,
            "method": method,
            "status": None,
            "error": repr(error),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }


def download(
    url: str,
    destination: Path,
    *,
    timeout: int,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/octet-stream,*/*",
            "Accept-Encoding": "identity",
        },
    )
    temporary = destination.with_name(destination.name + ".part")
    temporary.unlink(missing_ok=True)
    digest = hashlib.sha256()
    size = 0
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            with temporary.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_ARCHIVE_BYTES:
                        raise ValueError("Vault archive exceeded 4 GiB")
                    digest.update(chunk)
                    output.write(chunk)
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(temporary, destination)
            return {
                "url": url,
                "status": int(getattr(response, "status", 200)),
                "final_url": response.geturl(),
                "size": size,
                "sha256": digest.hexdigest(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "verified_download": True,
            }
    except Exception as error:
        temporary.unlink(missing_ok=True)
        return {
            "url": url,
            "status": None,
            "error": repr(error),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "verified_download": False,
        }


def safe_extract(archive: Path, destination: Path) -> None:
    destination_resolved = destination.resolve()
    with tarfile.open(archive, "r:*") as handle:
        members = handle.getmembers()
        for member in members:
            member_path = destination / member.name
            try:
                member_path.resolve().relative_to(destination_resolved)
            except ValueError as error:
                raise ValueError(f"unsafe archive path: {member.name}") from error
            if member.ischr() or member.isblk() or member.isfifo():
                raise ValueError(f"unsupported special archive member: {member.name}")
        handle.extractall(destination, filter="data")


def find_source_root(extracted: Path, source: str, version: str) -> Path:
    candidates: list[Path] = []
    for changelog in extracted.rglob("debian/changelog"):
        if not changelog.is_file():
            continue
        first = changelog.read_text(encoding="utf-8", errors="replace").splitlines()
        if not first:
            continue
        if first[0].startswith(f"{source} ({version}) "):
            candidates.append(changelog.parent.parent)
    if len(candidates) != 1:
        raise ValueError(
            f"exact source root selection is not unique for {source} {version}: {len(candidates)}"
        )
    return candidates[0]


def manifest_tree(root: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    counts = {"file": 0, "symlink": 0, "directory": 0}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            rows.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "target": target,
                    "mode": stat.S_IMODE(mode),
                    "sha256": hashlib.sha256(os.fsencode(target)).hexdigest(),
                }
            )
            counts["symlink"] += 1
        elif stat.S_ISDIR(mode):
            rows.append(
                {
                    "path": relative,
                    "type": "directory",
                    "mode": stat.S_IMODE(mode),
                }
            )
            counts["directory"] += 1
        elif stat.S_ISREG(mode):
            rows.append(
                {
                    "path": relative,
                    "type": "file",
                    "size": path.stat().st_size,
                    "mode": stat.S_IMODE(mode),
                    "sha256": sha256_file(path),
                }
            )
            counts["file"] += 1
        else:
            raise ValueError(f"unsupported extracted member type: {relative}")
    return rows, counts


def selected_candidates(archaeology_root: Path) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for result_path in sorted(archaeology_root.glob("*/result.json")):
        result = load_json(result_path)
        source = str(result.get("source", ""))
        version = str(result.get("source_version", ""))
        selected = result.get("selected")
        if (
            result.get("status") != "exact-revision-found"
            or source not in TARGETS
            or TARGETS[source] != version
            or not isinstance(selected, dict)
        ):
            continue
        revision = str(selected.get("revision", ""))
        directory = str(selected.get("directory", ""))
        changelog_sha256 = str(selected.get("changelog_sha256", ""))
        if not valid_hex40(revision) or not valid_hex40(directory):
            raise ValueError(f"invalid Software Heritage candidate: {result_path}")
        candidates.append(
            {
                "source": source,
                "source_version": version,
                "revision": revision,
                "directory": directory,
                "changelog_sha256": changelog_sha256,
                "archaeology_result": result_path.as_posix(),
            }
        )
    return candidates


def recover_candidate(
    candidate: dict[str, Any],
    *,
    evidence_root: Path,
    artifact_root: Path,
    timeout: int,
    poll_seconds: int,
    poll_interval: int,
) -> dict[str, Any]:
    source = candidate["source"]
    version = candidate["source_version"]
    directory = candidate["directory"]
    revision = candidate["revision"]
    source_evidence = evidence_root / source
    source_artifacts = artifact_root / source
    source_evidence.mkdir(parents=True, exist_ok=True)
    source_artifacts.mkdir(parents=True, exist_ok=True)

    swhid = f"swh:1:dir:{directory}"
    encoded = urllib.parse.quote(swhid, safe=":")
    endpoint = f"{API}/vault/flat/{encoded}/"
    attempts: list[dict[str, Any]] = []

    status, evidence = request_json(endpoint, timeout=timeout, method="POST")
    attempts.append(evidence)
    deadline = time.monotonic() + poll_seconds
    while (status or {}).get("status") not in {"done", "failed"} and time.monotonic() < deadline:
        time.sleep(poll_interval)
        status, evidence = request_json(endpoint, timeout=timeout)
        attempts.append(evidence)

    result: dict[str, Any] = {
        "schema": 1,
        "policy": "exact-software-heritage-revision-directory-and-changelog",
        **candidate,
        "swhid": swhid,
        "vault_endpoint": endpoint,
        "vault_status": status,
        "status": "vault-pending",
        "byte_identity_with_original_dsc_claimed": False,
        "promotion_allowed": False,
    }
    write_json(source_evidence / "vault-attempts.json", attempts)

    if not isinstance(status, dict) or status.get("status") != "done":
        if isinstance(status, dict) and status.get("status") == "failed":
            result["status"] = "vault-failed"
        write_json(source_evidence / "result.json", result)
        return result

    fetch_url = str(status.get("fetch_url", ""))
    if not fetch_url:
        fetch_url = endpoint + "raw/"
    elif fetch_url.startswith("/"):
        fetch_url = "https://archive.softwareheritage.org" + fetch_url
    archive = source_artifacts / f"{source}-{version}-swh-flat.tar.gz"
    download_evidence = download(fetch_url, archive, timeout=max(timeout, 120))
    write_json(source_evidence / "download.json", download_evidence)
    if not download_evidence.get("verified_download"):
        result["status"] = "vault-download-failed"
        write_json(source_evidence / "result.json", result)
        return result

    with tempfile.TemporaryDirectory(prefix="swh-source-tree-") as temporary:
        extracted = Path(temporary) / "extracted"
        extracted.mkdir()
        safe_extract(archive, extracted)
        root = find_source_root(extracted, source, version)
        changelog = root / "debian/changelog"
        changelog_sha256 = sha256_file(changelog)
        expected_changelog = str(candidate.get("changelog_sha256", ""))
        if expected_changelog and changelog_sha256 != expected_changelog:
            raise ValueError(
                f"Software Heritage changelog changed between discovery and Vault: {source}"
            )
        manifest, counts = manifest_tree(root)
        write_json(source_evidence / "tree-manifest.json", manifest)

    result.update(
        {
            "status": "exact-source-tree-recovered",
            "archive_file": archive.relative_to(artifact_root.parent).as_posix(),
            "archive_size": archive.stat().st_size,
            "archive_sha256": sha256_file(archive),
            "verified_changelog_sha256": changelog_sha256,
            "tree_counts": counts,
            "source_build_ready": True,
            "promotion_allowed": True,
            "promotion_scope": "exact-archived-git-revision-source-tree",
        }
    )
    write_json(source_evidence / "result.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archaeology-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--poll-seconds", type=int, default=900)
    parser.add_argument("--poll-interval", type=int, default=20)
    args = parser.parse_args()

    evidence_root = args.output_dir / "evidence"
    artifact_root = args.output_dir / "artifacts"
    evidence_root.mkdir(parents=True, exist_ok=True)
    artifact_root.mkdir(parents=True, exist_ok=True)
    candidates = selected_candidates(args.archaeology_root)
    results = [
        recover_candidate(
            candidate,
            evidence_root=evidence_root,
            artifact_root=artifact_root,
            timeout=args.timeout,
            poll_seconds=args.poll_seconds,
            poll_interval=args.poll_interval,
        )
        for candidate in candidates
    ]
    summary = {
        "schema": 1,
        "policy": "exact-software-heritage-source-tree-recovery",
        "candidate_count": len(candidates),
        "recovered_count": sum(result["status"] == "exact-source-tree-recovered" for result in results),
        "pending_count": sum(result["status"] == "vault-pending" for result in results),
        "failed_count": sum(result["status"] not in {"exact-source-tree-recovered", "vault-pending"} for result in results),
        "source_build_ready": bool(results) and all(result["status"] == "exact-source-tree-recovered" for result in results),
        "results": results,
    }
    write_json(evidence_root / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
