#!/usr/bin/env python3
"""Resolve stale rebuilt-package artifact names against immutable Actions runs.

The rebuild index records an Actions run and artifact name for every verified
DEB. Historical import jobs occasionally retained a short display name instead
of the uploaded artifact's full name. This resolver never guesses an arbitrary
artifact: it accepts the declared exact name, then a unique source-qualified
suffix match, or finally one unique non-expired artifact containing the locked
source name.

When historical naming leaves more than one source-qualified candidate, the
resolver downloads only those candidates and accepts one only if every locked
DEB filename, size, and SHA-256 occurs exactly once in that artifact. The
downstream repository materializer independently repeats package, version,
architecture, size, and SHA-256 verification before admitting any file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable


SHA256_LENGTH = 64


def load_rows(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise SystemExit("rebuild package index must be a JSON array")
    rows = [row for row in value if isinstance(row, dict)]
    if len(rows) != len(value):
        raise SystemExit("rebuild package index contains a non-object row")
    return rows


def artifact_pages(repository: str, run_id: str) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    page = 1
    while True:
        endpoint = (
            f"repos/{repository}/actions/runs/{run_id}/artifacts"
            f"?per_page=100&page={page}"
        )
        process = subprocess.run(
            ["gh", "api", endpoint],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode:
            raise RuntimeError(
                f"unable to list artifacts for run {run_id}: {process.stderr.strip()}"
            )
        value = json.loads(process.stdout)
        if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
            raise RuntimeError(f"malformed artifact listing for run {run_id}")
        rows = [row for row in value["artifacts"] if isinstance(row, dict)]
        artifacts.extend(rows)
        if len(rows) < 100:
            total = value.get("total_count")
            if isinstance(total, int) and total > len(artifacts):
                raise RuntimeError(
                    f"incomplete artifact listing for run {run_id}: "
                    f"{len(artifacts)} of {total}"
                )
            break
        page += 1
        if page > 100:
            raise RuntimeError(f"artifact pagination limit exceeded for run {run_id}")
    return artifacts


def source_prefixes(rows: list[dict[str, Any]]) -> set[str]:
    prefixes: set[str] = set()
    for row in rows:
        source = str(row.get("source") or "").strip()
        if source:
            prefixes.add(source.replace("+", "-").replace("_", "-"))
            prefixes.add(source)
    return prefixes


def locked_file_identities(rows: list[dict[str, Any]]) -> dict[str, tuple[int, str]]:
    identities: dict[str, tuple[int, str]] = {}
    for index, row in enumerate(rows):
        filename = Path(str(row.get("filename") or "")).name
        digest = str(row.get("sha256") or "").lower()
        try:
            size = int(row.get("size"))
        except (TypeError, ValueError) as error:
            raise RuntimeError(f"row {index} has an invalid locked size") from error
        if not filename or not filename.endswith(".deb"):
            raise RuntimeError(f"row {index} has an invalid locked DEB filename")
        if (
            len(digest) != SHA256_LENGTH
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise RuntimeError(f"row {index} has an invalid locked SHA-256")
        if size <= 0:
            raise RuntimeError(f"row {index} has an invalid locked size")
        identity = (size, digest)
        existing = identities.get(filename)
        if existing is not None and existing != identity:
            raise RuntimeError(f"conflicting locked identity for {filename}")
        identities[filename] = identity
    if not identities:
        raise RuntimeError("artifact group contains no locked DEB identities")
    return identities


def hash_zip_member(bundle: zipfile.ZipFile, member: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    with bundle.open(member) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_artifact_zip(
    archive: Path,
    rows: list[dict[str, Any]],
) -> tuple[bool, str]:
    expected = locked_file_identities(rows)
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = [member for member in bundle.infolist() if not member.is_dir()]
            verified: dict[str, list[str]] = defaultdict(list)
            for member in members:
                filename = Path(member.filename).name
                identity = expected.get(filename)
                if identity is None or member.file_size != identity[0]:
                    continue
                if hash_zip_member(bundle, member) == identity[1]:
                    verified[filename].append(member.filename)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        return False, f"{type(error).__name__}: {error}"

    missing = sorted(filename for filename in expected if not verified.get(filename))
    duplicated = sorted(
        filename for filename, matches in verified.items() if len(matches) != 1
    )
    if missing or duplicated:
        return (
            False,
            f"missing={missing!r}; duplicate_exact_members={duplicated!r}",
        )
    return True, f"verified {len(expected)} locked DEB member(s) by size and SHA-256"


def probe_artifact_contents(
    repository: str,
    artifact: dict[str, Any],
    rows: list[dict[str, Any]],
) -> tuple[bool, str]:
    artifact_id = str(artifact.get("id") or "").strip()
    if not artifact_id.isdigit():
        return False, "artifact ID is missing or invalid"
    with tempfile.TemporaryDirectory(prefix="artifact-name-probe-") as temporary:
        archive = Path(temporary) / f"artifact-{artifact_id}.zip"
        with archive.open("wb") as output:
            process = subprocess.run(
                [
                    "gh",
                    "api",
                    f"repos/{repository}/actions/artifacts/{artifact_id}/zip",
                ],
                stdout=output,
                stderr=subprocess.PIPE,
                check=False,
            )
        if process.returncode:
            stderr = process.stderr.decode("utf-8", errors="replace").strip()
            return False, f"artifact download failed: {stderr}"
        return inspect_artifact_zip(archive, rows)


CandidateVerifier = Callable[
    [dict[str, Any], list[dict[str, Any]]],
    tuple[bool, str],
]


def resolve_collision_by_locked_members(
    *,
    declared: str,
    rows: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    verifier: CandidateVerifier | None,
    collision_label: str,
) -> tuple[dict[str, Any], str] | None:
    if verifier is None:
        return None
    verified: list[dict[str, Any]] = []
    probe_results: list[dict[str, Any]] = []
    for artifact in candidates:
        name = str(artifact.get("name") or "")
        artifact_id = str(artifact.get("id") or "")
        try:
            passed, detail = verifier(artifact, rows)
        except Exception as error:
            passed = False
            detail = f"{type(error).__name__}: {error}"
        probe_results.append(
            {
                "id": artifact_id,
                "name": name,
                "passed": passed,
                "detail": detail,
            }
        )
        if passed:
            verified.append(artifact)
    if len(verified) == 1:
        return verified[0], f"verified-member-bytes-{collision_label}"
    raise RuntimeError(
        f"artifact name {declared!r} has {len(candidates)} {collision_label} "
        f"matches and {len(verified)} passed locked-member verification: "
        f"{probe_results}"
    )


def resolve_artifact(
    declared: str,
    rows: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    verify_candidate: CandidateVerifier | None = None,
) -> tuple[dict[str, Any], str]:
    available = [
        row
        for row in artifacts
        if row.get("expired") is not True
        and isinstance(row.get("name"), str)
        and row.get("name")
        and row.get("id") not in (None, "")
    ]
    exact = [row for row in available if row["name"] == declared]
    if len(exact) == 1:
        return exact[0], "exact"
    if len(exact) > 1:
        raise RuntimeError(f"duplicate exact artifact name: {declared}")

    prefixes = source_prefixes(rows)
    suffix = "-" + declared
    candidates = [
        row
        for row in available
        if row["name"].endswith(suffix)
        and any(
            row["name"] == prefix + suffix
            or row["name"].startswith(prefix + "-")
            for prefix in prefixes
        )
    ]
    if len(candidates) == 1:
        return candidates[0], "unique-source-suffix"
    if len(candidates) > 1:
        resolved = resolve_collision_by_locked_members(
            declared=declared,
            rows=rows,
            candidates=candidates,
            verifier=verify_candidate,
            collision_label="source-qualified-suffix",
        )
        if resolved is not None:
            return resolved
        names = sorted(str(row["name"]) for row in candidates)
        raise RuntimeError(
            f"artifact name {declared!r} has {len(candidates)} "
            f"source-qualified suffix matches: {names}"
        )

    source_candidates = [
        row
        for row in available
        if any(prefix in row["name"] for prefix in prefixes)
    ]
    if len(source_candidates) == 1:
        return source_candidates[0], "unique-source-qualified"
    if len(source_candidates) > 1:
        resolved = resolve_collision_by_locked_members(
            declared=declared,
            rows=rows,
            candidates=source_candidates,
            verifier=verify_candidate,
            collision_label="source-qualified",
        )
        if resolved is not None:
            return resolved
    names = sorted(str(row["name"]) for row in source_candidates)
    raise RuntimeError(
        f"artifact name {declared!r} has {len(source_candidates)} "
        f"source-qualified matches: {names}"
    )


def resolve_rows(
    rows: list[dict[str, Any]],
    repository: str,
    list_artifacts: Callable[[str, str], list[dict[str, Any]]] = artifact_pages,
    verify_candidate: CandidateVerifier | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    groups: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for index, row in enumerate(rows):
        run_id = str(row.get("actions_run_id") or "").strip()
        artifact_name = str(row.get("artifact_name") or "").strip()
        if not run_id or not artifact_name:
            raise RuntimeError(f"row {index} lacks actions_run_id or artifact_name")
        groups[(run_id, artifact_name)].append((index, row))

    if verify_candidate is None:
        verify_candidate = lambda artifact, members: probe_artifact_contents(
            repository, artifact, members
        )

    output = [dict(row) for row in rows]
    evidence: list[dict[str, Any]] = []
    listings: dict[str, list[dict[str, Any]]] = {}
    for (run_id, declared), members in sorted(groups.items()):
        artifacts = listings.setdefault(run_id, list_artifacts(repository, run_id))
        group_rows = [row for _, row in members]
        artifact, method = resolve_artifact(
            declared,
            group_rows,
            artifacts,
            verify_candidate=verify_candidate,
        )
        resolved = str(artifact["name"])
        artifact_id = str(artifact["id"])
        for index, _ in members:
            output[index]["declared_artifact_name"] = declared
            output[index]["artifact_name"] = resolved
            output[index]["resolved_artifact_id"] = artifact_id
            output[index]["artifact_name_resolution"] = method
        evidence.append(
            {
                "actions_run_id": run_id,
                "declared_artifact_name": declared,
                "resolved_artifact_name": resolved,
                "resolved_artifact_id": artifact_id,
                "resolved_artifact_digest": artifact.get("digest"),
                "resolution": method,
                "locked_member_bytes_verified": method.startswith(
                    "verified-member-bytes-"
                ),
                "package_count": len(members),
                "packages": sorted(str(row.get("package") or "") for row in group_rows),
            }
        )
    return output, evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--github-repository", required=True)
    args = parser.parse_args()

    resolved, evidence = resolve_rows(load_rows(args.input), args.github_repository)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(resolved, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.evidence.write_text(
        json.dumps(
            {
                "schema": 2,
                "policy": (
                    "exact-or-unique-source-qualified-or-locked-member-byte-"
                    "verified-artifact-resolution"
                ),
                "group_count": len(evidence),
                "rewritten_group_count": sum(
                    row["resolution"] != "exact" for row in evidence
                ),
                "locked_member_verified_group_count": sum(
                    row["locked_member_bytes_verified"] for row in evidence
                ),
                "groups": evidence,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
