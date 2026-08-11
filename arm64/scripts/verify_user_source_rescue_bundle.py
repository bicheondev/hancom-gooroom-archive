#!/usr/bin/env python3
"""Verify a user-supplied Hancom Gooroom source-rescue bundle.

Only a Sources index byte-identical to the reference ISO InRelease lock is
accepted. A source is complete only when every Checksums-Sha256 member in its
exact source stanza is present and byte-identical. No filename/version-only
promotion is possible.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any, Iterator

HEX64 = re.compile(r"^[0-9a-f]{64}$")
TARGETS = {
    ("gnome-flashback", "3.38.0-2+grm3u2+han3u4"),
    ("gooroom-dockbarx-applet", "0.3.1+grm3u1+han3u1"),
    ("gooroom-guide", "0.5.3+grm3u1+han3u1"),
    ("gooroom-integration-applet", "0.3.1+grm3u1+han3u3"),
    ("gooroom-session-manager", "0.3.9+grm3u1+han3u2"),
    ("linux", "5.10.179-1+grm3u1"),
    ("qtbase-opensource-src", "5.15.2+dfsg-9+grm3u1"),
}


def sha256(path: Path) -> str:
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


def parse_inrelease(path: Path) -> dict[str, dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="strict")
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        cut = text.find("\n\n")
        if cut < 0:
            raise SystemExit(f"malformed InRelease: {path}")
        text = text[cut + 2 :]
        signature = text.find("\n-----BEGIN PGP SIGNATURE-----")
        if signature >= 0:
            text = text[:signature]

    active = False
    rows: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        if line == "SHA256:":
            active = True
            continue
        if active and re.fullmatch(r"[A-Za-z0-9-]+:", line):
            break
        if not active:
            continue
        parts = line.split()
        if len(parts) == 3 and HEX64.fullmatch(parts[0]):
            rows[parts[2]] = {"sha256": parts[0], "size": int(parts[1])}

    for required in ("main/source/Sources", "main/source/Sources.gz"):
        if required not in rows:
            raise SystemExit(f"missing reference lock {required}: {path}")
    return rows


def parse_block(lines: list[str]) -> tuple[dict[str, str], str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in lines:
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields, "\n".join(lines) + "\n"


def stanzas(text: str) -> Iterator[tuple[dict[str, str], str]]:
    block: list[str] = []
    for line in text.splitlines():
        if line.strip():
            block.append(line)
        elif block:
            yield parse_block(block)
            block = []
    if block:
        yield parse_block(block)


def checksums(value: str) -> list[dict[str, Any]]:
    rows = []
    for line in value.splitlines():
        parts = line.split()
        if len(parts) == 3 and HEX64.fullmatch(parts[0]):
            rows.append(
                {"sha256": parts[0], "size": int(parts[1]), "filename": parts[2]}
            )
    return rows


def find_unique(
    root: Path, filename: str, size: int, digest: str
) -> tuple[Path | None, list[dict[str, Any]]]:
    inspected: list[dict[str, Any]] = []
    matches: list[Path] = []
    for path in sorted(root.rglob(filename)):
        if not path.is_file():
            continue
        row: dict[str, Any] = {
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
        }
        if path.stat().st_size == size:
            row["sha256"] = sha256(path)
            if row["sha256"] == digest:
                row["verified"] = True
                matches.append(path)
        inspected.append(row)
    if len(matches) > 1:
        unique_digests = {sha256(path) for path in matches}
        if len(unique_digests) != 1:
            raise SystemExit(f"ambiguous different files for {filename}")
    return (matches[0] if matches else None), inspected


def load_verified_sources(
    repo_root: Path, locks: dict[str, dict[str, Any]]
) -> tuple[bytes | None, dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    plain: bytes | None = None
    for name in ("Sources.gz", "Sources"):
        expected_key = "main/source/" + name
        expected = locks[expected_key]
        path, inspected = find_unique(
            repo_root, name, expected["size"], expected["sha256"]
        )
        attempts.extend(inspected)
        if path is None:
            continue
        data = path.read_bytes()
        if name.endswith(".gz"):
            data = gzip.decompress(data)
            plain_lock = locks["main/source/Sources"]
            if (
                len(data) != plain_lock["size"]
                or hashlib.sha256(data).hexdigest() != plain_lock["sha256"]
            ):
                raise SystemExit(
                    f"{path}: decompressed Sources does not match InRelease"
                )
        plain = data
        break
    return plain, {"attempts": attempts, "resolved": plain is not None}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--gooroom-inrelease", type=Path, required=True)
    parser.add_argument("--hancom-inrelease", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--release-tag", default="")
    parser.add_argument("--asset-name", default="")
    parser.add_argument("--asset-sha256", default="")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    repositories = {
        "gooroom": (
            args.gooroom_inrelease,
            parse_inrelease(args.gooroom_inrelease),
        ),
        "hancom": (
            args.hancom_inrelease,
            parse_inrelease(args.hancom_inrelease),
        ),
    }
    all_rows: list[dict[str, Any]] = []
    complete: list[dict[str, Any]] = []
    repository_results: list[dict[str, Any]] = []

    for repository, (inrelease, locks) in repositories.items():
        repository_root = args.bundle_dir / repository
        if not repository_root.exists():
            candidates = [
                path
                for path in args.bundle_dir.rglob(repository)
                if path.is_dir()
            ]
            repository_root = (
                candidates[0] if len(candidates) == 1 else repository_root
            )
        if repository_root.exists():
            source_bytes, index_result = load_verified_sources(
                repository_root, locks
            )
        else:
            source_bytes, index_result = None, {"attempts": [], "resolved": False}

        exact_rows: list[dict[str, Any]] = []
        if source_bytes is not None:
            for fields, raw in stanzas(
                source_bytes.decode("utf-8", errors="strict")
            ):
                key = (fields.get("Package", ""), fields.get("Version", ""))
                if key not in TARGETS:
                    continue
                members = checksums(fields.get("Checksums-Sha256", ""))
                member_rows: list[dict[str, Any]] = []
                all_members_present = bool(members) and any(
                    member["filename"].endswith(".dsc") for member in members
                )
                copied: list[dict[str, Any]] = []
                for member in members:
                    path, inspected = find_unique(
                        args.bundle_dir,
                        member["filename"],
                        member["size"],
                        member["sha256"],
                    )
                    member_row = {
                        **member,
                        "resolved": path is not None,
                        "path": (
                            path.relative_to(args.bundle_dir).as_posix()
                            if path
                            else None
                        ),
                        "inspected": inspected,
                    }
                    member_rows.append(member_row)
                    if path is None:
                        all_members_present = False
                    else:
                        target_dir = (
                            args.output_dir
                            / "verified-sources"
                            / key[0]
                            / key[1]
                        )
                        target_dir.mkdir(parents=True, exist_ok=True)
                        destination = target_dir / member["filename"]
                        if not destination.exists():
                            shutil.copy2(path, destination)
                        copied.append(
                            {
                                "filename": member["filename"],
                                "size": member["size"],
                                "sha256": member["sha256"],
                            }
                        )

                row = {
                    "repository": repository,
                    "source": key[0],
                    "source_version": key[1],
                    "directory": fields.get("Directory", ""),
                    "format": fields.get("Format", ""),
                    "members": member_rows,
                    "complete": all_members_present,
                    "raw_stanza": raw,
                }
                exact_rows.append(row)
                all_rows.append(row)
                if all_members_present:
                    lock = {
                        "schema": 1,
                        "status": "verified-user-source-rescue",
                        "source": key[0],
                        "source_version": key[1],
                        "repository": repository,
                        "inrelease_sha256": sha256(inrelease),
                        "source_index_sha256": hashlib.sha256(
                            source_bytes
                        ).hexdigest(),
                        "directory": fields.get("Directory", ""),
                        "members": copied,
                        "release_tag": args.release_tag,
                        "asset_name": args.asset_name,
                        "asset_sha256": args.asset_sha256,
                        "byte_identity_verified": True,
                        "promotion_allowed": False,
                    }
                    write_json(
                        args.output_dir
                        / "source-locks"
                        / key[0]
                        / key[1]
                        / "source-lock.json",
                        lock,
                    )
                    complete.append(lock)

        repository_results.append(
            {
                "repository": repository,
                "inrelease_sha256": sha256(inrelease),
                "index": index_result,
                "exact_target_count": len(exact_rows),
                "complete_target_count": sum(
                    row["complete"] for row in exact_rows
                ),
                "targets": exact_rows,
            }
        )

    summary = {
        "schema": 1,
        "policy": (
            "reference-InRelease-byte-identity-and-complete-dsc-member-set"
        ),
        "release_tag": args.release_tag,
        "asset_name": args.asset_name,
        "asset_sha256": args.asset_sha256,
        "target_count": len(TARGETS),
        "verified_source_index_count": sum(
            row["index"]["resolved"] for row in repository_results
        ),
        "exact_target_stanza_count": len(all_rows),
        "complete_source_count": len(complete),
        "complete_sources": [
            {
                "source": row["source"],
                "source_version": row["source_version"],
                "repository": row["repository"],
            }
            for row in complete
        ],
        "repositories": repository_results,
        "effective_source_authority_update_allowed": len(complete) > 0,
        "iso_assembly_allowed": False,
    }
    write_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
