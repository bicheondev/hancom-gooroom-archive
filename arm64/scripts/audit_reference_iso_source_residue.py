#!/usr/bin/env python3
"""Audit a Hancom Gooroom reference ISO/rootfs for exact source-package residue.

This script is intentionally evidentiary and fail-closed. It never promotes a
source from a binary version string alone. It records exact Debian Sources
stanzas, Packages/status stanzas, source-archive members, APT configuration,
repository URLs, and bounded exact-version text hits. Later workflows can use
that evidence to acquire and verify exact .dsc members without weakening the
exact-version policy.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import json
import lzma
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

MAX_TEXT_BYTES = 128 * 1024 * 1024
MAX_HITS_PER_TARGET = 160
MAX_EXCERPT = 500
URL_RE = re.compile(r"https?://[^\s\"'<>\]\[(){}]+", re.IGNORECASE)
SOURCE_FIELD_RE = re.compile(r"^\s*([^\s(]+)(?:\s*\(([^)]+)\))?\s*$")


@dataclass(frozen=True)
class Target:
    source: str
    version: str
    binary_packages: tuple[str, ...]


TARGETS: tuple[Target, ...] = (
    Target(
        "gnome-flashback",
        "3.38.0-2+grm3u2+han3u4",
        ("gnome-flashback", "gnome-flashback-common", "gnome-session-flashback"),
    ),
    Target(
        "gooroom-dockbarx-applet",
        "0.3.1+grm3u1+han3u1",
        ("gooroom-dockbarx-applet",),
    ),
    Target(
        "gooroom-guide",
        "0.5.3+grm3u1+han3u1",
        ("gooroom-guide",),
    ),
    Target(
        "gooroom-integration-applet",
        "0.3.1+grm3u1+han3u3",
        ("gooroom-integration-applet",),
    ),
    Target(
        "gooroom-session-manager",
        "0.3.9+grm3u1+han3u2",
        ("gooroom-session-manager",),
    ),
    Target(
        "linux",
        "5.10.179-1+grm3u1",
        ("linux-image-5.10.0-23-amd64",),
    ),
    Target(
        "qtbase-opensource-src",
        "5.15.2+dfsg-9+grm3u1",
        (
            "libqt5core5a",
            "libqt5dbus5",
            "libqt5gui5",
            "libqt5network5",
            "libqt5printsupport5",
            "libqt5sql5",
            "libqt5test5",
            "libqt5widgets5",
            "libqt5xml5",
        ),
    ),
)

TARGET_BY_SOURCE = {target.source: target for target in TARGETS}
TARGET_BY_BINARY = {
    package: target for target in TARGETS for package in target.binary_packages
}


class AuditError(RuntimeError):
    pass


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


def safe_name(origin: str) -> str:
    value = origin.strip("/").replace("/", "__")
    value = re.sub(r"[^A-Za-z0-9._+~-]", "_", value)
    return value or "root"


def logical_path(path: Path, iso_root: Path, rootfs: Path) -> str:
    try:
        return "iso:/" + path.relative_to(iso_root).as_posix()
    except ValueError:
        pass
    try:
        return "rootfs:/" + path.relative_to(rootfs).as_posix()
    except ValueError:
        return path.as_posix()


def compression_kind(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".gz"):
        return "gzip"
    if name.endswith((".xz", ".lzma")):
        return "xz"
    if name.endswith(".bz2"):
        return "bzip2"
    if name.endswith(".lz4"):
        return "lz4"
    if name.endswith((".zst", ".zstd")):
        return "zstd"
    try:
        with path.open("rb") as stream:
            magic = stream.read(8)
    except OSError:
        return "plain"
    if magic.startswith(b"\x1f\x8b"):
        return "gzip"
    if magic.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if magic.startswith(b"BZh"):
        return "bzip2"
    if magic.startswith(b"\x04\x22\x4d\x18"):
        return "lz4"
    if magic.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    return "plain"


def iter_text_lines(path: Path) -> Iterator[str]:
    """Yield decoded lines without materializing a potentially large APT index."""
    kind = compression_kind(path)
    if kind == "plain":
        if path.stat().st_size > MAX_TEXT_BYTES:
            raise AuditError(f"plain text candidate exceeds limit: {path}")
        with path.open("rb") as raw:
            sample = raw.read(4096)
            if b"\x00" in sample:
                raise AuditError(f"binary plain file: {path}")
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            yield from stream
        return

    if kind == "gzip":
        opener = gzip.open
    elif kind == "xz":
        opener = lzma.open
    elif kind == "bzip2":
        opener = bz2.open
    else:
        command = {
            "lz4": ["lz4", "-dc", str(path)],
            "zstd": ["zstd", "-dc", "--", str(path)],
        }[kind]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        try:
            yield from process.stdout
        finally:
            process.stdout.close()
            stderr = process.stderr.read() if process.stderr is not None else ""
            return_code = process.wait()
            if return_code:
                raise AuditError(
                    f"decompressor failed ({return_code}) for {path}: {stderr[-2000:]}"
                )
        return

    with opener(path, "rt", encoding="utf-8", errors="replace") as stream:  # type: ignore[arg-type]
        yield from stream


def read_text_bounded(path: Path, max_chars: int = 4_000_000) -> str:
    chunks: list[str] = []
    total = 0
    for line in iter_text_lines(path):
        chunks.append(line)
        total += len(line)
        if total > max_chars:
            chunks.append("\n[truncated by audit]\n")
            break
    return "".join(chunks)


def iter_deb822_stanzas(lines: Iterable[str]) -> Iterator[tuple[dict[str, str], str]]:
    block: list[str] = []
    for line in lines:
        if line.strip():
            block.append(line.rstrip("\n"))
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
        if line.startswith((" ", "\t")) and current is not None:
            fields[current] += "\n" + line
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields, "\n".join(block) + "\n"


def parse_source_field(value: str, fallback_version: str) -> tuple[str, str]:
    if not value:
        return "", fallback_version
    match = SOURCE_FIELD_RE.match(value)
    if not match:
        return value.strip(), fallback_version
    return match.group(1), match.group(2) or fallback_version


def parse_checksum_lines(value: str, kind: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        checksum, size, filename = parts
        try:
            parsed_size = int(size)
        except ValueError:
            continue
        rows.append(
            {
                "kind": kind,
                "checksum": checksum,
                "size": parsed_size,
                "filename": filename,
            }
        )
    return rows


def source_stanza_record(
    fields: dict[str, str], raw: str, logical: str
) -> dict[str, Any]:
    members = []
    members.extend(parse_checksum_lines(fields.get("Files", ""), "md5"))
    members.extend(parse_checksum_lines(fields.get("Checksums-Sha1", ""), "sha1"))
    members.extend(parse_checksum_lines(fields.get("Checksums-Sha256", ""), "sha256"))
    return {
        "index_path": logical,
        "package": fields.get("Package", ""),
        "version": fields.get("Version", ""),
        "directory": fields.get("Directory", ""),
        "binary": fields.get("Binary", ""),
        "architecture": fields.get("Architecture", ""),
        "format": fields.get("Format", ""),
        "vcs_git": fields.get("Vcs-Git", ""),
        "vcs_browser": fields.get("Vcs-Browser", ""),
        "members": members,
        "raw_stanza": raw,
    }


def package_stanza_record(
    fields: dict[str, str], raw: str, logical: str
) -> dict[str, Any]:
    package_version = fields.get("Version", "")
    parsed_source, parsed_source_version = parse_source_field(
        fields.get("Source", ""), package_version
    )
    return {
        "index_path": logical,
        "package": fields.get("Package", ""),
        "version": package_version,
        "architecture": fields.get("Architecture", ""),
        "source_field": fields.get("Source", ""),
        "parsed_source": parsed_source,
        "parsed_source_version": parsed_source_version,
        "filename": fields.get("Filename", ""),
        "sha256": fields.get("SHA256", ""),
        "size": fields.get("Size", ""),
        "raw_stanza": raw,
    }


def source_archive_kind(name: str) -> str | None:
    lower = name.lower()
    if lower.endswith(".dsc"):
        return "dsc"
    if ".orig.tar." in lower:
        return "orig"
    if ".debian.tar." in lower:
        return "debian"
    if lower.endswith(".diff.gz"):
        return "diff"
    if lower.endswith("_source.changes"):
        return "source-changes"
    if lower.endswith(".buildinfo"):
        return "buildinfo"
    return None


def relevant_roots(iso_root: Path, rootfs: Path) -> list[Path]:
    roots = [
        rootfs / "etc/apt",
        rootfs / "etc/os-release",
        rootfs / "etc/debian_version",
        rootfs / "var/lib/apt/lists",
        rootfs / "var/cache/apt/archives",
        rootfs / "var/log/apt",
        rootfs / "var/log/installer",
        rootfs / "var/lib/dpkg/status",
        iso_root / ".disk",
        iso_root / "dists",
        iso_root / "pool",
    ]
    for target in TARGETS:
        for package in target.binary_packages:
            roots.append(rootfs / "usr/share/doc" / package)
    return roots


def walk_selected(paths: Iterable[Path]) -> Iterator[Path]:
    seen: set[Path] = set()
    for candidate in paths:
        if not candidate.exists():
            continue
        if candidate.is_file() or candidate.is_symlink():
            if candidate not in seen:
                seen.add(candidate)
                yield candidate
            continue
        for root, dirs, files in os.walk(candidate, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in {"partial"} or "apt" in root)
            for name in sorted(files):
                path = Path(root) / name
                if path not in seen:
                    seen.add(path)
                    yield path


def find_source_archives(iso_root: Path, rootfs: Path) -> list[Path]:
    found: list[Path] = []
    for base in (iso_root, rootfs):
        for root, dirs, files in os.walk(base, followlinks=False):
            relative_parts = Path(root).relative_to(base).parts
            if base == rootfs and relative_parts and relative_parts[0] in {
                "proc",
                "sys",
                "dev",
                "run",
            }:
                dirs[:] = []
                continue
            for name in files:
                if source_archive_kind(name) is not None:
                    found.append(Path(root) / name)
    return sorted(set(found))


def classify_index(path: Path) -> str | None:
    name = path.name
    if "Sources" in name or name.endswith("_source_Sources"):
        return "sources"
    if "Packages" in name or name.endswith("_binary-amd64_Packages"):
        return "packages"
    if path.as_posix().endswith("/var/lib/dpkg/status"):
        return "status"
    return None


def copy_compact_text(path: Path, logical: str, output_dir: Path) -> None:
    text = read_text_bounded(path)
    target = output_dir / "selected-text" / f"{safe_name(logical)}.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--iso-root", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-iso-sha256", required=True)
    parser.add_argument("--expected-iso-size", type=int, required=True)
    parser.add_argument("--extraction-metadata", type=Path)
    args = parser.parse_args()

    for path, label in (
        (args.iso, "ISO"),
        (args.iso_root, "ISO root"),
        (args.rootfs, "rootfs"),
    ):
        if not path.exists():
            raise SystemExit(f"{label} is missing: {path}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    actual_size = args.iso.stat().st_size
    actual_sha256 = sha256_file(args.iso)
    if actual_size != args.expected_iso_size:
        raise SystemExit(
            f"ISO size mismatch: {actual_size} != {args.expected_iso_size}"
        )
    if actual_sha256 != args.expected_iso_sha256:
        raise SystemExit(
            f"ISO SHA-256 mismatch: {actual_sha256} != {args.expected_iso_sha256}"
        )

    extraction_metadata: dict[str, Any] = {}
    if args.extraction_metadata and args.extraction_metadata.is_file():
        extraction_metadata = json.loads(
            args.extraction_metadata.read_text(encoding="utf-8")
        )

    findings: dict[str, dict[str, Any]] = {
        target.source: {
            "source": target.source,
            "source_version": target.version,
            "binary_packages": list(target.binary_packages),
            "source_index_stanzas": [],
            "package_index_stanzas": [],
            "installed_status_stanzas": [],
            "exact_version_hits": [],
            "source_archives": [],
        }
        for target in TARGETS
    }
    repository_urls: set[str] = set()
    selected_files: list[dict[str, Any]] = []
    parse_errors: list[dict[str, str]] = []
    source_index_count = 0
    package_index_count = 0
    status_file_count = 0

    selected_paths = list(walk_selected(relevant_roots(args.iso_root, args.rootfs)))
    for path in selected_paths:
        if not path.is_file():
            continue
        logical = logical_path(path, args.iso_root, args.rootfs)
        try:
            size = path.stat().st_size
        except OSError as exc:
            parse_errors.append({"path": logical, "error": str(exc)})
            continue

        kind = classify_index(path)
        selected_files.append(
            {
                "path": logical,
                "size": size,
                "compression": compression_kind(path),
                "classification": kind or "selected-text",
            }
        )

        try:
            if kind == "sources":
                source_index_count += 1
                for fields, raw in iter_deb822_stanzas(iter_text_lines(path)):
                    package = fields.get("Package", "")
                    version = fields.get("Version", "")
                    target = TARGET_BY_SOURCE.get(package)
                    if target is None or version != target.version:
                        continue
                    findings[target.source]["source_index_stanzas"].append(
                        source_stanza_record(fields, raw, logical)
                    )
                    for url in URL_RE.findall(raw):
                        repository_urls.add(url.rstrip(".,;"))
            elif kind in {"packages", "status"}:
                if kind == "packages":
                    package_index_count += 1
                else:
                    status_file_count += 1
                for fields, raw in iter_deb822_stanzas(iter_text_lines(path)):
                    package = fields.get("Package", "")
                    package_version = fields.get("Version", "")
                    parsed_source, parsed_source_version = parse_source_field(
                        fields.get("Source", ""), package_version
                    )
                    target = TARGET_BY_BINARY.get(package) or TARGET_BY_SOURCE.get(
                        parsed_source
                    )
                    if target is None:
                        continue
                    exact = (
                        package_version == target.version
                        or parsed_source_version == target.version
                    )
                    if not exact:
                        continue
                    record = package_stanza_record(fields, raw, logical)
                    key = (
                        "installed_status_stanzas"
                        if kind == "status"
                        else "package_index_stanzas"
                    )
                    findings[target.source][key].append(record)
                    for url in URL_RE.findall(raw):
                        repository_urls.add(url.rstrip(".,;"))

            for line_number, line in enumerate(iter_text_lines(path), start=1):
                for url in URL_RE.findall(line):
                    repository_urls.add(url.rstrip(".,;"))
                for target in TARGETS:
                    if target.version not in line:
                        continue
                    target_hits = findings[target.source]["exact_version_hits"]
                    if len(target_hits) >= MAX_HITS_PER_TARGET:
                        continue
                    target_hits.append(
                        {
                            "path": logical,
                            "line": line_number,
                            "excerpt": line.strip()[:MAX_EXCERPT],
                        }
                    )

            if kind is None and size <= 8 * 1024 * 1024:
                copy_compact_text(path, logical, args.output_dir)
        except (AuditError, OSError, EOFError, lzma.LZMAError) as exc:
            parse_errors.append({"path": logical, "error": str(exc)})

    archive_records: list[dict[str, Any]] = []
    for path in find_source_archives(args.iso_root, args.rootfs):
        logical = logical_path(path, args.iso_root, args.rootfs)
        try:
            record = {
                "path": logical,
                "kind": source_archive_kind(path.name),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        except OSError as exc:
            parse_errors.append({"path": logical, "error": str(exc)})
            continue
        archive_records.append(record)
        for target in TARGETS:
            if target.version in path.name or target.source in path.name:
                findings[target.source]["source_archives"].append(record)

    for target in TARGETS:
        row = findings[target.source]
        if row["source_index_stanzas"]:
            status = "exact-source-index-stanza-found"
        elif any(target.version in item["path"] for item in row["source_archives"]):
            status = "exact-source-archive-residue-found"
        elif (
            row["package_index_stanzas"]
            or row["installed_status_stanzas"]
            or row["exact_version_hits"]
        ):
            status = "exact-version-residue-only"
        else:
            status = "not-found"
        row["status"] = status
        row["counts"] = {
            "source_index_stanzas": len(row["source_index_stanzas"]),
            "package_index_stanzas": len(row["package_index_stanzas"]),
            "installed_status_stanzas": len(row["installed_status_stanzas"]),
            "exact_version_hits": len(row["exact_version_hits"]),
            "source_archives": len(row["source_archives"]),
        }

        if row["source_index_stanzas"]:
            stanza_path = (
                args.output_dir
                / "exact-source-stanzas"
                / f"{safe_name(target.source)}.txt"
            )
            stanza_path.parent.mkdir(parents=True, exist_ok=True)
            stanza_path.write_text(
                "\n".join(
                    record["raw_stanza"] for record in row["source_index_stanzas"]
                ),
                encoding="utf-8",
            )
        if row["package_index_stanzas"] or row["installed_status_stanzas"]:
            package_path = (
                args.output_dir
                / "exact-package-stanzas"
                / f"{safe_name(target.source)}.txt"
            )
            package_path.parent.mkdir(parents=True, exist_ok=True)
            package_path.write_text(
                "\n".join(
                    record["raw_stanza"]
                    for key in ("package_index_stanzas", "installed_status_stanzas")
                    for record in row[key]
                ),
                encoding="utf-8",
            )

    target_rows = [findings[target.source] for target in TARGETS]
    exact_source_targets = sum(
        row["status"] == "exact-source-index-stanza-found" for row in target_rows
    )
    source_archive_targets = sum(
        row["status"] == "exact-source-archive-residue-found" for row in target_rows
    )
    residue_only_targets = sum(
        row["status"] == "exact-version-residue-only" for row in target_rows
    )
    missing_targets = sum(row["status"] == "not-found" for row in target_rows)

    summary = {
        "schema": 1,
        "policy": "exact-source-residue-audit-no-promotion-from-version-text-alone",
        "iso": {
            "name": args.iso.name,
            "size": actual_size,
            "sha256": actual_sha256,
            "verified": True,
        },
        "extraction": extraction_metadata,
        "target_count": len(TARGETS),
        "exact_source_index_target_count": exact_source_targets,
        "exact_source_archive_target_count": source_archive_targets,
        "exact_version_residue_only_target_count": residue_only_targets,
        "not_found_target_count": missing_targets,
        "source_index_file_count": source_index_count,
        "package_index_file_count": package_index_count,
        "dpkg_status_file_count": status_file_count,
        "source_archive_file_count": len(archive_records),
        "repository_url_count": len(repository_urls),
        "parse_error_count": len(parse_errors),
        "source_recovery_ready": exact_source_targets > 0 or source_archive_targets > 0,
        "promotion_allowed": False,
    }

    write_json(args.output_dir / "summary.json", summary)
    write_json(args.output_dir / "target-findings.json", target_rows)
    write_json(args.output_dir / "selected-file-inventory.json", selected_files)
    write_json(args.output_dir / "source-archive-manifest.json", archive_records)
    write_json(args.output_dir / "parse-errors.json", parse_errors)
    (args.output_dir / "repository-urls.txt").write_text(
        "\n".join(sorted(repository_urls)) + ("\n" if repository_urls else ""),
        encoding="utf-8",
    )
    (args.output_dir / "targets.tsv").write_text(
        "source\tsource_version\tstatus\tsource_stanzas\tpackage_stanzas\tstatus_stanzas\tversion_hits\tsource_archives\n"
        + "".join(
            "\t".join(
                [
                    row["source"],
                    row["source_version"],
                    row["status"],
                    str(row["counts"]["source_index_stanzas"]),
                    str(row["counts"]["package_index_stanzas"]),
                    str(row["counts"]["installed_status_stanzas"]),
                    str(row["counts"]["exact_version_hits"]),
                    str(row["counts"]["source_archives"]),
                ]
            )
            + "\n"
            for row in target_rows
        ),
        encoding="utf-8",
    )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditError as exc:
        print(f"audit error: {exc}", file=sys.stderr)
        raise SystemExit(2)
