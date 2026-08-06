#!/usr/bin/env python3
"""Validate one exact source build without requiring Architecture: all outputs."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SOURCE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9+.:~-]*)(?:\s*\(\s*(?:=\s*)?([^()]+?)\s*\))?\s*$"
)
LEGACY_MISSING_RE = re.compile(r"Expected binary package was not built:\s*([^\s]+)")
X86_RE = re.compile(r"(?:x86-64|Intel 80386|\bi[3-6]86\b)", re.I)
ARM64_RE = re.compile(r"(?:ARM aarch64|AArch64)", re.I)


def first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            return value
    return None


def parse_source(value: Any) -> tuple[str | None, str | None]:
    if isinstance(value, dict):
        name = first(value, "name", "source", "package", "source_name")
        version = first(value, "version", "source_version")
        return (
            str(name) if name is not None else None,
            str(version) if version is not None else None,
        )
    if not isinstance(value, str):
        return None, None
    match = SOURCE_RE.match(value)
    if match:
        return match.group(1), match.group(2)
    return value.split(" ", 1)[0].strip() or None, None


def package_name(row: dict[str, Any]) -> str | None:
    value = first(row, "package", "binary_package", "binary", "name")
    return str(value) if value is not None else None


def package_version(row: dict[str, Any]) -> str | None:
    value = first(row, "version", "binary_version")
    return str(value) if value is not None else None


def package_arch(row: dict[str, Any]) -> str | None:
    value = first(row, "architecture", "arch", "binary_architecture")
    return str(value) if value is not None else None


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root is not an object: {path}")
    return value


def lock_row(document: dict[str, Any], source: str) -> dict[str, Any]:
    rows = document.get("sources", [document])
    matches = [
        row
        for row in rows
        if isinstance(row, dict) and row.get("source") == source
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected one effective source-lock row for {source}; found {len(matches)}"
        )
    row = matches[0]
    if row.get("status") not in (None, "resolved"):
        raise SystemExit(f"source lock is not resolved: {row.get('status')}")
    selected = row.get("selected")
    if isinstance(selected, dict):
        if selected.get("declared_source") not in (None, source):
            raise SystemExit("selected commit declares another source package")
        if selected.get("declared_version") not in (
            None,
            row.get("source_version"),
        ):
            raise SystemExit("selected commit declares another source version")
    return row


def expected_from_reference(
    document: dict[str, Any], source: str, source_version: str
) -> tuple[dict[str, dict[str, str]], list[str]]:
    expected: dict[str, dict[str, str]] = {}
    issues: list[str] = []
    for item in document.get("packages", []):
        if not isinstance(item, dict):
            continue
        raw_source = first(item, "source", "source_package", "source_name")
        item_source, embedded_version = parse_source(raw_source)
        item_source = item_source or package_name(item)
        item_source_version = first(
            item,
            "source_version",
            "source-version",
            "sourceVersion",
        )
        item_source_version = (
            str(item_source_version)
            if item_source_version is not None
            else embedded_version
        )
        if item_source != source:
            continue
        if item_source_version and item_source_version != source_version:
            continue
        name = package_name(item)
        version = package_version(item)
        architecture = package_arch(item)
        if not name or not version or not architecture:
            issues.append(f"incomplete reference row: {item!r}")
            continue
        candidate = {
            "package": name,
            "version": version,
            "architecture": architecture,
            "origin": "amd64-reference",
        }
        previous = expected.get(name)
        if previous and previous != candidate:
            issues.append(f"conflicting reference rows for {name}")
        else:
            expected[name] = candidate
    return expected, issues


def expected_from_lock(
    row: dict[str, Any], source_version: str
) -> tuple[dict[str, dict[str, str]], list[str]]:
    packages = row.get("binary_packages", [])
    architectures = row.get("binary_architectures", [])
    issues: list[str] = []
    expected: dict[str, dict[str, str]] = {}
    if isinstance(packages, dict):
        packages = [
            {"package": name, **(value if isinstance(value, dict) else {})}
            for name, value in packages.items()
        ]
    if not isinstance(packages, list):
        return expected, ["binary_packages is not a list or object"]
    arch_map: dict[str, str] = {}
    if isinstance(architectures, dict):
        arch_map = {str(k): str(v) for k, v in architectures.items()}
    elif isinstance(architectures, list):
        for index, architecture in enumerate(architectures):
            if isinstance(architecture, dict):
                name = package_name(architecture)
                value = package_arch(architecture)
                if name and value:
                    arch_map[name] = value
            elif index < len(packages):
                package = packages[index]
                name = package_name(package) if isinstance(package, dict) else str(package)
                arch_map[name] = str(architecture)
    for index, package in enumerate(packages):
        if isinstance(package, dict):
            name = package_name(package)
            version = package_version(package) or source_version
            architecture = package_arch(package)
        else:
            name = str(package)
            version = source_version
            architecture = None
        if not name:
            issues.append(f"empty binary package at index {index}")
            continue
        architecture = architecture or arch_map.get(name)
        if not architecture:
            issues.append(f"architecture is absent for {name}")
            continue
        expected[name] = {
            "package": name,
            "version": str(version),
            "architecture": architecture,
            "origin": "effective-source-lock-fallback",
        }
    return expected, issues


def field(deb: Path, name: str, required: bool = False) -> str:
    process = subprocess.run(
        ["dpkg-deb", "-f", str(deb), name],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    value = process.stdout.strip()
    if process.returncode or (required and not value):
        raise RuntimeError(
            f"{deb.name}: cannot read {name}: "
            f"{process.stderr.strip() or 'empty field'}"
        )
    return value


def inspect(deb: Path) -> dict[str, str]:
    declared_source, declared_version = parse_source(field(deb, "Source"))
    return {
        "path": str(deb),
        "filename": deb.name,
        "package": field(deb, "Package", True),
        "version": field(deb, "Version", True),
        "architecture": field(deb, "Architecture", True),
        "source": declared_source or "",
        "declared_source_version": declared_version or "",
    }


def inspect_payload(deb: Path, metadata: dict[str, str]) -> list[str]:
    issues: list[str] = []
    with tempfile.TemporaryDirectory(prefix="arm64-output-") as directory:
        root = Path(directory)
        process = subprocess.run(
            ["dpkg-deb", "-x", str(deb), str(root)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.returncode:
            return [f"{deb.name}: extraction failed: {process.stderr.strip()}"]
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                magic = path.read_bytes()[:4]
            except OSError as error:
                issues.append(f"{deb.name}: cannot read {path}: {error}")
                continue
            if magic != b"\x7fELF" and magic[:2] != b"MZ":
                continue
            process = subprocess.run(
                ["file", "-b", str(path)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            description = process.stdout.strip()
            relative = path.relative_to(root)
            if process.returncode:
                issues.append(f"{deb.name}: file(1) failed for {relative}")
            elif X86_RE.search(description):
                issues.append(f"{deb.name}: x86 payload {relative}: {description}")
            elif (
                magic == b"\x7fELF"
                and metadata["architecture"] == "arm64"
                and not ARM64_RE.search(description)
            ):
                issues.append(
                    f"{deb.name}: non-AArch64 ELF {relative}: {description}"
                )
            elif metadata["architecture"] == "all":
                issues.append(
                    f"{deb.name}: Architecture: all contains executable "
                    f"machine payload {relative}: {description}"
                )
    return issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--legacy-log", type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    row = lock_row(load(args.lock), args.source)
    source_version = str(row.get("source_version", ""))
    if not source_version:
        raise SystemExit(f"source_version is absent for {args.source}")

    expected, expectation_issues = expected_from_reference(
        load(args.reference), args.source, source_version
    )
    expectation_origin = "amd64-reference"
    if not expected:
        expected, fallback_issues = expected_from_lock(row, source_version)
        expectation_issues.extend(fallback_issues)
        expectation_origin = "effective-source-lock-fallback"
    if not expected:
        expectation_issues.append("no expected binary package set was found")

    exact_reuse = {
        name: item
        for name, item in expected.items()
        if item["architecture"] == "all"
    }
    required_native = {
        name: item
        for name, item in expected.items()
        if item["architecture"] != "all"
    }

    built: list[dict[str, str]] = []
    metadata_issues: list[str] = []
    payload_issues: list[str] = []
    for deb in sorted(args.output_dir.rglob("*.deb")):
        try:
            metadata = inspect(deb)
        except Exception as error:
            metadata_issues.append(str(error))
            continue
        built.append(metadata)
        if metadata["source"] and metadata["source"] != args.source:
            metadata_issues.append(
                f"{deb.name}: Source {metadata['source']} != {args.source}"
            )
        if (
            metadata["declared_source_version"]
            and metadata["declared_source_version"] != source_version
        ):
            metadata_issues.append(
                f"{deb.name}: source version "
                f"{metadata['declared_source_version']} != {source_version}"
            )
        expected_item = expected.get(metadata["package"])
        if expected_item:
            if metadata["version"] != expected_item["version"]:
                metadata_issues.append(
                    f"{deb.name}: version {metadata['version']} != "
                    f"{expected_item['version']}"
                )
            wanted_arch = (
                "all" if expected_item["architecture"] == "all" else "arm64"
            )
            if metadata["architecture"] != wanted_arch:
                metadata_issues.append(
                    f"{deb.name}: architecture {metadata['architecture']} != "
                    f"{wanted_arch}"
                )
        elif metadata["package"].endswith("-dbgsym"):
            if metadata["version"] != source_version:
                metadata_issues.append(
                    f"{deb.name}: dbgsym version {metadata['version']} != "
                    f"{source_version}"
                )
            if metadata["architecture"] != "arm64":
                metadata_issues.append(
                    f"{deb.name}: dbgsym architecture is not arm64"
                )
        elif metadata["architecture"] not in ("arm64", "all"):
            metadata_issues.append(
                f"{deb.name}: unexpected architecture {metadata['architecture']}"
            )
        payload_issues.extend(inspect_payload(deb, metadata))

    by_package: dict[str, list[dict[str, str]]] = {}
    for metadata in built:
        by_package.setdefault(metadata["package"], []).append(metadata)
    missing_required: list[str] = []
    for name, item in sorted(required_native.items()):
        if not any(
            candidate["version"] == item["version"]
            and candidate["architecture"] == "arm64"
            for candidate in by_package.get(name, [])
        ):
            missing_required.append(f"{name}={item['version']}")

    legacy_missing: list[str] = []
    legacy_issues: list[str] = []
    if args.legacy_log:
        if not args.legacy_log.is_file():
            legacy_issues.append(f"legacy log is absent: {args.legacy_log}")
        else:
            text = args.legacy_log.read_text(encoding="utf-8", errors="replace")
            legacy_missing = sorted(set(LEGACY_MISSING_RE.findall(text)))
            for name in legacy_missing:
                if name not in exact_reuse:
                    architecture = expected.get(name, {}).get("architecture")
                    legacy_issues.append(
                        f"legacy builder omitted {name}; reference architecture="
                        f"{architecture!r}, not exact Architecture: all reuse"
                    )

    issues = (
        expectation_issues
        + metadata_issues
        + payload_issues
        + [f"missing required output: {item}" for item in missing_required]
        + legacy_issues
    )
    result = {
        "schema": "hancom-gooroom-arm64-source-output-validation-v3",
        "generated_at": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "status": "passed" if not issues else "failed",
        "source": args.source,
        "source_version": source_version,
        "expectation_origin": expectation_origin,
        "selected_source": row.get("selected"),
        "required_native_packages": list(required_native.values()),
        "exact_reuse_architecture_all_packages": list(exact_reuse.values()),
        "legacy_builder_missing_packages": legacy_missing,
        "built_packages": built,
        "missing_required_packages": missing_required,
        "expectation_issues": expectation_issues,
        "metadata_issues": metadata_issues,
        "payload_machine_issues": payload_issues,
        "legacy_compatibility_issues": legacy_issues,
        "issues": issues,
    }
    path = args.output_dir / "arm64-source-output-validation-v3.json"
    path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if not issues else 7


if __name__ == "__main__":
    raise SystemExit(main())
