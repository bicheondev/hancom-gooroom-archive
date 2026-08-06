#!/usr/bin/env python3
"""Select a bounded next wave from the exact effective source lock."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            return value
    return None


def package_name(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        item = first(value, "package", "binary_package", "binary", "name")
        return str(item) if item is not None else None
    return None


def package_arch(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        item = first(value, "architecture", "arch", "binary_architecture")
        return str(item) if item is not None else None
    return None


def binary_rows(row: dict[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
    packages = row.get("binary_packages", [])
    architectures = row.get("binary_architectures", [])
    issues: list[str] = []
    result: list[dict[str, str]] = []

    if isinstance(packages, dict):
        packages = [
            {"package": name, **(value if isinstance(value, dict) else {})}
            for name, value in packages.items()
        ]
    if not isinstance(packages, list):
        return result, ["binary_packages is not a list or object"]

    arch_map: dict[str, str] = {}
    if isinstance(architectures, dict):
        arch_map = {str(key): str(value) for key, value in architectures.items()}
    elif isinstance(architectures, list):
        for index, architecture in enumerate(architectures):
            if isinstance(architecture, dict):
                name = package_name(architecture)
                arch = package_arch(architecture)
                if name and arch:
                    arch_map[name] = arch
            elif index < len(packages):
                name = package_name(packages[index])
                if name:
                    arch_map[name] = str(architecture)
    else:
        issues.append("binary_architectures is not a list or object")

    seen: set[str] = set()
    for index, package in enumerate(packages):
        name = package_name(package)
        architecture = package_arch(package) or (arch_map.get(name) if name else None)
        if not name:
            issues.append(f"binary package name absent at index {index}")
            continue
        if name in seen:
            issues.append(f"duplicate binary package: {name}")
            continue
        seen.add(name)
        if not architecture:
            issues.append(f"architecture absent for binary package: {name}")
            continue
        result.append({"package": name, "architecture": architecture})
    return result, issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exclude-source", action="append", default=[])
    parser.add_argument("--maximum-selected-sources", type=int, default=8)
    parser.add_argument("--maximum-native-binaries", type=int, default=4)
    parser.add_argument("--maximum-total-binaries", type=int, default=8)
    parser.add_argument(
        "--defer-regex",
        default=(
            r"(?:chromium|firefox|webkit|qtbase|qtwebengine|libreoffice|"
            r"^linux(?:$|-)|gcc|llvm|clang|mesa|systemd|glibc|binutils|"
            r"xorg-server|virtualbox)"
        ),
    )
    args = parser.parse_args()

    document = json.loads(args.lock.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SystemExit("effective source lock root is not an object")
    deferred = re.compile(args.defer_regex, re.IGNORECASE)
    excluded = set(args.exclude_source)
    candidates: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    for row in document.get("sources", []):
        if not isinstance(row, dict):
            continue
        source = row.get("source")
        version = row.get("source_version")
        if not source or not version:
            rejected.append(
                {"source": source, "reason": "source name or version absent"}
            )
            continue
        source = str(source)
        version = str(version)
        if source in excluded:
            rejected.append({"source": source, "reason": "explicitly excluded"})
            continue
        if row.get("status") != "resolved" or not isinstance(
            row.get("selected"), dict
        ):
            rejected.append(
                {"source": source, "reason": "exact source commit is not resolved"}
            )
            continue
        selected = row["selected"]
        if selected.get("declared_source") not in (None, source):
            rejected.append(
                {"source": source, "reason": "selected commit declares another source"}
            )
            continue
        if selected.get("declared_version") not in (None, version):
            rejected.append(
                {"source": source, "reason": "selected commit declares another version"}
            )
            continue
        if deferred.search(source):
            rejected.append(
                {"source": source, "reason": "deferred heavyweight source"}
            )
            continue

        binaries, issues = binary_rows(row)
        if issues:
            rejected.append(
                {
                    "source": source,
                    "reason": "binary inventory is incomplete",
                    "issues": issues,
                }
            )
            continue
        native = [item for item in binaries if item["architecture"] != "all"]
        architecture_all = [
            item for item in binaries if item["architecture"] == "all"
        ]
        if not native:
            rejected.append(
                {"source": source, "reason": "no native binary package required"}
            )
            continue
        if len(native) > args.maximum_native_binaries:
            rejected.append(
                {
                    "source": source,
                    "reason": "native binary count exceeds bounded wave policy",
                    "native_binary_count": len(native),
                }
            )
            continue
        if len(binaries) > args.maximum_total_binaries:
            rejected.append(
                {
                    "source": source,
                    "reason": "total binary count exceeds bounded wave policy",
                    "binary_count": len(binaries),
                }
            )
            continue
        candidates.append(
            {
                "source": source,
                "source_version": version,
                "native_binary_count": len(native),
                "architecture_all_binary_count": len(architecture_all),
                "total_binary_count": len(binaries),
                "native_binary_packages": native,
                "architecture_all_binary_packages": architecture_all,
                "repository": selected.get("repository_full_name"),
                "commit_sha": selected.get("commit_sha"),
                "tree_sha": selected.get("tree_sha"),
            }
        )

    candidates.sort(
        key=lambda item: (
            item["native_binary_count"],
            item["total_binary_count"],
            item["source"],
        )
    )
    selected = candidates[: args.maximum_selected_sources]
    result = {
        "schema": "hancom-gooroom-arm64-build-wave-selection-v2",
        "generated_at": now(),
        "status": "selected" if selected else "empty",
        "selection_policy": {
            "exact_source_lock_required": True,
            "maximum_selected_sources": args.maximum_selected_sources,
            "maximum_native_binaries": args.maximum_native_binaries,
            "maximum_total_binaries": args.maximum_total_binaries,
            "defer_regex": args.defer_regex,
            "excluded_sources": sorted(excluded),
        },
        "selected": selected,
        "remaining_candidates": candidates[args.maximum_selected_sources :],
        "rejected": rejected,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if selected else 10


if __name__ == "__main__":
    raise SystemExit(main())
