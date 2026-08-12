#!/usr/bin/env python3
"""Regression tests for source-level architecture-set filtering."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from typing import Any, Callable

SCRIPT = Path(__file__).with_name("filter_arm64_binary_lock.py")
SPEC = importlib.util.spec_from_file_location("filter_arm64_binary_lock", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("could not load filter_arm64_binary_lock.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

REFERENCE_SHA256 = "0" * 64


def source_row(
    source: str,
    source_version: str,
    packages: list[str],
    architectures: list[str],
) -> dict[str, Any]:
    return {
        "source": source,
        "source_version": source_version,
        "status": "resolved",
        "repository_full_name": f"gooroom/{source}",
        "commit_sha": "1" * 40,
        "tree_sha": "2" * 40,
        "binary_packages": packages,
        "binary_architectures": architectures,
    }


def reference_row(
    package: str, source: str, source_version: str, architecture: str
) -> dict[str, str]:
    return {
        "package": package,
        "version": source_version,
        "architecture": architecture,
        "source": source,
        "source_version": source_version,
    }


def expect_failure(label: str, function: Callable[[], object]) -> None:
    try:
        function()
    except SystemExit:
        return
    raise AssertionError(f"{label}: expected fail-closed SystemExit")


def test_p7zip_source_level_architecture_set() -> None:
    row = source_row(
        "p7zip",
        "16.02+dfsg-8+grm3u1",
        ["p7zip", "p7zip-full"],
        ["amd64"],
    )
    document = {"schema": 2, "sources": [row]}
    reference = {
        "packages": [
            reference_row(
                "p7zip", "p7zip", "16.02+dfsg-8+grm3u1", "amd64"
            ),
            reference_row(
                "p7zip-full", "p7zip", "16.02+dfsg-8+grm3u1", "amd64"
            ),
        ]
    }
    before = copy.deepcopy(document)
    filtered, summary = MODULE.filter_document(
        document, "p7zip", reference, REFERENCE_SHA256
    )
    after = filtered["sources"][0]
    assert after["binary_packages"] == ["p7zip", "p7zip-full"]
    assert after["binary_architectures"] == ["amd64"]
    assert summary["omitted_architecture_all"] == []
    assert before == document, "filter_document mutated its input"


def test_mixed_architectures_omit_only_all() -> None:
    selected = source_row(
        "mixed",
        "1.0-1",
        ["mixed-native", "mixed-doc"],
        ["all", "amd64"],
    )
    untouched = source_row("other", "2.0-1", ["other"], ["amd64"])
    document = {"schema": 2, "sources": [selected, untouched], "marker": 7}
    reference = {
        "packages": [
            reference_row("mixed-native", "mixed", "1.0-1", "amd64"),
            reference_row("mixed-doc", "mixed", "1.0-1", "all"),
        ]
    }
    filtered, _ = MODULE.filter_document(
        document, "mixed", reference, REFERENCE_SHA256
    )
    after = filtered["sources"][0]
    assert after["binary_packages"] == ["mixed-native"]
    assert after["binary_architectures"] == ["amd64"]
    assert after["native_arm64_build_filter"] == {
        "policy": "dpkg-buildpackage--build=any",
        "architecture_resolution": "amd64-reference-lock",
        "reference_lock_sha256": REFERENCE_SHA256,
        "input_binary_architectures": ["all", "amd64"],
        "kept_architecture_dependent": [
            {"package": "mixed-native", "architecture": "amd64"}
        ],
        "omitted_architecture_all": [
            {"package": "mixed-doc", "architecture": "all"}
        ],
    }
    assert filtered["sources"][1] == untouched
    assert filtered["marker"] == 7


def test_fail_closed_cases() -> None:
    base = {
        "schema": 2,
        "sources": [source_row("sample", "1.0-1", ["sample"], ["amd64"])],
    }
    good_reference = {
        "packages": [reference_row("sample", "sample", "1.0-1", "amd64")]
    }

    mismatch = copy.deepcopy(base)
    mismatch["sources"][0]["binary_architectures"] = ["all"]
    expect_failure(
        "contradictory architecture summary",
        lambda: MODULE.filter_document(
            mismatch, "sample", good_reference, REFERENCE_SHA256
        ),
    )

    expect_failure(
        "missing reference row",
        lambda: MODULE.filter_document(
            base, "sample", {"packages": []}, REFERENCE_SHA256
        ),
    )

    duplicate_reference = {
        "packages": [
            reference_row("sample", "sample", "1.0-1", "amd64"),
            reference_row("sample", "sample", "1.0-1", "amd64"),
        ]
    }
    expect_failure(
        "duplicate reference row",
        lambda: MODULE.filter_document(
            base, "sample", duplicate_reference, REFERENCE_SHA256
        ),
    )

    duplicate_package = copy.deepcopy(base)
    duplicate_package["sources"][0]["binary_packages"] = ["sample", "sample"]
    expect_failure(
        "duplicate binary package",
        lambda: MODULE.filter_document(
            duplicate_package, "sample", good_reference, REFERENCE_SHA256
        ),
    )

    all_only = {
        "schema": 2,
        "sources": [source_row("docs", "1.0-1", ["docs"], ["all"])],
    }
    all_reference = {
        "packages": [reference_row("docs", "docs", "1.0-1", "all")]
    }
    expect_failure(
        "Architecture: all-only source",
        lambda: MODULE.filter_document(
            all_only, "docs", all_reference, REFERENCE_SHA256
        ),
    )


def main() -> int:
    test_p7zip_source_level_architecture_set()
    test_mixed_architectures_omit_only_all()
    test_fail_closed_cases()
    print("filter_arm64_binary_lock regression tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
