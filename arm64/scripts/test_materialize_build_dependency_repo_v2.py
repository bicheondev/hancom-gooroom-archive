#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("materialize_build_dependency_repo_v2.py")
spec = importlib.util.spec_from_file_location("materializer", SCRIPT)
assert spec is not None and spec.loader is not None
materializer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = materializer
spec.loader.exec_module(materializer)


def row(package: str, version: str, architecture: str, digest: str, filename: str):
    return {
        "package": package,
        "version": version,
        "architecture": architecture,
        "sha256": digest,
        "size": 123,
        "filename": filename,
    }


vendor = [row("demo-data", "1.0", "all", "a" * 64, "vendor.deb")]
rebuilt = [
    row("demo-data", "1.0", "all", "b" * 64, "rebuilt.deb"),
    row("demo-runtime", "1.0", "arm64", "c" * 64, "runtime.deb"),
]
retained, shadowed = materializer.apply_vendor_all_precedence(vendor, rebuilt)
assert [item["package"] for item in retained] == ["demo-runtime"]
assert len(shadowed) == 1
assert shadowed[0]["package"] == "demo-data"
assert shadowed[0]["shadowed_by"] == "iso-vendor-binary-lock"
assert shadowed[0]["vendor_authority"] == {
    "filename": "vendor.deb",
    "sha256": "a" * 64,
    "size": 123,
}

retained, shadowed = materializer.apply_vendor_all_precedence(
    vendor,
    [row("demo-data", "2.0", "all", "d" * 64, "new-version.deb")],
)
assert len(retained) == 1 and not shadowed

try:
    materializer.apply_vendor_all_precedence(
        [
            row("demo-data", "1.0", "all", "a" * 64, "one.deb"),
            row("demo-data", "1.0", "all", "b" * 64, "two.deb"),
        ],
        rebuilt,
    )
except RuntimeError as error:
    assert "vendor Architecture: all authority is ambiguous" in str(error)
else:
    raise AssertionError("ambiguous vendor authority must fail closed")

print("materialize_build_dependency_repo_v2 precedence tests: OK")
