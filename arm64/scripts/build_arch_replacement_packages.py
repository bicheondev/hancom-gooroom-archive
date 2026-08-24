#!/usr/bin/env python3
"""Build audited config-only ARM64 replacement packages.

No executable payload is generated. Each package embeds the immutable AMD64
reference identity in control fields so the package-pool auditor can prove why
an architecture-specific replacement exists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


REFERENCE_ISO_SHA256 = "ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_by_name(reference: dict[str, Any], name: str) -> dict[str, Any]:
    rows = [row for row in reference.get("packages", []) if row["package"] == name]
    if len(rows) != 1:
        raise RuntimeError(f"expected one reference row for {name}, got {len(rows)}")
    return rows[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = load_json(args.reference)
    reference_iso = reference.get("reference_iso") or {}
    if reference_iso.get("sha256") != REFERENCE_ISO_SHA256:
        raise RuntimeError("reference manifest ISO SHA-256 mismatch")

    original_meta = package_by_name(reference, "linux-image-amd64")
    original_kernel = package_by_name(reference, "linux-image-5.10.0-23-amd64")
    if original_meta["architecture"] != "amd64" or original_kernel["architecture"] != "amd64":
        raise RuntimeError("reference kernel package architecture is not amd64")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    build_root = args.output_dir / "build-linux-image-arm64"
    if build_root.exists():
        shutil.rmtree(build_root)
    control_dir = build_root / "DEBIAN"
    doc_dir = build_root / "usr/share/doc/linux-image-arm64"
    control_dir.mkdir(parents=True)
    doc_dir.mkdir(parents=True)

    version = original_meta["version"]
    kernel_version = original_kernel["version"]
    control = f"""Package: linux-image-arm64
Source: hancom-gooroom-arm64-arch-replacements
Version: {version}
Architecture: arm64
Maintainer: Hancom Gooroom ARM64 Port <noreply@example.invalid>
Depends: linux-image-5.10.0-23-arm64 (= {kernel_version})
Provides: linux-latest-modules-arm64
Section: kernel
Priority: optional
Description: ARM64 kernel metapackage replacing linux-image-amd64
 This config-only package preserves the reference metapackage version while
 depending on the exact ARM64 kernel replacement. It contains no executable
 payload.
X-Hancom-Gooroom-Reference-Package: linux-image-amd64
X-Hancom-Gooroom-Reference-Version: {version}
X-Hancom-Gooroom-Reference-Architecture: amd64
X-Hancom-Gooroom-Reference-ISO-SHA256: {REFERENCE_ISO_SHA256}
X-Hancom-Gooroom-Replacement-Policy: config-only-arm64-metapackage
X-Hancom-Gooroom-Required-Kernel: linux-image-5.10.0-23-arm64 (= {kernel_version})
"""
    (control_dir / "control").write_text(control, encoding="utf-8")
    (doc_dir / "README.Debian").write_text(
        "This package is a config-only ARM64 replacement for linux-image-amd64.\n"
        f"Reference ISO SHA-256: {REFERENCE_ISO_SHA256}\n"
        f"Reference package version: {version}\n"
        f"Required ARM64 kernel: linux-image-5.10.0-23-arm64 (= {kernel_version})\n",
        encoding="utf-8",
    )
    for path in build_root.rglob("*"):
        if path.is_dir():
            os.chmod(path, 0o755)
        elif path.is_file():
            os.chmod(path, 0o644)

    output = args.output_dir / f"linux-image-arm64_{version}_arm64.deb"
    subprocess.run(
        ["dpkg-deb", "--root-owner-group", "--build", str(build_root), str(output)],
        check=True,
    )
    fields = {}
    for field in (
        "Package",
        "Source",
        "Version",
        "Architecture",
        "Depends",
        "X-Hancom-Gooroom-Reference-Package",
        "X-Hancom-Gooroom-Reference-Version",
        "X-Hancom-Gooroom-Reference-Architecture",
        "X-Hancom-Gooroom-Reference-ISO-SHA256",
        "X-Hancom-Gooroom-Replacement-Policy",
        "X-Hancom-Gooroom-Required-Kernel",
    ):
        fields[field] = subprocess.run(
            ["dpkg-deb", "-f", str(output), field],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    expected = {
        "Package": "linux-image-arm64",
        "Source": "hancom-gooroom-arm64-arch-replacements",
        "Version": version,
        "Architecture": "arm64",
        "X-Hancom-Gooroom-Reference-Package": "linux-image-amd64",
        "X-Hancom-Gooroom-Reference-Version": version,
        "X-Hancom-Gooroom-Reference-Architecture": "amd64",
        "X-Hancom-Gooroom-Reference-ISO-SHA256": REFERENCE_ISO_SHA256,
        "X-Hancom-Gooroom-Replacement-Policy": "config-only-arm64-metapackage",
    }
    for field, value in expected.items():
        if fields[field] != value:
            raise RuntimeError(f"control field mismatch {field}: {fields[field]!r} != {value!r}")

    manifest = {
        "schema": 1,
        "policy": "config-only-explicit-architecture-replacement",
        "reference_iso_sha256": REFERENCE_ISO_SHA256,
        "reference_package": original_meta,
        "reference_kernel_package": original_kernel,
        "output": {
            "filename": output.name,
            "size": output.stat().st_size,
            "sha256": sha256_file(output),
            "control": fields,
            "executable_payload_count": 0,
        },
    }
    (args.output_dir / "architecture-replacements.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    shutil.rmtree(build_root)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
