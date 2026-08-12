#!/usr/bin/env python3
"""Behavioral tests for the reconstructed QtBase ARM64 verifier."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "arm64" / "scripts" / "verify_reconstructed_qtbase_arm64.py"
SOURCE = "qtbase-opensource-src"
VERSION = "5.15.2+dfsg-9+grm3u1"
REQUIRED_PACKAGES = (
    "libqt5core5a",
    "libqt5dbus5",
    "libqt5gui5",
    "libqt5network5",
    "libqt5printsupport5",
    "libqt5sql5",
    "libqt5test5",
    "libqt5widgets5",
    "libqt5xml5",
)


def authority() -> dict[str, Any]:
    return {
        "source": SOURCE,
        "source_version": VERSION,
        "source_status": "reconstructed-not-recovered-original-source",
        "byte_identity_claimed": False,
        "promotion_allowed": False,
        "policy": "test-reconstruction-authority",
        "claims": {
            "exact_package_name_and_version": True,
            "exact_vendor_changelog_preserved": True,
            "only_vendor_declared_code_patch_added": True,
            "lost_original_source_archive_recovered": False,
        },
        "base_authority": {},
        "security_patch_authority": {"patch": {}},
        "vendor_binary_authority": {},
        "reconstruction": {},
    }


def package_rows() -> list[dict[str, Any]]:
    return [
        {
            "package": package,
            "version": VERSION,
            "architecture": "arm64",
            "source": SOURCE,
            "source_version": VERSION,
            "filename": f"{package}_{VERSION}_arm64.deb",
            "size": 1,
            "sha256": "0" * 64,
            "aarch64_payload_count": 1,
            "foreign_payload_count": 0,
        }
        for package in REQUIRED_PACKAGES
    ]


def generic_result(payloads: list[dict[str, Any]] | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": 1,
        "source": SOURCE,
        "source_version": VERSION,
        "passed": True,
        "verification_passed": True,
        "foreign_payload_count": 0,
        "packages": package_rows(),
        "foreign_payloads": [],
    }
    if payloads is not None:
        result["payloads"] = payloads
    return result


def core_payload(machine: int = 183) -> dict[str, Any]:
    return {
        "package": "libqt5core5a",
        "path": "/usr/lib/aarch64-linux-gnu/libQt5Core.so.5.15.2",
        "kind": "ELF",
        "machine": machine,
        "sha256": "1" * 64,
        "size": 1,
    }


class ReconstructedQtBaseVerifierTests(unittest.TestCase):
    def run_verifier(self, generic: dict[str, Any]) -> tuple[subprocess.CompletedProcess[str], dict[str, Any] | None]:
        with tempfile.TemporaryDirectory(prefix="qtbase-verifier-test-") as temporary:
            root = Path(temporary)
            authority_path = root / "authority.json"
            generic_data_path = root / "generic.json"
            fake_verifier = root / "fake-generic-verifier.py"
            result_path = root / "result.json"
            output_dir = root / "output"
            output_dir.mkdir()
            authority_path.write_text(json.dumps(authority()) + "\n", encoding="utf-8")
            generic_data_path.write_text(json.dumps(generic) + "\n", encoding="utf-8")
            fake_verifier.write_text(
                "#!/usr/bin/env python3\n"
                "import argparse, json\n"
                "from pathlib import Path\n"
                "p=argparse.ArgumentParser()\n"
                "p.add_argument('--source')\n"
                "p.add_argument('--version')\n"
                "p.add_argument('--output-dir')\n"
                "p.add_argument('--result', type=Path, required=True)\n"
                "p.add_argument('--artifact-name')\n"
                "a=p.parse_args()\n"
                f"a.result.write_text(Path({str(generic_data_path)!r}).read_text(encoding='utf-8'), encoding='utf-8')\n",
                encoding="utf-8",
            )
            process = subprocess.run(
                [
                    sys.executable,
                    str(VERIFIER),
                    "--output-dir",
                    str(output_dir),
                    "--reconstruction-authority",
                    str(authority_path),
                    "--generic-verifier",
                    str(fake_verifier),
                    "--result",
                    str(result_path),
                    "--artifact-name",
                    "test-artifact",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            result = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else None
            return process, result

    def test_top_level_payload_schema_passes(self) -> None:
        process, result = self.run_verifier(generic_result([core_payload()]))
        self.assertEqual(process.returncode, 0, msg=process.stdout + process.stderr)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertTrue(result["native_arm64_build_verified"])
        self.assertFalse(result["promotion_allowed"])
        self.assertEqual(result["required_package_count"], 9)
        self.assertEqual(result["verified_core_payload"]["machine"], 183)
        self.assertEqual(result["verified_core_payload"]["architecture"], "arm64")

    def test_non_aarch64_core_payload_fails(self) -> None:
        process, result = self.run_verifier(generic_result([core_payload(machine=62)]))
        self.assertNotEqual(process.returncode, 0)
        self.assertIsNone(result)
        self.assertIn("not AArch64", process.stdout + process.stderr)

    def test_duplicate_exact_core_payload_fails(self) -> None:
        process, result = self.run_verifier(generic_result([core_payload(), core_payload()]))
        self.assertNotEqual(process.returncode, 0)
        self.assertIsNone(result)
        self.assertIn("not uniquely verified", process.stdout + process.stderr)

    def test_legacy_per_package_payload_summary_is_not_accepted(self) -> None:
        generic = generic_result(None)
        generic["packages"][0]["payload_summary"] = [core_payload()]
        process, result = self.run_verifier(generic)
        self.assertNotEqual(process.returncode, 0)
        self.assertIsNone(result)
        self.assertIn("verified payload list is missing", process.stdout + process.stderr)


if __name__ == "__main__":
    unittest.main()
