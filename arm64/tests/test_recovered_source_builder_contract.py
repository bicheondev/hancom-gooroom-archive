#!/usr/bin/env python3
"""Regression contract for the snapshot-pure recovered-source ARM64 builder."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "arm64" / "scripts" / "build_recovered_source_archive_arm64.sh"


class RecoveredSourceBuilderContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = BUILDER.read_text(encoding="utf-8")

    def test_shell_syntax_is_valid(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(BUILDER)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"bash -n failed:\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )

    def test_historical_dpkg_parallel_option_is_used(self) -> None:
        self.assertNotIn("--jobs-force=", self.text)
        self.assertEqual(self.text.count('-j"${BUILD_JOBS}"'), 1)
        self.assertIn('DEB_BUILD_OPTIONS="nocheck nodoc parallel=${BUILD_JOBS}"', self.text)

    def test_host_identity_is_captured_and_forwarded_once(self) -> None:
        required_once = (
            'HOST_UID="$(id -u)"',
            'HOST_GID="$(id -g)"',
            '-e HOST_UID',
            '-e HOST_GID',
        )
        for token in required_once:
            with self.subTest(token=token):
                self.assertEqual(self.text.count(token), 1)

    def test_container_restores_mounted_output_ownership_on_exit(self) -> None:
        self.assertEqual(self.text.count("restore_output_ownership()"), 1)
        self.assertEqual(self.text.count("trap restore_output_ownership EXIT"), 1)
        self.assertEqual(
            self.text.count('chown -R -- "${HOST_UID}:${HOST_GID}" /output'),
            1,
        )
        self.assertLess(
            self.text.index("trap restore_output_ownership EXIT"),
            self.text.index("apt-get update"),
            "ownership restoration must be armed before the first fallible container step",
        )

    def test_untrusted_identity_values_are_rejected_before_chown(self) -> None:
        uid_guard = '[[ "$HOST_UID" =~ ^[0-9]+$ ]]'
        gid_guard = '[[ "$HOST_GID" =~ ^[0-9]+$ ]]'
        chown = 'chown -R -- "${HOST_UID}:${HOST_GID}" /output'
        self.assertIn(uid_guard, self.text)
        self.assertIn(gid_guard, self.text)
        self.assertLess(self.text.index(uid_guard), self.text.index(chown))
        self.assertLess(self.text.index(gid_guard), self.text.index(chown))


if __name__ == "__main__":
    unittest.main()
