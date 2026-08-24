#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import audit_hancom_delta as auditor  # noqa: E402


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_deb(root: Path, version: str, marker: str, output: Path) -> None:
    control = root / "DEBIAN"
    payload = root / "usr/lib/gooroom-applauncher-applet"
    control.mkdir(parents=True)
    payload.mkdir(parents=True)
    (control / "control").write_text(
        "\n".join(
            [
                "Package: gooroom-applauncher-applet",
                f"Version: {version}",
                "Architecture: amd64",
                f"Source: gooroom-applauncher-applet ({version})",
                "Maintainer: Test <test@example.invalid>",
                "Description: synthetic delta-audit package",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (payload / "marker.txt").write_text(marker, encoding="utf-8")
    shutil.copy2("/bin/true", payload / "applet")
    subprocess.run(
        ["dpkg-deb", "--build", str(root), str(output)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def lock_for(target: Path, target_sha256: str | None = None) -> dict:
    return {
        "artifact": {"id": 1, "digest": "sha256:test"},
        "target": {
            "package": "gooroom-applauncher-applet",
            "source": "gooroom-applauncher-applet",
            "version": "0.4.0+grm3u1+han3u2",
            "architecture": "amd64",
            "sha256": target_sha256 or sha256(target),
        },
        "base_source": {
            "repository": "gooroom/gooroom-applauncher-applet",
            "version": "0.4.0+grm3u1",
            "commit": "f" * 40,
            "tree": "e" * 40,
        },
    }


class HancomDeltaAuditTest(unittest.TestCase):
    def test_records_non_elf_delta_without_reconstruction_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            target, base = work / "target.deb", work / "base.deb"
            build_deb(work / "target", "0.4.0+grm3u1+han3u2", "hancom\n", target)
            build_deb(work / "base", "0.4.0+grm3u1", "public\n", base)
            report = auditor.build(target, base, lock_for(target))
            self.assertTrue(report["audit_complete"])
            self.assertEqual(report["source_status"], "comparison-only")
            self.assertEqual(report["reconstruction_status"], "not-attempted")
            self.assertFalse(report["byte_identity_claimed"])
            changes = report["comparison"]["payload"]["non_elf_hash_changes"]
            self.assertEqual(
                [item["path"] for item in changes],
                ["usr/lib/gooroom-applauncher-applet/marker.txt"],
            )
            self.assertEqual(report["comparison"]["payload"]["elf_semantic_changes"], [])

    def test_rejects_wrong_exact_target_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            target, base = work / "target.deb", work / "base.deb"
            build_deb(work / "target", "0.4.0+grm3u1+han3u2", "hancom\n", target)
            build_deb(work / "base", "0.4.0+grm3u1", "public\n", base)
            with self.assertRaisesRegex(RuntimeError, "SHA256"):
                auditor.build(target, base, lock_for(target, "0" * 64))


if __name__ == "__main__":
    unittest.main()
