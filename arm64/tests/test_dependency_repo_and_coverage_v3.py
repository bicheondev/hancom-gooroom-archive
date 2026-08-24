#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "arm64/scripts"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_script(script: str, *arguments: object, expected: int = 0) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        [sys.executable, str(SCRIPTS / script), *(str(value) for value in arguments)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != expected:
        raise AssertionError(
            f"{script} returned {process.returncode}, expected {expected}\n"
            f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        )
    return process


def build_test_deb(root: Path) -> Path:
    package_root = root / "package"
    control = package_root / "DEBIAN/control"
    control.parent.mkdir(parents=True)
    control.write_text(
        "\n".join(
            [
                "Package: example",
                "Version: 1.0+grm1",
                "Architecture: arm64",
                "Maintainer: Test <test@example.invalid>",
                "Description: exact dependency repository fixture",
                "",
            ]
        ),
        encoding="utf-8",
    )
    payload = package_root / "usr/share/example/value.txt"
    payload.parent.mkdir(parents=True)
    payload.write_text("exact\n", encoding="utf-8")
    output = root / "example_1.0+grm1_arm64.deb"
    subprocess.run(
        ["dpkg-deb", "--build", "--root-owner-group", str(package_root), str(output)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return output


class DependencyRepositoryTests(unittest.TestCase):
    def test_persistent_release_asset_becomes_hash_locked_apt_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deb = build_test_deb(root)
            release_lock = root / "release-lock.json"
            output = root / "repository"
            write_json(
                release_lock,
                {
                    "summary": {
                        "complete": True,
                        "release_tag": "v-test",
                    },
                    "packages": [
                        {
                            "package": "example",
                            "version": "1.0+grm1",
                            "architecture": "arm64",
                            "source": "example",
                            "source_version": "1.0+grm1",
                            "source_type": "dsc",
                            "dsc_sha256": "a" * 64,
                            "filename": deb.name,
                            "size": deb.stat().st_size,
                            "sha256": sha256(deb),
                            "release_asset": {
                                "id": 1,
                                "name": deb.name,
                                "digest": "sha256:" + sha256(deb),
                                "browser_download_url": deb.resolve().as_uri(),
                            },
                        }
                    ],
                },
            )
            run_script(
                "materialize_rebuild_dependency_repo_v3.py",
                "--release-lock",
                release_lock,
                "--output-dir",
                output,
            )
            summary = json.loads((output / "summary.json").read_text())
            self.assertTrue(summary["ready"])
            self.assertEqual(summary["package_count"], 1)
            self.assertEqual(summary["source_type_counts"], {"dsc": 1})
            self.assertEqual(summary["packages_sha256"], sha256(output / "Packages"))
            self.assertIn("Package: example", (output / "Packages").read_text())
            subprocess.run(
                ["sha256sum", "--check", "SHA256SUMS"],
                cwd=output,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    def test_mismatched_release_digest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deb = build_test_deb(root)
            release_lock = root / "release-lock.json"
            output = root / "repository"
            write_json(
                release_lock,
                {
                    "summary": {"complete": True},
                    "packages": [
                        {
                            "package": "example",
                            "version": "1.0+grm1",
                            "architecture": "arm64",
                            "source": "example",
                            "source_version": "1.0+grm1",
                            "source_type": "git",
                            "tree_sha": "b" * 40,
                            "filename": deb.name,
                            "size": deb.stat().st_size,
                            "sha256": sha256(deb),
                            "release_asset": {
                                "id": 1,
                                "name": deb.name,
                                "digest": "sha256:" + "0" * 64,
                                "browser_download_url": deb.resolve().as_uri(),
                            },
                        }
                    ],
                },
            )
            run_script(
                "materialize_rebuild_dependency_repo_v3.py",
                "--release-lock",
                release_lock,
                "--output-dir",
                output,
                expected=2,
            )
            summary = json.loads((output / "summary.json").read_text())
            self.assertFalse(summary["ready"])
            self.assertEqual(summary["blocker_count"], 1)
            self.assertFalse(any(output.glob("*.deb")))


class CoverageTests(unittest.TestCase):
    def fixtures(self, root: Path, result_dsc_sha: str) -> tuple[Path, ...]:
        reference = root / "reference.json"
        source_lock = root / "source-lock.json"
        normalized = root / "normalized.json"
        release = root / "release.json"
        acquisition = root / "acquisition.json"
        results = root / "results"
        result_dir = results / "example/1.0-grm1"
        write_json(
            reference,
            {
                "sources": [
                    {"source": "example", "source_version": "1.0+grm1"}
                ],
                "packages": [
                    {
                        "package": "example",
                        "version": "1.0+grm1",
                        "architecture": "amd64",
                        "source": "example",
                        "source_version": "1.0+grm1",
                    }
                ],
            },
        )
        write_json(
            source_lock,
            {
                "summary": {
                    "source_target_count": 1,
                    "resolved_count": 1,
                    "signed_dsc_resolved_count": 1,
                    "git_resolved_count": 0,
                },
                "sources": [
                    {
                        "source": "example",
                        "source_version": "1.0+grm1",
                        "role": "rebuild-arm64",
                        "status": "resolved",
                        "provenance": "wayback-release-exact-signed-dsc",
                        "selected": {
                            "type": "dsc",
                            "dsc": {
                                "filename": "example_1.0+grm1.dsc",
                                "sha256": "a" * 64,
                            },
                        },
                    }
                ],
            },
        )
        write_json(
            normalized,
            {
                "summary": {"complete": True},
                "packages": [
                    {
                        "package": "example",
                        "reference_version": "1.0+grm1",
                        "reference_architecture": "amd64",
                        "source": "example",
                        "source_version": "1.0+grm1",
                        "status": "rebuild-arm64",
                    }
                ],
            },
        )
        write_json(
            release,
            {
                "summary": {"complete": True},
                "packages": [
                    {
                        "package": "example",
                        "version": "1.0+grm1",
                        "architecture": "arm64",
                        "source": "example",
                        "source_version": "1.0+grm1",
                        "source_type": "dsc",
                        "dsc_sha256": "a" * 64,
                    }
                ],
            },
        )
        write_json(
            acquisition,
            {"summary": {"ready_for_fetch": True}, "packages": [], "blockers": []},
        )
        write_json(
            result_dir / "result.json",
            {
                "source": "example",
                "source_version": "1.0+grm1",
                "source_type": "dsc",
                "dsc_sha256": result_dsc_sha,
                "actions_run_id": "100",
                "passed": True,
                "build_outcome": "success",
                "verify_outcome": "success",
            },
        )
        write_json(result_dir / "verification.json", {"passed": True, "packages": []})
        return reference, source_lock, results, normalized, release, acquisition

    def test_current_dsc_result_reaches_package_acquisition_phase_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = self.fixtures(root, "a" * 64)
            output = root / "coverage"
            run_script(
                "summarize_arm64_port_coverage_v2.py",
                "--reference",
                files[0],
                "--source-lock",
                files[1],
                "--results-dir",
                files[2],
                "--normalized-map",
                files[3],
                "--rebuild-release-lock",
                files[4],
                "--acquisition-plan",
                files[5],
                "--output-dir",
                output,
            )
            summary = json.loads((output / "summary.json").read_text())
            self.assertTrue(summary["native_rebuilds_complete"])
            self.assertTrue(summary["exact_package_layer_ready"])
            self.assertEqual(
                summary["highest_completed_phase"], "exact-package-acquisition-ready"
            )
            self.assertFalse(summary["port_complete"])

    def test_stale_dsc_result_is_not_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = self.fixtures(root, "b" * 64)
            output = root / "coverage"
            run_script(
                "summarize_arm64_port_coverage_v2.py",
                "--reference",
                files[0],
                "--source-lock",
                files[1],
                "--results-dir",
                files[2],
                "--normalized-map",
                files[3],
                "--rebuild-release-lock",
                files[4],
                "--acquisition-plan",
                files[5],
                "--output-dir",
                output,
            )
            summary = json.loads((output / "summary.json").read_text())
            self.assertFalse(summary["native_rebuilds_complete"])
            self.assertEqual(summary["native_rebuild_blocker_count"], 1)
            blockers = json.loads((output / "blockers.json").read_text())
            self.assertEqual(
                blockers["native_rebuild"][0]["reason"],
                "latest-result-authority-is-stale",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
