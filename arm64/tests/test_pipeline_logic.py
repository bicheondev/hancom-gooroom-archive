#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPOSITORY_ROOT / "arm64/scripts"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def run_script(name: str, *arguments: object, expected: int = 0) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        [sys.executable, str(SCRIPTS / name), *(str(value) for value in arguments)],
        cwd=REPOSITORY_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != expected:
        raise AssertionError(
            f"{name} returned {process.returncode}, expected {expected}\n"
            f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        )
    return process


class FailureClassificationTests(unittest.TestCase):
    def test_dependency_failure_is_classified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = {
                "source": "example",
                "source_version": "1.0+grm1",
                "actions_run_id": "100",
                "passed": False,
                "build_outcome": "failure",
                "build_exit_code": "1",
                "verify_outcome": "skipped",
                "diagnostics": [
                    {
                        "filename": "apt-solver-simulation.log",
                        "tail": "E: Unable to locate package gooroom-build-helper",
                    }
                ],
            }
            write_json(root / "results/example/1.0/result.json", result)
            output = root / "classification"
            run_script(
                "classify_native_rebuild_failures.py",
                "--results",
                root / "results",
                "--output-dir",
                output,
            )
            document = json.loads(
                (output / "classifications.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                document["sources"][0]["category"], "dependency-resolution"
            )
            self.assertEqual(
                document["summary"]["dependency_resolution_failure_count"], 1
            )


class DependencyRetrySelectionTests(unittest.TestCase):
    def fixtures(self, root: Path, previous_hash: str | None) -> tuple[Path, ...]:
        lock = root / "lock.json"
        reference = root / "reference.json"
        classifications = root / "classifications.json"
        dependency = root / "dependency.json"
        write_json(
            lock,
            {
                "sources": [
                    {
                        "source": "example",
                        "source_version": "1.0+grm1",
                        "status": "resolved",
                        "selected": {
                            "type": "git",
                            "repository_full_name": "gooroom/example",
                            "commit_sha": "1" * 40,
                            "tree_sha": "2" * 40,
                            "declared_source": "example",
                            "declared_version": "1.0+grm1",
                        },
                    }
                ]
            },
        )
        write_json(
            reference,
            {
                "packages": [
                    {
                        "package": "example",
                        "version": "1.0+grm1",
                        "architecture": "amd64",
                        "source": "example",
                        "source_version": "1.0+grm1",
                    },
                    {
                        "package": "example-common",
                        "version": "1.0+grm1",
                        "architecture": "all",
                        "source": "example",
                        "source_version": "1.0+grm1",
                    },
                ]
            },
        )
        write_json(
            classifications,
            {
                "sources": [
                    {
                        "source": "example",
                        "source_version": "1.0+grm1",
                        "passed": False,
                        "category": "dependency-resolution",
                        "dependency_repository_packages_sha256": previous_hash,
                        "actions_run_id": "99",
                    }
                ]
            },
        )
        write_json(
            dependency,
            {
                "summary": {
                    "ready": True,
                    "packages_sha256": "a" * 64,
                    "release_lock_sha256": "b" * 64,
                }
            },
        )
        return lock, reference, classifications, dependency

    def test_changed_dependency_hash_selects_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, reference, classifications, dependency = self.fixtures(
                root, "c" * 64
            )
            output = root / "wave.json"
            run_script(
                "select_dependency_retry_wave.py",
                "--lock",
                lock,
                "--reference",
                reference,
                "--classifications",
                classifications,
                "--dependency-repository",
                dependency,
                "--limit",
                4,
                "--output",
                output,
            )
            wave = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(wave["summary"]["selected_count"], 1)
            self.assertEqual(wave["selected"][0]["source"], "example")
            self.assertEqual(
                wave["selected"][0]["dependency_repository_packages_sha256"],
                "a" * 64,
            )

    def test_identical_dependency_hash_blocks_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, reference, classifications, dependency = self.fixtures(
                root, "a" * 64
            )
            output = root / "wave.json"
            run_script(
                "select_dependency_retry_wave.py",
                "--lock",
                lock,
                "--reference",
                reference,
                "--classifications",
                classifications,
                "--dependency-repository",
                dependency,
                "--limit",
                4,
                "--output",
                output,
            )
            wave = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(wave["summary"]["selected_count"], 0)
            reasons = {row["reason"] for row in wave["skipped"]}
            self.assertIn("same-dependency-repository-already-attempted", reasons)


class AcquisitionPlanTests(unittest.TestCase):
    def test_persistent_release_is_preferred_for_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            normalized = root / "normalized.json"
            vendor = root / "vendor.json"
            release = root / "release.json"
            results = root / "results"
            output = root / "output"
            write_json(
                normalized,
                {
                    "summary": {"complete": True},
                    "packages": [
                        {
                            "package": "debian-exact",
                            "reference_version": "1.0-1",
                            "reference_architecture": "amd64",
                            "source": "debian-exact",
                            "source_version": "1.0-1",
                            "status": "exact-arm64",
                            "selected": {
                                "package": "debian-exact",
                                "version": "1.0-1",
                                "architecture": "arm64",
                                "url": "https://snapshot.example/debian-exact.deb",
                                "filename": "debian-exact_1.0-1_arm64.deb",
                                "sha256": "1" * 64,
                                "size": 10,
                            },
                        },
                        {
                            "package": "vendor-common",
                            "reference_version": "2.0+grm1",
                            "reference_architecture": "all",
                            "source": "vendor-common",
                            "source_version": "2.0+grm1",
                            "status": "reuse-all",
                            "selected": None,
                        },
                        {
                            "package": "rebuilt-app",
                            "reference_version": "3.0+grm1",
                            "reference_architecture": "amd64",
                            "source": "rebuilt-app",
                            "source_version": "3.0+grm1",
                            "status": "rebuild-arm64",
                            "selected": None,
                        },
                        {
                            "package": "amd64-only-firmware",
                            "reference_version": "4.0",
                            "reference_architecture": "amd64",
                            "source": "amd64-only-firmware",
                            "source_version": "4.0",
                            "status": "exclude",
                            "selected": None,
                        },
                    ],
                },
            )
            write_json(
                vendor,
                {
                    "packages": [
                        {
                            "package": "vendor-common",
                            "version": "2.0+grm1",
                            "architecture": "all",
                            "status": "verified",
                            "url": "https://vendor.example/vendor-common.deb",
                            "local_filename": "vendor-common_2.0+grm1_all.deb",
                            "actual_sha256": "2" * 64,
                            "actual_size": 20,
                        }
                    ]
                },
            )
            write_json(
                release,
                {
                    "summary": {"complete": True, "release_tag": "v-test"},
                    "packages": [
                        {
                            "package": "rebuilt-app",
                            "version": "3.0+grm1",
                            "architecture": "arm64",
                            "source": "rebuilt-app",
                            "source_version": "3.0+grm1",
                            "filename": "rebuilt-app_3.0+grm1_arm64.deb",
                            "size": 30,
                            "sha256": "3" * 64,
                            "commit_sha": "4" * 40,
                            "tree_sha": "5" * 40,
                            "release_asset": {
                                "id": 123,
                                "browser_download_url": "https://release.example/rebuilt-app.deb",
                                "digest": "sha256:" + "3" * 64,
                            },
                        }
                    ],
                },
            )
            results.mkdir()
            run_script(
                "build_package_acquisition_plan_v2.py",
                "--normalized-map",
                normalized,
                "--vendor-binary-lock",
                vendor,
                "--rebuild-results",
                results,
                "--rebuild-release-lock",
                release,
                "--output-dir",
                output,
            )
            plan = json.loads(
                (output / "package-acquisition-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(plan["summary"]["ready_for_fetch"])
            methods = {
                row["package"]: row["acquisition"]["method"]
                for row in plan["packages"]
            }
            self.assertEqual(
                methods["rebuilt-app"], "download-release-exact"
            )
            self.assertEqual(methods["vendor-common"], "download-vendor-exact")
            self.assertEqual(
                methods["amd64-only-firmware"], "exclude-from-arm64"
            )


class WorkflowSecretAuditTests(unittest.TestCase):
    def test_literal_is_fingerprinted_but_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / "workflows"
            output = root / "output"
            workflows.mkdir()
            literal = "ghs_" + "A" * 40
            (workflows / "safe.yml").write_text(
                "env:\n  GH_TOKEN: ${{ github.token }}\n", encoding="utf-8"
            )
            (workflows / "bad.yml").write_text(
                f"env:\n  GH_TOKEN: {literal}\n", encoding="utf-8"
            )
            run_script(
                "audit_workflow_secret_literals.py",
                "--workflow-dir",
                workflows,
                "--output-dir",
                output,
                expected=2,
            )
            report_text = (output / "workflow-secret-audit.json").read_text(
                encoding="utf-8"
            )
            report = json.loads(report_text)
            self.assertFalse(report["summary"]["passed"])
            self.assertGreaterEqual(report["summary"]["finding_count"], 1)
            self.assertNotIn(literal, report_text)
            self.assertTrue(
                all("sha256" in finding for finding in report["findings"])
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
