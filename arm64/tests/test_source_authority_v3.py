#!/usr/bin/env python3
from __future__ import annotations

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


def invoke(script: str, *args: object, expected: int = 0) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        [sys.executable, str(SCRIPTS / script), *(str(arg) for arg in args)],
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


def reference() -> dict[str, object]:
    return {
        "sources": [
            {
                "source": "example",
                "source_version": "1.0+grm1",
                "custom_candidate": True,
            }
        ],
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
        ],
    }


def git_lock() -> dict[str, object]:
    return {
        "sources": [
            {
                "source": "example",
                "source_version": "1.0+grm1",
                "status": "resolved",
                "selected": {
                    "repository_full_name": "gooroom/example",
                    "commit_sha": "1" * 40,
                    "tree_sha": "2" * 40,
                    "declared_source": "example",
                    "declared_version": "1.0+grm1",
                    "ref_kind": "tag",
                    "ref_name": "debian/1.0+grm1",
                },
            }
        ]
    }


def wayback_lock(dsc_sha: str = "3" * 64) -> dict[str, object]:
    return {
        "summary": {
            "release_complete": True,
            "release_tag": "v3.3-arm64-sources",
            "release_id": 10,
            "release_url": "https://example.invalid/release",
        },
        "sources": [
            {
                "source": "example",
                "source_version": "1.0+grm1",
                "role": "rebuild-arm64",
                "dsc_sha256": dsc_sha,
                "capture_timestamp": "20230101000000",
                "files": [
                    {
                        "filename": "example_1.0+grm1.dsc",
                        "size": 100,
                        "sha256": dsc_sha,
                        "release_asset_id": 1,
                        "release_digest": "sha256:" + dsc_sha,
                        "browser_download_url": "https://example.invalid/example_1.0+grm1.dsc",
                    },
                    {
                        "filename": "example_1.0.orig.tar.xz",
                        "size": 200,
                        "sha256": "4" * 64,
                        "release_asset_id": 2,
                        "release_digest": "sha256:" + "4" * 64,
                        "browser_download_url": "https://example.invalid/example_1.0.orig.tar.xz",
                    },
                    {
                        "filename": "example_1.0+grm1.debian.tar.xz",
                        "size": 300,
                        "sha256": "5" * 64,
                        "release_asset_id": 3,
                        "release_digest": "sha256:" + "5" * 64,
                        "browser_download_url": "https://example.invalid/example_1.0+grm1.debian.tar.xz",
                    },
                ],
            }
        ],
    }


class SourceAuthorityMergeTests(unittest.TestCase):
    def test_signed_dsc_is_preferred_over_exact_git(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ref = root / "reference.json"
            git = root / "git.json"
            vendor = root / "vendor.json"
            wayback = root / "wayback.json"
            output = root / "output"
            write_json(ref, reference())
            write_json(git, git_lock())
            write_json(vendor, {"sources": []})
            write_json(wayback, wayback_lock())
            invoke(
                "merge_exact_source_authority_v3.py",
                "--reference",
                ref,
                "--git-lock",
                git,
                "--vendor-pool-lock",
                vendor,
                "--wayback-release-lock",
                wayback,
                "--output-dir",
                output,
            )
            lock = json.loads(
                (output / "effective-source-lock.json").read_text(encoding="utf-8")
            )
            row = lock["sources"][0]
            self.assertEqual(row["selected"]["type"], "dsc")
            self.assertEqual(
                row["provenance"], "wayback-release-exact-signed-dsc"
            )
            self.assertEqual(lock["summary"]["signed_dsc_resolved_count"], 1)

    def test_git_is_used_when_no_signed_dsc_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ref = root / "reference.json"
            git = root / "git.json"
            vendor = root / "vendor.json"
            output = root / "output"
            write_json(ref, reference())
            write_json(git, git_lock())
            write_json(vendor, {"sources": []})
            invoke(
                "merge_exact_source_authority_v3.py",
                "--reference",
                ref,
                "--git-lock",
                git,
                "--vendor-pool-lock",
                vendor,
                "--output-dir",
                output,
            )
            lock = json.loads(
                (output / "effective-source-lock.json").read_text(encoding="utf-8")
            )
            self.assertEqual(lock["sources"][0]["selected"]["type"], "git")
            self.assertEqual(lock["summary"]["git_resolved_count"], 1)

    def test_conflicting_signed_dsc_identities_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ref = root / "reference.json"
            git = root / "git.json"
            vendor = root / "vendor.json"
            wayback = root / "wayback.json"
            output = root / "output"
            write_json(ref, reference())
            write_json(git, git_lock())
            write_json(
                vendor,
                {
                    "sources": [
                        {
                            "source": "example",
                            "source_version": "1.0+grm1",
                            "status": "resolved",
                            "selected": {
                                "signature_valid": True,
                                "signed_source": "example",
                                "signed_version": "1.0+grm1",
                                "repository": "gooroom",
                                "suite": "gooroom-3.0",
                                "dsc_name": "example_1.0+grm1.dsc",
                                "dsc_size": 101,
                                "dsc_sha256": "6" * 64,
                                "url": "https://vendor.invalid/example_1.0+grm1.dsc",
                                "files": [
                                    {
                                        "name": "example_1.0.orig.tar.xz",
                                        "size": 200,
                                        "sha256": "4" * 64,
                                    }
                                ],
                                "source_urls": [
                                    "https://vendor.invalid/example_1.0.orig.tar.xz"
                                ],
                            },
                        }
                    ]
                },
            )
            write_json(wayback, wayback_lock())
            invoke(
                "merge_exact_source_authority_v3.py",
                "--reference",
                ref,
                "--git-lock",
                git,
                "--vendor-pool-lock",
                vendor,
                "--wayback-release-lock",
                wayback,
                "--output-dir",
                output,
                expected=2,
            )
            lock = json.loads(
                (output / "effective-source-lock.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                lock["sources"][0]["status"], "ambiguous-exact-signed-source"
            )
            self.assertFalse(lock["summary"]["build_allowed"])


class DscSelectorTests(unittest.TestCase):
    def test_curated_batch_accepts_exact_dsc_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock_path = root / "lock.json"
            reference_path = root / "reference.json"
            plan_path = root / "plan.json"
            output_path = root / "selected.json"
            write_json(reference_path, reference())
            write_json(
                lock_path,
                {
                    "sources": [
                        {
                            "source": "example",
                            "source_version": "1.0+grm1",
                            "status": "resolved",
                            "provenance": "wayback-release-exact-signed-dsc",
                            "selected": {
                                "type": "dsc",
                                "signature_verified": True,
                                "signed_source": "example",
                                "signed_version": "1.0+grm1",
                                "dsc": {
                                    "filename": "example_1.0+grm1.dsc",
                                    "size": 100,
                                    "sha256": "3" * 64,
                                    "url": "https://example.invalid/example_1.0+grm1.dsc",
                                },
                                "files": [
                                    {
                                        "filename": "example_1.0.orig.tar.xz",
                                        "size": 200,
                                        "sha256": "4" * 64,
                                        "url": "https://example.invalid/example_1.0.orig.tar.xz",
                                    }
                                ],
                            },
                        }
                    ]
                },
            )
            write_json(plan_path, {"batches": {"desktop-core": ["example"]}})
            invoke(
                "select_native_rebuild_batch_v3.py",
                "--lock",
                lock_path,
                "--reference",
                reference_path,
                "--plan",
                plan_path,
                "--batch",
                "desktop-core",
                "--output",
                output_path,
            )
            result = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(result["summary"]["selected_count"], 1)
            self.assertEqual(result["selected"][0]["source_type"], "dsc")
            self.assertEqual(result["selected"][0]["dsc_sha256"], "3" * 64)


class AcquisitionDscTests(unittest.TestCase):
    def test_dsc_rebuild_release_asset_is_a_valid_exact_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            normalized = root / "normalized.json"
            vendor = root / "vendor.json"
            release = root / "release.json"
            results = root / "results"
            output = root / "output"
            results.mkdir()
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
                            "selected": None,
                        }
                    ],
                },
            )
            write_json(vendor, {"packages": []})
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
                            "dsc_filename": "example_1.0+grm1.dsc",
                            "dsc_sha256": "3" * 64,
                            "filename": "example_1.0+grm1_arm64.deb",
                            "size": 500,
                            "sha256": "7" * 64,
                            "release_asset": {
                                "id": 50,
                                "name": "example_1.0+grm1_arm64.deb",
                                "digest": "sha256:" + "7" * 64,
                                "browser_download_url": "https://example.invalid/example_1.0+grm1_arm64.deb",
                            },
                        }
                    ],
                },
            )
            invoke(
                "build_package_acquisition_plan_v3.py",
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
            acquisition = plan["packages"][0]["acquisition"]
            self.assertEqual(acquisition["method"], "download-release-exact")
            self.assertEqual(acquisition["source_type"], "dsc")
            self.assertEqual(acquisition["dsc_sha256"], "3" * 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
