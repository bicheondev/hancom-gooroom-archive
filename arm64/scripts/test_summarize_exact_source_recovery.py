#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

SCRIPT = Path(__file__).with_name("summarize_exact_source_recovery.py")
SPEC = importlib.util.spec_from_file_location("summarize_exact_source_recovery", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot import summarizer")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seal(directory: Path) -> None:
    members = sorted(
        path
        for path in directory.rglob("*")
        if path.is_file() and path.name != "LOCKSUMS.sha256"
    )
    (directory / "LOCKSUMS.sha256").write_text(
        "".join(
            f"{sha256(path)}  ./{path.relative_to(directory).as_posix()}\n"
            for path in members
        ),
        encoding="utf-8",
    )


def targets() -> list[tuple[str, str]]:
    return [("alpha", "1.0-1"), ("beta", "2.0-1"), ("gamma", "3.0-1")]


def make_reference(root: Path) -> Path:
    directory = root / "reference"
    directory.mkdir()
    write_json(
        directory / "summary.json",
        {
            "schema": 1,
            "policy": MODULE.REFERENCE_POLICY,
            "iso": {
                "name": "reference.iso",
                "size": 1,
                "sha256": "0" * 64,
                "verified": True,
            },
            "target_count": 3,
            "exact_source_index_target_count": 0,
            "exact_source_archive_target_count": 0,
            "exact_version_residue_only_target_count": 3,
            "not_found_target_count": 0,
            "source_recovery_ready": False,
            "promotion_allowed": False,
        },
    )
    (directory / "targets.tsv").write_text(
        "source\tsource_version\tstatus\tsource_stanzas\tpackage_stanzas\tstatus_stanzas\tversion_hits\tsource_archives\n"
        + "".join(
            f"{source}\t{version}\texact-version-residue-only\t0\t1\t1\t2\t0\n"
            for source, version in targets()
        ),
        encoding="utf-8",
    )
    seal(directory)
    return directory


def archive_manifest(source: str) -> list[dict[str, Any]]:
    return [
        {"filename": f"{source}_1.dsc", "size": 100, "sha256": "1" * 64},
        {"filename": f"{source}.tar.xz", "size": 200, "sha256": "2" * 64},
    ]


def make_authority(
    root: Path,
    name: str,
    expected: list[tuple[str, str]],
    recovered: set[tuple[str, str]],
    *,
    commoncrawl: bool,
    runner_exit: int = 0,
) -> Path:
    directory = root / name
    directory.mkdir()
    rows: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    for source, version in expected:
        key = (source, version)
        if key in recovered:
            files = archive_manifest(source)
            rows.append(
                {
                    "source": source,
                    "version": version,
                    "status": MODULE.RECOVERED_STATUS,
                    "reason": "verified exact archive",
                    "source_stanza_candidate_count": 1,
                    "candidate_results": [],
                    "selected_candidate": {
                        "status": MODULE.RECOVERED_STATUS,
                        "archive_manifest": copy.deepcopy(files),
                    },
                }
            )
            manifests.append({"source": source, "version": version, "files": files})
        else:
            rows.append(
                {
                    "source": source,
                    "version": version,
                    "status": MODULE.UNRESOLVED_STATUS,
                    "reason": "not found",
                    "source_stanza_candidate_count": 0,
                    "candidate_results": [],
                }
            )
    write_json(directory / "target-results.json", rows)
    write_json(directory / "recovered-source-manifest.json", manifests)
    if commoncrawl:
        write_json(
            directory / "targets-input.json",
            [{"source": source, "version": version} for source, version in expected],
        )
        summary = {
            "schema": 1,
            "policy": MODULE.COMMONCRAWL_POLICY,
            "input_target_count": len(expected),
            "exact_source_archive_recovered_count": len(recovered),
            "unresolved_count": len(expected) - len(recovered),
            "source_recovery_ready": bool(recovered),
            "all_input_targets_recovered": len(recovered) == len(expected),
            "promotion_allowed": False,
        }
    else:
        summary = {
            "schema": 2,
            "policy": MODULE.WAYBACK_POLICY,
            "target_count": len(expected),
            "exact_source_archive_recovered_count": len(recovered),
            "unresolved_count": len(expected) - len(recovered),
            "source_recovery_ready": bool(recovered),
            "all_targets_recovered": len(recovered) == len(expected),
            "promotion_allowed": False,
        }
    write_json(directory / "summary.json", summary)
    write_json(
        directory / "runner-status.json",
        {
            "schema": 1,
            "compile_exit_code": runner_exit,
            "recovery_exit_code": runner_exit,
            "workflow_run_id": "1",
            "workflow_run_attempt": "1",
            "head_sha": "a" * 40,
            "generated_at": "2026-08-12T00:00:00Z",
        },
    )
    seal(directory)
    return directory


def expect_failure(label: str, action: Callable[[], object]) -> None:
    try:
        action()
    except MODULE.ValidationError:
        return
    raise AssertionError(f"{label}: expected ValidationError")


def run_case(reference: Path, wayback: Path, common: Path, output: Path) -> dict[str, Any]:
    return MODULE.consolidate(
        reference=reference,
        wayback_v2=wayback,
        commoncrawl=common,
        output_dir=output,
    )


def test_all_unresolved() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        reference = make_reference(root)
        all_targets = targets()
        wayback = make_authority(root, "wayback", all_targets, set(), commoncrawl=False)
        common = make_authority(root, "common", all_targets, set(), commoncrawl=True)
        summary = run_case(reference, wayback, common, root / "output")
        assert summary["recovered_pending_verification_count"] == 0
        assert summary["unresolved_count"] == 3
        assert summary["package_layer_promotion_allowed"] is False
        assert summary["iso_assembly_allowed"] is False
        assert json.loads((root / "output" / "recovered-source-manifest.json").read_text()) == []


def test_staged_recovery() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        reference = make_reference(root)
        all_targets = targets()
        wayback = make_authority(
            root, "wayback", all_targets, {all_targets[0]}, commoncrawl=False
        )
        remaining = all_targets[1:]
        common = make_authority(
            root, "common", remaining, {remaining[0]}, commoncrawl=True
        )
        summary = run_case(reference, wayback, common, root / "output")
        assert summary["wayback_v2_recovered_count"] == 1
        assert summary["commoncrawl_input_target_count"] == 2
        assert summary["commoncrawl_recovered_count"] == 1
        assert summary["recovered_pending_verification_count"] == 2
        assert summary["unresolved_count"] == 1
        rows = json.loads((root / "output" / "target-results.json").read_text())
        assert [row["recovery_authority"] for row in rows] == [
            "wayback-v2",
            "commoncrawl",
            "none",
        ]
        assert all(row["package_layer_promotion_allowed"] is False for row in rows)


def test_commoncrawl_scope_mismatch_fails() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        reference = make_reference(root)
        all_targets = targets()
        wayback = make_authority(
            root, "wayback", all_targets, {all_targets[0]}, commoncrawl=False
        )
        common = make_authority(root, "common", all_targets, set(), commoncrawl=True)
        expect_failure(
            "Common Crawl scope mismatch",
            lambda: run_case(reference, wayback, common, root / "output"),
        )


def test_manifest_mismatch_fails() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        reference = make_reference(root)
        all_targets = targets()
        wayback = make_authority(
            root, "wayback", all_targets, {all_targets[0]}, commoncrawl=False
        )
        manifest_path = wayback / "recovered-source-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest[0]["files"][0]["sha256"] = "3" * 64
        write_json(manifest_path, manifest)
        seal(wayback)
        common = make_authority(root, "common", all_targets[1:], set(), commoncrawl=True)
        expect_failure(
            "manifest mismatch",
            lambda: run_case(reference, wayback, common, root / "output"),
        )


def test_unsealed_extra_fails() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        reference = make_reference(root)
        all_targets = targets()
        wayback = make_authority(root, "wayback", all_targets, set(), commoncrawl=False)
        (wayback / "unsealed.txt").write_text("not sealed", encoding="utf-8")
        common = make_authority(root, "common", all_targets, set(), commoncrawl=True)
        expect_failure(
            "unsealed file",
            lambda: run_case(reference, wayback, common, root / "output"),
        )


def test_unhealthy_runner_fails() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        reference = make_reference(root)
        all_targets = targets()
        wayback = make_authority(
            root, "wayback", all_targets, set(), commoncrawl=False, runner_exit=1
        )
        common = make_authority(root, "common", all_targets, set(), commoncrawl=True)
        expect_failure(
            "unhealthy runner",
            lambda: run_case(reference, wayback, common, root / "output"),
        )


def main() -> int:
    test_all_unresolved()
    test_staged_recovery()
    test_commoncrawl_scope_mismatch_fails()
    test_manifest_mismatch_fails()
    test_unsealed_extra_fails()
    test_unhealthy_runner_fails()
    print("summarize_exact_source_recovery regression tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
