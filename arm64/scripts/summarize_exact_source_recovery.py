#!/usr/bin/env python3
"""Consolidate exact-source recovery evidence without promoting packages.

The reference ISO residue authority defines the exact Source/Version target set.
The bounded Wayback pass may recover a subset. Common Crawl is allowed to cover
only the still-unresolved Wayback subset. Recovered archives remain pending a
separate package-layer verifier, so this program never permits package
promotion or final ISO assembly.

Every input authority must be completely sealed by LOCKSUMS.sha256. Missing,
duplicate, contradictory, unsealed, or malformed evidence fails closed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, NoReturn, Sequence

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
LOCKSUM_RE = re.compile(r"^([0-9a-f]{64}) ([ *])(.+)$")

RECOVERED_STATUS = "exact-source-archive-recovered"
UNRESOLVED_STATUS = "unresolved"
PENDING_STATUS = "recovered-pending-package-layer-verification"

REFERENCE_POLICY = "exact-source-residue-audit-no-promotion-from-version-text-alone"
WAYBACK_POLICY = "exact-source-version-and-all-sha256-members-required-bounded-v2"
COMMONCRAWL_POLICY = "commoncrawl-exact-source-version-and-all-sha256-members-required"
CONSOLIDATED_POLICY = "consolidated-exact-source-recovery-non-promoting"


class ValidationError(RuntimeError):
    """Raised when an authority cannot be accepted without guessing."""


@dataclass(frozen=True, order=True)
class Target:
    source: str
    version: str

    def as_dict(self) -> dict[str, str]:
        return {"source": self.source, "version": self.version}


@dataclass(frozen=True)
class SealedAuthority:
    label: str
    locksum_sha256: str
    sealed_tree_sha256: str
    sealed_file_count: int
    sealed_byte_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "locksum_sha256": self.locksum_sha256,
            "sealed_tree_sha256": self.sealed_tree_sha256,
            "sealed_file_count": self.sealed_file_count,
            "sealed_byte_count": self.sealed_byte_count,
            "verified": True,
        }


@dataclass
class RecoveryAuthority:
    label: str
    seal: SealedAuthority
    summary: dict[str, Any]
    runner: dict[str, Any]
    rows: dict[Target, dict[str, Any]]
    manifests: dict[Target, list[dict[str, Any]]]

    @property
    def recovered(self) -> set[Target]:
        return {
            target
            for target, row in self.rows.items()
            if row["status"] == RECOVERED_STATUS
        }

    @property
    def unresolved(self) -> set[Target]:
        return set(self.rows) - self.recovered


def fail(message: str) -> NoReturn:
    raise ValidationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label}: expected an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label}: expected an array")
    return value


def require_string(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 32 for character in value)
    ):
        fail(f"{label}: expected a non-empty printable string")
    return value


def require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{label}: expected an integer >= {minimum}")
    return value


def require_exact(value: Any, expected: Any, label: str) -> None:
    if value != expected:
        fail(f"{label}: expected {expected!r}, got {value!r}")


def read_json(path: Path, label: str) -> Any:
    if not path.is_file() or path.is_symlink():
        fail(f"{label}: required JSON file is missing or is a symlink: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label}: cannot parse {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_lock_authority(path: Path, label: str) -> SealedAuthority:
    if not path.is_dir() or path.is_symlink():
        fail(f"{label}: authority directory is missing or is a symlink: {path}")
    lock_path = path / "LOCKSUMS.sha256"
    if not lock_path.is_file() or lock_path.is_symlink():
        fail(f"{label}: LOCKSUMS.sha256 is missing")

    try:
        lines = lock_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError(f"{label}: cannot read LOCKSUMS.sha256: {exc}") from exc
    if not lines:
        fail(f"{label}: LOCKSUMS.sha256 is empty")

    listed: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        match = LOCKSUM_RE.fullmatch(line)
        if match is None:
            fail(f"{label}: malformed LOCKSUMS line {line_number}")
        expected_digest, _mode, raw_name = match.groups()
        if not raw_name.startswith("./"):
            fail(f"{label}: LOCKSUMS path must start with './': {raw_name!r}")
        relative = PurePosixPath(raw_name[2:])
        if (
            not relative.parts
            or relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            fail(f"{label}: unsafe LOCKSUMS path: {raw_name!r}")
        normalized = relative.as_posix()
        if normalized == "LOCKSUMS.sha256":
            fail(f"{label}: LOCKSUMS must not hash itself")
        if normalized in listed:
            fail(f"{label}: duplicate LOCKSUMS path: {normalized}")
        listed[normalized] = expected_digest

    actual: dict[str, Path] = {}
    for candidate in path.rglob("*"):
        if candidate.is_symlink():
            fail(f"{label}: symlink is not allowed in a sealed authority: {candidate}")
        if candidate.is_file() and candidate != lock_path:
            actual[candidate.relative_to(path).as_posix()] = candidate

    unlisted = sorted(set(actual) - set(listed))
    missing = sorted(set(listed) - set(actual))
    if unlisted or missing:
        fail(
            f"{label}: LOCKSUMS inventory mismatch; "
            f"unlisted={unlisted!r} missing={missing!r}"
        )

    tree_digest = hashlib.sha256()
    total_bytes = 0
    for relative in sorted(listed):
        candidate = actual[relative]
        actual_digest = sha256_file(candidate)
        expected_digest = listed[relative]
        if actual_digest != expected_digest:
            fail(
                f"{label}: SHA-256 mismatch for {relative}: "
                f"expected {expected_digest}, got {actual_digest}"
            )
        tree_digest.update(f"{expected_digest}  {relative}\n".encode("utf-8"))
        total_bytes += candidate.stat().st_size

    return SealedAuthority(
        label=label,
        locksum_sha256=sha256_file(lock_path),
        sealed_tree_sha256=tree_digest.hexdigest(),
        sealed_file_count=len(listed),
        sealed_byte_count=total_bytes,
    )


def parse_nonnegative_int(value: str, label: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise ValidationError(f"{label}: expected an integer, got {value!r}") from exc
    if number < 0:
        fail(f"{label}: expected a non-negative integer")
    return number


def load_reference(
    path: Path,
) -> tuple[SealedAuthority, dict[str, Any], list[Target], dict[Target, dict[str, Any]]]:
    seal = verify_lock_authority(path, "reference-iso-residue")
    summary = require_dict(read_json(path / "summary.json", "reference.summary"), "reference.summary")
    require_exact(summary.get("schema"), 1, "reference.summary.schema")
    require_exact(summary.get("policy"), REFERENCE_POLICY, "reference.summary.policy")
    require_exact(summary.get("promotion_allowed"), False, "reference.summary.promotion_allowed")
    require_exact(summary.get("source_recovery_ready"), False, "reference.summary.source_recovery_ready")

    iso = require_dict(summary.get("iso"), "reference.summary.iso")
    require_exact(iso.get("verified"), True, "reference.summary.iso.verified")
    require_int(iso.get("size"), "reference.summary.iso.size", minimum=1)
    iso_digest = require_string(iso.get("sha256"), "reference.summary.iso.sha256")
    if SHA256_RE.fullmatch(iso_digest) is None:
        fail("reference.summary.iso.sha256: invalid digest")

    targets_path = path / "targets.tsv"
    if not targets_path.is_file() or targets_path.is_symlink():
        fail("reference: targets.tsv is missing or is a symlink")
    required_columns = {
        "source",
        "source_version",
        "status",
        "source_stanzas",
        "package_stanzas",
        "status_stanzas",
        "version_hits",
        "source_archives",
    }
    ordered: list[Target] = []
    metadata: dict[Target, dict[str, Any]] = {}
    seen_sources: set[str] = set()
    try:
        with targets_path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream, delimiter="\t")
            if reader.fieldnames is None or not required_columns.issubset(reader.fieldnames):
                fail(f"reference: targets.tsv columns are incomplete: {reader.fieldnames!r}")
            for line_number, row in enumerate(reader, start=2):
                source = require_string(row.get("source"), f"reference.targets:{line_number}.source")
                version = require_string(
                    row.get("source_version"),
                    f"reference.targets:{line_number}.source_version",
                )
                status = require_string(row.get("status"), f"reference.targets:{line_number}.status")
                if SOURCE_RE.fullmatch(source) is None:
                    fail(f"reference.targets:{line_number}.source: invalid Debian source name")
                target = Target(source, version)
                if target in metadata:
                    fail(f"reference: duplicate target {source}={version}")
                if source in seen_sources:
                    fail(f"reference: one source name maps to multiple versions: {source}")
                seen_sources.add(source)
                target_metadata = {
                    "status": status,
                    "source_stanzas": parse_nonnegative_int(
                        row["source_stanzas"], f"reference.targets:{line_number}.source_stanzas"
                    ),
                    "package_stanzas": parse_nonnegative_int(
                        row["package_stanzas"], f"reference.targets:{line_number}.package_stanzas"
                    ),
                    "status_stanzas": parse_nonnegative_int(
                        row["status_stanzas"], f"reference.targets:{line_number}.status_stanzas"
                    ),
                    "version_hits": parse_nonnegative_int(
                        row["version_hits"], f"reference.targets:{line_number}.version_hits"
                    ),
                    "source_archives": parse_nonnegative_int(
                        row["source_archives"], f"reference.targets:{line_number}.source_archives"
                    ),
                }
                ordered.append(target)
                metadata[target] = target_metadata
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise ValidationError(f"reference: cannot parse targets.tsv: {exc}") from exc

    if not ordered:
        fail("reference: target list is empty")
    require_exact(summary.get("target_count"), len(ordered), "reference.summary.target_count")
    require_exact(summary.get("exact_source_index_target_count"), 0, "reference.summary.exact_source_index_target_count")
    require_exact(
        summary.get("exact_source_archive_target_count"),
        sum(row["source_archives"] > 0 for row in metadata.values()),
        "reference.summary.exact_source_archive_target_count",
    )
    require_exact(
        summary.get("exact_version_residue_only_target_count"),
        sum(row["status"] == "exact-version-residue-only" for row in metadata.values()),
        "reference.summary.exact_version_residue_only_target_count",
    )
    require_exact(summary.get("not_found_target_count"), 0, "reference.summary.not_found_target_count")
    return seal, summary, ordered, metadata


def target_from_mapping(value: Any, label: str) -> Target:
    row = require_dict(value, label)
    source = require_string(row.get("source"), f"{label}.source")
    version = require_string(row.get("version"), f"{label}.version")
    if SOURCE_RE.fullmatch(source) is None:
        fail(f"{label}.source: invalid Debian source name")
    return Target(source, version)


def unique_target_map(rows: list[Any], label: str) -> dict[Target, dict[str, Any]]:
    result: dict[Target, dict[str, Any]] = {}
    for index, value in enumerate(rows):
        row_label = f"{label}[{index}]"
        row = require_dict(value, row_label)
        target = target_from_mapping(row, row_label)
        if target in result:
            fail(f"{label}: duplicate target {target.source}={target.version}")
        result[target] = row
    return result


def validate_runner(path: Path, label: str) -> dict[str, Any]:
    runner = require_dict(read_json(path / "runner-status.json", f"{label}.runner"), f"{label}.runner")
    require_exact(runner.get("schema"), 1, f"{label}.runner.schema")
    require_exact(runner.get("compile_exit_code"), 0, f"{label}.runner.compile_exit_code")
    require_exact(runner.get("recovery_exit_code"), 0, f"{label}.runner.recovery_exit_code")
    require_string(runner.get("workflow_run_id"), f"{label}.runner.workflow_run_id")
    require_string(runner.get("workflow_run_attempt"), f"{label}.runner.workflow_run_attempt")
    head_sha = require_string(runner.get("head_sha"), f"{label}.runner.head_sha")
    if COMMIT_RE.fullmatch(head_sha) is None:
        fail(f"{label}.runner.head_sha: invalid commit SHA")
    require_string(runner.get("generated_at"), f"{label}.runner.generated_at")
    return runner


def canonical_manifest_files(value: Any, label: str) -> list[dict[str, Any]]:
    rows = require_list(value, label)
    if not rows:
        fail(f"{label}: recovered archive manifest is empty")
    files: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, value_row in enumerate(rows):
        row = require_dict(value_row, f"{label}[{index}]")
        filename = require_string(row.get("filename"), f"{label}[{index}].filename")
        if (
            filename in {".", ".."}
            or "/" in filename
            or "\\" in filename
            or Path(filename).name != filename
        ):
            fail(f"{label}[{index}].filename: unsafe archive member")
        if filename in names:
            fail(f"{label}: duplicate archive member {filename!r}")
        names.add(filename)
        size = require_int(row.get("size"), f"{label}[{index}].size")
        digest = require_string(row.get("sha256"), f"{label}[{index}].sha256")
        if SHA256_RE.fullmatch(digest) is None:
            fail(f"{label}[{index}].sha256: invalid digest")
        files.append({"filename": filename, "size": size, "sha256": digest})
    if sum(row["filename"].endswith(".dsc") for row in files) != 1:
        fail(f"{label}: expected exactly one .dsc member")
    return sorted(files, key=lambda row: row["filename"])


def validate_manifest_document(path: Path, label: str) -> dict[Target, list[dict[str, Any]]]:
    rows = require_list(read_json(path, label), label)
    result: dict[Target, list[dict[str, Any]]] = {}
    for index, value in enumerate(rows):
        row_label = f"{label}[{index}]"
        row = require_dict(value, row_label)
        target = target_from_mapping(row, row_label)
        if target in result:
            fail(f"{label}: duplicate manifest for {target.source}={target.version}")
        result[target] = canonical_manifest_files(row.get("files"), f"{row_label}.files")
    return result


def validate_recovery_rows(
    label: str,
    rows: dict[Target, dict[str, Any]],
    manifests: dict[Target, list[dict[str, Any]]],
) -> None:
    recovered: set[Target] = set()
    for target, row in rows.items():
        status = require_string(row.get("status"), f"{label}.{target.source}.status")
        if status not in {RECOVERED_STATUS, UNRESOLVED_STATUS}:
            fail(f"{label}.{target.source}.status: unsupported state {status!r}")
        require_string(row.get("reason"), f"{label}.{target.source}.reason")
        require_list(row.get("candidate_results"), f"{label}.{target.source}.candidate_results")
        if status == RECOVERED_STATUS:
            recovered.add(target)
            selected = require_dict(
                row.get("selected_candidate"),
                f"{label}.{target.source}.selected_candidate",
            )
            require_exact(
                selected.get("status"),
                RECOVERED_STATUS,
                f"{label}.{target.source}.selected_candidate.status",
            )
            selected_manifest = canonical_manifest_files(
                selected.get("archive_manifest"),
                f"{label}.{target.source}.selected_candidate.archive_manifest",
            )
            if target not in manifests:
                fail(f"{label}: recovered target lacks a compact manifest: {target}")
            if manifests[target] != selected_manifest:
                fail(f"{label}: selected-candidate and compact manifests disagree: {target}")
        elif target in manifests:
            fail(f"{label}: unresolved target unexpectedly has a recovered manifest: {target}")
    if set(manifests) != recovered:
        fail(
            f"{label}: recovered row/manifest target sets disagree: "
            f"rows={sorted(recovered)!r} manifests={sorted(manifests)!r}"
        )


def load_recovery_authority(
    path: Path,
    *,
    label: str,
    policy: str,
    schema: int,
    expected_targets: set[Target],
    target_count_field: str,
    all_recovered_field: str,
    require_targets_input: bool,
) -> RecoveryAuthority:
    seal = verify_lock_authority(path, label)
    summary = require_dict(read_json(path / "summary.json", f"{label}.summary"), f"{label}.summary")
    require_exact(summary.get("schema"), schema, f"{label}.summary.schema")
    require_exact(summary.get("policy"), policy, f"{label}.summary.policy")
    require_exact(summary.get("promotion_allowed"), False, f"{label}.summary.promotion_allowed")
    if summary.get("runner_failed") not in {None, False}:
        fail(f"{label}: summary reports a failed producer runner")
    runner = validate_runner(path, label)

    if require_targets_input:
        input_rows = require_list(
            read_json(path / "targets-input.json", f"{label}.targets-input"),
            f"{label}.targets-input",
        )
        input_targets = set(unique_target_map(input_rows, f"{label}.targets-input"))
        if input_targets != expected_targets:
            fail(
                f"{label}: input target set is stale or contradictory; "
                f"expected={sorted(expected_targets)!r} actual={sorted(input_targets)!r}"
            )

    result_rows = require_list(
        read_json(path / "target-results.json", f"{label}.target-results"),
        f"{label}.target-results",
    )
    rows = unique_target_map(result_rows, f"{label}.target-results")
    if set(rows) != expected_targets:
        fail(
            f"{label}: result target set mismatch; "
            f"expected={sorted(expected_targets)!r} actual={sorted(rows)!r}"
        )
    manifests = validate_manifest_document(
        path / "recovered-source-manifest.json",
        f"{label}.recovered-source-manifest",
    )
    validate_recovery_rows(label, rows, manifests)

    recovered_count = sum(row["status"] == RECOVERED_STATUS for row in rows.values())
    unresolved_count = len(rows) - recovered_count
    require_exact(summary.get(target_count_field), len(rows), f"{label}.summary.{target_count_field}")
    require_exact(
        summary.get("exact_source_archive_recovered_count"),
        recovered_count,
        f"{label}.summary.exact_source_archive_recovered_count",
    )
    require_exact(summary.get("unresolved_count"), unresolved_count, f"{label}.summary.unresolved_count")
    require_exact(
        summary.get("source_recovery_ready"),
        recovered_count > 0,
        f"{label}.summary.source_recovery_ready",
    )
    require_exact(
        summary.get(all_recovered_field),
        unresolved_count == 0,
        f"{label}.summary.{all_recovered_field}",
    )
    return RecoveryAuthority(label, seal, summary, runner, rows, manifests)


def compact_evidence_row(authority: RecoveryAuthority, target: Target) -> dict[str, Any]:
    row = authority.rows[target]
    compact: dict[str, Any] = {
        "status": row["status"],
        "reason": row["reason"],
        "candidate_attempt_count": len(row["candidate_results"]),
    }
    for field in ("source_stanza_candidate_count", "direct_dsc_hit_count"):
        if field in row:
            compact[field] = require_int(row[field], f"{authority.label}.{target.source}.{field}")
    return compact


def authority_metadata(authority: RecoveryAuthority) -> dict[str, Any]:
    metadata = authority.seal.as_dict()
    metadata["runner"] = {
        "compile_exit_code": authority.runner["compile_exit_code"],
        "recovery_exit_code": authority.runner["recovery_exit_code"],
        "workflow_run_id": authority.runner["workflow_run_id"],
        "workflow_run_attempt": authority.runner["workflow_run_attempt"],
        "head_sha": authority.runner["head_sha"],
        "generated_at": authority.runner["generated_at"],
    }
    return metadata


def target_set_sha256(targets: Sequence[Target]) -> str:
    payload = "".join(f"{target.source}\t{target.version}\n" for target in sorted(targets))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def markdown(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def consolidate(
    *,
    reference: Path,
    wayback_v2: Path,
    commoncrawl: Path,
    output_dir: Path,
) -> dict[str, Any]:
    for input_path in (reference, wayback_v2, commoncrawl):
        try:
            output_dir.resolve().relative_to(input_path.resolve())
        except ValueError:
            pass
        else:
            fail(f"output directory must not be inside input authority: {input_path}")

    reference_seal, reference_summary, ordered_targets, reference_metadata = load_reference(reference)
    reference_set = set(ordered_targets)
    wayback = load_recovery_authority(
        wayback_v2,
        label="wayback-v2",
        policy=WAYBACK_POLICY,
        schema=2,
        expected_targets=reference_set,
        target_count_field="target_count",
        all_recovered_field="all_targets_recovered",
        require_targets_input=False,
    )
    commoncrawl_expected = reference_set - wayback.recovered
    common = load_recovery_authority(
        commoncrawl,
        label="commoncrawl",
        policy=COMMONCRAWL_POLICY,
        schema=1,
        expected_targets=commoncrawl_expected,
        target_count_field="input_target_count",
        all_recovered_field="all_input_targets_recovered",
        require_targets_input=True,
    )

    target_rows: list[dict[str, Any]] = []
    pending_manifest: list[dict[str, Any]] = []
    unresolved_targets: list[dict[str, Any]] = []
    pending_count = 0

    for target in ordered_targets:
        evidence: dict[str, Any] = {
            "wayback_v2": compact_evidence_row(wayback, target)
        }
        selected: RecoveryAuthority | None = None
        if target in wayback.recovered:
            selected = wayback
        else:
            evidence["commoncrawl"] = compact_evidence_row(common, target)
            if target in common.recovered:
                selected = common

        if selected is not None:
            status = PENDING_STATUS
            recovery_authority = selected.label
            reason = (
                f"exact archive recovered by {selected.label}; "
                "separate package-layer verification is required"
            )
            pending_count += 1
            pending_manifest.append(
                {
                    **target.as_dict(),
                    "status": PENDING_STATUS,
                    "recovery_authority": selected.label,
                    "package_layer_verified": False,
                    "files": selected.manifests[target],
                }
            )
        else:
            status = UNRESOLVED_STATUS
            recovery_authority = "none"
            reason = (
                "no complete exact source archive was recovered by the bounded "
                "Wayback or Common Crawl authorities"
            )
            unresolved_targets.append(
                {
                    **target.as_dict(),
                    "reference_residue": reference_metadata[target],
                    "wayback_v2_reason": wayback.rows[target]["reason"],
                    "commoncrawl_reason": common.rows[target]["reason"],
                }
            )

        target_rows.append(
            {
                **target.as_dict(),
                "status": status,
                "recovery_authority": recovery_authority,
                "reason": reason,
                "reference_residue": reference_metadata[target],
                "package_layer_verified": False,
                "package_layer_promotion_allowed": False,
                "iso_assembly_allowed": False,
                "evidence": evidence,
            }
        )

    unresolved_count = len(ordered_targets) - pending_count
    if pending_count + unresolved_count != len(ordered_targets):
        fail("internal error: consolidated target accounting is not exhaustive")

    authorities = {
        "reference_iso_residue": {
            **reference_seal.as_dict(),
            "summary_sha256": sha256_file(reference / "summary.json"),
            "targets_sha256": sha256_file(reference / "targets.tsv"),
            "iso": reference_summary["iso"],
        },
        "wayback_v2": {
            **authority_metadata(wayback),
            "summary_sha256": sha256_file(wayback_v2 / "summary.json"),
        },
        "commoncrawl": {
            **authority_metadata(common),
            "summary_sha256": sha256_file(commoncrawl / "summary.json"),
        },
    }

    blocking_reasons: list[str] = []
    if unresolved_count:
        blocking_reasons.append("unresolved exact source archives remain")
    if pending_count:
        blocking_reasons.append("recovered source archives require package-layer verification")
    blocking_reasons.append("recovery evidence is explicitly non-promoting")

    summary: dict[str, Any] = {
        "schema": 1,
        "policy": CONSOLIDATED_POLICY,
        "decision": "blocked",
        "input_authorities_verified": True,
        "producer_runners_healthy": True,
        "target_count": len(ordered_targets),
        "target_set_sha256": target_set_sha256(ordered_targets),
        "wayback_v2_recovered_count": len(wayback.recovered),
        "commoncrawl_input_target_count": len(common.rows),
        "commoncrawl_recovered_count": len(common.recovered),
        "recovered_pending_verification_count": pending_count,
        "unresolved_count": unresolved_count,
        "package_layer_verification_required_count": pending_count,
        "source_recovery_complete": unresolved_count == 0,
        "package_layer_promotion_allowed": False,
        "iso_assembly_allowed": False,
        "blocking_reasons": blocking_reasons,
        "input_authority_locks": {
            name: value["locksum_sha256"] for name, value in authorities.items()
        },
    }

    if output_dir.exists() and any(output_dir.iterdir()):
        fail(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "summary.json", summary)
    write_json(output_dir / "target-results.json", target_rows)
    write_json(output_dir / "recovered-source-manifest.json", pending_manifest)
    write_json(output_dir / "unresolved-targets.json", unresolved_targets)
    write_json(output_dir / "input-authorities.json", authorities)

    report_lines = [
        "# Consolidated exact-source recovery authority",
        "",
        "**Decision: blocked.** This report is non-promoting; neither package-layer publication nor final ISO assembly is authorized.",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Reference targets | {len(ordered_targets)} |",
        f"| Wayback v2 recovered | {len(wayback.recovered)} |",
        f"| Common Crawl input targets | {len(common.rows)} |",
        f"| Common Crawl recovered | {len(common.recovered)} |",
        f"| Recovered, pending verification | {pending_count} |",
        f"| Unresolved | {unresolved_count} |",
        "| Package-layer promotion allowed | false |",
        "| ISO assembly allowed | false |",
        "",
        "## Target state",
        "",
        "| Source | Exact version | Wayback v2 | Common Crawl | Consolidated |",
        "|---|---|---|---|---|",
    ]
    for row in target_rows:
        evidence = row["evidence"]
        common_status = evidence.get("commoncrawl", {}).get("status", "not-requested")
        report_lines.append(
            "| "
            + " | ".join(
                [
                    markdown(row["source"]),
                    markdown(row["version"]),
                    markdown(evidence["wayback_v2"]["status"]),
                    markdown(common_status),
                    markdown(row["status"]),
                ]
            )
            + " |"
        )
    report_lines.extend(
        [
            "",
            "## Authority locks",
            "",
            "| Authority | LOCKSUMS SHA-256 | Sealed files |",
            "|---|---|---:|",
        ]
    )
    for name in ("reference_iso_residue", "wayback_v2", "commoncrawl"):
        value = authorities[name]
        report_lines.append(
            f"| {markdown(name)} | `{value['locksum_sha256']}` | {value['sealed_file_count']} |"
        )
    report_lines.extend(
        [
            "",
            "> Exact Source/Version and archive-member hashes establish recovery provenance, not package-layer acceptance. A separate verifier must consume the recovered bytes and explicitly authorize promotion.",
            "",
        ]
    )
    (output_dir / "REPORT.md").write_text("\n".join(report_lines), encoding="utf-8")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--wayback-v2", type=Path, required=True)
    parser.add_argument("--commoncrawl", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = consolidate(
            reference=args.reference,
            wayback_v2=args.wayback_v2,
            commoncrawl=args.commoncrawl,
            output_dir=args.output_dir,
        )
    except (ValidationError, OSError, UnicodeError) as exc:
        print(f"exact-source consolidation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
