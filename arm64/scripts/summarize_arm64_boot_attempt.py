#!/usr/bin/env python3
"""Record a bounded, fail-closed ARM64 ISO assembly and UEFI boot attempt."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ERROR_RE = re.compile(
    r"(?:^E:|error|failed|failure|unable|missing|not found|"
    r"no installation candidate|unmet depend|cannot|panic|segmentation fault)",
    re.IGNORECASE,
)
TEXT_SUFFIXES = {".log", ".txt", ".json", ".tsv", ".size", ".sha256"}
MAX_INLINE_HASH_SIZE = 64 * 1024 * 1024


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_optional(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return None, "JSON root is not an object"
        return value, None
    except Exception as error:
        return None, repr(error)


def stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sidecar_sha256(path: Path) -> str | None:
    candidates = [
        path.with_name(path.name + ".sha256"),
        path.parent / f"{path.name}.sha256",
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        for line in candidate.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            fields = line.split()
            if not fields:
                continue
            digest = fields[0].lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                return digest
    return None


def copy_tail(source: Path, destination: Path, lines: int = 320) -> None:
    text = source.read_text(encoding="utf-8", errors="replace").splitlines()
    destination.write_text("\n".join(text[-lines:]) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempt-root", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--readiness-marker", required=True)
    parser.add_argument("--assembly-exit-code", type=int, required=True)
    parser.add_argument("--boot-outcome", required=True)
    parser.add_argument("--build-result-name", required=True)
    parser.add_argument("--wrapper-result-name")
    parser.add_argument("--qemu-log-name", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    parser.add_argument("--head-sha")
    parser.add_argument("--head-branch")
    parser.add_argument("--workflow-name")
    parser.add_argument("--repository")
    parser.add_argument("--server-url")
    args = parser.parse_args()

    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    build_path = args.attempt_root / args.build_result_name
    build_result, build_error = load_optional(build_path)
    wrapper_path = (
        args.attempt_root / args.wrapper_result_name
        if args.wrapper_result_name
        else None
    )
    wrapper_result: dict[str, Any] | None = None
    wrapper_error: str | None = None
    if wrapper_path is not None:
        wrapper_result, wrapper_error = load_optional(wrapper_path)
    qemu_path = args.attempt_root / args.qemu_log_name
    qemu_lines = (
        qemu_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if qemu_path.is_file()
        else []
    )
    marker_found = any(args.readiness_marker in line for line in qemu_lines)

    reasons: list[str] = []
    if args.assembly_exit_code != 0:
        reasons.append(f"assembly exit code={args.assembly_exit_code}")
    if args.boot_outcome != "success":
        reasons.append(f"boot step outcome={args.boot_outcome}")
    if build_result is None:
        reasons.append(
            f"build result missing or invalid: {args.build_result_name}"
            + (f" ({build_error})" if build_error else "")
        )
    if wrapper_path is not None and wrapper_result is None:
        reasons.append(
            f"wrapper result missing or invalid: {args.wrapper_result_name}"
            + (f" ({wrapper_error})" if wrapper_error else "")
        )
    if wrapper_result is not None:
        wrapper_rc = wrapper_result.get("builder_exit_code")
        if wrapper_rc not in (None, 0):
            reasons.append(f"wrapper builder exit code={wrapper_rc}")
    if not qemu_path.is_file():
        reasons.append(f"QEMU log missing: {args.qemu_log_name}")
    if not marker_found:
        reasons.append(f"readiness marker missing: {args.readiness_marker}")

    artifact_files: list[dict[str, Any]] = []
    diagnostic_matches: list[dict[str, Any]] = []
    for path in sorted(args.attempt_root.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(args.attempt_root))
        size = path.stat().st_size
        item: dict[str, Any] = {"path": relative, "size": size}
        if size <= MAX_INLINE_HASH_SIZE:
            item["sha256"] = stream_sha256(path)
            item["sha256_evidence"] = "computed"
        else:
            digest = sidecar_sha256(path)
            if digest:
                item["sha256"] = digest
                item["sha256_evidence"] = "sidecar"
            else:
                item["sha256"] = None
                item["sha256_evidence"] = "not-recomputed-large-file"
        artifact_files.append(item)
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        matches = [
            {"line": index + 1, "text": line[:1000]}
            for index, line in enumerate(lines)
            if ERROR_RE.search(line)
        ]
        if matches:
            diagnostic_matches.append(
                {"path": relative, "matches": matches[-120:]}
            )

    run_url = None
    if args.server_url and args.repository and args.run_id:
        run_url = (
            f"{args.server_url.rstrip('/')}/{args.repository}/actions/runs/{args.run_id}"
        )
    result = {
        "schema": args.schema,
        "generated_at": now(),
        "status": "failed" if reasons else "passed",
        "reasons": reasons,
        "workflow_run": {
            "workflow_name": args.workflow_name,
            "repository": args.repository,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "head_branch": args.head_branch,
            "head_sha": args.head_sha,
            "url": run_url,
        },
        "assembly_exit_code": args.assembly_exit_code,
        "boot_outcome": args.boot_outcome,
        "readiness_marker": args.readiness_marker,
        "readiness_marker_found": marker_found,
        "build_result": build_result,
        "wrapper_result": wrapper_result,
        "qemu_error_lines": [
            line[:1000] for line in qemu_lines if ERROR_RE.search(line)
        ][-160:],
        "qemu_log_tail": qemu_lines[-240:],
        "diagnostic_matches": diagnostic_matches,
        "artifact_files": artifact_files,
    }
    (args.evidence_dir / "summary.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    if build_path.is_file():
        shutil.copy2(build_path, args.evidence_dir / build_path.name)
    if wrapper_path is not None and wrapper_path.is_file():
        shutil.copy2(wrapper_path, args.evidence_dir / wrapper_path.name)
    for path in sorted(args.attempt_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(args.attempt_root)
        safe_name = "__".join(relative.parts) + ".tail"
        copy_tail(path, args.evidence_dir / safe_name)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if not reasons else 9


if __name__ == "__main__":
    raise SystemExit(main())
