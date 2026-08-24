#!/usr/bin/env python3
"""Run the exact Hancom Gooroom 3.3 source recovery from a user network.

This entry point intentionally uses the same repository scripts and the same
signed InRelease evidence as GitHub Actions.  It requires only Python 3 and does
not require root, an account, or a GitHub token.  Unresolved attempts are useful
negative evidence and are always retained in the result ZIP.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def run(command: list[str]) -> int:
    print("+", " ".join(command), flush=True)
    process = subprocess.run(command, check=False)
    return process.returncode


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def zip_tree(root: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", allowZip64=True) as archive:
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            suffixes = "".join(path.suffixes).lower()
            compressed = suffixes.endswith(
                (".gz", ".xz", ".bz2", ".zst", ".zip", ".deb")
            )
            archive.write(
                path,
                path.relative_to(root.parent).as_posix(),
                compress_type=(
                    zipfile.ZIP_STORED if compressed else zipfile.ZIP_DEFLATED
                ),
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("work/user-exact-source-recovery"),
    )
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument(
        "--index-only",
        action="store_true",
        help="Recover the signed Sources indices but skip .dsc/tar members.",
    )
    args = parser.parse_args()

    script = Path(__file__).resolve()
    repository = script.parents[2]
    output = (repository / args.output_dir).resolve()
    if output.exists():
        shutil.rmtree(output)
    index_output = output / "source-index-recovery"
    archive_output = output / "source-archive-recovery"
    output.mkdir(parents=True, exist_ok=True)

    gooroom_inrelease = repository / (
        "arm64/locks/reference-iso-source-residue/latest/selected-text/"
        "rootfs___var__lib__apt__lists__update.hancomgooroom.com_"
        "gooroom_dists_gooroom-3.0_InRelease.txt"
    )
    hancom_inrelease = repository / (
        "arm64/locks/reference-iso-source-residue/latest/selected-text/"
        "rootfs___var__lib__apt__lists__update.hancomgooroom.com_"
        "hancom_dists_hancom-3.0_InRelease.txt"
    )
    index_script = repository / "arm64/scripts/recover_locked_apt_source_indices.py"
    archive_script = repository / "arm64/scripts/recover_locked_apt_source_archives.py"

    for required in (
        gooroom_inrelease,
        hancom_inrelease,
        index_script,
        archive_script,
    ):
        if not required.is_file():
            raise SystemExit(f"required repository file is missing: {required}")

    index_rc = run(
        [
            sys.executable,
            str(index_script),
            "--gooroom-inrelease",
            str(gooroom_inrelease),
            "--hancom-inrelease",
            str(hancom_inrelease),
            "--output-dir",
            str(index_output),
            "--timeout",
            str(args.timeout),
        ]
    )
    index_summary = load(index_output / "summary.json")

    archive_rc: int | None = None
    archive_summary: dict[str, Any] = {}
    if not args.index_only:
        archive_rc = run(
            [
                sys.executable,
                str(archive_script),
                "--index-root",
                str(index_output),
                "--output-dir",
                str(archive_output),
                "--timeout",
                str(args.timeout),
            ]
        )
        archive_summary = load(archive_output / "summary.json")

    controller = {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "mode": "index-only" if args.index_only else "full",
        "python": sys.version,
        "index_exit_code": index_rc,
        "archive_exit_code": archive_rc,
        "index_summary": index_summary,
        "archive_summary": archive_summary,
        "accepted_authority": (
            "byte-identical Sources index locked by reference ISO InRelease; "
            "source members locked by exact Sources stanza SHA-256"
        ),
    }
    (output / "controller-summary.json").write_text(
        json.dumps(controller, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    lock_rows = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "LOCKSUMS.sha256":
            lock_rows.append(
                f"{sha256(path)}  {path.relative_to(output).as_posix()}"
            )
    (output / "LOCKSUMS.sha256").write_text(
        "\n".join(lock_rows) + "\n", encoding="utf-8"
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result_zip = repository / (
        f"Hancom-Gooroom-3.3-exact-source-recovery-{timestamp}.zip"
    )
    zip_tree(output, result_zip)
    result_sha256 = sha256(result_zip)
    result_zip.with_suffix(result_zip.suffix + ".sha256").write_text(
        f"{result_sha256}  {result_zip.name}\n", encoding="utf-8"
    )

    print()
    print(f"Result ZIP: {result_zip}")
    print(f"SHA-256:    {result_sha256}")
    print("Upload the ZIP to the ChatGPT conversation even when recovery is incomplete.")

    if args.index_only:
        return 0 if int(index_summary.get("resolved_index_count", 0)) > 0 else 2
    return 0 if bool(archive_summary.get("source_build_ready")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
