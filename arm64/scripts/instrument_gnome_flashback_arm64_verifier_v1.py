#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


WORKFLOW = Path(
    ".github/workflows/arm64-reconstruct-build-promote-gnome-flashback-han3u4.yml"
)


def block(lines: list[str]) -> str:
    return "\n".join(lines) + "\n"


def main() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    slash = chr(92)

    old_verify = block(
        [
            "          rm -rf work/arm64-verification work/arm64-artifact",
            f"          python3 arm64/scripts/verify_gnome_flashback_han3u4_arm64.py {slash}",
            f"            --target-deb-dir work/target-debs {slash}",
            f"            --candidate-deb-dir work/arm64-build/debs {slash}",
            "            --output-dir work/arm64-verification",
            "          jq -e '",
        ]
    )
    new_verify = block(
        [
            "          rm -rf work/arm64-verification work/arm64-artifact",
            f"          rm -f work/arm64-verifier.stdout work/arm64-verifier.stderr {slash}",
            "            work/arm64-verifier.exit-status",
            "          set +e",
            f"          python3 arm64/scripts/verify_gnome_flashback_han3u4_arm64.py {slash}",
            f"            --target-deb-dir work/target-debs {slash}",
            f"            --candidate-deb-dir work/arm64-build/debs {slash}",
            f"            --output-dir work/arm64-verification {slash}",
            f"            >work/arm64-verifier.stdout {slash}",
            "            2>work/arm64-verifier.stderr",
            "          verifier_status=$?",
            "          set -e",
            "          printf '%s\\n' \"$verifier_status\" > work/arm64-verifier.exit-status",
            "          cat work/arm64-verifier.stdout",
            "          cat work/arm64-verifier.stderr >&2",
            "          test \"$verifier_status\" -eq 0",
            "          jq -e '",
        ]
    )
    count = text.count(old_verify)
    if count != 1:
        raise SystemExit(f"verifier anchor count mismatch: {count}")
    text = text.replace(old_verify, new_verify)

    old_diag = block(
        [
            "            work/arm64-build/build.log",
            "            work/arm64-build/debootstrap.log",
            "            work/arm64-verification",
            "            work/arm64-artifact/verification-summary.json",
        ]
    )
    new_diag = block(
        [
            "            work/arm64-build/build.log",
            "            work/arm64-build/debootstrap.log",
            "            work/arm64-build/debs",
            "            work/arm64-verification",
            "            work/arm64-artifact/verification-summary.json",
            "            work/arm64-verifier.stdout",
            "            work/arm64-verifier.stderr",
            "            work/arm64-verifier.exit-status",
        ]
    )
    count = text.count(old_diag)
    if count != 1:
        raise SystemExit(f"diagnostic anchor count mismatch: {count}")
    text = text.replace(old_diag, new_diag)

    if text.count("work/arm64-verifier.stderr") != 4:
        raise SystemExit("instrumented verifier stderr paths are not exact")
    if text.count("            work/arm64-build/debs\n") != 1:
        raise SystemExit("candidate DEB diagnostic path is not exact")

    WORKFLOW.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
