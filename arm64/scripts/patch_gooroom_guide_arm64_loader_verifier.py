#!/usr/bin/env python3
"""Separate the AArch64 loader from ordinary DT_NEEDED dependencies.

The patch is intentionally one-shot and fails unless the reviewed verifier blob
and source anchors are exact.  The loader is not ignored: it is removed only
from the cross-architecture runtime-library comparison and is then required
separately exactly once, alongside the exact PT_INTERP check.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

TARGET = Path("arm64/scripts/verify_gooroom_guide_arm64.py")
EXPECTED_BLOB = "5965872ba744e9ac3c442c498c341cdd81fdaeba"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new)


def main() -> int:
    payload = TARGET.read_bytes()
    actual = hashlib.sha1(f"blob {len(payload)}\0".encode() + payload).hexdigest()
    if actual != EXPECTED_BLOB:
        raise SystemExit(f"unexpected verifier blob: {actual}")
    text = payload.decode("utf-8")

    text = replace_once(
        text,
        '''            dynamic = dynamic_identity(path)\n            target_dynamic = expected.get("dynamic", {})\n            row = {\n''',
        '''            dynamic = dynamic_identity(path)\n            raw_needed = dynamic["needed"]\n            loader_needed = [\n                name for name in raw_needed if name == AARCH64_LOADER\n            ]\n            runtime_needed = [\n                name for name in raw_needed if name != AARCH64_LOADER\n            ]\n            target_dynamic = expected.get("dynamic", {})\n            row = {\n''',
        "loader/runtime dependency split",
    )

    text = replace_once(
        text,
        '''                "needed": dynamic["needed"],\n                "expected_needed": target_dynamic.get("needed", []),\n''',
        '''                "raw_needed": raw_needed,\n                "loader_needed": loader_needed,\n                "loader_needed_count": len(loader_needed),\n                "loader_needed_verified": loader_needed == [AARCH64_LOADER],\n                "needed": runtime_needed,\n                "expected_needed": target_dynamic.get("needed", []),\n                "needed_identical": runtime_needed\n                == target_dynamic.get("needed", []),\n''',
        "record normalized dependency evidence",
    )

    text = replace_once(
        text,
        '''                and row["interpreter_basename"] == AARCH64_LOADER\n                and row["needed"] == row["expected_needed"]\n                and row["soname"] == row["expected_soname"]\n''',
        '''                and row["interpreter_basename"] == AARCH64_LOADER\n                and row["loader_needed_verified"]\n                and row["needed_identical"]\n                and row["soname"] == row["expected_soname"]\n''',
        "strict loader and normalized dependency policy",
    )

    TARGET.write_text(text, encoding="utf-8")
    print(TARGET)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
