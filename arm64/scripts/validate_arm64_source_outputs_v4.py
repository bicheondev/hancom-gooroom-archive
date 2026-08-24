#!/usr/bin/env python3
"""Run the v3 exact-output policy with bounded executable-header reads.

The v3 policy is intentionally retained verbatim except for two mechanical
changes: executable inspection reads four bytes instead of loading an entire
payload file, and the emitted evidence schema/file name is versioned as v4.
This keeps the accepted package policy stable while making it safe for large
ARM64 packages such as browsers and Qt libraries.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    base = script_dir / "validate_arm64_source_outputs_v3.py"
    if not base.is_file():
        print(f"base v3 validator is missing: {base}", file=sys.stderr)
        return 69

    text = base.read_text(encoding="utf-8")
    old = '''            try:
                magic = path.read_bytes()[:4]
            except OSError as error:
'''
    new = '''            try:
                with path.open("rb") as stream:
                    magic = stream.read(4)
            except OSError as error:
'''
    if text.count(old) != 1:
        print(
            "refusing to patch an unexpected v3 validator revision: "
            f"header-read block count={text.count(old)}",
            file=sys.stderr,
        )
        return 70
    text = text.replace(old, new)
    schema_old = "hancom-gooroom-arm64-source-output-validation-v3"
    filename_old = "arm64-source-output-validation-v3.json"
    if text.count(schema_old) != 1 or text.count(filename_old) != 1:
        print("unexpected v3 evidence schema/file-name count", file=sys.stderr)
        return 70
    text = text.replace(
        schema_old,
        "hancom-gooroom-arm64-source-output-validation-v4",
    ).replace(
        filename_old,
        "arm64-source-output-validation-v4.json",
    )

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="validate-arm64-v4-",
            suffix=".py",
            delete=False,
        ) as temporary:
            temporary.write(text)
            temporary_path = Path(temporary.name)
        process = subprocess.run(
            [sys.executable, str(temporary_path), *sys.argv[1:]],
            check=False,
        )
        return process.returncode
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
