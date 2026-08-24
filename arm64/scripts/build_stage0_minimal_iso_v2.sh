#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 REFERENCE_JSON VENDOR_LOCK_JSON VENDOR_DEB_DIR OUTPUT_DIR" >&2
  exit 64
}
[ "$#" -eq 4 ] || usage

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$SCRIPT_DIR/build_stage0_minimal_iso.sh"
OUTPUT_DIR="$4"
PATCHED="$(mktemp)"
trap 'rm -f "$PATCHED"' EXIT

python3 - "$BASE" "$PATCHED" <<'PY'
from pathlib import Path
import sys

base = Path(sys.argv[1])
patched = Path(sys.argv[2])
text = base.read_text(encoding="utf-8")

replacements = {
    "After=multi-user.target\n": "After=basic.target\n",
    'mmd -i "$EFI_IMAGE" ::/EFI ::/EFI/BOOT\n': (
        'mmd -i "$EFI_IMAGE" ::/EFI\n'
        'mmd -i "$EFI_IMAGE" ::/EFI/BOOT\n'
    ),
}
for old, new in replacements.items():
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"refusing to patch an unexpected minimal-stage0 builder: {old!r} count={count}"
        )
    text = text.replace(old, new)
patched.write_text(text, encoding="utf-8")
PY
chmod +x "$PATCHED"

"$PATCHED" "$@"

mkdir -p "$OUTPUT_DIR"
python3 - "$BASE" "$PATCHED" "$OUTPUT_DIR/stage0-minimal-wrapper-policy.json" <<'PY'
from pathlib import Path
import hashlib
import json
import sys

base = Path(sys.argv[1]).read_bytes()
patched = Path(sys.argv[2]).read_bytes()
out = Path(sys.argv[3])
out.write_text(
    json.dumps(
        {
            "status": "applied",
            "base_builder_sha256": hashlib.sha256(base).hexdigest(),
            "executed_builder_sha256": hashlib.sha256(patched).hexdigest(),
            "changes": [
                "remove the systemd multi-user target ordering cycle",
                "create nested EFI directories with deterministic mtools calls",
            ],
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY
