#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 APT_SOURCE_LOCK_JSON SOURCE OUTPUT_DIR" >&2
  exit 64
}
[ "$#" -eq 3 ] || usage

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$SCRIPT_DIR/build_locked_apt_source_arm64.sh"
OUTPUT="$3"
PATCHED="$(mktemp)"
trap 'rm -f "$PATCHED"' EXIT

python3 - "$BASE" "$PATCHED" "$SCRIPT_DIR" <<'PY'
from pathlib import Path
import sys

base = Path(sys.argv[1])
patched = Path(sys.argv[2])
script_dir = sys.argv[3]
text = base.read_text(encoding="utf-8")
replacements = {
    'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n': (
        f'SCRIPT_DIR={script_dir!r}\n'
    ),
    'mkdir -p /build/source\nDSC="$(find /build/input': (
        'rm -rf /build/source\nDSC="$(find /build/input'
    ),
    'dpkg-buildpackage --build=any --unsigned-source --unsigned-changes\n': (
        'dpkg-buildpackage -B -us -uc\n'
    ),
}
for old, new in replacements.items():
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"refusing to patch an unexpected APT source builder: {old!r} count={count}"
        )
    text = text.replace(old, new)
patched.write_text(text, encoding="utf-8")
PY
chmod +x "$PATCHED"

"$PATCHED" "$@"

OUTPUT="$(readlink -f "$OUTPUT")"
find "$OUTPUT" -maxdepth 1 -type f \
  ! -name SHA256SUMS \
  ! -name apt-builder-wrapper-policy.json \
  -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > "$OUTPUT/SHA256SUMS"
sha256sum --check "$OUTPUT/SHA256SUMS"

python3 - "$BASE" "$PATCHED" "$OUTPUT/apt-builder-wrapper-policy.json" <<'PY'
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
                "leave the dpkg-source extraction target absent before extraction",
                "use the Bullseye-compatible dpkg-buildpackage -B -us -uc form",
                "recompute SHA256SUMS after build-result.json exists",
            ],
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY
sha256sum "$OUTPUT/apt-builder-wrapper-policy.json" \
  >> "$OUTPUT/SHA256SUMS"
