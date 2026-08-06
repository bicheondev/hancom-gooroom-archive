#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 LOCK_JSON SOURCE_NAME OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$SCRIPT_DIR/build_locked_source_arm64.sh"
[ -f "$BASE" ] || {
  echo "base exact-source builder missing: $BASE" >&2
  exit 69
}

TEMP="$(mktemp)"
trap 'rm -f "$TEMP"' EXIT
python3 - "$BASE" "$TEMP" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text(encoding='utf-8')
replacements = {
    'dpkg-checkbuilddeps -B\n': 'dpkg-checkbuilddeps\n',
    'dpkg-buildpackage -us -uc -B -j2\n': 'dpkg-buildpackage -us -uc -b -j2\n',
    '"build_mode": "native-arm64-historical-chroot-binary-arch",':
        '"build_mode": "native-arm64-historical-chroot-all-binaries",',
}
for old, new in replacements.items():
    count = source.count(old)
    if count != 1:
        raise SystemExit(f'refusing unexpected builder revision for {old!r}: count={count}')
    source = source.replace(old, new, 1)
Path(sys.argv[2]).write_text(source, encoding='utf-8')
PY
chmod 0755 "$TEMP"
bash -n "$TEMP"
exec "$TEMP" "$@"
