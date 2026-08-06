#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_BUILDER="$SCRIPT_DIR/build_locked_source_arm64.sh"

[ "$#" -eq 3 ] || {
  echo "usage: $0 LOCK_JSON p7zip OUTPUT_DIR" >&2
  exit 64
}
[ "$2" = p7zip ] || {
  echo "this exact build-mode adapter is restricted to source p7zip" >&2
  exit 64
}
[ -f "$BASE_BUILDER" ] || {
  echo "base exact-source builder is missing: $BASE_BUILDER" >&2
  exit 69
}

PATCHED_BUILDER="$(mktemp)"
trap 'rm -f "$PATCHED_BUILDER"' EXIT

python3 - "$BASE_BUILDER" "$PATCHED_BUILDER" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
text = source.read_text(encoding="utf-8")

replacements = {
    'export DEB_BUILD_OPTIONS="nocheck nodoc parallel=2"':
        'export DEB_BUILD_OPTIONS="nocheck parallel=2"',
    'export DEB_BUILD_PROFILES="pkg.nocheck nodoc"':
        'export DEB_BUILD_PROFILES="pkg.nocheck"',
    'dpkg-checkbuilddeps -B':
        'dpkg-checkbuilddeps',
    'dpkg-buildpackage -us -uc -B -j2':
        'dpkg-buildpackage -us -uc -b -j2',
    '"build_mode": "native-arm64-historical-chroot-binary-arch"':
        '"build_mode": "native-arm64-historical-chroot-full-binary-with-docs"',
}

for old, new in replacements.items():
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"refusing to adapt an unexpected base builder: {old!r} count={count}"
        )
    text = text.replace(old, new, 1)

destination.write_text(text, encoding="utf-8")
PY

chmod 0755 "$PATCHED_BUILDER"
exec "$PATCHED_BUILDER" "$@"
