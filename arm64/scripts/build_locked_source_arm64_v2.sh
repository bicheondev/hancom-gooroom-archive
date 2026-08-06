#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_SCRIPT="$SCRIPT_DIR/build_locked_source_arm64.sh"

[ -f "$BASE_SCRIPT" ] || {
  echo "base builder is missing: $BASE_SCRIPT" >&2
  exit 69
}

PATCHED_SCRIPT="$(mktemp)"
trap 'rm -f "$PATCHED_SCRIPT"' EXIT

python3 - "$BASE_SCRIPT" "$PATCHED_SCRIPT" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
text = source.read_text(encoding="utf-8")

old = '''rm -f ./*-build-deps_*.deb
mk-build-deps --build-dep debian/control
DUMMY_PACKAGE="$(find . -maxdepth 1 -type f -name '*-build-deps_*.deb' -print -quit)"
[ -n "$DUMMY_PACKAGE" ]
'''
new = '''rm -f ./*-build-deps*.deb
mk-build-deps --build-dep debian/control
DUMMY_PACKAGE="$(find . -maxdepth 1 -type f -name '*-build-deps*.deb' -print -quit)"
if [ -z "$DUMMY_PACKAGE" ]; then
  echo "mk-build-deps did not produce a dependency metapackage" >&2
  find . -maxdepth 1 -type f -printf '%f\\n' | sort >&2
  exit 21
fi
'''

count = text.count(old)
if count != 1:
    raise SystemExit(
        f"refusing to patch an unexpected builder revision: dependency block count={count}"
    )

destination.write_text(text.replace(old, new), encoding="utf-8")
PY

chmod +x "$PATCHED_SCRIPT"
exec "$PATCHED_SCRIPT" "$@"
