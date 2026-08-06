#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_WRAPPER="$SCRIPT_DIR/run_locked_source_arm64.sh"

[ -f "$BASE_WRAPPER" ] || {
  echo "base compatibility wrapper not found: $BASE_WRAPPER" >&2
  exit 69
}
command -v python3 >/dev/null || {
  echo "python3 is required" >&2
  exit 69
}

# Keep the patched wrapper beside the checked-in scripts so its BASH_SOURCE
# directory still resolves the exact generic builder and helper paths. The
# immutable component lock itself is never rewritten; its recorded SHA-256
# therefore remains the SHA-256 of the checked-in canonical lock.
PATCHED_WRAPPER="$(mktemp "$SCRIPT_DIR/.run-locked-component-compat.XXXXXX")"
cleanup() {
  rm -f "$PATCHED_WRAPPER"
}
trap cleanup EXIT

python3 - "$BASE_WRAPPER" "$PATCHED_WRAPPER" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
old = '''      and .upstream.snapshot == $snapshot
      and .composition.extract == "upstream.files.orig only"
'''
new = '''      and .upstream.snapshot == $snapshot
      and (
        .composition.extract == "upstream.files.orig only"
        or (
          .composition.extract == "orig-only-strip-one-component"
          and .composition.overlay == "replace debian/ with exact packaging Git tree"
          and .composition.do_not_apply == "Debian debian.tar.xz"
        )
      )
'''
count = source.count(old)
if count != 1:
    raise SystemExit(
        f"expected exactly one legacy source-composition assertion, found {count}"
    )
source = source.replace(old, new)
Path(sys.argv[2]).write_text(source, encoding="utf-8")
PY
chmod +x "$PATCHED_WRAPPER"

set +e
"$PATCHED_WRAPPER" "$@"
rc=$?
set -e
exit "$rc"
