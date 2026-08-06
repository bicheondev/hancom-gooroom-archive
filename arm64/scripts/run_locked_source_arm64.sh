#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_BUILDER="$SCRIPT_DIR/build_locked_source_arm64.sh"

[ -f "$BASE_BUILDER" ] || {
  echo "base builder not found: $BASE_BUILDER" >&2
  exit 69
}

PATCHED_BUILDER="$(mktemp)"
trap 'rm -f "$PATCHED_BUILDER"' EXIT

# mk-build-deps names its generated binary package either
#   <source>-build-deps_<version>_<arch>.deb
# or
#   <source>-build-deps-depends_<version>_<arch>.deb
# depending on the devscripts/equivs generation. The original strict glob only
# accepted the first form and stopped immediately after a successful dummy
# package build. Patch exactly that compatibility point while preserving the
# locked source, snapshot, commit/tree, and output validation logic unchanged.
python3 - "$BASE_BUILDER" "$PATCHED_BUILDER" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
old = "-name '*-build-deps_*.deb'"
new = "-name '*-build-deps*.deb'"
count = source.count(old)
if count != 1:
    raise SystemExit(f"expected exactly one build-deps glob, found {count}")
Path(sys.argv[2]).write_text(source.replace(old, new), encoding="utf-8")
PY

chmod +x "$PATCHED_BUILDER"
exec "$PATCHED_BUILDER" "$@"
