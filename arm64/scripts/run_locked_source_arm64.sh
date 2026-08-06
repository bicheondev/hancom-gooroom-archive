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

# Old Bullseye devscripts/equivs and rootful build containers have three
# compatibility quirks:
#
# 1. The generated package can be named either
#      <source>-build-deps_<version>_<arch>.deb
#    or
#      <source>-build-deps-depends_<version>_<arch>.deb
# 2. Some revisions return a non-zero status after successfully writing the
#    dummy package. Treat that return code as fatal only when no package exists.
# 3. `cp -a` from the privileged container can preserve root ownership and make
#    the mounted output directory unwritable by the host runner. Normalise only
#    the output permissions before the container exits.
#
# Patch only these compatibility points. Exact source/version, commit/tree,
# Debian snapshot, output architecture, and package validation remain unchanged.
python3 - "$BASE_BUILDER" "$PATCHED_BUILDER" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")

old_glob = "-name '*-build-deps_*.deb'"
new_glob = "-name '*-build-deps*.deb'"
if source.count(old_glob) != 1:
    raise SystemExit(
        f"expected exactly one strict build-deps glob, found {source.count(old_glob)}"
    )
source = source.replace(old_glob, new_glob)

old_command = """mk-build-deps --build-dep debian/control
DUMMY_PACKAGE=\"$(find . -maxdepth 1 -type f -name '*-build-deps*.deb' -print -quit)\"
[ -n \"$DUMMY_PACKAGE\" ]
"""
new_command = """set +e
mk-build-deps --build-dep debian/control
MK_BUILD_DEPS_RC=$?
set -e
DUMMY_PACKAGE=\"$(find . -maxdepth 1 -type f -name '*-build-deps*.deb' -print -quit)\"
if [ -z \"$DUMMY_PACKAGE\" ]; then
  echo \"mk-build-deps produced no dependency package (exit $MK_BUILD_DEPS_RC)\" >&2
  exit \"$MK_BUILD_DEPS_RC\"
fi
if [ \"$MK_BUILD_DEPS_RC\" -ne 0 ]; then
  echo \"mk-build-deps returned $MK_BUILD_DEPS_RC after creating $DUMMY_PACKAGE; continuing with explicit APT validation\" >&2
fi
"""
if source.count(old_command) != 1:
    raise SystemExit(
        f"expected exactly one mk-build-deps block, found {source.count(old_command)}"
    )
source = source.replace(old_command, new_command)

old_copy = '''cp -av "$ROOT/build/output/." /out/ || true
exit "$BUILD_RC"
'''
new_copy = '''cp -av "$ROOT/build/output/." /out/ || true
# The rootful container may preserve root ownership on /out itself.  The host
# runner must be able to append the immutable build lock and checksum manifest.
chmod -R a+rwX /out || true
exit "$BUILD_RC"
'''
if source.count(old_copy) != 1:
    raise SystemExit(
        f"expected exactly one chroot output copy block, found {source.count(old_copy)}"
    )
source = source.replace(old_copy, new_copy)

Path(sys.argv[2]).write_text(source, encoding="utf-8")
PY

chmod +x "$PATCHED_BUILDER"
exec "$PATCHED_BUILDER" "$@"
