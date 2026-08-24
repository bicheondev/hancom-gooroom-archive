#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_BUILDER="$SCRIPT_DIR/build_stage0_live_iso.sh"
[ -f "$BASE_BUILDER" ] || {
  echo "stage-0 base builder not found: $BASE_BUILDER" >&2
  exit 69
}

PATCHED_BUILDER="$(mktemp)"
trap 'rm -f "$PATCHED_BUILDER"' EXIT

# Keep the checked-in base builder as the exact build specification and apply
# only narrowly asserted compatibility fixes here. Every replacement must match
# exactly once; a changed base script therefore fails instead of silently
# producing a different image.
python3 - "$BASE_BUILDER" "$PATCHED_BUILDER" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")

# arc-icon-theme is not published by the Debian Bullseye snapshot. The exact
# Hancom/Gooroom Architecture: all DEB has already been SHA-256 verified and is
# overlaid immediately after the base desktop installation, so asking APT for a
# second copy is both unnecessary and impossible.
old_package_line = "  arc-icon-theme dconf-cli eog evince file-roller fonts-nanum fonts-noto-cjk \\\n"
new_package_line = "  dconf-cli eog evince file-roller fonts-nanum fonts-noto-cjk \\\n"
if source.count(old_package_line) != 1:
    raise SystemExit(
        f"expected exactly one arc-icon-theme APT line, found {source.count(old_package_line)}"
    )
source = source.replace(old_package_line, new_package_line)

# Avoid shell-dependent word splitting inside parameter expansion when creating
# the live user. This changes no account data; it only expresses the same group
# list with explicit branches.
old_useradd = '''  group_list="$(IFS=,; echo "${supplementary[*]}")"
  useradd -m -u 1000 -s /bin/bash ${group_list:+-G "$group_list"} gooroom
'''
new_useradd = '''  group_list="$(IFS=,; echo "${supplementary[*]}")"
  if [ -n "$group_list" ]; then
    useradd -m -u 1000 -s /bin/bash -G "$group_list" gooroom
  else
    useradd -m -u 1000 -s /bin/bash gooroom
  fi
'''
if source.count(old_useradd) != 1:
    raise SystemExit(
        f"expected exactly one live-user creation block, found {source.count(old_useradd)}"
    )
source = source.replace(old_useradd, new_useradd)

Path(sys.argv[2]).write_text(source, encoding="utf-8")
PY

chmod +x "$PATCHED_BUILDER"
exec "$PATCHED_BUILDER" "$@"
