#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 EFFECTIVE_LOCK SOURCE BUILD_DEP_REPOSITORY OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 4 ] || usage
LOCK_JSON="$1"
SOURCE_NAME="$2"
BUILD_DEP_REPOSITORY="$3"
OUTPUT_DIR="$4"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_BUILDER="$SCRIPT_DIR/build_locked_dsc_arm64_v2.sh"

[ -f "$BASE_BUILDER" ] || {
  echo "base DSC builder missing: $BASE_BUILDER" >&2
  exit 69
}
[ -d "$BUILD_DEP_REPOSITORY" ] || {
  echo "build dependency repository missing: $BUILD_DEP_REPOSITORY" >&2
  exit 2
}
[ -f "$BUILD_DEP_REPOSITORY/Packages" ] || {
  echo "build dependency repository has no Packages index" >&2
  exit 2
}
[ -f "$BUILD_DEP_REPOSITORY/Release" ] || {
  echo "build dependency repository has no Release metadata" >&2
  exit 2
}
BUILD_DEP_REPOSITORY="$(cd "$BUILD_DEP_REPOSITORY" && pwd)"

PATCHED="$(mktemp)"
trap 'rm -f "$PATCHED"' EXIT
python3 - "$BASE_BUILDER" "$PATCHED" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
text = source.read_text(encoding="utf-8")

patches = [
    (
        'BOOTSTRAP_IMAGE="${HANCOM_GOOROOM_BOOTSTRAP_IMAGE:-arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"\n',
        'BOOTSTRAP_IMAGE="${HANCOM_GOOROOM_BOOTSTRAP_IMAGE:-arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"\nBUILD_DEP_REPO_ABS="${HANCOM_GOOROOM_BUILD_DEP_REPO:?HANCOM_GOOROOM_BUILD_DEP_REPO is required}"\n[ -f "$BUILD_DEP_REPO_ABS/Packages" ]\n[ -f "$BUILD_DEP_REPO_ABS/Release" ]\n',
        1,
        'outer dependency repository variable',
    ),
    (
        ': "${SNAPSHOT:?}"\nexport DEBIAN_FRONTEND=noninteractive\n',
        ': "${SNAPSHOT:?}"\n[ -f /build-deps/Packages ]\n[ -f /build-deps/Release ]\nexport DEBIAN_FRONTEND=noninteractive\n',
        1,
        'container dependency repository gate',
    ),
    (
        'cat > "$ROOT/etc/apt/sources.list" <<EOF\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free\n',
        'cat > "$ROOT/etc/apt/sources.list" <<EOF\ndeb [trusted=yes] file:/build-deps ./\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free\n',
        1,
        'chroot local APT source',
    ),
    (
        'cleanup() {\n  umount -R "$ROOT/dev" 2>/dev/null || true\n',
        'cleanup() {\n  umount "$ROOT/build-deps" 2>/dev/null || true\n  umount -R "$ROOT/dev" 2>/dev/null || true\n',
        1,
        'dependency repository cleanup',
    ),
    (
        'trap cleanup EXIT\nmount --rbind /dev "$ROOT/dev"; mount --make-rslave "$ROOT/dev"\n',
        'trap cleanup EXIT\nmkdir -p "$ROOT/build-deps"\nmount --bind /build-deps "$ROOT/build-deps"\nmount --rbind /dev "$ROOT/dev"; mount --make-rslave "$ROOT/dev"\n',
        1,
        'dependency repository chroot bind mount',
    ),
    (
        '  --volume "$SOURCE_ROOT:/src:ro" \\\n  --volume "$WORK_DIR/build-inside.sh:/build-inside.sh:ro" \\\n',
        '  --volume "$SOURCE_ROOT:/src:ro" \\\n  --volume "$BUILD_DEP_REPO_ABS:/build-deps:ro" \\\n  --volume "$WORK_DIR/build-inside.sh:/build-inside.sh:ro" \\\n',
        1,
        'Docker dependency repository mount',
    ),
]

for old, new, expected_count, description in patches:
    count = text.count(old)
    if count != expected_count:
        raise SystemExit(
            f"refusing to patch unexpected base builder: {description}: "
            f"found {count}, expected {expected_count}"
        )
    text = text.replace(old, new, expected_count)

destination.write_text(text, encoding="utf-8")
PY
chmod +x "$PATCHED"

export HANCOM_GOOROOM_BUILD_DEP_REPO="$BUILD_DEP_REPOSITORY"
exec "$PATCHED" "$LOCK_JSON" "$SOURCE_NAME" "$OUTPUT_DIR"
