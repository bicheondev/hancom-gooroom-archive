#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_SCRIPT="$SCRIPT_DIR/build_recovered_source_archive_arm64.sh"

if [[ ! -f "$SOURCE_SCRIPT" ]]; then
  echo "missing generic source builder: $SOURCE_SCRIPT" >&2
  exit 66
fi

PATCHED_SCRIPT="$(mktemp)"
cleanup() {
  rm -f "$PATCHED_SCRIPT"
}
trap cleanup EXIT

sed \
  -e 's/aarch64|arm64) ;;/x86_64|amd64) ;;/' \
  -e 's/native ARM64 host required/native AMD64 host required/' \
  -e 's/--arch=arm64/--arch=amd64/g' \
  -e 's#linux/arm64#linux/amd64#g' \
  "$SOURCE_SCRIPT" > "$PATCHED_SCRIPT"

if grep -Eq -- 'aarch64\|arm64\)|--arch=arm64|linux/arm64' "$PATCHED_SCRIPT"; then
  echo "failed to derive a strictly native AMD64 builder" >&2
  exit 65
fi

exec bash "$PATCHED_SCRIPT" "$@"
