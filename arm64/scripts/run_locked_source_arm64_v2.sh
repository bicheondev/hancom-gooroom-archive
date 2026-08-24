#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 EFFECTIVE_LOCK_JSON SOURCE OUTPUT_DIR" >&2
  exit 64
}
[ "$#" -eq 3 ] || usage

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="$1"
SOURCE="$2"
OUTPUT="$3"
FILTERED_LOCK="$(mktemp)"
trap 'rm -f "$FILTERED_LOCK"' EXIT

python3 "$SCRIPT_DIR/filter_arm64_binary_lock.py" \
  "$LOCK" "$SOURCE" "$FILTERED_LOCK"

"$SCRIPT_DIR/run_locked_source_arm64.sh" \
  "$FILTERED_LOCK" "$SOURCE" "$OUTPUT"

mkdir -p "$OUTPUT"
cp "$FILTERED_LOCK" "$OUTPUT/effective-source-lock.native-arm64.json"
sha256sum "$OUTPUT/effective-source-lock.native-arm64.json" \
  > "$OUTPUT/effective-source-lock.native-arm64.json.sha256"
