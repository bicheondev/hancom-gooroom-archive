#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 LOCK_JSON SOURCE_NAME OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
LOCK_JSON="$1"
SOURCE_NAME="$2"
OUTPUT_DIR="$3"

command -v jq >/dev/null || {
  echo 'jq is required' >&2
  exit 69
}

selected_type="$(jq -r --arg source "$SOURCE_NAME" '
  first(
    .sources[]
    | select(.source == $source and .status == "resolved" and .selected != null)
    | .selected.type // "git"
  ) // empty
' "$LOCK_JSON")"

case "$selected_type" in
  git)
    exec bash arm64/scripts/build_locked_source_arm64_v2.sh \
      "$LOCK_JSON" "$SOURCE_NAME" "$OUTPUT_DIR"
    ;;
  dsc)
    exec bash arm64/scripts/build_locked_dsc_source_arm64_v2.sh \
      "$LOCK_JSON" "$SOURCE_NAME" "$OUTPUT_DIR"
    ;;
  '')
    echo "No resolved exact source authority for $SOURCE_NAME" >&2
    exit 2
    ;;
  *)
    echo "Unsupported exact source authority type for $SOURCE_NAME: $selected_type" >&2
    exit 2
    ;;
esac
