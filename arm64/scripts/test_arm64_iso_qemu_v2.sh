#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$SCRIPT_DIR/test_arm64_iso_qemu.sh"
[ "$#" -eq 2 ] || { echo "usage: $0 ISO OUTPUT_DIR" >&2; exit 64; }
ISO="$1"
OUTPUT_DIR="$2"
mkdir -p "$OUTPUT_DIR"

BOOT_MARKER='HANCOM_GOOROOM_3_3_ARM64_BOOT_OK'
GRAPHICAL_MARKER='HANCOM_GOOROOM_3_3_ARM64_GRAPHICAL_OK'

# Make the base runner wait for the stronger graphical marker. Its serial log
# remains available afterward so the earlier boot marker can be proved too.
HANCOM_GOOROOM_BOOT_MARKER="$GRAPHICAL_MARKER" \
  HANCOM_GOOROOM_QEMU_TIMEOUT="${HANCOM_GOOROOM_QEMU_TIMEOUT:-1800}" \
  "$BASE" "$ISO" "$OUTPUT_DIR"

grep -Fq "$BOOT_MARKER" "$OUTPUT_DIR/serial.log"
grep -Fq "$GRAPHICAL_MARKER" "$OUTPUT_DIR/serial.log"

result="$OUTPUT_DIR/qemu-boot-result.json"
temporary="$result.tmp"
jq \
  --arg boot_marker "$BOOT_MARKER" \
  --arg graphical_marker "$GRAPHICAL_MARKER" \
  '. + {
    boot_marker:$boot_marker,
    graphical_marker:$graphical_marker,
    boot_marker_found:true,
    graphical_marker_found:true,
    passed:true
  }' "$result" > "$temporary"
mv "$temporary" "$result"
cat "$result"
