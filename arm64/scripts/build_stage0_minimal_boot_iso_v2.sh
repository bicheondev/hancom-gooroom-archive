#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_SCRIPT="$SCRIPT_DIR/build_stage0_minimal_boot_iso.sh"
[ -f "$BASE_SCRIPT" ] || {
  echo "minimal boot base builder is missing: $BASE_SCRIPT" >&2
  exit 69
}

PATCHED_SCRIPT="$(mktemp)"
trap 'rm -f "$PATCHED_SCRIPT"' EXIT
python3 - "$BASE_SCRIPT" "$PATCHED_SCRIPT" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
text = source.read_text(encoding='utf-8')
old = '''rm -f "$ROOTFS/root/install-minimal-boot.sh" "$ROOTFS/usr/sbin/policy-rc.d"

kernel="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | sort -V | tail -n1)"
'''
new = '''rm -f "$ROOTFS/root/install-minimal-boot.sh" "$ROOTFS/usr/sbin/policy-rc.d"

# Freeze a real root filesystem, never the host's bind-mounted /dev, /proc,
# /sys, or /run trees.
umount -R "$ROOTFS/dev"
umount "$ROOTFS/proc"
umount "$ROOTFS/sys"
umount -R "$ROOTFS/run"
MOUNTED=false

kernel="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | sort -V | tail -n1)"
'''
if text.count(old) != 1:
    raise SystemExit('refusing to patch an unexpected minimal boot builder revision')
destination.write_text(text.replace(old, new), encoding='utf-8')
PY
chmod +x "$PATCHED_SCRIPT"
exec "$PATCHED_SCRIPT" "$@"
