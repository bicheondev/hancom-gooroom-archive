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
unmount_old = '''rm -f "$ROOTFS/root/install-minimal-boot.sh" "$ROOTFS/usr/sbin/policy-rc.d"

kernel="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | sort -V | tail -n1)"
'''
unmount_new = '''rm -f "$ROOTFS/root/install-minimal-boot.sh" "$ROOTFS/usr/sbin/policy-rc.d"

# Freeze only the guest rootfs, never the host bind mounts.
umount -R "$ROOTFS/dev"
umount "$ROOTFS/proc"
umount "$ROOTFS/sys"
umount -R "$ROOTFS/run"
MOUNTED=false

kernel="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | sort -V | tail -n1)"
'''
grub_old = '''menuentry 'Hancom Gooroom 3.3 ARM64 minimal boot proof' {
  linux /live/vmlinuz boot=live components console=ttyAMA0,115200n8 console=tty0 systemd.unit=multi-user.target
  initrd /live/initrd.img
}
'''
grub_new = '''menuentry 'Hancom Gooroom 3.3 ARM64 minimal boot proof' {
  insmod iso9660
  insmod search_fs_file
  search --no-floppy --file --set=root /live/filesystem.squashfs
  linux /live/vmlinuz boot=live components console=ttyAMA0,115200n8 console=tty0 systemd.unit=multi-user.target
  initrd /live/initrd.img
}
'''
if text.count(unmount_old) != 1:
    raise SystemExit('unexpected minimal builder revision at unmount insertion')
if text.count(grub_old) != 1:
    raise SystemExit('unexpected minimal builder revision at GRUB menu')
text = text.replace(unmount_old, unmount_new).replace(grub_old, grub_new)
destination.write_text(text, encoding='utf-8')
PY
chmod +x "$PATCHED_SCRIPT"
exec "$PATCHED_SCRIPT" "$@"
