#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 ROOTFS OUTPUT_ISO OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
ROOTFS="$1"
OUTPUT_ISO="$2"
OUTPUT_DIR="$3"
LABEL="${HANCOM_GOOROOM_ISO_LABEL:-HGOOROOM_3_3_ARM64}"
VOLUME_NAME="${HANCOM_GOOROOM_VOLUME_NAME:-Hancom Gooroom 3.3 ARM64}"

for command in grub-mkstandalone xorriso mksquashfs mkfs.vfat mmd mcopy \
  sha256sum md5sum file jq; do
  command -v "$command" >/dev/null || {
    echo "required command missing: $command" >&2
    exit 69
  }
done
[ -d "$ROOTFS" ]
ROOTFS="$(cd "$ROOTFS" && pwd)"
mkdir -p "$(dirname "$OUTPUT_ISO")" "$OUTPUT_DIR"
OUTPUT_ISO="$(cd "$(dirname "$OUTPUT_ISO")" && pwd)/$(basename "$OUTPUT_ISO")"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
ISO_ROOT="$WORK_DIR/iso-root"
mkdir -p "$ISO_ROOT/live" "$ISO_ROOT/boot/grub" "$ISO_ROOT/.disk"

kernel_name="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' | sort -V | tail -n1)"
initrd_name="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'initrd.img-*' -printf '%f\n' | sort -V | tail -n1)"
test -n "$kernel_name"
test -n "$initrd_name"
cp "$ROOTFS/boot/$kernel_name" "$ISO_ROOT/live/vmlinuz"
cp "$ROOTFS/boot/$initrd_name" "$ISO_ROOT/live/initrd.img"

# Keep the live image independent of the host filesystem. All ownership is
# normalized to root and all SquashFS timestamps are fixed for reproducibility.
mksquashfs "$ROOTFS" "$ISO_ROOT/live/filesystem.squashfs" \
  -noappend -comp xz -b 1M -Xdict-size 100% \
  -all-root -all-time 0 -mkfs-time 0 \
  -processors "$(nproc)"

du -sx --block-size=1 "$ROOTFS" | awk '{print $1}' \
  > "$ISO_ROOT/live/filesystem.size"
python3 - "$ROOTFS/var/lib/dpkg/status" "$ISO_ROOT/live/filesystem.manifest" <<'PY'
import sys
from pathlib import Path
status = Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')
rows = []
stanza = {}
key = None
for line in status.splitlines() + ['']:
    if not line.strip():
        if stanza.get('Status', '').startswith('install ok installed') and stanza.get('Package'):
            rows.append((stanza['Package'], stanza.get('Version', ''), stanza.get('Architecture', '')))
        stanza = {}
        key = None
        continue
    if line[0].isspace():
        if key:
            stanza[key] += '\n' + line[1:]
        continue
    if ':' in line:
        key, value = line.split(':', 1)
        stanza[key] = value.lstrip()
Path(sys.argv[2]).write_text(
    ''.join(f'{package} {version} {architecture}\n' for package, version, architecture in sorted(rows)),
    encoding='utf-8',
)
PY

cat > "$ISO_ROOT/boot/grub/grub.cfg" <<'EOF'
set default=0
set timeout=5
set timeout_style=menu

if loadfont /boot/grub/unicode.pf2; then
  insmod all_video
  insmod gfxterm
  terminal_output gfxterm
fi

menuentry "Hancom Gooroom 3.3 ARM64 Live" --class debian --class gnu-linux {
  linux /live/vmlinuz boot=live components quiet splash locales=ko_KR.UTF-8 keyboard-layouts=kr console=tty0 console=ttyAMA0,115200
  initrd /live/initrd.img
}

menuentry "Hancom Gooroom 3.3 ARM64 Live (safe graphics)" --class debian --class gnu-linux {
  linux /live/vmlinuz boot=live components nomodeset locales=ko_KR.UTF-8 keyboard-layouts=kr console=tty0 console=ttyAMA0,115200
  initrd /live/initrd.img
}

menuentry "Hancom Gooroom 3.3 ARM64 serial diagnostics" --class debian --class gnu-linux {
  linux /live/vmlinuz boot=live components systemd.unit=multi-user.target console=ttyAMA0,115200
  initrd /live/initrd.img
}
EOF

# Reuse GRUB's own font if the package-layer rootfs provides it. It is optional;
# the firmware console still works without a graphical font.
for font in \
  "$ROOTFS/usr/share/grub/unicode.pf2" \
  "$ROOTFS/boot/grub/fonts/unicode.pf2" \
  /usr/share/grub/unicode.pf2; do
  if [ -f "$font" ]; then
    cp "$font" "$ISO_ROOT/boot/grub/unicode.pf2"
    break
  fi
done

cat > "$WORK_DIR/grub-embedded.cfg" <<EOF
search --no-floppy --label --set=root $LABEL
set prefix=(\$root)/boot/grub
configfile /boot/grub/grub.cfg
EOF

grub-mkstandalone \
  -O arm64-efi \
  --modules='part_gpt part_msdos fat iso9660 normal linux configfile search search_fs_file search_fs_uuid search_label all_video gfxterm font echo test regexp' \
  --locales='' \
  --themes='' \
  -o "$WORK_DIR/BOOTAA64.EFI" \
  "boot/grub/grub.cfg=$WORK_DIR/grub-embedded.cfg"

file "$WORK_DIR/BOOTAA64.EFI" | tee "$OUTPUT_DIR/bootaa64-file.txt"
if ! grep -Eqi 'aarch64|arm64|application.*efi' "$OUTPUT_DIR/bootaa64-file.txt"; then
  echo 'BOOTAA64.EFI was not identified as ARM64 EFI' >&2
  exit 3
fi

truncate -s 32M "$ISO_ROOT/boot/grub/efi.img"
mkfs.vfat -F 16 -n HGOOROOMEFI "$ISO_ROOT/boot/grub/efi.img"
mmd -i "$ISO_ROOT/boot/grub/efi.img" ::/EFI ::/EFI/BOOT
mcopy -i "$ISO_ROOT/boot/grub/efi.img" \
  "$WORK_DIR/BOOTAA64.EFI" ::/EFI/BOOT/BOOTAA64.EFI
mdir -i "$ISO_ROOT/boot/grub/efi.img" ::/EFI/BOOT \
  | tee "$OUTPUT_DIR/efi-image-directory.txt"

printf '%s\n' "$VOLUME_NAME" > "$ISO_ROOT/.disk/info"
printf 'full_cd/single\n' > "$ISO_ROOT/.disk/base_installable"
printf 'Hancom Gooroom 3.3 ARM64 live image\n' > "$ISO_ROOT/README.diskdefines"

(
  cd "$ISO_ROOT"
  find . -type f ! -name md5sum.txt -print0 \
    | sort -z \
    | xargs -0 md5sum \
    > md5sum.txt
)

xorriso -as mkisofs \
  -r -J -joliet-long \
  -V "$LABEL" \
  -o "$OUTPUT_ISO" \
  -e boot/grub/efi.img \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  "$ISO_ROOT" \
  2>&1 | tee "$OUTPUT_DIR/xorriso-build.log"

xorriso -indev "$OUTPUT_ISO" -report_el_torito plain \
  > "$OUTPUT_DIR/el-torito.txt" 2>&1
xorriso -indev "$OUTPUT_ISO" -report_system_area plain \
  > "$OUTPUT_DIR/system-area.txt" 2>&1
xorriso -osirrox on -indev "$OUTPUT_ISO" \
  -extract /boot/grub/efi.img "$WORK_DIR/extracted-efi.img" \
  > "$OUTPUT_DIR/extract-efi.log" 2>&1
cmp "$ISO_ROOT/boot/grub/efi.img" "$WORK_DIR/extracted-efi.img"

sha256sum "$OUTPUT_ISO" > "$OUTPUT_DIR/iso.sha256"
stat -c '%n\t%s' "$OUTPUT_ISO" > "$OUTPUT_DIR/iso-size.tsv"
sha256sum \
  "$ISO_ROOT/live/vmlinuz" \
  "$ISO_ROOT/live/initrd.img" \
  "$ISO_ROOT/live/filesystem.squashfs" \
  "$ISO_ROOT/boot/grub/efi.img" \
  > "$OUTPUT_DIR/iso-component.sha256"

cat > "$OUTPUT_DIR/iso-build.json" <<EOF
{
  "schema": 1,
  "architecture": "arm64",
  "volume_label": $(jq -Rn --arg v "$LABEL" '$v'),
  "volume_name": $(jq -Rn --arg v "$VOLUME_NAME" '$v'),
  "kernel_source_name": $(jq -Rn --arg v "$kernel_name" '$v'),
  "initrd_source_name": $(jq -Rn --arg v "$initrd_name" '$v'),
  "efi_default_path": "EFI/BOOT/BOOTAA64.EFI",
  "iso_filename": $(jq -Rn --arg v "$(basename "$OUTPUT_ISO")" '$v'),
  "iso_size": $(stat -c '%s' "$OUTPUT_ISO"),
  "iso_sha256": $(sha256sum "$OUTPUT_ISO" | awk '{print "\""$1"\""}')
}
EOF
cat "$OUTPUT_DIR/iso-build.json"
