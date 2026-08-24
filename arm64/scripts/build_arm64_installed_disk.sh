#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 ROOTFS OUTPUT_QCOW2 OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
ROOTFS="$1"
OUTPUT_QCOW2="$2"
OUTPUT_DIR="$3"
DISK_SIZE_GIB="${HANCOM_GOOROOM_INSTALLED_DISK_GIB:-12}"

[ "$(id -u)" -eq 0 ] || {
  echo "root privileges are required" >&2
  exit 77
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 host required" >&2; exit 78 ;;
esac
[[ "$DISK_SIZE_GIB" =~ ^[0-9]+$ ]] || {
  echo "invalid disk size: $DISK_SIZE_GIB" >&2
  exit 64
}
[ "$DISK_SIZE_GIB" -ge 8 ]

for command in sgdisk losetup partprobe mkfs.vfat mkfs.ext4 mount umount \
  rsync blkid chroot qemu-img sha256sum jq; do
  command -v "$command" >/dev/null || {
    echo "required command missing: $command" >&2
    exit 69
  }
done

ROOTFS="$(cd "$ROOTFS" && pwd)"
mkdir -p "$(dirname "$OUTPUT_QCOW2")" "$OUTPUT_DIR"
OUTPUT_QCOW2="$(cd "$(dirname "$OUTPUT_QCOW2")" && pwd)/$(basename "$OUTPUT_QCOW2")"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

WORK_DIR="$(mktemp -d)"
RAW_DISK="$WORK_DIR/installed.raw"
MOUNT_ROOT="$WORK_DIR/root"
LOOP_DEVICE=""
mounted=()
cleanup() {
  set +e
  for target in "${mounted[@]}"; do
    umount -R "$target" 2>/dev/null || umount -l "$target" 2>/dev/null || true
  done
  if [ -n "$LOOP_DEVICE" ]; then
    losetup -d "$LOOP_DEVICE" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

truncate -s "${DISK_SIZE_GIB}G" "$RAW_DISK"
sgdisk --zap-all "$RAW_DISK"
sgdisk \
  --new=1:2048:+512M \
  --typecode=1:EF00 \
  --change-name=1:'EFI System Partition' \
  --new=2:0:0 \
  --typecode=2:8300 \
  --change-name=2:'Hancom Gooroom ARM64 root' \
  "$RAW_DISK"
sgdisk --verify "$RAW_DISK" | tee "$OUTPUT_DIR/sgdisk-verify.txt"
sgdisk --print "$RAW_DISK" | tee "$OUTPUT_DIR/partition-table.txt"

LOOP_DEVICE="$(losetup --find --show --partscan "$RAW_DISK")"
for _ in $(seq 1 30); do
  [ -b "${LOOP_DEVICE}p1" ] && [ -b "${LOOP_DEVICE}p2" ] && break
  partprobe "$LOOP_DEVICE" || true
  sleep 1
done
ESP="${LOOP_DEVICE}p1"
ROOT_PARTITION="${LOOP_DEVICE}p2"
[ -b "$ESP" ]
[ -b "$ROOT_PARTITION" ]

mkfs.vfat -F 32 -n HGOOROOMEFI "$ESP" \
  > "$OUTPUT_DIR/mkfs-vfat.log" 2>&1
mkfs.ext4 -F -L HGOOROOM_ROOT -m 0 "$ROOT_PARTITION" \
  > "$OUTPUT_DIR/mkfs-ext4.log" 2>&1

mkdir -p "$MOUNT_ROOT"
mount "$ROOT_PARTITION" "$MOUNT_ROOT"
mounted=("$MOUNT_ROOT")
mkdir -p "$MOUNT_ROOT/boot/efi"
mount "$ESP" "$MOUNT_ROOT/boot/efi"
mounted=("$MOUNT_ROOT/boot/efi" "${mounted[@]}")

rsync -aHAX --numeric-ids --delete \
  --exclude=/boot/efi/*** \
  "$ROOTFS/" "$MOUNT_ROOT/" \
  2>&1 | tee "$OUTPUT_DIR/rootfs-rsync.log"

ROOT_UUID="$(blkid -s UUID -o value "$ROOT_PARTITION")"
ESP_UUID="$(blkid -s UUID -o value "$ESP")"
[ -n "$ROOT_UUID" ]
[ -n "$ESP_UUID" ]
cat > "$MOUNT_ROOT/etc/fstab" <<EOF
UUID=$ROOT_UUID / ext4 defaults,noatime,errors=remount-ro 0 1
UUID=$ESP_UUID /boot/efi vfat umask=0077 0 1
EOF

mkdir -p \
  "$MOUNT_ROOT/proc" "$MOUNT_ROOT/sys" "$MOUNT_ROOT/dev" "$MOUNT_ROOT/run" \
  "$MOUNT_ROOT/etc/default/grub.d"
cp -L /etc/resolv.conf "$MOUNT_ROOT/etc/resolv.conf"
cat > "$MOUNT_ROOT/etc/default/grub.d/99-hancom-gooroom-arm64-console.cfg" <<'EOF'
GRUB_TIMEOUT=3
GRUB_TIMEOUT_STYLE=menu
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash console=tty0 console=ttyAMA0,115200"
GRUB_CMDLINE_LINUX="console=ttyAMA0,115200"
EOF

mount -t proc proc "$MOUNT_ROOT/proc"
mounted=("$MOUNT_ROOT/proc" "${mounted[@]}")
mount -t sysfs sysfs "$MOUNT_ROOT/sys"
mounted=("$MOUNT_ROOT/sys" "${mounted[@]}")
mount --rbind /dev "$MOUNT_ROOT/dev"
mount --make-rslave "$MOUNT_ROOT/dev"
mounted=("$MOUNT_ROOT/dev" "${mounted[@]}")
mount --rbind /run "$MOUNT_ROOT/run"
mount --make-rslave "$MOUNT_ROOT/run"
mounted=("$MOUNT_ROOT/run" "${mounted[@]}")

cat > "$MOUNT_ROOT/tmp/install-hancom-arm64-bootloader.sh" <<'CHROOT'
#!/bin/bash
set -Eeuo pipefail
export HOME=/root
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive

[ "$(dpkg --print-architecture)" = arm64 ]
for package in grub-efi-arm64-bin grub2-common systemd-sysv initramfs-tools; do
  dpkg-query -W -f='${db:Status-Abbrev}\t${Version}\t${Architecture}\n' "$package"
done
command -v grub-install
command -v update-grub

update-initramfs -u -k all
grub-install \
  --target=arm64-efi \
  --efi-directory=/boot/efi \
  --bootloader-id=HancomGooroom \
  --removable \
  --no-nvram \
  --recheck
update-grub
systemctl enable hancom-gooroom-arm64-boot-marker.service
systemctl set-default graphical.target

test -s /boot/efi/EFI/BOOT/BOOTAA64.EFI
test -s /boot/grub/grub.cfg
file /boot/efi/EFI/BOOT/BOOTAA64.EFI
sha256sum /boot/efi/EFI/BOOT/BOOTAA64.EFI
CHROOT
chmod +x "$MOUNT_ROOT/tmp/install-hancom-arm64-bootloader.sh"

set +e
chroot "$MOUNT_ROOT" /bin/bash /tmp/install-hancom-arm64-bootloader.sh \
  > >(tee "$OUTPUT_DIR/bootloader-install.log") \
  2> >(tee "$OUTPUT_DIR/bootloader-install.stderr.log" >&2)
rc=$?
set -e
rm -f "$MOUNT_ROOT/tmp/install-hancom-arm64-bootloader.sh"
if [ "$rc" -ne 0 ]; then
  exit "$rc"
fi

cp "$MOUNT_ROOT/boot/grub/grub.cfg" "$OUTPUT_DIR/grub.cfg"
cp "$MOUNT_ROOT/etc/fstab" "$OUTPUT_DIR/fstab"
file "$MOUNT_ROOT/boot/efi/EFI/BOOT/BOOTAA64.EFI" \
  > "$OUTPUT_DIR/installed-bootaa64-file.txt"
sha256sum "$MOUNT_ROOT/boot/efi/EFI/BOOT/BOOTAA64.EFI" \
  > "$OUTPUT_DIR/installed-bootaa64.sha256"

sync
cleanup_mounts=("${mounted[@]}")
for target in "${cleanup_mounts[@]}"; do
  umount -R "$target" 2>/dev/null || umount -l "$target" 2>/dev/null || true
done
mounted=()
losetup -d "$LOOP_DEVICE"
LOOP_DEVICE=""

qemu-img convert -p -f raw -O qcow2 -c "$RAW_DISK" "$OUTPUT_QCOW2" \
  2>&1 | tee "$OUTPUT_DIR/qemu-img-convert.log"
qemu-img check "$OUTPUT_QCOW2" | tee "$OUTPUT_DIR/qemu-img-check.txt"
qemu-img info --output=json "$OUTPUT_QCOW2" > "$OUTPUT_DIR/qcow2-info.json"
sha256sum "$OUTPUT_QCOW2" > "$OUTPUT_DIR/installed-disk.sha256"
stat -c '%n\t%s' "$OUTPUT_QCOW2" > "$OUTPUT_DIR/installed-disk-size.tsv"

jq -n \
  --arg architecture arm64 \
  --arg root_uuid "$ROOT_UUID" \
  --arg esp_uuid "$ESP_UUID" \
  --arg disk_filename "$(basename "$OUTPUT_QCOW2")" \
  --arg disk_sha256 "$(sha256sum "$OUTPUT_QCOW2" | awk '{print $1}')" \
  --argjson disk_size "$(stat -c '%s' "$OUTPUT_QCOW2")" \
  --argjson virtual_size_gib "$DISK_SIZE_GIB" \
  '{
    schema: 1,
    architecture: $architecture,
    partition_table: "gpt",
    root_filesystem: "ext4",
    efi_filesystem: "fat32",
    root_uuid: $root_uuid,
    esp_uuid: $esp_uuid,
    removable_efi_path: "EFI/BOOT/BOOTAA64.EFI",
    disk_filename: $disk_filename,
    disk_sha256: $disk_sha256,
    disk_size: $disk_size,
    virtual_size_gib: $virtual_size_gib
  }' > "$OUTPUT_DIR/installed-disk-build.json"
cat "$OUTPUT_DIR/installed-disk-build.json"
