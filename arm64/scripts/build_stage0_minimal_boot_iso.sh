#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 REFERENCE_JSON OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
REFERENCE_JSON="$1"
OUTPUT_DIR="$2"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
ISO_NAME="${HANCOM_GOOROOM_MINIMAL_ISO_NAME:-Hancom-Gooroom-3.3-arm64-minimal-boot.iso}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1690761599}"

[ "${EUID:-$(id -u)}" -eq 0 ] || {
  echo "minimal boot ISO assembly must run as root" >&2
  exit 77
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 host required" >&2; exit 77 ;;
esac
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid snapshot timestamp: $SNAPSHOT" >&2
  exit 64
}
for command in debootstrap jq sha256sum mksquashfs xorriso \
  grub-mkstandalone mkfs.vfat mmd mcopy file; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done

REFERENCE_JSON="$(readlink -f "$REFERENCE_JSON")"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(readlink -f "$OUTPUT_DIR")"
WORK="$(mktemp -d)"
ROOTFS="$WORK/rootfs"
ISO_ROOT="$WORK/iso"
MOUNTED=false

cleanup() {
  set +e
  if [ "$MOUNTED" = true ]; then
    umount -R "$ROOTFS/dev" 2>/dev/null || true
    umount "$ROOTFS/proc" 2>/dev/null || true
    umount "$ROOTFS/sys" 2>/dev/null || true
    umount -R "$ROOTFS/run" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$ROOTFS" "$ISO_ROOT/live" "$ISO_ROOT/boot/grub" "$OUTPUT_DIR"
reference_sha="$(jq -r '.reference_iso.sha256' "$REFERENCE_JSON")"
reference_count="$(jq -r '.package_count' "$REFERENCE_JSON")"
[ "$reference_sha" = ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a ]
[ "$reference_count" = 1279 ]

DEBIAN_KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
[ -f "$DEBIAN_KEYRING" ] || {
  echo "Debian archive keyring missing" >&2
  exit 69
}

bootstrap_log="$OUTPUT_DIR/minimal-debootstrap.log"
if ! debootstrap \
  --arch=arm64 \
  --variant=minbase \
  --keyring="$DEBIAN_KEYRING" \
  --include=ca-certificates,debian-archive-keyring \
  bullseye \
  "$ROOTFS" \
  "https://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
  > "$bootstrap_log" 2>&1; then
  cat "$bootstrap_log" >&2
  exit 20
fi

cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main
EOF
cat > "$ROOTFS/etc/apt/apt.conf.d/99hancom-gooroom-snapshot" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "10";
Acquire::https::Timeout "45";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
cp -L /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
printf '#!/bin/sh\nexit 101\n' > "$ROOTFS/usr/sbin/policy-rc.d"
chmod +x "$ROOTFS/usr/sbin/policy-rc.d"

mount --rbind /dev "$ROOTFS/dev"
mount --make-rslave "$ROOTFS/dev"
mount -t proc proc "$ROOTFS/proc"
mount -t sysfs sysfs "$ROOTFS/sys"
mount --rbind /run "$ROOTFS/run"
mount --make-rslave "$ROOTFS/run"
MOUNTED=true

cat > "$ROOTFS/root/install-minimal-boot.sh" <<'CHROOT'
#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

apt-get update
apt-get install -y --no-install-recommends \
  initramfs-tools live-boot linux-image-arm64 systemd-sysv udev

cat > /etc/os-release <<'EOF'
PRETTY_NAME="Hancom Gooroom 3.3 ARM64 Minimal Boot Proof"
NAME="Hancom Gooroom"
VERSION_ID="3.3-minimal-boot"
VERSION="3.3 ARM64 Minimal Boot Proof"
VERSION_CODENAME=bullseye
ID=hancom-gooroom
ID_LIKE=debian
EOF
printf 'hancom-gooroom-arm64\n' > /etc/hostname
cat > /etc/hosts <<'EOF'
127.0.0.1 localhost
127.0.1.1 hancom-gooroom-arm64
::1 localhost ip6-localhost ip6-loopback
EOF

cat > /usr/local/sbin/hancom-gooroom-arm64-ready <<'EOF'
#!/bin/sh
marker=HANCOM_GOOROOM_ARM64_MINIMAL_READY
printf '%s\n' "$marker" > /dev/console 2>/dev/null || true
printf '%s\n' "$marker" > /dev/ttyAMA0 2>/dev/null || true
printf '%s\n' "$marker"
EOF
chmod 0755 /usr/local/sbin/hancom-gooroom-arm64-ready
cat > /etc/systemd/system/hancom-gooroom-arm64-ready.service <<'EOF'
[Unit]
Description=Emit the Hancom Gooroom ARM64 minimal boot readiness marker
After=local-fs.target systemd-remount-fs.service
Before=getty.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hancom-gooroom-arm64-ready
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl enable hancom-gooroom-arm64-ready.service
systemctl set-default multi-user.target

rm -f /etc/machine-id
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id
rm -f /var/lib/apt/lists/*_Packages /var/lib/apt/lists/*_Translation-*
apt-get clean
update-initramfs -u -k all
CHROOT
chmod +x "$ROOTFS/root/install-minimal-boot.sh"
chroot "$ROOTFS" /bin/bash /root/install-minimal-boot.sh \
  > >(tee "$OUTPUT_DIR/minimal-chroot-install.log") \
  2> >(tee "$OUTPUT_DIR/minimal-chroot-install.stderr.log" >&2)
rm -f "$ROOTFS/root/install-minimal-boot.sh" "$ROOTFS/usr/sbin/policy-rc.d"

kernel="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | sort -V | tail -n1)"
initrd="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'initrd.img-*' | sort -V | tail -n1)"
[ -f "$kernel" ]
[ -f "$initrd" ]
kernel_version="${kernel##*/vmlinuz-}"
file "$kernel" | grep -Eiq 'ARM aarch64|Linux kernel ARM64|ARM64'
cp "$kernel" "$ISO_ROOT/live/vmlinuz"
cp "$initrd" "$ISO_ROOT/live/initrd.img"
printf '%s\n' "$kernel_version" > "$OUTPUT_DIR/minimal-kernel-version.txt"
chroot "$ROOTFS" dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | sort > "$OUTPUT_DIR/minimal-packages.tsv"

# Avoid embedding volatile package caches and logs in the boot proof.
rm -rf "$ROOTFS/var/cache/apt/archives/"*.deb
find "$ROOTFS/var/log" -type f -exec truncate -s 0 '{}' ';'
find "$ROOTFS" -xdev -print0 | xargs -0 touch -h -d "@$SOURCE_DATE_EPOCH"

mksquashfs "$ROOTFS" "$ISO_ROOT/live/filesystem.squashfs" \
  -noappend -comp xz -b 1M -processors "$(nproc)" \
  -all-time "$SOURCE_DATE_EPOCH" -mkfs-time "$SOURCE_DATE_EPOCH" \
  > "$OUTPUT_DIR/minimal-mksquashfs.log"
du -sx --block-size=1 "$ROOTFS" | cut -f1 \
  > "$ISO_ROOT/live/filesystem.size"

cat > "$WORK/grub.cfg" <<'EOF'
set default=0
set timeout=0

menuentry 'Hancom Gooroom 3.3 ARM64 minimal boot proof' {
  linux /live/vmlinuz boot=live components console=ttyAMA0,115200n8 console=tty0 systemd.unit=multi-user.target
  initrd /live/initrd.img
}
EOF
cp "$WORK/grub.cfg" "$ISO_ROOT/boot/grub/grub.cfg"

grub-mkstandalone \
  -O arm64-efi \
  -o "$WORK/BOOTAA64.EFI" \
  --modules='part_gpt part_msdos fat iso9660 normal linux search search_fs_file configfile' \
  "boot/grub/grub.cfg=$WORK/grub.cfg"

ESP="$ISO_ROOT/boot/grub/efi.img"
dd if=/dev/zero of="$ESP" bs=1M count=64 status=none
mkfs.vfat -F 32 -n HANCOMARM64 "$ESP" >/dev/null
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$WORK/BOOTAA64.EFI" ::/EFI/BOOT/BOOTAA64.EFI

xorriso -as mkisofs \
  -iso-level 3 \
  -full-iso9660-filenames \
  -volid HANCOM_GOOROOM_ARM64 \
  -eltorito-alt-boot \
  -e boot/grub/efi.img \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  -output "$OUTPUT_DIR/$ISO_NAME" \
  "$ISO_ROOT" \
  > "$OUTPUT_DIR/minimal-xorriso.log" 2>&1

iso_sha="$(sha256sum "$OUTPUT_DIR/$ISO_NAME" | cut -d' ' -f1)"
iso_size="$(stat -c %s "$OUTPUT_DIR/$ISO_NAME")"
printf '%s  %s\n' "$iso_sha" "$ISO_NAME" \
  > "$OUTPUT_DIR/$ISO_NAME.sha256"
printf '%s\n' "$iso_size" > "$OUTPUT_DIR/$ISO_NAME.size"

jq -n \
  --arg schema hancom-gooroom-arm64-minimal-boot-proof-v1 \
  --arg status built \
  --arg reference_iso_sha256 "$reference_sha" \
  --arg snapshot "$SNAPSHOT" \
  --arg kernel_version "$kernel_version" \
  --arg iso_name "$ISO_NAME" \
  --arg iso_sha256 "$iso_sha" \
  --argjson iso_size "$iso_size" \
  '{
    schema: $schema,
    status: $status,
    scope: "ARM64 UEFI and live-boot chain proof; not the final desktop ISO",
    reference_iso_sha256: $reference_iso_sha256,
    debian_snapshot: $snapshot,
    architecture: "arm64",
    firmware: "UEFI",
    kernel_version: $kernel_version,
    readiness_marker: "HANCOM_GOOROOM_ARM64_MINIMAL_READY",
    iso: {
      filename: $iso_name,
      sha256: $iso_sha256,
      size: $iso_size
    }
  }' > "$OUTPUT_DIR/minimal-boot-result.json"
