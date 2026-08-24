#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 REFERENCE_JSON VENDOR_LOCK_JSON VENDOR_DEB_DIR OUTPUT_DIR" >&2
  exit 64
}
[ "$#" -eq 4 ] || usage

REFERENCE_JSON="$(readlink -f "$1")"
VENDOR_LOCK_JSON="$(readlink -f "$2")"
VENDOR_DEB_DIR="$(readlink -f "$3")"
OUTPUT_DIR="$4"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
ISO_NAME="${HANCOM_GOOROOM_STAGE0_ISO_NAME:-Hancom-Gooroom-3.3-arm64-stage0-minimal.iso}"

[ "${EUID:-$(id -u)}" -eq 0 ] || {
  echo "minimal stage-0 assembly must run as root" >&2
  exit 77
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "minimal stage-0 assembly requires a native ARM64 host" >&2; exit 77 ;;
esac
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || exit 64
for command in debootstrap jq dpkg-deb sha256sum mksquashfs xorriso \
  grub-mkstandalone mkfs.vfat mmd mcopy file rsync; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(readlink -f "$OUTPUT_DIR")"
WORK="$(mktemp -d)"
ROOTFS="$WORK/rootfs"
ISO_ROOT="$WORK/iso"
OVERLAY="$WORK/overlay"
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

mkdir -p "$ROOTFS" "$ISO_ROOT/live" "$ISO_ROOT/boot/grub" "$OVERLAY"

REFERENCE_SHA="$(jq -r '.reference_iso.sha256' "$REFERENCE_JSON")"
REFERENCE_COUNT="$(jq -r '.package_count' "$REFERENCE_JSON")"
VERIFIED_COUNT="$(jq -r '.summary.verified_count' "$VENDOR_LOCK_JSON")"
UNRESOLVED_COUNT="$(jq -r '.summary.unresolved_count' "$VENDOR_LOCK_JSON")"
[ "$REFERENCE_SHA" = ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a ]
[ "$REFERENCE_COUNT" = 1279 ]
[ "$VERIFIED_COUNT" = 123 ]
[ "$UNRESOLVED_COUNT" = 0 ]

ESSENTIAL_OVERLAYS=(
  gooroom-artwork-common
  gooroom-artwork-gnome-flashback
  gooroom-bootsplash-theme
  gooroom-icon-themes
  gooroom-info
  gooroom-translations
  hancom-gooroom-themepack
)
printf 'package\tversion\tarchitecture\tsha256\tfilename\n' \
  > "$OUTPUT_DIR/stage0-minimal-exact-overlays.tsv"
for package in "${ESSENTIAL_OVERLAYS[@]}"; do
  reference="$(jq -c --arg p "$package" '
    .packages[] | select(.package == $p and .architecture == "all")
  ' "$REFERENCE_JSON" | head -n1)"
  locked="$(jq -c --arg p "$package" '
    .packages[] | select(.package == $p and .architecture == "all" and .status == "verified")
  ' "$VENDOR_LOCK_JSON" | head -n1)"
  [ -n "$reference" ] || { echo "exact reference overlay missing: $package" >&2; exit 2; }
  [ -n "$locked" ] || { echo "verified exact overlay missing: $package" >&2; exit 2; }
  version="$(jq -r '.version' <<<"$reference")"
  [ "$(jq -r '.version' <<<"$locked")" = "$version" ]
  filename="$(jq -r '.local_filename' <<<"$locked")"
  expected_sha="$(jq -r '.actual_sha256' <<<"$locked")"
  deb="$VENDOR_DEB_DIR/$filename"
  [ -f "$deb" ]
  printf '%s  %s\n' "$expected_sha" "$deb" | sha256sum --check --strict
  [ "$(dpkg-deb -f "$deb" Package)" = "$package" ]
  [ "$(dpkg-deb -f "$deb" Version)" = "$version" ]
  [ "$(dpkg-deb -f "$deb" Architecture)" = all ]
  package_root="$WORK/package-$package"
  mkdir -p "$package_root"
  dpkg-deb -x "$deb" "$package_root"
  if find "$package_root" -type f -print0 | xargs -0 -r file | grep -E 'ELF|PE32|Mach-O'; then
    echo "machine-code payload found in essential Architecture: all overlay: $package" >&2
    exit 2
  fi
  rsync -aHAX "$package_root/" "$OVERLAY/"
  printf '%s\t%s\tall\t%s\t%s\n' \
    "$package" "$version" "$expected_sha" "$filename" \
    >> "$OUTPUT_DIR/stage0-minimal-exact-overlays.tsv"
done

DEBIAN_KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
[ -f "$DEBIAN_KEYRING" ]
BOOTSTRAP_LOG="$OUTPUT_DIR/stage0-minimal-debootstrap.log"
deBootstrapMirror="https://snapshot.debian.org/archive/debian/${SNAPSHOT}/"
if ! debootstrap \
  --arch=arm64 \
  --variant=minbase \
  --keyring="$DEBIAN_KEYRING" \
  --include=ca-certificates,debian-archive-keyring \
  bullseye "$ROOTFS" "$deBootstrapMirror" \
  >"$BOOTSTRAP_LOG" 2>&1; then
  cat "$BOOTSTRAP_LOG" >&2
  exit 20
fi

cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
cat > "$ROOTFS/etc/apt/apt.conf.d/99snapshot" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
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

cat > "$ROOTFS/root/install-minimal-stage0.sh" <<'CHROOT'
#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
apt-get update
apt-get install -y --no-install-recommends \
  busybox ca-certificates console-setup dbus initramfs-tools iproute2 \
  iputils-ping kmod less linux-image-arm64 live-boot live-config locales \
  network-manager plymouth sudo systemd-sysv systemd-timesyncd udev
sed -i '/^# *ko_KR.UTF-8 UTF-8/s/^# *//' /etc/locale.gen
sed -i '/^# *en_US.UTF-8 UTF-8/s/^# *//' /etc/locale.gen
locale-gen
update-locale LANG=ko_KR.UTF-8 LANGUAGE=ko_KR:ko:en_US:en
CHROOT
chmod +x "$ROOTFS/root/install-minimal-stage0.sh"
chroot "$ROOTFS" /bin/bash /root/install-minimal-stage0.sh \
  > >(tee "$OUTPUT_DIR/stage0-minimal-install.log") \
  2> >(tee "$OUTPUT_DIR/stage0-minimal-install.stderr.log" >&2)

rsync -aHAX "$OVERLAY/" "$ROOTFS/"
cat > "$ROOTFS/etc/os-release" <<'EOF'
PRETTY_NAME="Hancom Gooroom 3.3 ARM64 Stage 0 Minimal"
NAME="Hancom Gooroom"
VERSION_ID="3.3-stage0-minimal"
VERSION="3.3 ARM64 Stage 0 Minimal"
VERSION_CODENAME=bullseye
ID=hancom-gooroom
ID_LIKE=debian
HOME_URL="https://github.com/bicheondev/hancom-gooroom-archive"
EOF
printf 'hancom-gooroom\n' > "$ROOTFS/etc/hostname"
cat > "$ROOTFS/etc/hosts" <<'EOF'
127.0.0.1 localhost
127.0.1.1 hancom-gooroom
::1 localhost ip6-localhost ip6-loopback
EOF

cat > "$ROOTFS/usr/local/sbin/hancom-gooroom-stage0-ready" <<'EOF'
#!/bin/sh
marker=HANCOM_GOOROOM_ARM64_STAGE0_READY
printf '%s\n' "$marker" > /dev/console 2>/dev/null || true
if [ -c /dev/ttyAMA0 ]; then
  printf '%s\n' "$marker" > /dev/ttyAMA0 2>/dev/null || true
fi
logger -t hancom-gooroom-stage0 "$marker" 2>/dev/null || true
exit 0
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/hancom-gooroom-stage0-ready"
cat > "$ROOTFS/etc/systemd/system/hancom-gooroom-stage0-ready.service" <<'EOF'
[Unit]
Description=Emit Hancom Gooroom ARM64 stage-0 readiness marker
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hancom-gooroom-stage0-ready
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
ln -s ../hancom-gooroom-stage0-ready.service \
  "$ROOTFS/etc/systemd/system/multi-user.target.wants/hancom-gooroom-stage0-ready.service"
ln -sf /lib/systemd/system/serial-getty@.service \
  "$ROOTFS/etc/systemd/system/getty.target.wants/serial-getty@ttyAMA0.service"

cat > "$ROOTFS/etc/default/grub.d/99-hancom-gooroom-stage0.cfg" <<'EOF'
GRUB_CMDLINE_LINUX_DEFAULT="console=ttyAMA0,115200n8 console=tty0"
EOF
rm -f "$ROOTFS/etc/machine-id"
touch "$ROOTFS/etc/machine-id"
rm -f "$ROOTFS/var/lib/dbus/machine-id"
chroot "$ROOTFS" update-initramfs -u -k all
chroot "$ROOTFS" apt-get clean
rm -rf "$ROOTFS/var/lib/apt/lists/"* "$ROOTFS/tmp/"* "$ROOTFS/var/tmp/"*
rm -f "$ROOTFS/root/install-minimal-stage0.sh" "$ROOTFS/usr/sbin/policy-rc.d"

KERNEL_PATH="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | sort -V | tail -n1)"
[ -n "$KERNEL_PATH" ]
KERNEL_VERSION="${KERNEL_PATH##*/vmlinuz-}"
INITRD_PATH="$ROOTFS/boot/initrd.img-$KERNEL_VERSION"
[ -f "$INITRD_PATH" ]
printf '%s\n' "$KERNEL_VERSION" > "$OUTPUT_DIR/stage0-minimal-kernel-version.txt"
cp "$KERNEL_PATH" "$ISO_ROOT/live/vmlinuz"
cp "$INITRD_PATH" "$ISO_ROOT/live/initrd.img"

chroot "$ROOTFS" dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | sort > "$OUTPUT_DIR/stage0-minimal-manifest.tsv"

umount -R "$ROOTFS/dev"
umount "$ROOTFS/proc"
umount "$ROOTFS/sys"
umount -R "$ROOTFS/run"
MOUNTED=false

mksquashfs "$ROOTFS" "$ISO_ROOT/live/filesystem.squashfs" \
  -noappend -comp xz -b 1M -processors 2 \
  > "$OUTPUT_DIR/stage0-minimal-mksquashfs.log"
printf '%s' "$(du -sx --block-size=1 "$ROOTFS" | cut -f1)" \
  > "$ISO_ROOT/live/filesystem.size"

cat > "$WORK/grub.cfg" <<'EOF'
set default=0
set timeout=0
terminal_output console
menuentry 'Hancom Gooroom 3.3 ARM64 Stage 0 Minimal' {
  linux /live/vmlinuz boot=live components console=ttyAMA0,115200n8 console=tty0 systemd.unit=multi-user.target
  initrd /live/initrd.img
}
EOF
grub-mkstandalone \
  -O arm64-efi \
  -o "$WORK/BOOTAA64.EFI" \
  --modules="part_gpt part_msdos fat iso9660 normal linux search search_fs_file configfile all_video" \
  "boot/grub/grub.cfg=$WORK/grub.cfg"

EFI_IMAGE="$ISO_ROOT/boot/grub/efi.img"
truncate -s 64M "$EFI_IMAGE"
mkfs.vfat -n HANCOM_ARM64 "$EFI_IMAGE" >/dev/null
mmd -i "$EFI_IMAGE" ::/EFI ::/EFI/BOOT
mcopy -i "$EFI_IMAGE" "$WORK/BOOTAA64.EFI" ::/EFI/BOOT/BOOTAA64.EFI

ISO_PATH="$OUTPUT_DIR/$ISO_NAME"
xorriso -as mkisofs \
  -iso-level 3 \
  -full-iso9660-filenames \
  -volid HANCOM_GOOROOM_ARM64 \
  -eltorito-alt-boot \
  -e boot/grub/efi.img \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  -output "$ISO_PATH" \
  "$ISO_ROOT" \
  > "$OUTPUT_DIR/stage0-minimal-xorriso.log" 2>&1

file "$ISO_PATH" > "$OUTPUT_DIR/stage0-minimal-file.txt"
sha256sum "$ISO_PATH" > "$ISO_PATH.sha256"
stat -c '%s' "$ISO_PATH" > "$ISO_PATH.size"
OVERLAY_COUNT="$(($(wc -l < "$OUTPUT_DIR/stage0-minimal-exact-overlays.tsv") - 1))"
MANIFEST_COUNT="$(wc -l < "$OUTPUT_DIR/stage0-minimal-manifest.tsv")"
jq -n \
  --arg status assembled \
  --arg iso "$ISO_NAME" \
  --arg iso_sha256 "$(sha256sum "$ISO_PATH" | cut -d' ' -f1)" \
  --arg reference_iso_sha256 "$REFERENCE_SHA" \
  --arg snapshot "$SNAPSHOT" \
  --arg kernel_version "$KERNEL_VERSION" \
  --argjson overlay_count "$OVERLAY_COUNT" \
  --argjson manifest_count "$MANIFEST_COUNT" \
  '{
    status: $status,
    stage: "minimal-stage0",
    iso: $iso,
    iso_sha256: $iso_sha256,
    reference_iso_sha256: $reference_iso_sha256,
    debian_snapshot: $snapshot,
    architecture: "arm64",
    firmware: "UEFI",
    kernel_version: $kernel_version,
    exact_architecture_all_overlay_count: $overlay_count,
    installed_package_count: $manifest_count,
    readiness_marker: "HANCOM_GOOROOM_ARM64_STAGE0_READY"
  }' > "$OUTPUT_DIR/stage0-minimal-build-result.json"
