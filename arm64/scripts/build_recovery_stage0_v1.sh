#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 REFERENCE_AMD64_ISO OUTPUT_ISO EVIDENCE_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
REFERENCE_ISO="$1"
OUTPUT_ISO="$2"
EVIDENCE_DIR="$3"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
ISO_LABEL="${HANCOM_GOOROOM_STAGE0_LABEL:-HGOOROOM_33_ARM64}"
BOOT_MARKER="HANCOM_GOOROOM_3_3_ARM64_STAGE0_BOOT_OK"
GRAPHICAL_MARKER="HANCOM_GOOROOM_3_3_ARM64_STAGE0_GRAPHICAL_OK"

[ "$(id -u)" -eq 0 ] || {
  echo "root privileges are required" >&2
  exit 77
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 runner required, got $(uname -m)" >&2; exit 78 ;;
esac
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid Debian snapshot timestamp: $SNAPSHOT" >&2
  exit 64
}
[ -f "$REFERENCE_ISO" ]

for command in \
  debootstrap chroot mount umount rsync xorriso unsquashfs mksquashfs \
  grub-mkstandalone mkfs.vfat mmd mcopy qemu-system-aarch64 file jq \
  sha256sum gzip python3; do
  command -v "$command" >/dev/null || {
    echo "required command missing: $command" >&2
    exit 69
  }
done

REFERENCE_ISO="$(cd "$(dirname "$REFERENCE_ISO")" && pwd)/$(basename "$REFERENCE_ISO")"
mkdir -p "$(dirname "$OUTPUT_ISO")" "$EVIDENCE_DIR"
OUTPUT_ISO="$(cd "$(dirname "$OUTPUT_ISO")" && pwd)/$(basename "$OUTPUT_ISO")"
EVIDENCE_DIR="$(cd "$EVIDENCE_DIR" && pwd)"
WORK_DIR="$(mktemp -d)"
ROOTFS="$WORK_DIR/rootfs"
ISO_ROOT="$WORK_DIR/iso-root"
BRAND_ROOT="$WORK_DIR/reference-brand"
mkdir -p "$ROOTFS" "$ISO_ROOT/live" "$ISO_ROOT/boot/grub" "$ISO_ROOT/.disk" "$BRAND_ROOT"

mounted=()
cleanup() {
  set +e
  for target in "${mounted[@]}"; do
    umount -R "$target" 2>/dev/null || umount -l "$target" 2>/dev/null || true
  done
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

printf '%s\n' "$SNAPSHOT" > "$EVIDENCE_DIR/debian-snapshot.txt"
sha256sum "$REFERENCE_ISO" > "$EVIDENCE_DIR/reference-iso.sha256"

# Build a dated, native ARM64 base. The historical snapshot is immutable and
# is recorded in the evidence directory; no current Debian package is allowed
# to leak into this recovery image.
debootstrap \
  --arch=arm64 \
  --variant=minbase \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  --include=ca-certificates,debian-archive-keyring \
  bullseye \
  "$ROOTFS" \
  "http://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
  2>&1 | tee "$EVIDENCE_DIR/debootstrap.log"

cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
cat > "$ROOTFS/etc/apt/apt.conf.d/99snapshot" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
cp -L /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
mkdir -p "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" "$ROOTFS/run"
mount -t proc proc "$ROOTFS/proc"
mounted=("$ROOTFS/proc")
mount -t sysfs sysfs "$ROOTFS/sys"
mounted=("$ROOTFS/sys" "${mounted[@]}")
mount --rbind /dev "$ROOTFS/dev"
mount --make-rslave "$ROOTFS/dev"
mounted=("$ROOTFS/dev" "${mounted[@]}")
mount --rbind /run "$ROOTFS/run"
mount --make-rslave "$ROOTFS/run"
mounted=("$ROOTFS/run" "${mounted[@]}")

cat > "$ROOTFS/tmp/install-stage0.sh" <<'CHROOT'
#!/bin/bash
set -Eeuo pipefail
export HOME=/root
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d
apt-get update

required=(
  systemd-sysv initramfs-tools linux-image-arm64
  live-boot live-config
  locales sudo dbus-x11 policykit-1
  xserver-xorg xserver-xorg-video-all xserver-xorg-input-all
  lightdm lightdm-gtk-greeter
  gnome-session gnome-shell gnome-session-flashback gnome-panel metacity
  gnome-terminal nautilus network-manager network-manager-gnome
  console-setup keyboard-configuration
  fonts-noto-cjk fonts-noto-color-emoji
  plymouth ca-certificates curl wget file
)
optional=(
  live-config-systemd gnome-control-center gnome-settings-daemon
  gnome-tweaks eog evince file-roller gedit gnome-screenshot
  pulseaudio pavucontrol alsa-utils
)
install=("${required[@]}")
for package in "${optional[@]}"; do
  if apt-cache show "$package" >/dev/null 2>&1; then
    install+=("$package")
  fi
done
apt-get install -y --no-install-recommends "${install[@]}"

sed -i 's/^# *ko_KR.UTF-8 UTF-8/ko_KR.UTF-8 UTF-8/' /etc/locale.gen || true
sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen || true
locale-gen
update-locale LANG=ko_KR.UTF-8

groupadd -f netdev
id -u gooroom >/dev/null 2>&1 || useradd -m -s /bin/bash gooroom
usermod -aG sudo,audio,video,plugdev,netdev gooroom
passwd -d gooroom
cat > /etc/sudoers.d/90-gooroom-live <<'EOF'
gooroom ALL=(ALL) NOPASSWD: ALL
EOF
chmod 0440 /etc/sudoers.d/90-gooroom-live

mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-hancom-gooroom-live.conf <<'EOF'
[Seat:*]
autologin-user=gooroom
autologin-user-timeout=0
user-session=gnome-flashback-metacity
greeter-session=lightdm-gtk-greeter
EOF

cat > /etc/default/locale <<'EOF'
LANG=ko_KR.UTF-8
LANGUAGE=ko_KR:ko:en_US:en
LC_ALL=ko_KR.UTF-8
EOF
cat > /etc/hostname <<'EOF'
hancom-gooroom
EOF
cat > /etc/hosts <<'EOF'
127.0.0.1 localhost
127.0.1.1 hancom-gooroom
::1 localhost ip6-localhost ip6-loopback
EOF

mkdir -p /etc/live/config.conf.d
cat > /etc/live/config.conf.d/99-hancom-gooroom-arm64.conf <<'EOF'
LIVE_HOSTNAME="hancom-gooroom"
LIVE_USERNAME="gooroom"
LIVE_USER_FULLNAME="Hancom Gooroom Live User"
LIVE_LOCALES="ko_KR.UTF-8"
LIVE_KEYBOARD_LAYOUTS="kr"
EOF

cat > /etc/os-release <<'EOF'
PRETTY_NAME="Hancom Gooroom 3.3 ARM64 Stage-0"
NAME="Hancom Gooroom"
VERSION_ID="3.3-stage0"
VERSION="3.3 ARM64 Stage-0"
ID=hancom-gooroom-arm64
ID_LIKE=debian
HOME_URL="https://github.com/bicheondev/hancom-gooroom-archive"
EOF
ln -sfn ../etc/os-release /usr/lib/os-release

cat > /usr/local/sbin/hancom-gooroom-stage0-marker <<'EOF'
#!/bin/sh
boot='HANCOM_GOOROOM_3_3_ARM64_STAGE0_BOOT_OK'
graphical='HANCOM_GOOROOM_3_3_ARM64_STAGE0_GRAPHICAL_OK'
printf '%s\n' "$boot" >/dev/console 2>/dev/null || true
printf '%s\n' "$boot" >/dev/ttyAMA0 2>/dev/null || true
if systemctl is-active --quiet lightdm.service; then
  printf '%s\n' "$graphical" >/dev/console 2>/dev/null || true
  printf '%s\n' "$graphical" >/dev/ttyAMA0 2>/dev/null || true
fi
logger -t hancom-gooroom-arm64 "$boot" 2>/dev/null || true
exit 0
EOF
chmod 0755 /usr/local/sbin/hancom-gooroom-stage0-marker
cat > /etc/systemd/system/hancom-gooroom-stage0-marker.service <<'EOF'
[Unit]
Description=Hancom Gooroom ARM64 stage-0 boot marker
After=multi-user.target lightdm.service
Wants=lightdm.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hancom-gooroom-stage0-marker
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target graphical.target
EOF
systemctl enable NetworkManager.service || true
systemctl enable lightdm.service || true
systemctl enable hancom-gooroom-stage0-marker.service
systemctl set-default graphical.target

if command -v glib-compile-schemas >/dev/null; then
  glib-compile-schemas /usr/share/glib-2.0/schemas || true
fi
if command -v update-mime-database >/dev/null; then
  update-mime-database /usr/share/mime || true
fi
if command -v update-desktop-database >/dev/null; then
  update-desktop-database /usr/share/applications || true
fi
if command -v fc-cache >/dev/null; then
  fc-cache -f || true
fi
ldconfig
update-initramfs -u -k all

dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  | sort > /tmp/stage0-installed-packages.tsv
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
rm -f /usr/sbin/policy-rc.d
CHROOT
chmod +x "$ROOTFS/tmp/install-stage0.sh"

set +e
chroot "$ROOTFS" /bin/bash /tmp/install-stage0.sh \
  > >(tee "$EVIDENCE_DIR/chroot-install.log") \
  2> >(tee "$EVIDENCE_DIR/chroot-install.stderr.log" >&2)
install_rc=$?
set -e
cp "$ROOTFS/tmp/stage0-installed-packages.tsv" "$EVIDENCE_DIR/" 2>/dev/null || true
rm -f "$ROOTFS/tmp/install-stage0.sh" "$ROOTFS/tmp/stage0-installed-packages.tsv"
[ "$install_rc" -eq 0 ] || exit "$install_rc"

# Recover only architecture-neutral visual assets from the exact AMD64 image.
# Every regular file is scanned first; any x86 or foreign ELF is removed and
# recorded rather than copied into the ARM64 root filesystem.
REF_SQUASHFS="$WORK_DIR/reference-filesystem.squashfs"
if ! xorriso -osirrox on -indev "$REFERENCE_ISO" \
    -extract /live/filesystem.squashfs "$REF_SQUASHFS" \
    > "$EVIDENCE_DIR/reference-squashfs-extract.log" 2>&1; then
  xorriso -osirrox on -indev "$REFERENCE_ISO" \
    -extract /casper/filesystem.squashfs "$REF_SQUASHFS" \
    >> "$EVIDENCE_DIR/reference-squashfs-extract.log" 2>&1
fi
for path in \
  usr/share/backgrounds \
  usr/share/gnome-background-properties \
  usr/share/icons \
  usr/share/pixmaps \
  usr/share/themes \
  usr/share/plymouth/themes; do
  unsquashfs -f -d "$BRAND_ROOT" "$REF_SQUASHFS" "$path" \
    >> "$EVIDENCE_DIR/reference-brand-extract.log" 2>&1 || true
done
: > "$EVIDENCE_DIR/reference-brand-blocked-elfs.tsv"
if [ -d "$BRAND_ROOT" ]; then
  while IFS= read -r -d '' asset; do
    description="$(file -b "$asset" || true)"
    if grep -Eqi 'ELF .* (x86-64|Intel 80386)|PE32(\+)? .* (x86-64|Intel 80386)' <<<"$description"; then
      printf '%s\t%s\n' "${asset#$BRAND_ROOT/}" "$description" \
        >> "$EVIDENCE_DIR/reference-brand-blocked-elfs.tsv"
      rm -f "$asset"
    fi
  done < <(find "$BRAND_ROOT" -type f -print0)
  rsync -aHAX --ignore-errors "$BRAND_ROOT/" "$ROOTFS/"
fi

# Rebuild caches after applying the reference visual layer.
cat > "$ROOTFS/tmp/rebuild-stage0-caches.sh" <<'CHROOT'
#!/bin/bash
set -Eeuo pipefail
if command -v glib-compile-schemas >/dev/null; then
  glib-compile-schemas /usr/share/glib-2.0/schemas || true
fi
if command -v update-mime-database >/dev/null; then
  update-mime-database /usr/share/mime || true
fi
if command -v update-desktop-database >/dev/null; then
  update-desktop-database /usr/share/applications || true
fi
if command -v fc-cache >/dev/null; then
  fc-cache -f || true
fi
if command -v gtk-update-icon-cache >/dev/null; then
  find /usr/share/icons -mindepth 1 -maxdepth 1 -type d -print0 \
    | while IFS= read -r -d '' theme; do
        [ -f "$theme/index.theme" ] && gtk-update-icon-cache -f -t "$theme" || true
      done
fi
ldconfig
update-initramfs -u -k all
CHROOT
chmod +x "$ROOTFS/tmp/rebuild-stage0-caches.sh"
chroot "$ROOTFS" /bin/bash /tmp/rebuild-stage0-caches.sh \
  > "$EVIDENCE_DIR/cache-rebuild.log" 2>&1
rm -f "$ROOTFS/tmp/rebuild-stage0-caches.sh"

# Clear per-machine state before sealing the live root.
rm -f "$ROOTFS/etc/machine-id"
: > "$ROOTFS/etc/machine-id"
rm -f "$ROOTFS/var/lib/dbus/machine-id"
ln -s /etc/machine-id "$ROOTFS/var/lib/dbus/machine-id"
rm -f "$ROOTFS/etc/ssh/ssh_host_"* 2>/dev/null || true
rm -f "$ROOTFS/var/lib/systemd/random-seed"
find "$ROOTFS/var/log" -type f -exec truncate -s 0 '{}' + 2>/dev/null || true

# Unmount before SquashFS creation.
cleanup_mounts=("${mounted[@]}")
for target in "${cleanup_mounts[@]}"; do
  umount -R "$target" 2>/dev/null || umount -l "$target" 2>/dev/null || true
done
mounted=()

kernel="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' | sort -V | tail -n1)"
initrd="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'initrd.img-*' -printf '%f\n' | sort -V | tail -n1)"
test -n "$kernel"
test -n "$initrd"
cp "$ROOTFS/boot/$kernel" "$ISO_ROOT/live/vmlinuz"
cp "$ROOTFS/boot/$initrd" "$ISO_ROOT/live/initrd.img"

mksquashfs "$ROOTFS" "$ISO_ROOT/live/filesystem.squashfs" \
  -noappend -comp xz -b 1M -Xdict-size 100% \
  -all-root -all-time 0 -mkfs-time 0 \
  -processors "$(nproc)" \
  2>&1 | tee "$EVIDENCE_DIR/mksquashfs.log"
du -sx --block-size=1 "$ROOTFS" | awk '{print $1}' > "$ISO_ROOT/live/filesystem.size"
cp "$EVIDENCE_DIR/stage0-installed-packages.tsv" "$ISO_ROOT/live/filesystem.manifest"

cat > "$ISO_ROOT/boot/grub/grub.cfg" <<'EOF'
set default=0
set timeout=3
set timeout_style=menu

menuentry "Hancom Gooroom 3.3 ARM64 Stage-0" {
  linux /live/vmlinuz boot=live components quiet splash hostname=hancom-gooroom username=gooroom locales=ko_KR.UTF-8 keyboard-layouts=kr console=tty0 console=ttyAMA0,115200
  initrd /live/initrd.img
}
menuentry "Hancom Gooroom 3.3 ARM64 Stage-0 (serial diagnostics)" {
  linux /live/vmlinuz boot=live components systemd.unit=multi-user.target hostname=hancom-gooroom username=gooroom console=ttyAMA0,115200
  initrd /live/initrd.img
}
EOF
cat > "$WORK_DIR/grub-embedded.cfg" <<EOF
search --no-floppy --label --set=root $ISO_LABEL
set prefix=(\$root)/boot/grub
configfile /boot/grub/grub.cfg
EOF

grub-mkstandalone \
  -O arm64-efi \
  --modules='part_gpt part_msdos fat iso9660 normal linux configfile search search_label all_video gfxterm font echo test regexp' \
  --locales='' --themes='' \
  -o "$WORK_DIR/BOOTAA64.EFI" \
  "boot/grub/grub.cfg=$WORK_DIR/grub-embedded.cfg"
file "$WORK_DIR/BOOTAA64.EFI" | tee "$EVIDENCE_DIR/bootaa64-file.txt"

truncate -s 64M "$ISO_ROOT/boot/grub/efi.img"
mkfs.vfat -F 16 -n HGOOROOMEFI "$ISO_ROOT/boot/grub/efi.img"
mmd -i "$ISO_ROOT/boot/grub/efi.img" ::/EFI ::/EFI/BOOT
mcopy -i "$ISO_ROOT/boot/grub/efi.img" \
  "$WORK_DIR/BOOTAA64.EFI" ::/EFI/BOOT/BOOTAA64.EFI
mmdir="$EVIDENCE_DIR/efi-directory.txt"
mdir -i "$ISO_ROOT/boot/grub/efi.img" ::/EFI/BOOT > "$mmdir"

printf 'Hancom Gooroom 3.3 ARM64 Stage-0\n' > "$ISO_ROOT/.disk/info"
printf 'full_cd/single\n' > "$ISO_ROOT/.disk/base_installable"
printf 'Hancom Gooroom 3.3 ARM64 Stage-0 recovery image\n' > "$ISO_ROOT/README.diskdefines"
(
  cd "$ISO_ROOT"
  find . -type f ! -name md5sum.txt -print0 | sort -z | xargs -0 md5sum > md5sum.txt
)

xorriso -as mkisofs \
  -r -J -joliet-long \
  -V "$ISO_LABEL" \
  -o "$OUTPUT_ISO" \
  -e boot/grub/efi.img \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  "$ISO_ROOT" \
  2>&1 | tee "$EVIDENCE_DIR/xorriso-build.log"

xorriso -indev "$OUTPUT_ISO" -report_el_torito plain \
  > "$EVIDENCE_DIR/el-torito.txt" 2>&1
xorriso -indev "$OUTPUT_ISO" -report_system_area plain \
  > "$EVIDENCE_DIR/system-area.txt" 2>&1
sha256sum "$OUTPUT_ISO" > "$OUTPUT_ISO.sha256"
stat -c '%n\t%s' "$OUTPUT_ISO" > "$EVIDENCE_DIR/iso-size.tsv"
sha256sum \
  "$ISO_ROOT/live/vmlinuz" \
  "$ISO_ROOT/live/initrd.img" \
  "$ISO_ROOT/live/filesystem.squashfs" \
  "$ISO_ROOT/boot/grub/efi.img" \
  > "$EVIDENCE_DIR/iso-components.sha256"

# Boot the exact produced image in AArch64 UEFI QEMU. The artifact is accepted
# only after systemd in the live root emits the stage-0 marker over ttyAMA0.
CODE=''
VARS_TEMPLATE=''
for candidate in \
  /usr/share/AAVMF/AAVMF_CODE.fd \
  /usr/share/AAVMF/AAVMF_CODE.ms.fd; do
  [ -f "$candidate" ] && CODE="$candidate" && break
done
for candidate in \
  /usr/share/AAVMF/AAVMF_VARS.fd \
  /usr/share/AAVMF/AAVMF_VARS.ms.fd; do
  [ -f "$candidate" ] && VARS_TEMPLATE="$candidate" && break
done
[ -n "$CODE" ] || {
  echo 'AAVMF_CODE.fd was not found' >&2
  exit 70
}
VARS="$WORK_DIR/AAVMF_VARS.fd"
if [ -n "$VARS_TEMPLATE" ]; then
  cp "$VARS_TEMPLATE" "$VARS"
else
  truncate -s 64M "$VARS"
fi
SERIAL_LOG="$EVIDENCE_DIR/qemu-serial.log"
QEMU_LOG="$EVIDENCE_DIR/qemu.log"
: > "$SERIAL_LOG"
: > "$QEMU_LOG"
if [ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  accel=( -accel kvm -cpu host )
else
  accel=( -accel tcg,thread=multi -cpu max )
fi
qemu=(
  qemu-system-aarch64
  -machine virt,gic-version=3
  "${accel[@]}"
  -smp 4 -m 4096
  -drive "if=pflash,format=raw,readonly=on,file=$CODE"
  -drive "if=pflash,format=raw,file=$VARS"
  -device virtio-gpu-pci
  -device qemu-xhci
  -device usb-kbd
  -device usb-tablet
  -device virtio-scsi-pci,id=scsi0
  -drive "if=none,media=cdrom,readonly=on,file=$OUTPUT_ISO,id=cdrom0"
  -device scsi-cd,drive=cdrom0
  -netdev user,id=net0
  -device virtio-net-pci,netdev=net0
  -boot order=d,menu=off
  -display none -monitor none
  -serial "file:$SERIAL_LOG"
  -no-reboot
)
printf '%q ' "${qemu[@]}" > "$EVIDENCE_DIR/qemu-command.txt"
printf '\n' >> "$EVIDENCE_DIR/qemu-command.txt"
"${qemu[@]}" > "$QEMU_LOG" 2>&1 &
qemu_pid=$!
start="$(date +%s)"
found=false
graphical=false
while kill -0 "$qemu_pid" 2>/dev/null; do
  if grep -Fq "$BOOT_MARKER" "$SERIAL_LOG"; then
    found=true
    grep -Fq "$GRAPHICAL_MARKER" "$SERIAL_LOG" && graphical=true || true
    break
  fi
  now="$(date +%s)"
  [ $((now - start)) -lt 1200 ] || break
  sleep 5
done
kill -TERM "$qemu_pid" 2>/dev/null || true
sleep 3
kill -KILL "$qemu_pid" 2>/dev/null || true
wait "$qemu_pid" 2>/dev/null || true
end="$(date +%s)"
tail -n 500 "$SERIAL_LOG" > "$EVIDENCE_DIR/qemu-serial-tail.log" || true
tail -n 200 "$QEMU_LOG" > "$EVIDENCE_DIR/qemu-tail.log" || true
jq -n \
  --arg boot_marker "$BOOT_MARKER" \
  --arg graphical_marker "$GRAPHICAL_MARKER" \
  --argjson boot_marker_found "$found" \
  --argjson graphical_marker_found "$graphical" \
  --argjson elapsed_seconds "$((end - start))" \
  '{
    schema:1,
    architecture:"arm64",
    firmware:"AAVMF",
    boot_marker:$boot_marker,
    graphical_marker:$graphical_marker,
    boot_marker_found:$boot_marker_found,
    graphical_marker_found:$graphical_marker_found,
    elapsed_seconds:$elapsed_seconds,
    passed:$boot_marker_found
  }' > "$EVIDENCE_DIR/qemu-boot-result.json"
cat "$EVIDENCE_DIR/qemu-boot-result.json"
[ "$found" = true ] || exit 2

cat > "$EVIDENCE_DIR/stage0-build.json" <<EOF
{
  "schema": 1,
  "name": "Hancom Gooroom 3.3 ARM64 Stage-0",
  "architecture": "arm64",
  "debian_snapshot": $(jq -Rn --arg v "$SNAPSHOT" '$v'),
  "reference_iso_sha256": $(sha256sum "$REFERENCE_ISO" | awk '{print "\""$1"\""}'),
  "iso_filename": $(jq -Rn --arg v "$(basename "$OUTPUT_ISO")" '$v'),
  "iso_size": $(stat -c '%s' "$OUTPUT_ISO"),
  "iso_sha256": $(sha256sum "$OUTPUT_ISO" | awk '{print "\""$1"\""}'),
  "uefi_default_path": "EFI/BOOT/BOOTAA64.EFI",
  "qemu_boot_marker_verified": true,
  "full_version_equivalence_claimed": false
}
EOF
find "$EVIDENCE_DIR" -type f ! -name LOCKSUMS.sha256 -print0 \
  | sort -z | xargs -0 sha256sum > "$EVIDENCE_DIR/LOCKSUMS.sha256"
cat "$EVIDENCE_DIR/stage0-build.json"
