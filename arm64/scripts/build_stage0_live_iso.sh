#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 REFERENCE_JSON VENDOR_LOCK_JSON VENDOR_DEB_DIR OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 4 ] || usage
REFERENCE_JSON="$1"
VENDOR_LOCK_JSON="$2"
VENDOR_DEB_DIR="$3"
OUTPUT_DIR="$4"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
ISO_NAME="${HANCOM_GOOROOM_STAGE0_ISO_NAME:-Hancom-Gooroom-3.3-arm64-stage0.iso}"

[ "${EUID:-$(id -u)}" -eq 0 ] || {
  echo "stage-0 ISO assembly must run as root" >&2
  exit 77
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "stage-0 ISO assembly requires a native ARM64 host" >&2; exit 77 ;;
esac
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid snapshot timestamp: $SNAPSHOT" >&2
  exit 64
}

for command in debootstrap jq dpkg-deb sha256sum mksquashfs xorriso \
  grub-mkstandalone mkfs.vfat mmd mcopy file rsync; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done

REFERENCE_JSON="$(readlink -f "$REFERENCE_JSON")"
VENDOR_LOCK_JSON="$(readlink -f "$VENDOR_LOCK_JSON")"
VENDOR_DEB_DIR="$(readlink -f "$VENDOR_DEB_DIR")"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(readlink -f "$OUTPUT_DIR")"
WORK="$(mktemp -d)"
ROOTFS="$WORK/rootfs"
ISO_ROOT="$WORK/iso"
OVERLAY_ROOT="$WORK/overlay"
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

mkdir -p "$ROOTFS" "$ISO_ROOT/live" "$ISO_ROOT/boot/grub" \
  "$ISO_ROOT/EFI/BOOT" "$OVERLAY_ROOT" "$OUTPUT_DIR"

REFERENCE_ISO_SHA="$(jq -r '.reference_iso.sha256' "$REFERENCE_JSON")"
REFERENCE_PACKAGE_COUNT="$(jq -r '.package_count' "$REFERENCE_JSON")"
VENDOR_VERIFIED_COUNT="$(jq -r '.summary.verified_count' "$VENDOR_LOCK_JSON")"
VENDOR_UNRESOLVED_COUNT="$(jq -r '.summary.unresolved_count' "$VENDOR_LOCK_JSON")"
[ "$REFERENCE_ISO_SHA" = ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a ]
[ "$REFERENCE_PACKAGE_COUNT" = 1279 ]
[ "$VENDOR_VERIFIED_COUNT" = 123 ]
[ "$VENDOR_UNRESOLVED_COUNT" = 0 ]

# Only architecture-independent packages are overlaid at stage 0. Each package
# is accepted only after checking the immutable reference inventory and the
# historical vendor index SHA-256 lock. Native vendor executables are never
# copied into this ARM64 image.
BRANDING_PACKAGES=(
  arc-icon-theme
  arc-theme
  flat-remix-gtk-theme
  gedit-common
  gnome-control-center-data
  gnome-flashback-common
  gnome-panel-data
  gnome-session-flashback
  gnome-settings-daemon-common
  gooroom-artwork-common
  gooroom-artwork-gnome-flashback
  gooroom-bootsplash-theme
  gooroom-icon-themes
  gooroom-info
  gooroom-translations
  hancom-gooroom-themepack
  libgtk-3-common
  libgtk2.0-common
  libnma-common
  metacity-common
  nautilus-data
)

printf 'package\tversion\tarchitecture\tsha256\tfilename\n' \
  > "$OUTPUT_DIR/stage0-exact-overlay-packages.tsv"
for package in "${BRANDING_PACKAGES[@]}"; do
  reference_entry="$(jq -c --arg package "$package" '
    .packages[]
    | select(.package == $package and .architecture == "all")
  ' "$REFERENCE_JSON" | head -n1)"
  lock_entry="$(jq -c --arg package "$package" '
    .packages[]
    | select(.package == $package and .architecture == "all" and .status == "verified")
  ' "$VENDOR_LOCK_JSON" | head -n1)"
  [ -n "$reference_entry" ] || {
    echo "reference architecture-all package missing: $package" >&2
    exit 2
  }
  [ -n "$lock_entry" ] || {
    echo "verified vendor package missing: $package" >&2
    exit 2
  }

  version="$(jq -r '.version' <<<"$reference_entry")"
  locked_version="$(jq -r '.version' <<<"$lock_entry")"
  filename="$(jq -r '.local_filename' <<<"$lock_entry")"
  expected_sha="$(jq -r '.actual_sha256' <<<"$lock_entry")"
  deb="$VENDOR_DEB_DIR/$filename"
  [ "$version" = "$locked_version" ]
  [ -f "$deb" ] || {
    echo "vendor DEB is absent: $deb" >&2
    exit 2
  }
  printf '%s  %s\n' "$expected_sha" "$deb" | sha256sum --check --strict
  [ "$(dpkg-deb -f "$deb" Package)" = "$package" ]
  [ "$(dpkg-deb -f "$deb" Version)" = "$version" ]
  [ "$(dpkg-deb -f "$deb" Architecture)" = all ]

  package_root="$WORK/package-$package"
  rm -rf "$package_root"
  mkdir -p "$package_root"
  dpkg-deb -x "$deb" "$package_root"
  find "$package_root" -type f -print0 \
    | xargs -0 -r file \
    > "$WORK/$package.file-report.txt"
  if grep -E 'ELF|PE32|Mach-O' "$WORK/$package.file-report.txt"; then
    echo "architecture-specific executable found in architecture-all package: $package" >&2
    exit 2
  fi
  rsync -aHAX "$package_root/" "$OVERLAY_ROOT/"
  printf '%s\t%s\tall\t%s\t%s\n' \
    "$package" "$version" "$expected_sha" "$filename" \
    >> "$OUTPUT_DIR/stage0-exact-overlay-packages.tsv"
done

DEBIAN_KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
[ -f "$DEBIAN_KEYRING" ] || {
  echo "Debian archive keyring is missing" >&2
  exit 69
}

echo "Bootstrapping Debian Bullseye ARM64 from $SNAPSHOT"
deBootstrapLog="$OUTPUT_DIR/stage0-debootstrap.log"
if ! debootstrap \
  --arch=arm64 \
  --variant=minbase \
  --keyring="$DEBIAN_KEYRING" \
  --include=ca-certificates,debian-archive-keyring \
  bullseye \
  "$ROOTFS" \
  "http://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
  > "$deBootstrapLog" 2>&1; then
  cat "$deBootstrapLog" >&2
  exit 20
fi

cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
rm -f "$ROOTFS/etc/apt/sources.list.d/"*
cat > "$ROOTFS/etc/apt/apt.conf.d/99snapshot" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
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

cat > "$ROOTFS/root/install-stage0.sh" <<'CHROOT_INSTALL'
#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

apt-get update
apt-get install -y --no-install-recommends \
  apt-utils bash-completion ca-certificates console-setup dbus dbus-user-session \
  initramfs-tools iproute2 iputils-ping jq keyboard-configuration less locales \
  live-boot live-config linux-image-arm64 nano network-manager plymouth rsync \
  sudo systemd-sysv systemd-timesyncd udev xdg-user-dirs

apt-get install -y \
  arc-icon-theme dconf-cli eog evince file-roller fonts-nanum fonts-noto-cjk \
  gedit gnome-control-center gnome-flashback gnome-panel gnome-session-flashback \
  gnome-settings-daemon gnome-terminal gnome-themes-extra gtk2-engines-murrine \
  gtk2-engines-pixbuf hicolor-icon-theme ibus ibus-hangul lightdm \
  lightdm-gtk-greeter metacity nautilus network-manager-gnome \
  numix-icon-theme-circle papirus-icon-theme policykit-1 pulseaudio \
  qemu-guest-agent spice-vdagent xserver-xorg xserver-xorg-input-all \
  xserver-xorg-video-all

sed -i '/^# *ko_KR.UTF-8 UTF-8/s/^# *//' /etc/locale.gen
sed -i '/^# *en_US.UTF-8 UTF-8/s/^# *//' /etc/locale.gen
locale-gen
update-locale LANG=ko_KR.UTF-8 LANGUAGE=ko_KR:ko:en_US:en LC_MESSAGES=ko_KR.UTF-8
CHROOT_INSTALL
chmod +x "$ROOTFS/root/install-stage0.sh"
chroot "$ROOTFS" /bin/bash /root/install-stage0.sh \
  > >(tee "$OUTPUT_DIR/stage0-chroot-install.log") \
  2> >(tee "$OUTPUT_DIR/stage0-chroot-install.stderr.log" >&2)

# Apply exact architecture-independent Hancom/Gooroom payloads after the base
# desktop is installed, then rebuild all architecture-neutral caches.
rsync -aHAX "$OVERLAY_ROOT/" "$ROOTFS/"

cat > "$ROOTFS/usr/share/glib-2.0/schemas/90_hancom-gooroom-stage0.gschema.override" <<'EOF'
[org.gnome.desktop.background]
picture-uri='file:///usr/share/backgrounds/hancom-gooroom/hancom_gooroom_theme_bg_1.jpg'
picture-options='zoom'
primary-color='#000000'
secondary-color='#000000'

[org.gnome.desktop.screensaver]
picture-uri='file:///usr/share/backgrounds/hancom-gooroom/hancom_gooroom_theme_bg_1.jpg'
picture-options='zoom'

[org.gnome.desktop.interface]
gtk-theme='Flat-Remix-GTK-Blue-Darker'
icon-theme='Hancom-Gooroom-Numix-Circle'
font-name='나눔고딕 11'
document-font-name='나눔고딕 11'

[org.gnome.desktop.wm.preferences]
theme='Arc-Darker'
EOF

cat > "$ROOTFS/root/finalize-stage0.sh" <<'CHROOT_FINALIZE'
#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

cat > /etc/os-release <<'EOF'
PRETTY_NAME="Hancom Gooroom 3.3 ARM64 Stage 0"
NAME="Hancom Gooroom"
VERSION_ID="3.3-stage0"
VERSION="3.3 ARM64 Stage 0"
VERSION_CODENAME=bullseye
ID=hancom-gooroom
ID_LIKE=debian
HOME_URL="https://github.com/bicheondev/hancom-gooroom-archive"
EOF
cat > /etc/lsb-release <<'EOF'
DISTRIB_ID=HancomGooroom
DISTRIB_RELEASE=3.3-stage0
DISTRIB_CODENAME=bullseye
DISTRIB_DESCRIPTION="Hancom Gooroom 3.3 ARM64 Stage 0"
EOF
printf 'hancom-gooroom\n' > /etc/hostname
cat > /etc/hosts <<'EOF'
127.0.0.1 localhost
127.0.1.1 hancom-gooroom
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

if ! id gooroom >/dev/null 2>&1; then
  supplementary=()
  for group in sudo adm audio video plugdev netdev cdrom dip; do
    getent group "$group" >/dev/null && supplementary+=("$group")
  done
  group_list="$(IFS=,; echo "${supplementary[*]}")"
  useradd -m -u 1000 -s /bin/bash ${group_list:+-G "$group_list"} gooroom
fi
printf 'gooroom:gooroom\n' | chpasswd
install -d -m 0750 /etc/sudoers.d
printf 'gooroom ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/90-gooroom-live
chmod 0440 /etc/sudoers.d/90-gooroom-live
install -d -o gooroom -g gooroom /home/gooroom
cat > /home/gooroom/.dmrc <<'EOF'
[Desktop]
Session=gnome-flashback-metacity
Language=ko_KR.UTF-8
EOF
chown gooroom:gooroom /home/gooroom/.dmrc

install -d /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-hancom-gooroom-live.conf <<'EOF'
[Seat:*]
autologin-user=gooroom
autologin-user-timeout=0
user-session=gnome-flashback-metacity
greeter-session=lightdm-gtk-greeter
EOF

install -d /etc/live/config.conf.d
cat > /etc/live/config.conf.d/10-hancom-gooroom.conf <<'EOF'
LIVE_HOSTNAME="hancom-gooroom"
LIVE_USERNAME="gooroom"
LIVE_USER_FULLNAME="Hancom Gooroom"
LIVE_LOCALES="ko_KR.UTF-8,en_US.UTF-8"
LIVE_TIMEZONE="Asia/Seoul"
LIVE_KEYBOARD_LAYOUTS="kr"
EOF

glib-compile-schemas /usr/share/glib-2.0/schemas
for theme in \
  Gooroom-Arc Gooroom-Faenza Gooroom-Numix-Circle Gooroom-Papirus \
  Hancom-Gooroom-Numix-Circle Hancom-Gooroom-Papirus; do
  [ -d "/usr/share/icons/$theme" ] || continue
  gtk-update-icon-cache --force --ignore-theme-index "/usr/share/icons/$theme" || true
done

if plymouth-set-default-theme --list 2>/dev/null | grep -qx hancom-gooroom; then
  plymouth-set-default-theme hancom-gooroom
elif plymouth-set-default-theme --list 2>/dev/null | grep -qx gooroom-logo; then
  plymouth-set-default-theme gooroom-logo
fi

cat > /usr/local/sbin/hancom-gooroom-stage0-ready <<'EOF'
#!/bin/sh
message='HANCOM_GOOROOM_ARM64_STAGE0_READY'
printf '%s\n' "$message" > /dev/console 2>/dev/null || true
printf '%s\n' "$message" > /dev/ttyAMA0 2>/dev/null || true
mkdir -p /run/hancom-gooroom
: > /run/hancom-gooroom/stage0-ready
EOF
chmod 0755 /usr/local/sbin/hancom-gooroom-stage0-ready
cat > /etc/systemd/system/hancom-gooroom-stage0-ready.service <<'EOF'
[Unit]
Description=Report Hancom Gooroom ARM64 stage-0 boot readiness
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hancom-gooroom-stage0-ready
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable NetworkManager.service
systemctl enable lightdm.service
systemctl enable qemu-guest-agent.service || true
systemctl enable hancom-gooroom-stage0-ready.service
systemctl set-default graphical.target

rm -f /usr/sbin/policy-rc.d
update-initramfs -u -k all
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
find /var/log -type f -exec truncate -s 0 '{}' +
rm -f /etc/machine-id
: > /etc/machine-id
CHROOT_FINALIZE
chmod +x "$ROOTFS/root/finalize-stage0.sh"
chroot "$ROOTFS" /bin/bash /root/finalize-stage0.sh \
  > >(tee "$OUTPUT_DIR/stage0-chroot-finalize.log") \
  2> >(tee "$OUTPUT_DIR/stage0-chroot-finalize.stderr.log" >&2)

chroot "$ROOTFS" dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | sort > "$OUTPUT_DIR/stage0-installed-packages.tsv"

python3 - "$REFERENCE_JSON" "$OUTPUT_DIR/stage0-exact-overlay-packages.tsv" \
  "$OUTPUT_DIR/stage0-installed-packages.tsv" "$SNAPSHOT" \
  > "$OUTPUT_DIR/stage0-manifest.json" <<'PY'
import csv, json, sys
from pathlib import Path
reference = json.loads(Path(sys.argv[1]).read_text())
overlay_path = Path(sys.argv[2])
installed_path = Path(sys.argv[3])
snapshot = sys.argv[4]
overlays = list(csv.DictReader(overlay_path.open(), delimiter='\t'))
installed = list(csv.DictReader(installed_path.open(), delimiter='\t', fieldnames=['package','version','architecture']))
custom_sources = [source for source in reference['sources'] if source.get('custom_candidate')]
native_custom = []
for source in custom_sources:
    arches = sorted({
        package['architecture']
        for package in reference['packages']
        if package['source'] == source['source'] and package['source_version'] == source['source_version']
    })
    if 'amd64' in arches:
        native_custom.append({
            'source': source['source'],
            'source_version': source['source_version'],
            'binary_packages': source['binary_packages'],
        })
manifest = {
    'schema': 1,
    'status': 'bring-up-not-release',
    'product': 'Hancom Gooroom 3.3 ARM64 Stage 0',
    'target': 'generic ARM64 UEFI virtual machine',
    'reference_iso': reference['reference_iso'],
    'debian_snapshot': snapshot,
    'reference_package_count': reference['package_count'],
    'installed_debian_package_count': len(installed),
    'exact_architecture_independent_overlay_count': len(overlays),
    'exact_architecture_independent_overlays': overlays,
    'native_custom_source_count_not_yet_integrated': len(native_custom),
    'native_custom_sources_not_yet_integrated': native_custom,
    'release_gate': 'blocked until every native custom source is exact-locked, rebuilt for ARM64, integrated, and boot-tested',
}
print(json.dumps(manifest, ensure_ascii=False, indent=2))
PY

install -D -m 0644 "$OUTPUT_DIR/stage0-manifest.json" \
  "$ROOTFS/usr/share/doc/hancom-gooroom-arm64-stage0/manifest.json"
install -D -m 0644 "$OUTPUT_DIR/stage0-exact-overlay-packages.tsv" \
  "$ROOTFS/usr/share/doc/hancom-gooroom-arm64-stage0/exact-overlay-packages.tsv"
install -D -m 0644 "$OUTPUT_DIR/stage0-manifest.json" \
  "$ISO_ROOT/HANCOM_GOOROOM_ARM64_STAGE0.json"
install -D -m 0644 "$OUTPUT_DIR/stage0-exact-overlay-packages.tsv" \
  "$ISO_ROOT/HANCOM_GOOROOM_EXACT_OVERLAYS.tsv"

# All filesystem mutations are complete; release chroot mounts before creating
# the deterministic SquashFS.
umount -R "$ROOTFS/dev"
umount "$ROOTFS/proc"
umount "$ROOTFS/sys"
umount -R "$ROOTFS/run"
MOUNTED=false

KERNEL_PATH="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | sort -V | tail -n1)"
[ -n "$KERNEL_PATH" ]
KERNEL_VERSION="${KERNEL_PATH##*/vmlinuz-}"
INITRD_PATH="$ROOTFS/boot/initrd.img-$KERNEL_VERSION"
[ -f "$INITRD_PATH" ]
cp "$KERNEL_PATH" "$ISO_ROOT/live/vmlinuz"
cp "$INITRD_PATH" "$ISO_ROOT/live/initrd.img"
printf '%s\n' "$KERNEL_VERSION" > "$OUTPUT_DIR/stage0-kernel-version.txt"

mksquashfs "$ROOTFS" "$ISO_ROOT/live/filesystem.squashfs" \
  -noappend -comp xz -b 1M -Xdict-size 100% \
  > "$OUTPUT_DIR/stage0-mksquashfs.log"
du -sx --block-size=1 "$ROOTFS" | cut -f1 > "$ISO_ROOT/live/filesystem.size"
cp "$OUTPUT_DIR/stage0-installed-packages.tsv" "$ISO_ROOT/live/filesystem.manifest"

cat > "$ISO_ROOT/boot/grub/grub.cfg" <<'EOF'
set default=0
set timeout=5

if loadfont /boot/grub/unicode.pf2; then
  insmod all_video
  insmod gfxterm
  insmod png
  set gfxmode=auto
  set gfxpayload=keep
  terminal_output gfxterm
  background_image /boot/grub/hancom-bg.png
fi

menuentry 'Hancom Gooroom 3.3 ARM64 Stage 0' {
  linux /live/vmlinuz boot=live components username=gooroom hostname=hancom-gooroom locales=ko_KR.UTF-8 keyboard-layouts=kr timezone=Asia/Seoul quiet splash console=tty0 console=ttyAMA0,115200n8 systemd.show_status=1
  initrd /live/initrd.img
}

menuentry 'Hancom Gooroom 3.3 ARM64 Stage 0 (safe graphics)' {
  linux /live/vmlinuz boot=live components username=gooroom hostname=hancom-gooroom locales=ko_KR.UTF-8 keyboard-layouts=kr timezone=Asia/Seoul nomodeset console=tty0 console=ttyAMA0,115200n8 systemd.show_status=1
  initrd /live/initrd.img
}
EOF

cat > "$WORK/grub-embedded.cfg" <<'EOF'
search --no-floppy --file --set=root /live/filesystem.squashfs
set prefix=($root)/boot/grub
configfile /boot/grub/grub.cfg
EOF

cp /usr/share/grub/unicode.pf2 "$ISO_ROOT/boot/grub/unicode.pf2"
cp "$ROOTFS/usr/share/backgrounds/hancom-gooroom/hancom-gooroom-bootmenu-bg01.png" \
  "$ISO_ROOT/boot/grub/hancom-bg.png"

grub-mkstandalone \
  -O arm64-efi \
  --modules='part_gpt part_msdos fat iso9660 normal linux configfile search search_fs_file search_fs_uuid search_label all_video gfxterm font png echo reboot halt test' \
  --locales='' \
  --fonts='' \
  -o "$ISO_ROOT/EFI/BOOT/BOOTAA64.EFI" \
  "boot/grub/grub.cfg=$WORK/grub-embedded.cfg"
file "$ISO_ROOT/EFI/BOOT/BOOTAA64.EFI" \
  | tee "$OUTPUT_DIR/stage0-efi-file-report.txt"
grep -Eiq 'PE32\+.*(Aarch64|ARM aarch64)' "$OUTPUT_DIR/stage0-efi-file-report.txt"

EFI_IMAGE="$ISO_ROOT/boot/grub/efi.img"
truncate -s 16M "$EFI_IMAGE"
mkfs.vfat -n HG33EFI "$EFI_IMAGE" >/dev/null
mmd -i "$EFI_IMAGE" ::/EFI ::/EFI/BOOT
mcopy -i "$EFI_IMAGE" "$ISO_ROOT/EFI/BOOT/BOOTAA64.EFI" ::/EFI/BOOT/BOOTAA64.EFI

find "$ISO_ROOT" -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  | sed "s#  $ISO_ROOT/#  #" \
  > "$ISO_ROOT/SHA256SUMS"

ISO_PATH="$OUTPUT_DIR/$ISO_NAME"
if ! xorriso -as mkisofs \
  -r -J -joliet-long -l -iso-level 3 \
  -V HG33_ARM64_S0 \
  -o "$ISO_PATH" \
  -eltorito-alt-boot \
  -e boot/grub/efi.img \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  "$ISO_ROOT" \
  > "$OUTPUT_DIR/stage0-xorriso-build.log" 2>&1; then
  cat "$OUTPUT_DIR/stage0-xorriso-build.log" >&2
  echo 'Retrying as an EFI El Torito ISO without the optional hybrid GPT flag.' >&2
  xorriso -as mkisofs \
    -r -J -joliet-long -l -iso-level 3 \
    -V HG33_ARM64_S0 \
    -o "$ISO_PATH" \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
    -no-emul-boot \
    "$ISO_ROOT" \
    > "$OUTPUT_DIR/stage0-xorriso-build.log" 2>&1
fi

xorriso -indev "$ISO_PATH" -report_el_torito plain \
  > "$OUTPUT_DIR/stage0-el-torito.txt" 2>&1
xorriso -indev "$ISO_PATH" -report_system_area plain \
  > "$OUTPUT_DIR/stage0-system-area.txt" 2>&1 || true
sha256sum "$ISO_PATH" > "$ISO_PATH.sha256"
stat -c '%s' "$ISO_PATH" > "$ISO_PATH.size"

cat > "$OUTPUT_DIR/stage0-build-result.json" <<EOF
{
  "schema": 1,
  "status": "built-awaiting-boot-test",
  "iso": $(jq -Rn --arg v "$ISO_NAME" '$v'),
  "size": $(cat "$ISO_PATH.size"),
  "sha256": $(jq -Rn --arg v "$(awk '{print $1}' "$ISO_PATH.sha256")" '$v'),
  "architecture": "arm64",
  "firmware": "UEFI fallback BOOTAA64.EFI",
  "kernel_version": $(jq -Rn --arg v "$KERNEL_VERSION" '$v'),
  "debian_snapshot": $(jq -Rn --arg v "$SNAPSHOT" '$v'),
  "release_status": "stage0-bring-up-not-final"
}
EOF
cat "$OUTPUT_DIR/stage0-build-result.json"
