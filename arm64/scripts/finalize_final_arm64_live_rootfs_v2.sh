#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 ROOTFS OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
ROOTFS="$1"
OUTPUT_DIR="$2"
[ "$(id -u)" -eq 0 ] || {
  echo "root privileges required" >&2
  exit 77
}
case "$(uname -m)" in aarch64|arm64) ;; *) exit 78 ;; esac
ROOTFS="$(cd "$ROOTFS" && pwd)"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

for directory in proc sys dev run; do mkdir -p "$ROOTFS/$directory"; done
cp -L /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
mkdir -p \
  "$ROOTFS/usr/local/sbin" \
  "$ROOTFS/etc/systemd/system/multi-user.target.wants" \
  "$ROOTFS/etc/systemd/system/graphical.target.wants" \
  "$ROOTFS/etc/live/config.conf.d" \
  "$ROOTFS/usr/share/doc/hancom-gooroom-arm64"

cat > "$ROOTFS/etc/live/config.conf.d/99-hancom-gooroom-arm64.conf" <<'EOF'
LIVE_HOSTNAME="hancom-gooroom"
LIVE_USERNAME="gooroom"
LIVE_USER_FULLNAME="Hancom Gooroom Live User"
LIVE_LOCALES="ko_KR.UTF-8"
LIVE_KEYBOARD_LAYOUTS="kr"
EOF
cat > "$ROOTFS/usr/share/doc/hancom-gooroom-arm64/PORT-PROVENANCE" <<'EOF'
Hancom Gooroom 3.3 ARM64 port.

The package layer was assembled from an immutable AMD64 reference inventory.
GitHub sources were accepted only when debian/changelog declared the exact
reference Source and Version. Versions absent from public Git were accepted only
through an exact vendor-signed .dsc whose complete components passed SHA-256.
Architecture-independent packages were reused at the exact reference version;
architecture-dependent packages were exact ARM64 mappings or verified native
rebuilds. See the corresponding release evidence archive for full locks.
EOF

cat > "$ROOTFS/usr/local/sbin/hancom-gooroom-arm64-final-markers" <<'EOF'
#!/bin/sh
set -u
boot='HANCOM_GOOROOM_3_3_ARM64_FINAL_BOOT_OK'
graphical='HANCOM_GOOROOM_3_3_ARM64_FINAL_GRAPHICAL_OK'
installer='HANCOM_GOOROOM_3_3_ARM64_INSTALLER_PRESENT'
emit() {
  printf '%s\n' "$1" >/dev/console 2>/dev/null || true
  printf '%s\n' "$1" >/dev/ttyAMA0 2>/dev/null || true
  logger -t hancom-gooroom-arm64 "$1" 2>/dev/null || true
}
emit "$boot"
for _ in $(seq 1 120); do
  if systemctl is-active --quiet display-manager.service 2>/dev/null \
     || systemctl is-active --quiet lightdm.service 2>/dev/null \
     || systemctl is-active --quiet gdm3.service 2>/dev/null; then
    if pgrep -x Xorg >/dev/null 2>&1 \
       || pgrep -x Xwayland >/dev/null 2>&1 \
       || pgrep -x gnome-shell >/dev/null 2>&1; then
      emit "$graphical"
      break
    fi
  fi
  sleep 1
done
if command -v calamares >/dev/null 2>&1 \
   || command -v gooroom-installer >/dev/null 2>&1 \
   || find /usr/share/applications -maxdepth 1 -type f \
        \( -iname '*calamares*.desktop' -o -iname '*installer*.desktop' \) \
        -print -quit 2>/dev/null | grep -q .; then
  emit "$installer"
fi
exit 0
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/hancom-gooroom-arm64-final-markers"
cat > "$ROOTFS/etc/systemd/system/hancom-gooroom-arm64-final-markers.service" <<'EOF'
[Unit]
Description=Hancom Gooroom 3.3 ARM64 final live boot markers
After=multi-user.target display-manager.service lightdm.service gdm3.service
Wants=display-manager.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hancom-gooroom-arm64-final-markers
TimeoutStartSec=180
RemainAfterExit=yes

[Install]
WantedBy=graphical.target
EOF
ln -sfn ../hancom-gooroom-arm64-final-markers.service \
  "$ROOTFS/etc/systemd/system/graphical.target.wants/hancom-gooroom-arm64-final-markers.service"

# Ensure one supported display manager is selected without replacing a vendor
# choice already recorded in /etc/X11/default-display-manager.
if [ ! -s "$ROOTFS/etc/X11/default-display-manager" ]; then
  if [ -x "$ROOTFS/usr/sbin/lightdm" ]; then
    mkdir -p "$ROOTFS/etc/X11"
    printf '/usr/sbin/lightdm\n' > "$ROOTFS/etc/X11/default-display-manager"
  elif [ -x "$ROOTFS/usr/sbin/gdm3" ]; then
    mkdir -p "$ROOTFS/etc/X11"
    printf '/usr/sbin/gdm3\n' > "$ROOTFS/etc/X11/default-display-manager"
  fi
fi

if [ -x "$ROOTFS/usr/sbin/lightdm" ]; then
  mkdir -p "$ROOTFS/etc/lightdm/lightdm.conf.d"
  cat > "$ROOTFS/etc/lightdm/lightdm.conf.d/90-hancom-gooroom-live.conf" <<'EOF'
[Seat:*]
autologin-user=gooroom
autologin-user-timeout=0
EOF
fi

mounted=()
cleanup() {
  set +e
  for target in "${mounted[@]}"; do
    umount -R "$target" 2>/dev/null || umount -l "$target" 2>/dev/null || true
  done
}
trap cleanup EXIT
mount -t proc proc "$ROOTFS/proc"; mounted=("$ROOTFS/proc")
mount -t sysfs sysfs "$ROOTFS/sys"; mounted=("$ROOTFS/sys" "${mounted[@]}")
mount --rbind /dev "$ROOTFS/dev"; mount --make-rslave "$ROOTFS/dev"; mounted=("$ROOTFS/dev" "${mounted[@]}")
mount --rbind /run "$ROOTFS/run"; mount --make-rslave "$ROOTFS/run"; mounted=("$ROOTFS/run" "${mounted[@]}")

cat > "$ROOTFS/tmp/finalize-final-arm64-live-v2.sh" <<'CHROOT'
#!/usr/bin/env bash
set -Eeuo pipefail
export HOME=/root LANG=C.UTF-8 LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive

for package in live-boot live-config systemd-sysv initramfs-tools; do
  dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' "$package"
done

id -u gooroom >/dev/null 2>&1 || useradd -m -s /bin/bash gooroom
for group in sudo audio video plugdev netdev; do
  getent group "$group" >/dev/null || groupadd "$group"
done
usermod -aG sudo,audio,video,plugdev,netdev gooroom
passwd -d gooroom
mkdir -p /etc/sudoers.d
cat > /etc/sudoers.d/90-gooroom-live <<'EOF'
gooroom ALL=(ALL) NOPASSWD: ALL
EOF
chmod 0440 /etc/sudoers.d/90-gooroom-live

systemctl enable hancom-gooroom-arm64-final-markers.service
if [ -x /usr/sbin/lightdm ]; then systemctl enable lightdm.service || true; fi
if [ -x /usr/sbin/gdm3 ]; then systemctl enable gdm3.service || true; fi
if systemctl list-unit-files NetworkManager.service >/dev/null 2>&1; then
  systemctl enable NetworkManager.service || true
fi
systemctl set-default graphical.target

if command -v glib-compile-schemas >/dev/null && [ -d /usr/share/glib-2.0/schemas ]; then
  glib-compile-schemas /usr/share/glib-2.0/schemas
fi
if command -v update-mime-database >/dev/null && [ -d /usr/share/mime ]; then
  update-mime-database /usr/share/mime
fi
if command -v update-desktop-database >/dev/null && [ -d /usr/share/applications ]; then
  update-desktop-database /usr/share/applications
fi
if command -v gtk-update-icon-cache >/dev/null && [ -d /usr/share/icons ]; then
  while IFS= read -r theme; do
    [ -f "$theme/index.theme" ] && gtk-update-icon-cache -f -t "$theme" || true
  done < <(find /usr/share/icons -mindepth 1 -maxdepth 1 -type d -print)
fi
if command -v fc-cache >/dev/null; then fc-cache -f; fi
if command -v update-ca-certificates >/dev/null; then update-ca-certificates; fi
if command -v ldconfig >/dev/null; then ldconfig; fi
update-initramfs -u -k all

dpkg --audit
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  | sort > /tmp/final-live-installed-packages.tsv
systemctl list-unit-files --no-pager > /tmp/final-live-unit-files.txt || true
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
find /var/log -type f -exec truncate -s 0 '{}' + 2>/dev/null || true
CHROOT
chmod 0755 "$ROOTFS/tmp/finalize-final-arm64-live-v2.sh"

set +e
chroot "$ROOTFS" /bin/bash /tmp/finalize-final-arm64-live-v2.sh \
  > >(tee "$OUTPUT_DIR/live-finalize.log") \
  2> >(tee "$OUTPUT_DIR/live-finalize.stderr.log" >&2)
rc=$?
set -e
cp "$ROOTFS/tmp/final-live-installed-packages.tsv" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$ROOTFS/tmp/final-live-unit-files.txt" "$OUTPUT_DIR/" 2>/dev/null || true
rm -f \
  "$ROOTFS/tmp/finalize-final-arm64-live-v2.sh" \
  "$ROOTFS/tmp/final-live-installed-packages.tsv" \
  "$ROOTFS/tmp/final-live-unit-files.txt"
[ "$rc" -eq 0 ] || exit "$rc"

rm -f "$ROOTFS/etc/machine-id"
: > "$ROOTFS/etc/machine-id"
rm -f "$ROOTFS/var/lib/dbus/machine-id"
ln -s /etc/machine-id "$ROOTFS/var/lib/dbus/machine-id"
rm -f "$ROOTFS/etc/ssh/ssh_host_"* 2>/dev/null || true
rm -f "$ROOTFS/var/lib/systemd/random-seed"

cleanup
mounted=()
trap - EXIT

kernel="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' | sort -V | tail -n1)"
initrd="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'initrd.img-*' -printf '%f\n' | sort -V | tail -n1)"
test -n "$kernel"
test -n "$initrd"
printf '%s\n' "$kernel" > "$OUTPUT_DIR/kernel-name.txt"
printf '%s\n' "$initrd" > "$OUTPUT_DIR/initrd-name.txt"
sha256sum "$ROOTFS/boot/$kernel" "$ROOTFS/boot/$initrd" \
  > "$OUTPUT_DIR/kernel-initrd.sha256"
jq -n \
  --arg kernel "$kernel" \
  --arg initrd "$initrd" \
  '{
    schema:2,
    architecture:"arm64",
    kernel:$kernel,
    initrd:$initrd,
    boot_marker:"HANCOM_GOOROOM_3_3_ARM64_FINAL_BOOT_OK",
    graphical_marker:"HANCOM_GOOROOM_3_3_ARM64_FINAL_GRAPHICAL_OK",
    installer_marker:"HANCOM_GOOROOM_3_3_ARM64_INSTALLER_PRESENT",
    default_target:"graphical.target"
  }' > "$OUTPUT_DIR/live-finalization.json"
cat "$OUTPUT_DIR/live-finalization.json"
