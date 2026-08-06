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
  echo "root privileges are required" >&2
  exit 77
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 host required" >&2; exit 78 ;;
esac

ROOTFS="$(cd "$ROOTFS" && pwd)"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

for path in proc sys dev run; do
  mkdir -p "$ROOTFS/$path"
done
cp -L /etc/resolv.conf "$ROOTFS/etc/resolv.conf"

mkdir -p "$ROOTFS/usr/local/sbin" "$ROOTFS/etc/systemd/system/multi-user.target.wants"
cat > "$ROOTFS/usr/local/sbin/hancom-gooroom-arm64-ci-marker" <<'EOF'
#!/bin/sh
marker='HANCOM_GOOROOM_3_3_ARM64_BOOT_OK'
printf '%s\n' "$marker" >/dev/console 2>/dev/null || true
printf '%s\n' "$marker" >/dev/ttyAMA0 2>/dev/null || true
logger -t hancom-gooroom-arm64 "$marker" 2>/dev/null || true
exit 0
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/hancom-gooroom-arm64-ci-marker"
cat > "$ROOTFS/etc/systemd/system/hancom-gooroom-arm64-boot-marker.service" <<'EOF'
[Unit]
Description=Hancom Gooroom ARM64 virtual-machine boot marker
ConditionVirtualization=vm
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hancom-gooroom-arm64-ci-marker
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
ln -sfn ../hancom-gooroom-arm64-boot-marker.service \
  "$ROOTFS/etc/systemd/system/multi-user.target.wants/hancom-gooroom-arm64-boot-marker.service"

python3 - "$ROOTFS" "$OUTPUT_DIR/original-vendor-sources.json" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
records = []
paths = [root / 'etc/apt/sources.list']
list_dir = root / 'etc/apt/sources.list.d'
if list_dir.exists():
    paths.extend(sorted(list_dir.glob('*.list')))
for path in paths:
    if not path.exists():
        continue
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    output = []
    changed = False
    for number, line in enumerate(lines, 1):
        if 'update.hancomgooroom.com/gooroom' in line or 'update.hancomgooroom.com/hancom' in line:
            records.append({'path': str(path.relative_to(root)), 'line': number, 'content': line})
            if line.lstrip().startswith('#'):
                output.append(line)
            else:
                output.append('# ARM64 port: vendor archive has no binary-arm64 index')
                output.append('# ' + line)
                changed = True
        else:
            output.append(line)
    if changed:
        path.write_text('\n'.join(output) + '\n', encoding='utf-8')
Path(sys.argv[2]).write_text(json.dumps(records, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
PY

cat > "$ROOTFS/etc/apt/sources.list.d/arm64-port-debian.list" <<'EOF'
# Runtime update source for the ARM64 port. The immutable image itself records
# and verifies the exact dated snapshot used during construction.
deb [arch=arm64] http://deb.debian.org/debian bullseye main contrib non-free
deb [arch=arm64] http://deb.debian.org/debian bullseye-updates main contrib non-free
deb [arch=arm64] http://security.debian.org/debian-security bullseye-security main contrib non-free
EOF
mkdir -p "$ROOTFS/usr/share/doc/hancom-gooroom-arm64"
cat > "$ROOTFS/usr/share/doc/hancom-gooroom-arm64/README" <<'EOF'
This is the ARM64 port of Hancom Gooroom 3.3.

The original Hancom/Gooroom archives expose AMD64 and Architecture: all
packages but no binary-arm64 index. Original vendor source lines are retained
as comments. Native binaries were mapped to the exact Debian version or rebuilt
from an exact source commit and verified tree.
EOF

if [ ! -d "$ROOTFS/etc/live/config.conf.d" ] || \
   ! find "$ROOTFS/etc/live/config.conf.d" -type f -print -quit 2>/dev/null | grep -q .; then
  mkdir -p "$ROOTFS/etc/live/config.conf.d"
  cat > "$ROOTFS/etc/live/config.conf.d/99-hancom-gooroom-arm64.conf" <<'EOF'
LIVE_HOSTNAME="hancom-gooroom"
LIVE_USERNAME="gooroom"
LIVE_USER_FULLNAME="Hancom Gooroom Live User"
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

cat > "$ROOTFS/tmp/finalize-hancom-arm64.sh" <<'CHROOT'
#!/bin/bash
set -Eeuo pipefail
export HOME=/root
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive

for package in live-boot live-config systemd-sysv initramfs-tools; do
  dpkg-query -W -f='${db:Status-Abbrev}\t${Version}\t${Architecture}\n' "$package"
done

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
    gtk-update-icon-cache -f -t "$theme" || true
  done < <(
    find /usr/share/icons -mindepth 1 -maxdepth 1 -type d \
      -exec test -f '{}/index.theme' ';' -print 2>/dev/null
  )
fi
if command -v fc-cache >/dev/null; then
  fc-cache -f
fi
if command -v update-ca-certificates >/dev/null; then
  update-ca-certificates
fi
if command -v ldconfig >/dev/null; then
  ldconfig
fi
systemctl enable hancom-gooroom-arm64-boot-marker.service
systemctl set-default graphical.target
update-initramfs -u -k all

dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  | sort > /tmp/final-installed-packages.tsv
systemctl list-unit-files --no-pager > /tmp/systemd-unit-files.txt || true

rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /var/tmp/*
find /tmp -mindepth 1 -maxdepth 1 \
  ! -name final-installed-packages.tsv \
  ! -name systemd-unit-files.txt \
  -exec rm -rf '{}' +
find /var/log -type f -exec truncate -s 0 '{}' + 2>/dev/null || true
CHROOT
chmod +x "$ROOTFS/tmp/finalize-hancom-arm64.sh"

set +e
chroot "$ROOTFS" /bin/bash /tmp/finalize-hancom-arm64.sh \
  > >(tee "$OUTPUT_DIR/live-finalize.log") \
  2> >(tee "$OUTPUT_DIR/live-finalize.stderr.log" >&2)
rc=$?
set -e
cp "$ROOTFS/tmp/final-installed-packages.tsv" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$ROOTFS/tmp/systemd-unit-files.txt" "$OUTPUT_DIR/" 2>/dev/null || true
rm -f \
  "$ROOTFS/tmp/finalize-hancom-arm64.sh" \
  "$ROOTFS/tmp/final-installed-packages.tsv" \
  "$ROOTFS/tmp/systemd-unit-files.txt"
if [ "$rc" -ne 0 ]; then
  exit "$rc"
fi

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
cat > "$OUTPUT_DIR/live-finalization.json" <<EOF
{
  "schema": 2,
  "architecture": "arm64",
  "kernel": $(jq -Rn --arg v "$kernel" '$v'),
  "initrd": $(jq -Rn --arg v "$initrd" '$v'),
  "boot_marker": "HANCOM_GOOROOM_3_3_ARM64_BOOT_OK",
  "vendor_amd64_sources_disabled": true,
  "default_target": "graphical.target"
}
EOF
cat "$OUTPUT_DIR/live-finalization.json"
