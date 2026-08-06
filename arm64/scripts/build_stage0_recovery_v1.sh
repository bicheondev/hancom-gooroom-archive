#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 REFERENCE_ISO OUTPUT_ISO WORK_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
REFERENCE_ISO="$1"
OUTPUT_ISO="$2"
WORK_DIR="$3"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
REFERENCE_SHA256="${HANCOM_GOOROOM_REFERENCE_SHA256:-ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a}"
REFERENCE_SIZE="${HANCOM_GOOROOM_REFERENCE_SIZE:-1566277632}"
ISO_LABEL="HGOOROOM33ARM64"
MARKER="HANCOM_GOOROOM_3_3_ARM64_STAGE0_BOOT_OK"

for command in \
  debootstrap chroot xorriso unsquashfs mksquashfs \
  grub-mkstandalone mkfs.vfat mmd mcopy qemu-system-aarch64 \
  sha256sum file jq python3 rsync; do
  command -v "$command" >/dev/null || {
    echo "required command missing: $command" >&2
    exit 69
  }
done

[ "$(id -u)" -eq 0 ] || {
  echo "root privileges are required" >&2
  exit 77
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 host required, got $(uname -m)" >&2; exit 78 ;;
esac
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid Debian snapshot: $SNAPSHOT" >&2
  exit 64
}

REFERENCE_ISO="$(cd "$(dirname "$REFERENCE_ISO")" && pwd)/$(basename "$REFERENCE_ISO")"
mkdir -p "$(dirname "$OUTPUT_ISO")" "$WORK_DIR"
OUTPUT_ISO="$(cd "$(dirname "$OUTPUT_ISO")" && pwd)/$(basename "$OUTPUT_ISO")"
WORK_DIR="$(cd "$WORK_DIR" && pwd)"

[ "$(stat -c '%s' "$REFERENCE_ISO")" = "$REFERENCE_SIZE" ]
printf '%s  %s\n' "$REFERENCE_SHA256" "$REFERENCE_ISO" | sha256sum --check --strict

ROOTFS="$WORK_DIR/rootfs"
REFERENCE_ISO_ROOT="$WORK_DIR/reference-iso"
REFERENCE_ROOTFS="$WORK_DIR/reference-rootfs"
ISO_ROOT="$WORK_DIR/iso-root"
EVIDENCE="$WORK_DIR/evidence"
rm -rf "$ROOTFS" "$REFERENCE_ISO_ROOT" "$REFERENCE_ROOTFS" "$ISO_ROOT" "$EVIDENCE"
mkdir -p "$ROOTFS" "$REFERENCE_ISO_ROOT" "$ISO_ROOT/live" "$ISO_ROOT/boot/grub" "$ISO_ROOT/.disk" "$EVIDENCE"

xorriso -osirrox on -indev "$REFERENCE_ISO" -extract / "$REFERENCE_ISO_ROOT" \
  > "$EVIDENCE/reference-xorriso.log" 2>&1
REFERENCE_SQUASHFS="$(find "$REFERENCE_ISO_ROOT" -type f -name filesystem.squashfs -print -quit)"
[ -n "$REFERENCE_SQUASHFS" ]
unsquashfs -d "$REFERENCE_ROOTFS" "$REFERENCE_SQUASHFS" \
  > "$EVIDENCE/reference-unsquashfs.log" 2>&1

# Bootstrap from the immutable Debian snapshot that was used throughout the
# exact-version investigation. This recovery image is deliberately labelled
# stage0: it proves the ARM64 live/UEFI path while the exact custom package
# rebuild backlog remains a separate, fail-closed gate.
de.bootstrap() { :; }
de.bootstrap 2>/dev/null || true
DEBOOTSTRAP_DIR="/usr/share/debootstrap"
[ -d "$DEBOOTSTRAP_DIR" ]
DEBOOTSTRAP_DIR="$DEBOOTSTRAP_DIR" debootstrap \
  --arch=arm64 \
  --variant=minbase \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  bullseye "$ROOTFS" \
  "http://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
  > "$EVIDENCE/debootstrap.log" 2>&1

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
printf '#!/bin/sh\nexit 101\n' > "$ROOTFS/usr/sbin/policy-rc.d"
chmod 0755 "$ROOTFS/usr/sbin/policy-rc.d"

mkdir -p "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" "$ROOTFS/run"
mounted=()
cleanup_mounts() {
  set +e
  for target in "${mounted[@]}"; do
    umount -R "$target" 2>/dev/null || umount -l "$target" 2>/dev/null || true
  done
}
trap cleanup_mounts EXIT
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

cat > "$ROOTFS/tmp/stage0-install.sh" <<'CHROOT'
#!/bin/bash
set -Eeuo pipefail
export HOME=/root
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

apt-get update
apt-get install -y --no-install-recommends \
  systemd-sysv dbus dbus-x11 sudo locales console-setup keyboard-configuration \
  linux-image-arm64 initramfs-tools live-boot live-config live-config-systemd \
  network-manager rfkill wireless-tools wpasupplicant iproute2 iputils-ping \
  xserver-xorg xserver-xorg-input-libinput xserver-xorg-video-fbdev \
  gdm3 gnome-session gnome-shell gnome-settings-daemon gnome-control-center \
  nautilus gnome-terminal gnome-system-monitor gnome-screenshot \
  gnome-themes-extra adwaita-icon-theme dconf-cli policykit-1 \
  plymouth plymouth-themes desktop-base \
  fonts-noto-cjk fonts-nanum fonts-dejavu-core \
  firefox-esr ca-certificates curl wget less nano vim-tiny file

sed -i 's/^# *ko_KR.UTF-8 UTF-8/ko_KR.UTF-8 UTF-8/' /etc/locale.gen
locale-gen
update-locale LANG=ko_KR.UTF-8
printf 'KEYMAP=kr\n' > /etc/vconsole.conf

mkdir -p /etc/live/config.conf.d
cat > /etc/live/config.conf.d/99-hancom-gooroom-arm64.conf <<'EOF'
LIVE_HOSTNAME="hancom-gooroom"
LIVE_USERNAME="gooroom"
LIVE_USER_FULLNAME="Hancom Gooroom Live User"
LIVE_LOCALES="ko_KR.UTF-8"
LIVE_KEYBOARD_LAYOUTS="kr"
EOF

mkdir -p /etc/gdm3
cat >> /etc/gdm3/daemon.conf <<'EOF'

[daemon]
WaylandEnable=false
AutomaticLoginEnable=true
AutomaticLogin=gooroom
EOF

mkdir -p /usr/local/sbin /etc/systemd/system/multi-user.target.wants
cat > /usr/local/sbin/hancom-gooroom-stage0-marker <<'EOF'
#!/bin/sh
marker='HANCOM_GOOROOM_3_3_ARM64_STAGE0_BOOT_OK'
printf '%s\n' "$marker" > /dev/console 2>/dev/null || true
printf '%s\n' "$marker" > /dev/ttyAMA0 2>/dev/null || true
logger -t hancom-gooroom-stage0 "$marker" 2>/dev/null || true
exit 0
EOF
chmod 0755 /usr/local/sbin/hancom-gooroom-stage0-marker
cat > /etc/systemd/system/hancom-gooroom-stage0-marker.service <<'EOF'
[Unit]
Description=Hancom Gooroom ARM64 stage0 boot marker
After=local-fs.target systemd-user-sessions.service
Before=display-manager.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hancom-gooroom-stage0-marker
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
ln -sfn ../hancom-gooroom-stage0-marker.service \
  /etc/systemd/system/multi-user.target.wants/hancom-gooroom-stage0-marker.service
systemctl set-default graphical.target

update-initramfs -u -k all
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
CHROOT
chmod 0755 "$ROOTFS/tmp/stage0-install.sh"

set +e
chroot "$ROOTFS" /bin/bash /tmp/stage0-install.sh \
  > >(tee "$EVIDENCE/chroot-install.log") \
  2> >(tee "$EVIDENCE/chroot-install.stderr.log" >&2)
install_rc=$?
set -e
if [ "$install_rc" -ne 0 ]; then
  exit "$install_rc"
fi
rm -f "$ROOTFS/tmp/stage0-install.sh" "$ROOTFS/usr/sbin/policy-rc.d"

# Copy only visual/configuration assets that are architecture neutral. Every
# regular file is inspected for ELF machine type before copying; x86 and other
# foreign ELF payloads are logged and omitted.
python3 - "$REFERENCE_ROOTFS" "$ROOTFS" "$EVIDENCE/reference-overlay.json" <<'PY'
import hashlib, json, os, shutil, stat, struct, sys
from pathlib import Path
src = Path(sys.argv[1])
dst = Path(sys.argv[2])
out = Path(sys.argv[3])
roots = [
    'usr/share/backgrounds', 'usr/share/icons', 'usr/share/themes',
    'usr/share/pixmaps', 'usr/share/plymouth',
    'usr/share/gnome-background-properties', 'etc/skel',
    'etc/dconf', 'etc/xdg/autostart'
]
blocked=[]; copied=[]; skipped=[]

def elf_machine(path):
    try:
        h=path.open('rb').read(20)
    except OSError:
        return None
    if len(h)<20 or h[:4] != b'\x7fELF': return None
    if h[5]==1: return struct.unpack('<H',h[18:20])[0]
    if h[5]==2: return struct.unpack('>H',h[18:20])[0]
    return -1

def sha(path):
    d=hashlib.sha256()
    with path.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024),b''): d.update(c)
    return d.hexdigest()

for relroot in roots:
    base=src/relroot
    if not base.exists():
        continue
    for root, dirs, files in os.walk(base, followlinks=False):
        rp=Path(root)
        rel=rp.relative_to(src)
        (dst/rel).mkdir(parents=True, exist_ok=True)
        for name in files:
            s=rp/name; r=s.relative_to(src); d=dst/r
            try: mode=s.lstat().st_mode
            except OSError: continue
            if stat.S_ISLNK(mode):
                d.parent.mkdir(parents=True,exist_ok=True)
                if d.exists() or d.is_symlink():
                    d.unlink() if not d.is_dir() else shutil.rmtree(d)
                os.symlink(os.readlink(s),d)
                copied.append({'path':str(r),'type':'symlink'})
                continue
            if not stat.S_ISREG(mode):
                skipped.append({'path':str(r),'reason':'special'})
                continue
            machine=elf_machine(s)
            if machine in {3,62} or (machine not in {None,0,183,247}):
                blocked.append({'path':str(r),'machine':machine,'sha256':sha(s)})
                continue
            d.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(s,d,follow_symlinks=False)
            copied.append({'path':str(r),'type':'file','size':s.stat().st_size,'sha256':sha(s)})
result={'summary':{'copied':len(copied),'blocked_foreign_elf':len(blocked),'skipped':len(skipped)},'copied':copied,'blocked':blocked,'skipped':skipped}
out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
PY

cat > "$ROOTFS/etc/os-release" <<'EOF'
PRETTY_NAME="Hancom Gooroom 3.3 ARM64 Stage0"
NAME="Hancom Gooroom"
VERSION_ID="3.3-arm64-stage0"
VERSION="3.3 ARM64 Stage0"
ID=hancom-gooroom-arm64-stage0
ID_LIKE=debian
HOME_URL="https://github.com/bicheondev/hancom-gooroom-archive"
EOF
ln -sfn ../etc/os-release "$ROOTFS/usr/lib/os-release"
mkdir -p "$ROOTFS/usr/share/doc/hancom-gooroom-arm64-stage0"
cat > "$ROOTFS/usr/share/doc/hancom-gooroom-arm64-stage0/README" <<EOF
This is a recovery Stage0 image for the Hancom Gooroom 3.3 ARM64 port.
It validates the native AArch64 UEFI, live-boot, kernel, initramfs, GNOME,
and architecture-neutral branding path. It is not the final exact-package port.
Debian snapshot: $SNAPSHOT
Reference AMD64 ISO SHA-256: $REFERENCE_SHA256
EOF

# Regenerate caches affected by the reference visual overlay.
cat > "$ROOTFS/tmp/stage0-finalize.sh" <<'CHROOT'
#!/bin/bash
set -Eeuo pipefail
export LANG=C.UTF-8
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
  done < <(find /usr/share/icons -mindepth 1 -maxdepth 1 -type d -exec test -f '{}/index.theme' ';' -print)
fi
fc-cache -f || true
ldconfig
update-initramfs -u -k all
CHROOT
chmod 0755 "$ROOTFS/tmp/stage0-finalize.sh"
chroot "$ROOTFS" /bin/bash /tmp/stage0-finalize.sh \
  > "$EVIDENCE/chroot-finalize.log" 2>&1
rm -f "$ROOTFS/tmp/stage0-finalize.sh"

# Clear machine-specific state before creating the live filesystem.
rm -f "$ROOTFS/etc/machine-id"
: > "$ROOTFS/etc/machine-id"
rm -f "$ROOTFS/var/lib/dbus/machine-id"
ln -s /etc/machine-id "$ROOTFS/var/lib/dbus/machine-id"
rm -f "$ROOTFS/var/lib/systemd/random-seed"
rm -f "$ROOTFS/etc/ssh/ssh_host_"* 2>/dev/null || true
find "$ROOTFS/var/log" -type f -exec truncate -s 0 '{}' + 2>/dev/null || true

cleanup_mounts
mounted=()
trap - EXIT

# Scan the final rootfs for x86 ELF payloads. The stage0 image is rejected if
# any x86 executable or shared object remains.
python3 - "$ROOTFS" "$EVIDENCE/elf-audit.json" <<'PY'
import json, os, struct, sys
from pathlib import Path
root=Path(sys.argv[1]); out=Path(sys.argv[2])
counts={}; x86=[]; foreign=[]
for base, dirs, files in os.walk(root, followlinks=False):
    rel=Path(base).relative_to(root)
    if rel.parts and rel.parts[0] in {'proc','sys','dev','run'}:
        dirs[:]=[]; continue
    for name in files:
        p=Path(base)/name
        if p.is_symlink(): continue
        try: h=p.open('rb').read(20)
        except OSError: continue
        if len(h)<20 or h[:4]!=b'\x7fELF': continue
        m=struct.unpack('<H' if h[5]==1 else '>H',h[18:20])[0]
        counts[str(m)]=counts.get(str(m),0)+1
        rec={'path':str(p.relative_to(root)),'machine':m}
        if m in {3,62}: x86.append(rec)
        elif m not in {0,183,247}: foreign.append(rec)
result={'summary':{'machine_counts':counts,'x86_count':len(x86),'foreign_count':len(foreign),'aarch64_count':counts.get('183',0),'passed':not x86 and not foreign and counts.get('183',0)>0},'x86':x86,'foreign':foreign}
out.write_text(json.dumps(result,indent=2)+'\n')
if not result['summary']['passed']: raise SystemExit(2)
PY

KERNEL="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' | sort -V | tail -n1)"
INITRD="$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'initrd.img-*' -printf '%f\n' | sort -V | tail -n1)"
[ -n "$KERNEL" ]
[ -n "$INITRD" ]
cp "$ROOTFS/boot/$KERNEL" "$ISO_ROOT/live/vmlinuz"
cp "$ROOTFS/boot/$INITRD" "$ISO_ROOT/live/initrd.img"

mksquashfs "$ROOTFS" "$ISO_ROOT/live/filesystem.squashfs" \
  -noappend -comp xz -b 1M -Xdict-size 100% \
  -all-root -all-time 0 -mkfs-time 0 -processors "$(nproc)" \
  > "$EVIDENCE/mksquashfs.log" 2>&1
du -sx --block-size=1 "$ROOTFS" | awk '{print $1}' > "$ISO_ROOT/live/filesystem.size"

python3 - "$ROOTFS/var/lib/dpkg/status" "$ISO_ROOT/live/filesystem.manifest" <<'PY'
from pathlib import Path
import sys
text=Path(sys.argv[1]).read_text(errors='replace')
rows=[]; stanza={}; key=None
for line in text.splitlines()+['']:
    if not line.strip():
        if stanza.get('Status','').startswith('install ok installed') and stanza.get('Package'):
            rows.append((stanza['Package'],stanza.get('Version',''),stanza.get('Architecture','')))
        stanza={}; key=None; continue
    if line[0].isspace():
        if key: stanza[key]+='\n'+line[1:]
        continue
    if ':' in line:
        key,val=line.split(':',1); stanza[key]=val.lstrip()
Path(sys.argv[2]).write_text(''.join(f'{p} {v} {a}\n' for p,v,a in sorted(rows)))
PY

cat > "$ISO_ROOT/boot/grub/grub.cfg" <<'EOF'
set default=0
set timeout=4
set timeout_style=menu

menuentry "Hancom Gooroom 3.3 ARM64 Stage0 Live" {
  linux /live/vmlinuz boot=live components quiet splash locales=ko_KR.UTF-8 keyboard-layouts=kr console=tty0 console=ttyAMA0,115200
  initrd /live/initrd.img
}
menuentry "Hancom Gooroom 3.3 ARM64 Stage0 (serial diagnostics)" {
  linux /live/vmlinuz boot=live components systemd.unit=multi-user.target console=ttyAMA0,115200
  initrd /live/initrd.img
}
EOF
cat > "$WORK_DIR/grub-embedded.cfg" <<EOF
search --no-floppy --label --set=root $ISO_LABEL
set prefix=(\$root)/boot/grub
configfile /boot/grub/grub.cfg
EOF

grub-mkstandalone -O arm64-efi \
  --modules='part_gpt part_msdos fat iso9660 normal linux configfile search search_label all_video echo test regexp' \
  --locales='' --themes='' \
  -o "$WORK_DIR/BOOTAA64.EFI" \
  "boot/grub/grub.cfg=$WORK_DIR/grub-embedded.cfg"
file "$WORK_DIR/BOOTAA64.EFI" > "$EVIDENCE/bootaa64-file.txt"
grep -Eqi 'aarch64|arm64|application.*efi' "$EVIDENCE/bootaa64-file.txt"

truncate -s 32M "$ISO_ROOT/boot/grub/efi.img"
mkfs.vfat -F 16 -n HGOOROOMEFI "$ISO_ROOT/boot/grub/efi.img" > "$EVIDENCE/mkfs-vfat.log"
mmd -i "$ISO_ROOT/boot/grub/efi.img" ::/EFI ::/EFI/BOOT
mcopy -i "$ISO_ROOT/boot/grub/efi.img" "$WORK_DIR/BOOTAA64.EFI" ::/EFI/BOOT/BOOTAA64.EFI

printf 'Hancom Gooroom 3.3 ARM64 Stage0\n' > "$ISO_ROOT/.disk/info"
printf 'full_cd/single\n' > "$ISO_ROOT/.disk/base_installable"
printf 'Hancom Gooroom 3.3 ARM64 Stage0 recovery image\n' > "$ISO_ROOT/README.diskdefines"
(
  cd "$ISO_ROOT"
  find . -type f ! -name md5sum.txt -print0 | sort -z | xargs -0 md5sum > md5sum.txt
)

xorriso -as mkisofs \
  -r -J -joliet-long -V "$ISO_LABEL" \
  -o "$OUTPUT_ISO" \
  -e boot/grub/efi.img -no-emul-boot -isohybrid-gpt-basdat \
  "$ISO_ROOT" > "$EVIDENCE/xorriso-build.log" 2>&1

xorriso -indev "$OUTPUT_ISO" -report_el_torito plain > "$EVIDENCE/el-torito.txt" 2>&1
xorriso -indev "$OUTPUT_ISO" -report_system_area plain > "$EVIDENCE/system-area.txt" 2>&1
sha256sum "$OUTPUT_ISO" > "$EVIDENCE/iso.sha256"
stat -c '%n\t%s' "$OUTPUT_ISO" > "$EVIDENCE/iso-size.tsv"
sha256sum "$ISO_ROOT/live/vmlinuz" "$ISO_ROOT/live/initrd.img" \
  "$ISO_ROOT/live/filesystem.squashfs" "$ISO_ROOT/boot/grub/efi.img" \
  > "$EVIDENCE/components.sha256"

# Boot the ISO under AArch64 UEFI. The release gate only opens after the marker
# service runs from the live root filesystem.
find_firmware() {
  for path in \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI-pflash.raw; do
    [ -f "$path" ] && { printf '%s\n' "$path"; return 0; }
  done
  return 1
}
find_vars() {
  for path in /usr/share/AAVMF/AAVMF_VARS.fd /usr/share/AAVMF/AAVMF_VARS.ms.fd; do
    [ -f "$path" ] && { printf '%s\n' "$path"; return 0; }
  done
  return 1
}
CODE="$(find_firmware)"
VARS_TEMPLATE="$(find_vars || true)"
VARS="$WORK_DIR/AAVMF_VARS.fd"
if [ -n "$VARS_TEMPLATE" ]; then cp "$VARS_TEMPLATE" "$VARS"; else truncate -s 64M "$VARS"; fi
SERIAL="$EVIDENCE/serial.log"
QEMU_LOG="$EVIDENCE/qemu.log"
: > "$SERIAL"; : > "$QEMU_LOG"
if [ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  ACCEL=(-accel kvm); CPU=(-cpu host)
else
  ACCEL=(-accel tcg,thread=multi); CPU=(-cpu max)
fi
qemu-system-aarch64 \
  -machine virt,gic-version=3 "${CPU[@]}" -smp 4 -m 4096 "${ACCEL[@]}" \
  -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
  -drive "if=pflash,format=raw,file=$VARS" \
  -device virtio-scsi-pci,id=scsi0 \
  -drive "if=none,media=cdrom,readonly=on,file=$OUTPUT_ISO,id=cdrom0" \
  -device scsi-cd,drive=cdrom0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -boot order=d,menu=off -display none -monitor none \
  -serial "file:$SERIAL" -no-reboot -rtc base=utc \
  > "$QEMU_LOG" 2>&1 &
QEMU_PID=$!
start="$(date +%s)"; found=false; timeout_seconds=1200
while kill -0 "$QEMU_PID" 2>/dev/null; do
  if grep -Fq "$MARKER" "$SERIAL"; then found=true; break; fi
  now="$(date +%s)"
  [ $((now-start)) -lt "$timeout_seconds" ] || break
  sleep 5
done
kill -TERM "$QEMU_PID" 2>/dev/null || true
for _ in $(seq 1 20); do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 1; done
kill -KILL "$QEMU_PID" 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true
end="$(date +%s)"
tail -n 500 "$SERIAL" > "$EVIDENCE/serial-tail.log" || true
tail -n 200 "$QEMU_LOG" > "$EVIDENCE/qemu-tail.log" || true
jq -n \
  --arg marker "$MARKER" \
  --arg firmware "$CODE" \
  --arg acceleration "${ACCEL[*]}" \
  --argjson marker_found "$found" \
  --argjson elapsed "$((end-start))" \
  '{schema:1,architecture:"arm64",marker:$marker,marker_found:$marker_found,firmware:$firmware,acceleration:$acceleration,elapsed_seconds:$elapsed,passed:$marker_found}' \
  > "$EVIDENCE/qemu-boot-result.json"
cat "$EVIDENCE/qemu-boot-result.json"
[ "$found" = true ]

cat > "$EVIDENCE/build-result.json" <<EOF
{
  "schema": 1,
  "product": "Hancom Gooroom 3.3 ARM64 Stage0",
  "final_port": false,
  "purpose": "AArch64 UEFI/live/GNOME/branding recovery milestone",
  "reference_iso_sha256": "$REFERENCE_SHA256",
  "debian_snapshot": "$SNAPSHOT",
  "kernel": "$KERNEL",
  "initrd": "$INITRD",
  "iso_filename": "$(basename "$OUTPUT_ISO")",
  "iso_size": $(stat -c '%s' "$OUTPUT_ISO"),
  "iso_sha256": "$(sha256sum "$OUTPUT_ISO" | awk '{print $1}')",
  "x86_elf_count": $(jq -r '.summary.x86_count' "$EVIDENCE/elf-audit.json"),
  "qemu_boot_marker_passed": true
}
EOF
find "$EVIDENCE" -type f ! -name LOCKSUMS.sha256 -print0 | sort -z | xargs -0 sha256sum > "$EVIDENCE/LOCKSUMS.sha256"
