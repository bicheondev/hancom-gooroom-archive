#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hg-arm64-common.sh
source "$SCRIPT_DIR/hg-arm64-common.sh"

usage() {
  cat <<'EOF'
Usage:
  hg-arm64-finalize.sh \
    --source-iso Hancom-Gooroom-3.3-amd64.hybrid.iso \
    (--rootfs DIR | --rootfs-squashfs FILE) \
    [--kernel FILE] [--initrd FILE] \
    [--apt-pool DIR | --live-only] \
    --output Hancom-Gooroom-3.3-arm64.hybrid.iso \
    [--volume-id ID] [--keep-work]

The source ISO hash is locked by default. The finalizer removes x86 boot
payloads, rejects foreign ELF/packages, builds BOOTAA64.EFI and a FAT ESP,
assembles a GPT AArch64 UEFI ISO, and runs the strict validator before
promotion.
EOF
}

source_iso=''
rootfs_input=''
squashfs_input=''
kernel_input=''
initrd_input=''
apt_pool=''
output=''
volume_id="$HG_VOLUME_ID"
live_only=0
keep_work=0

while (($#)); do
  case "$1" in
    --source-iso)
      source_iso="${2:?missing value for --source-iso}"
      shift 2
      ;;
    --rootfs)
      rootfs_input="${2:?missing value for --rootfs}"
      shift 2
      ;;
    --rootfs-squashfs)
      squashfs_input="${2:?missing value for --rootfs-squashfs}"
      shift 2
      ;;
    --kernel)
      kernel_input="${2:?missing value for --kernel}"
      shift 2
      ;;
    --initrd)
      initrd_input="${2:?missing value for --initrd}"
      shift 2
      ;;
    --apt-pool)
      apt_pool="${2:?missing value for --apt-pool}"
      shift 2
      ;;
    --live-only)
      live_only=1
      shift
      ;;
    --output)
      output="${2:?missing value for --output}"
      shift 2
      ;;
    --volume-id)
      volume_id="${2:?missing value for --volume-id}"
      shift 2
      ;;
    --keep-work)
      keep_work=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      hg_die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$source_iso" && -n "$output" ]] \
  || hg_die '--source-iso and --output are required'
[[ -f "$source_iso" ]] || hg_die "source ISO does not exist: $source_iso"
if [[ -n "$rootfs_input" && -n "$squashfs_input" ]]; then
  hg_die '--rootfs and --rootfs-squashfs are mutually exclusive'
fi
if [[ -z "$rootfs_input" && -z "$squashfs_input" ]]; then
  hg_die 'one of --rootfs or --rootfs-squashfs is required'
fi
if [[ -n "$apt_pool" && "$live_only" -eq 1 ]]; then
  hg_die '--apt-pool and --live-only are mutually exclusive'
fi
[[ ${#volume_id} -le 32 ]] || hg_die 'ISO volume ID must be 32 characters or fewer'

hg_require_root
hg_require_cmd \
  xorriso mksquashfs unsquashfs grub-mkstandalone \
  dd mkfs.vfat mmd mcopy file readelf find sha256sum \
  md5sum python3 strings rsync

source_iso="$(hg_realpath "$source_iso")"
output="$(hg_realpath "$output")"
[[ "$source_iso" != "$output" ]] || hg_die 'output must differ from source ISO'
mkdir -p "$(dirname "$output")"

actual_source_sha="$(hg_sha256 "$source_iso")"
[[ "$actual_source_sha" == "$HG_SOURCE_ISO_SHA256" ]] \
  || hg_die "source ISO SHA-256 mismatch: $actual_source_sha"

if [[ -n "$rootfs_input" ]]; then
  [[ -d "$rootfs_input" ]] || hg_die "rootfs directory does not exist: $rootfs_input"
  rootfs_input="$(hg_realpath "$rootfs_input")"
else
  [[ -f "$squashfs_input" ]] || hg_die "SquashFS does not exist: $squashfs_input"
  squashfs_input="$(hg_realpath "$squashfs_input")"
fi
if [[ -n "$kernel_input" ]]; then
  [[ -f "$kernel_input" ]] || hg_die "kernel does not exist: $kernel_input"
  kernel_input="$(hg_realpath "$kernel_input")"
fi
if [[ -n "$initrd_input" ]]; then
  [[ -f "$initrd_input" ]] || hg_die "initrd does not exist: $initrd_input"
  initrd_input="$(hg_realpath "$initrd_input")"
fi
if [[ -n "$apt_pool" ]]; then
  [[ -d "$apt_pool/pool" && -d "$apt_pool/dists" ]] \
    || hg_die "APT pool is missing pool/ or dists/: $apt_pool"
  apt_pool="$(hg_realpath "$apt_pool")"
fi

work="$(hg_make_workdir hg-arm64-finalize)"
if [[ "$keep_work" -eq 0 ]]; then
  trap 'rm -rf "$work"' EXIT
else
  hg_log "keeping finalizer workspace: $work"
fi

iso_root="$work/iso-root"
rootfs="$work/rootfs"
live_dir="$iso_root/live"
esp="$work/efi.img"
candidate="$output.candidate"
failed="$output.failed"
mkdir -p "$iso_root" "$rootfs"
rm -f "$candidate" "$failed"

hg_log 'extracting the locked source ISO'
xorriso -osirrox on -indev "$source_iso" -extract / "$iso_root" \
  > "$work/source-extract.stdout" 2> "$work/source-extract.stderr"

if [[ -n "$rootfs_input" ]]; then
  hg_log 'copying ARM64 root filesystem into a controlled staging tree'
  rsync -aHAX --numeric-ids --delete "$rootfs_input/" "$rootfs/"
else
  hg_log 'extracting supplied ARM64 SquashFS'
  unsquashfs -d "$rootfs" "$squashfs_input" \
    > "$work/unsquashfs.stdout" 2> "$work/unsquashfs.stderr"
fi
[[ -d "$rootfs/etc" ]] || hg_die 'staged rootfs has no /etc directory'

foreign_elf="$work/foreign-elf.tsv"
foreign_packages="$work/foreign-packages.tsv"
if ! hg_scan_foreign_elf "$rootfs" "$foreign_elf"; then
  hg_die "rootfs contains $(wc -l < "$foreign_elf") non-AArch64 ELF files; see $foreign_elf"
fi
if ! hg_scan_dpkg_architectures "$rootfs" "$foreign_packages"; then
  hg_die "rootfs contains foreign package records; see $foreign_packages"
fi
if [[ -f "$rootfs/var/lib/dpkg/arch" ]] \
    && grep -Evq '^(arm64|all|[[:space:]]*)$' "$rootfs/var/lib/dpkg/arch"; then
  hg_die 'rootfs registers a foreign dpkg architecture'
fi

if [[ -z "$kernel_input" ]]; then
  kernel_input="$(find "$rootfs/boot" -maxdepth 1 -type f -name 'vmlinuz*' -print 2>/dev/null \
    | LC_ALL=C sort -V | tail -1)"
fi
if [[ -z "$initrd_input" ]]; then
  initrd_input="$(find "$rootfs/boot" -maxdepth 1 -type f \( -name 'initrd*' -o -name 'initramfs*' \) -print 2>/dev/null \
    | LC_ALL=C sort -V | tail -1)"
fi
[[ -n "$kernel_input" && -f "$kernel_input" ]] || hg_die 'ARM64 kernel was not supplied or found in rootfs/boot'
[[ -n "$initrd_input" && -s "$initrd_input" ]] || hg_die 'initramfs was not supplied or found in rootfs/boot'
hg_assert_arm64_kernel "$kernel_input"
if command -v lsinitramfs >/dev/null 2>&1; then
  lsinitramfs "$initrd_input" > "$work/initramfs.list" \
    || hg_die 'initramfs could not be enumerated'
  [[ -s "$work/initramfs.list" ]] || hg_die 'initramfs inventory is empty'
fi

hg_log 'removing all inherited x86 boot payloads'
rm -rf \
  "$iso_root/isolinux" \
  "$iso_root/boot/grub/i386-pc" \
  "$iso_root/boot/grub/x86_64-efi" \
  "$iso_root/EFI/BOOT/BOOTX64.EFI" \
  "$iso_root/efi/boot/bootx64.efi"
find "$iso_root" -type f \( -iname 'isolinux.bin' -o -iname 'bootx64.efi' \) -delete

if [[ -n "$apt_pool" ]]; then
  hg_log 'replacing inherited package repositories with the verified ARM64 pool'
  rm -rf "$iso_root/pool" "$iso_root/dists"
  cp -a "$apt_pool/pool" "$iso_root/pool"
  cp -a "$apt_pool/dists" "$iso_root/dists"
  if [[ -f "$apt_pool/evidence/accepted.tsv" ]] \
      && awk -F '\t' 'NR > 1 && $3 != "arm64" && $3 != "all" { bad=1 } END { exit bad ? 0 : 1 }' \
        "$apt_pool/evidence/accepted.tsv"; then
    hg_die 'APT evidence contains a foreign accepted architecture'
  fi
elif [[ "$live_only" -eq 1 ]]; then
  hg_warn 'creating a live-only image; offline installer repositories are removed'
  rm -rf "$iso_root/pool" "$iso_root/dists" "$iso_root/install"
else
  if [[ -d "$iso_root/pool" || -d "$iso_root/dists" ]]; then
    hg_die 'source ISO contains an inherited package repository; provide --apt-pool or explicitly choose --live-only'
  fi
fi

mkdir -p "$live_dir" "$iso_root/EFI/BOOT" "$iso_root/boot/grub"
rm -f "$live_dir/filesystem.squashfs" "$live_dir/filesystem.size" \
  "$live_dir/vmlinuz" "$live_dir/initrd.img"

hg_log 'building deterministic ARM64 live SquashFS'
mksquashfs "$rootfs" "$live_dir/filesystem.squashfs" \
  -noappend -comp xz -b 1048576 -no-progress \
  > "$work/mksquashfs.stdout" 2> "$work/mksquashfs.stderr"
printf '%s\n' "$(du -sx --block-size=1 "$rootfs" | awk '{print $1}')" \
  > "$live_dir/filesystem.size"
cp -a "$kernel_input" "$live_dir/vmlinuz"
cp -a "$initrd_input" "$live_dir/initrd.img"

if [[ -f "$rootfs/var/lib/dpkg/status" ]]; then
  awk '
    /^Package: / { package=$2 }
    /^Version: / { version=$2 }
    /^Architecture: / {
      architecture=$2
      print package " " version " " architecture
    }
  ' "$rootfs/var/lib/dpkg/status" | LC_ALL=C sort \
    > "$iso_root/live/filesystem.packages"
fi

cat > "$iso_root/boot/grub/grub.cfg" <<EOF
set default=0
set timeout=5

insmod all_video
insmod part_gpt
insmod fat
insmod iso9660
insmod search
insmod search_label

search --no-floppy --label --set=root $volume_id

menuentry 'Hancom Gooroom 3.3 ARM64 Live' {
    linux /live/vmlinuz boot=live components quiet splash ---
    initrd /live/initrd.img
}

menuentry 'Hancom Gooroom 3.3 ARM64 Live (safe graphics)' {
    linux /live/vmlinuz boot=live components nomodeset ---
    initrd /live/initrd.img
}
EOF

grub_mkstandalone_args=(
  -O arm64-efi
  -o "$iso_root/EFI/BOOT/BOOTAA64.EFI"
  --modules='part_gpt part_msdos fat iso9660 normal linux search search_label configfile all_video echo reboot halt'
  "boot/grub/grub.cfg=$iso_root/boot/grub/grub.cfg"
)
hg_log 'building standalone AArch64 GRUB EFI executable'
grub-mkstandalone "${grub_mkstandalone_args[@]}"
hg_assert_aarch64_pe "$iso_root/EFI/BOOT/BOOTAA64.EFI"

hg_log 'building a 64 MiB FAT32 EFI System Partition image'
dd if=/dev/zero of="$esp" bs=1M count=64 status=none
mkfs.vfat -F 32 -n HGA64EFI "$esp" >/dev/null
mmd -i "$esp" ::/EFI ::/EFI/BOOT ::/boot ::/boot/grub
mcopy -i "$esp" "$iso_root/EFI/BOOT/BOOTAA64.EFI" ::/EFI/BOOT/BOOTAA64.EFI
mcopy -i "$esp" "$iso_root/boot/grub/grub.cfg" ::/boot/grub/grub.cfg

(
  cd "$iso_root"
  find . -type f ! -name md5sum.txt -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 md5sum > md5sum.txt
)

hg_log 'assembling GPT AArch64 UEFI ISO candidate'
xorriso -as mkisofs \
  -iso-level 3 \
  -full-iso9660-filenames \
  -r -J -joliet-long \
  -V "$volume_id" \
  -o "$candidate" \
  -partition_offset 16 \
  -append_partition 2 0xef "$esp" \
  -appended_part_as_gpt \
  -e --interval:appended_partition_2:all:: \
  -no-emul-boot \
  "$iso_root" \
  > "$work/xorriso-build.stdout" 2> "$work/xorriso-build.stderr"

candidate_report="$work/candidate.validation.md"
candidate_json="$work/candidate.validation.json"
set +e
bash "$SCRIPT_DIR/hg-arm64-validate.sh" \
  --iso "$candidate" \
  --report "$candidate_report" \
  --json "$candidate_json"
validation_rc=$?
set -e
if [[ "$validation_rc" -ne 0 ]]; then
  mv -f "$candidate" "$failed"
  cp -a "$candidate_report" "$failed.validation.md" || true
  cp -a "$candidate_json" "$failed.validation.json" || true
  hg_die "candidate failed validation and was preserved as $failed"
fi

mv -f "$candidate" "$output"
cp -a "$candidate_report" "$output.validation.md"
cp -a "$candidate_json" "$output.validation.json"
hg_write_sha256_sidecar "$output"

cat > "$output.build-info.txt" <<EOF
schema=1
source_iso=$source_iso
source_iso_sha256=$actual_source_sha
rootfs_source=${rootfs_input:-$squashfs_input}
kernel=$kernel_input
kernel_sha256=$(hg_sha256 "$kernel_input")
initrd=$initrd_input
initrd_sha256=$(hg_sha256 "$initrd_input")
apt_pool=${apt_pool:-none}
live_only=$live_only
volume_id=$volume_id
output=$output
output_sha256=$(hg_sha256 "$output")
validation=passed
EOF

hg_log "final ARM64 ISO: $output"
hg_log "SHA-256: $(hg_sha256 "$output")"
