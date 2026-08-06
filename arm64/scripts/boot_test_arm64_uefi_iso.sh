#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 ISO OUTPUT_LOG READINESS_MARKER TIMEOUT_SECONDS [MEMORY_MIB] [CPUS]" >&2
  exit 64
}

[ "$#" -ge 4 ] && [ "$#" -le 6 ] || usage
ISO="$(readlink -f "$1")"
OUTPUT_LOG="$2"
READINESS_MARKER="$3"
TIMEOUT_SECONDS="$4"
MEMORY_MIB="${5:-2048}"
CPUS="${6:-2}"

[ -f "$ISO" ] || {
  echo "ISO is missing: $ISO" >&2
  exit 66
}
[[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]]
[[ "$MEMORY_MIB" =~ ^[1-9][0-9]*$ ]]
[[ "$CPUS" =~ ^[1-9][0-9]*$ ]]
command -v qemu-system-aarch64 >/dev/null || {
  echo "qemu-system-aarch64 is missing" >&2
  exit 69
}

mkdir -p "$(dirname "$OUTPUT_LOG")"
OUTPUT_LOG="$(readlink -f "$OUTPUT_LOG")"

# Prefer the non-Secure-Boot AAVMF pair deterministically. `find | head` may
# select a Microsoft/Secure-Boot code image with an incompatible VARS template,
# depending on package traversal order.
CODE=""
for candidate in \
  /usr/share/AAVMF/AAVMF_CODE.fd \
  /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
  /usr/share/qemu-efi-aarch64/QEMU_EFI-pflash.raw; do
  if [ -f "$candidate" ]; then
    CODE="$candidate"
    break
  fi
done
if [ -z "$CODE" ]; then
  CODE="$(find /usr/share/AAVMF /usr/share/qemu-efi-aarch64 \
    -type f \( -iname 'AAVMF_CODE*.fd' -o -iname 'QEMU_EFI*.fd' \) \
    2>/dev/null | sort | head -n1)"
fi

VARS=""
for candidate in \
  /usr/share/AAVMF/AAVMF_VARS.fd \
  /usr/share/qemu-efi-aarch64/QEMU_VARS.fd; do
  if [ -f "$candidate" ]; then
    VARS="$candidate"
    break
  fi
done
if [ -z "$VARS" ]; then
  VARS="$(find /usr/share/AAVMF /usr/share/qemu-efi-aarch64 \
    -type f -iname 'AAVMF_VARS*.fd' 2>/dev/null | sort | head -n1)"
fi

[ -n "$CODE" ] || {
  echo "ARM64 UEFI firmware code image is missing" >&2
  exit 69
}

accel=tcg
cpu=max
if [ -c /dev/kvm ]; then
  accel=kvm
  cpu=host
fi
qemu=(
  qemu-system-aarch64
  -machine "virt,gic-version=3,accel=$accel"
  -cpu "$cpu"
  -smp "$CPUS"
  -m "$MEMORY_MIB"
  -nographic
  -monitor none
  -serial stdio
  # AAVMF already contains the virtio drivers. Ubuntu's QEMU package does not
  # ship efi-virtio.rom, so explicitly disable optional PCI expansion ROMs
  # instead of failing before firmware can inspect the ISO.
  -device virtio-rng-pci,romfile=
  -drive "if=none,id=cdrom,media=cdrom,format=raw,readonly=on,file=$ISO"
  -device virtio-scsi-pci,id=scsi0,romfile=
  -device scsi-cd,drive=cdrom,bus=scsi0.0,bootindex=0
  -boot order=d,menu=off,strict=on
  -no-reboot
)
if [ -n "$VARS" ]; then
  vars_copy="$(dirname "$OUTPUT_LOG")/AAVMF_VARS.$$.fd"
  cp "$VARS" "$vars_copy"
  qemu+=(
    -drive "if=pflash,format=raw,readonly=on,file=$CODE"
    -drive "if=pflash,format=raw,file=$vars_copy"
  )
else
  vars_copy=""
  qemu+=( -bios "$CODE" )
fi

# Preserve the exact virtual-machine invocation and firmware identity even when
# QEMU exits before writing guest serial output.
printf '%q ' "${qemu[@]}" > "$OUTPUT_LOG.command.txt"
printf '\n' >> "$OUTPUT_LOG.command.txt"
printf 'code=%s\nvars=%s\naccel=%s\ncpu=%s\n' \
  "$CODE" "${VARS:-}" "$accel" "$cpu" > "$OUTPUT_LOG.firmware.txt"

cleanup() {
  set +e
  if [ -n "${qemu_pid:-}" ]; then
    kill -- "-$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
  [ -z "$vars_copy" ] || rm -f "$vars_copy"
}
trap cleanup EXIT INT TERM

: > "$OUTPUT_LOG"
setsid "${qemu[@]}" > "$OUTPUT_LOG" 2>&1 &
qemu_pid=$!
found=false
for _ in $(seq 1 "$TIMEOUT_SECONDS"); do
  if grep -Fq "$READINESS_MARKER" "$OUTPUT_LOG"; then
    found=true
    break
  fi
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    break
  fi
  sleep 1
done
kill -- "-$qemu_pid" 2>/dev/null || true
wait "$qemu_pid" 2>/dev/null || true
qemu_pid=""
tail -n 400 "$OUTPUT_LOG"
[ "$found" = true ] || {
  echo "readiness marker not found: $READINESS_MARKER" >&2
  exit 12
}
