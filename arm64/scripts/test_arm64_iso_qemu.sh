#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 ISO OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
ISO="$1"
OUTPUT_DIR="$2"
MARKER="${HANCOM_GOOROOM_BOOT_MARKER:-HANCOM_GOOROOM_3_3_ARM64_BOOT_OK}"
TIMEOUT_SECONDS="${HANCOM_GOOROOM_QEMU_TIMEOUT:-1200}"

for command in qemu-system-aarch64 grep jq sha256sum; do
  command -v "$command" >/dev/null || {
    echo "required command missing: $command" >&2
    exit 69
  }
done
[ -f "$ISO" ]
ISO="$(cd "$(dirname "$ISO")" && pwd)/$(basename "$ISO")"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

find_firmware() {
  for path in \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    /usr/share/AAVMF/AAVMF_CODE.ms.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI-pflash.raw; do
    if [ -f "$path" ]; then
      printf '%s\n' "$path"
      return 0
    fi
  done
  return 1
}
find_vars() {
  for path in \
    /usr/share/AAVMF/AAVMF_VARS.fd \
    /usr/share/AAVMF/AAVMF_VARS.ms.fd; do
    if [ -f "$path" ]; then
      printf '%s\n' "$path"
      return 0
    fi
  done
  return 1
}

CODE="$(find_firmware)" || {
  echo 'No AArch64 UEFI firmware image was found.' >&2
  exit 70
}
VARS_TEMPLATE="$(find_vars || true)"
VARS="$OUTPUT_DIR/AAVMF_VARS.fd"
if [ -n "$VARS_TEMPLATE" ]; then
  cp "$VARS_TEMPLATE" "$VARS"
else
  truncate -s 64M "$VARS"
fi

SERIAL_LOG="$OUTPUT_DIR/serial.log"
QEMU_LOG="$OUTPUT_DIR/qemu.log"
: > "$SERIAL_LOG"
: > "$QEMU_LOG"

acceleration=( -accel tcg,thread=multi )
if [ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  acceleration=( -accel kvm )
fi

qemu_command=(
  qemu-system-aarch64
  -machine virt,gic-version=3
  -cpu max
  -smp 4
  -m 4096
  "${acceleration[@]}"
  -drive "if=pflash,format=raw,readonly=on,file=$CODE"
  -drive "if=pflash,format=raw,file=$VARS"
  -device virtio-scsi-pci,id=scsi0
  -drive "if=none,media=cdrom,readonly=on,file=$ISO,id=cdrom0"
  -device scsi-cd,drive=cdrom0
  -netdev user,id=net0
  -device virtio-net-pci,netdev=net0
  -boot order=d,menu=off
  -display none
  -monitor none
  -serial "file:$SERIAL_LOG"
  -no-reboot
  -rtc base=utc
)

printf '%q ' "${qemu_command[@]}" > "$OUTPUT_DIR/qemu-command.txt"
printf '\n' >> "$OUTPUT_DIR/qemu-command.txt"
printf '%s\n' "$CODE" > "$OUTPUT_DIR/uefi-code-path.txt"
printf '%s\n' "${acceleration[*]}" > "$OUTPUT_DIR/acceleration.txt"
sha256sum "$ISO" > "$OUTPUT_DIR/tested-iso.sha256"

set +e
"${qemu_command[@]}" > "$QEMU_LOG" 2>&1 &
qemu_pid=$!
set -e
start_epoch="$(date +%s)"
found=false
process_exit=""

while true; do
  if grep -Fq "$MARKER" "$SERIAL_LOG"; then
    found=true
    break
  fi
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    set +e
    wait "$qemu_pid"
    process_exit=$?
    set -e
    break
  fi
  now="$(date +%s)"
  if [ $((now - start_epoch)) -ge "$TIMEOUT_SECONDS" ]; then
    break
  fi
  sleep 5
done

if kill -0 "$qemu_pid" 2>/dev/null; then
  kill -TERM "$qemu_pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$qemu_pid" 2>/dev/null || break
    sleep 1
  done
  kill -KILL "$qemu_pid" 2>/dev/null || true
  set +e
  wait "$qemu_pid"
  process_exit=$?
  set -e
fi

end_epoch="$(date +%s)"
tail -n 400 "$SERIAL_LOG" > "$OUTPUT_DIR/serial-tail.log" || true
tail -n 200 "$QEMU_LOG" > "$OUTPUT_DIR/qemu-tail.log" || true

jq -n \
  --arg marker "$MARKER" \
  --arg iso "$(basename "$ISO")" \
  --arg firmware "$CODE" \
  --arg acceleration "${acceleration[*]}" \
  --arg process_exit "$process_exit" \
  --argjson marker_found "$found" \
  --argjson elapsed_seconds "$((end_epoch - start_epoch))" \
  --argjson timeout_seconds "$TIMEOUT_SECONDS" \
  '{
    schema: 1,
    architecture: "arm64",
    iso: $iso,
    firmware: $firmware,
    acceleration: $acceleration,
    marker: $marker,
    marker_found: $marker_found,
    elapsed_seconds: $elapsed_seconds,
    timeout_seconds: $timeout_seconds,
    qemu_exit_code: $process_exit,
    passed: $marker_found
  }' > "$OUTPUT_DIR/qemu-boot-result.json"
cat "$OUTPUT_DIR/qemu-boot-result.json"

if [ "$found" != true ]; then
  echo "QEMU did not observe the ARM64 boot marker." >&2
  cat "$OUTPUT_DIR/serial-tail.log" >&2 || true
  cat "$OUTPUT_DIR/qemu-tail.log" >&2 || true
  exit 2
fi
