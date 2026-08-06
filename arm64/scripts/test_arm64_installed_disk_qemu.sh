#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 QCOW2 OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
DISK="$1"
OUTPUT_DIR="$2"
MARKER="${HANCOM_GOOROOM_BOOT_MARKER:-HANCOM_GOOROOM_3_3_ARM64_BOOT_OK}"
TIMEOUT_SECONDS="${HANCOM_GOOROOM_QEMU_TIMEOUT:-1200}"

for command in qemu-system-aarch64 qemu-img grep jq sha256sum; do
  command -v "$command" >/dev/null || {
    echo "required command missing: $command" >&2
    exit 69
  }
done
[ -f "$DISK" ]
DISK="$(cd "$(dirname "$DISK")" && pwd)/$(basename "$DISK")"
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

qemu-img check "$DISK" > "$OUTPUT_DIR/qemu-img-check.txt"
qemu-img info --output=json "$DISK" > "$OUTPUT_DIR/qemu-img-info.json"
sha256sum "$DISK" > "$OUTPUT_DIR/tested-disk.sha256"

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
  -drive "if=none,format=qcow2,file=$DISK,id=disk0,cache=none,discard=unmap"
  -device scsi-hd,drive=disk0,bootindex=1
  -netdev user,id=net0
  -device virtio-net-pci,netdev=net0
  -boot order=c,menu=off
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
tail -n 500 "$SERIAL_LOG" > "$OUTPUT_DIR/serial-tail.log" || true
tail -n 250 "$QEMU_LOG" > "$OUTPUT_DIR/qemu-tail.log" || true

jq -n \
  --arg marker "$MARKER" \
  --arg disk "$(basename "$DISK")" \
  --arg disk_sha256 "$(sha256sum "$DISK" | awk '{print $1}')" \
  --arg firmware "$CODE" \
  --arg acceleration "${acceleration[*]}" \
  --arg process_exit "$process_exit" \
  --argjson marker_found "$found" \
  --argjson elapsed_seconds "$((end_epoch - start_epoch))" \
  --argjson timeout_seconds "$TIMEOUT_SECONDS" \
  '{
    schema: 1,
    architecture: "arm64",
    boot_medium: "installed-gpt-qcow2",
    disk: $disk,
    disk_sha256: $disk_sha256,
    firmware: $firmware,
    acceleration: $acceleration,
    marker: $marker,
    marker_found: $marker_found,
    elapsed_seconds: $elapsed_seconds,
    timeout_seconds: $timeout_seconds,
    qemu_exit_code: $process_exit,
    passed: $marker_found
  }' > "$OUTPUT_DIR/installed-boot-result.json"
cat "$OUTPUT_DIR/installed-boot-result.json"

if [ "$found" != true ]; then
  echo "QEMU did not observe the installed-system ARM64 boot marker." >&2
  cat "$OUTPUT_DIR/serial-tail.log" >&2 || true
  cat "$OUTPUT_DIR/qemu-tail.log" >&2 || true
  exit 2
fi
