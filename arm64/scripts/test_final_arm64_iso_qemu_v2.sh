#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 ISO OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
ISO="$1"
OUTPUT_DIR="$2"
BOOT_MARKER="HANCOM_GOOROOM_3_3_ARM64_FINAL_BOOT_OK"
GRAPHICAL_MARKER="HANCOM_GOOROOM_3_3_ARM64_FINAL_GRAPHICAL_OK"
INSTALLER_MARKER="HANCOM_GOOROOM_3_3_ARM64_INSTALLER_PRESENT"
TIMEOUT_SECONDS="${HANCOM_GOOROOM_QEMU_TIMEOUT:-1800}"

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

find_code() {
  for path in \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    /usr/share/AAVMF/AAVMF_CODE.ms.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI-pflash.raw; do
    [ -f "$path" ] && printf '%s\n' "$path" && return 0
  done
  return 1
}
find_vars() {
  for path in \
    /usr/share/AAVMF/AAVMF_VARS.fd \
    /usr/share/AAVMF/AAVMF_VARS.ms.fd; do
    [ -f "$path" ] && printf '%s\n' "$path" && return 0
  done
  return 1
}
CODE="$(find_code)" || { echo "AArch64 UEFI firmware missing" >&2; exit 70; }
VARS_TEMPLATE="$(find_vars || true)"
VARS="$OUTPUT_DIR/AAVMF_VARS.fd"
if [ -n "$VARS_TEMPLATE" ]; then cp "$VARS_TEMPLATE" "$VARS"; else truncate -s 64M "$VARS"; fi
SERIAL="$OUTPUT_DIR/serial.log"
QEMU_LOG="$OUTPUT_DIR/qemu.log"
: > "$SERIAL"; : > "$QEMU_LOG"

if [ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  acceleration=( -accel kvm -cpu host )
else
  acceleration=( -accel tcg,thread=multi -cpu max )
fi
qemu=(
  qemu-system-aarch64
  -machine virt,gic-version=3
  "${acceleration[@]}"
  -smp 6 -m 6144
  -drive "if=pflash,format=raw,readonly=on,file=$CODE"
  -drive "if=pflash,format=raw,file=$VARS"
  -device virtio-gpu-pci
  -device qemu-xhci
  -device usb-kbd
  -device usb-tablet
  -device virtio-scsi-pci,id=scsi0
  -drive "if=none,media=cdrom,readonly=on,file=$ISO,id=cdrom0"
  -device scsi-cd,drive=cdrom0
  -netdev user,id=net0
  -device virtio-net-pci,netdev=net0
  -boot order=d,menu=off
  -display none
  -monitor none
  -serial "file:$SERIAL"
  -no-reboot
  -rtc base=utc
)
printf '%q ' "${qemu[@]}" > "$OUTPUT_DIR/qemu-command.txt"
printf '\n' >> "$OUTPUT_DIR/qemu-command.txt"
printf '%s\n' "$CODE" > "$OUTPUT_DIR/uefi-code-path.txt"
printf '%s\n' "${acceleration[*]}" > "$OUTPUT_DIR/acceleration.txt"
sha256sum "$ISO" > "$OUTPUT_DIR/tested-iso.sha256"

"${qemu[@]}" > "$QEMU_LOG" 2>&1 &
pid=$!
start="$(date +%s)"
boot=false
graphical=false
installer=false
process_exit=''
while true; do
  grep -Fq "$BOOT_MARKER" "$SERIAL" && boot=true || true
  grep -Fq "$GRAPHICAL_MARKER" "$SERIAL" && graphical=true || true
  grep -Fq "$INSTALLER_MARKER" "$SERIAL" && installer=true || true
  if [ "$boot" = true ] && [ "$graphical" = true ]; then break; fi
  if ! kill -0 "$pid" 2>/dev/null; then
    set +e; wait "$pid"; process_exit=$?; set -e
    break
  fi
  now="$(date +%s)"
  [ $((now - start)) -lt "$TIMEOUT_SECONDS" ] || break
  sleep 5
done

if kill -0 "$pid" 2>/dev/null; then
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  kill -KILL "$pid" 2>/dev/null || true
  set +e; wait "$pid"; process_exit=$?; set -e
fi
end="$(date +%s)"
tail -n 600 "$SERIAL" > "$OUTPUT_DIR/serial-tail.log" || true
tail -n 300 "$QEMU_LOG" > "$OUTPUT_DIR/qemu-tail.log" || true

jq -n \
  --arg iso "$(basename "$ISO")" \
  --arg firmware "$CODE" \
  --arg acceleration "${acceleration[*]}" \
  --arg boot_marker "$BOOT_MARKER" \
  --arg graphical_marker "$GRAPHICAL_MARKER" \
  --arg installer_marker "$INSTALLER_MARKER" \
  --arg process_exit "$process_exit" \
  --argjson boot_marker_found "$boot" \
  --argjson graphical_marker_found "$graphical" \
  --argjson installer_marker_found "$installer" \
  --argjson elapsed_seconds "$((end-start))" \
  --argjson timeout_seconds "$TIMEOUT_SECONDS" \
  '{
    schema:2,
    architecture:"arm64",
    iso:$iso,
    firmware:$firmware,
    acceleration:$acceleration,
    boot_marker:$boot_marker,
    graphical_marker:$graphical_marker,
    installer_marker:$installer_marker,
    boot_marker_found:$boot_marker_found,
    graphical_marker_found:$graphical_marker_found,
    installer_marker_found:$installer_marker_found,
    elapsed_seconds:$elapsed_seconds,
    timeout_seconds:$timeout_seconds,
    qemu_exit_code:$process_exit,
    passed:($boot_marker_found and $graphical_marker_found)
  }' > "$OUTPUT_DIR/qemu-boot-result.json"
cat "$OUTPUT_DIR/qemu-boot-result.json"
if [ "$boot" != true ] || [ "$graphical" != true ]; then
  echo "Final ARM64 live ISO did not reach both boot and graphical markers." >&2
  cat "$OUTPUT_DIR/serial-tail.log" >&2 || true
  cat "$OUTPUT_DIR/qemu-tail.log" >&2 || true
  exit 2
fi
