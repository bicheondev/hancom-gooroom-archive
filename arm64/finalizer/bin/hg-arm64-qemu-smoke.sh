#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hg-arm64-common.sh
source "$SCRIPT_DIR/hg-arm64-common.sh"

usage() {
  cat <<'EOF'
Usage:
  hg-arm64-qemu-smoke.sh ISO [--firmware PATH] [--timeout SECONDS]
                              [--memory MiB] [--log PATH]
                              [--marker TEXT]

Boots an AArch64 ISO with UEFI and succeeds only when serial output proves that
the Linux kernel was entered. A timeout after kernel evidence is expected.
EOF
}

iso=''
firmware=''
timeout_seconds=180
memory=4096
log=''
marker=''

while (($#)); do
  case "$1" in
    --firmware)
      firmware="${2:?missing value for --firmware}"
      shift 2
      ;;
    --timeout)
      timeout_seconds="${2:?missing value for --timeout}"
      shift 2
      ;;
    --memory)
      memory="${2:?missing value for --memory}"
      shift 2
      ;;
    --log)
      log="${2:?missing value for --log}"
      shift 2
      ;;
    --marker)
      marker="${2:?missing value for --marker}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      hg_die "unknown argument: $1"
      ;;
    *)
      [[ -z "$iso" ]] || hg_die "unexpected positional argument: $1"
      iso="$1"
      shift
      ;;
  esac
done

[[ -n "$iso" && -f "$iso" ]] || hg_die 'a valid ISO path is required'
[[ "$timeout_seconds" =~ ^[0-9]+$ && "$timeout_seconds" -ge 10 ]] \
  || hg_die '--timeout must be an integer of at least 10 seconds'
[[ "$memory" =~ ^[0-9]+$ && "$memory" -ge 1024 ]] \
  || hg_die '--memory must be an integer of at least 1024 MiB'
hg_require_cmd qemu-system-aarch64 timeout grep tee uname

iso="$(hg_realpath "$iso")"
log="${log:-$iso.qemu-smoke.log}"
mkdir -p "$(dirname "$log")"

if [[ -z "$firmware" ]]; then
  for candidate in \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    /usr/share/AAVMF/AAVMF_CODE.ms.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/edk2/aarch64/QEMU_EFI.fd \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    /usr/local/share/qemu/edk2-aarch64-code.fd
  do
    if [[ -f "$candidate" ]]; then
      firmware="$candidate"
      break
    fi
  done
fi
[[ -n "$firmware" && -f "$firmware" ]] \
  || hg_die 'AArch64 UEFI firmware was not found; use --firmware'
firmware="$(hg_realpath "$firmware")"

accel=(-accel 'tcg,thread=multi' -cpu max)
case "$(uname -s)-$(uname -m)" in
  Linux-aarch64|Linux-arm64)
    if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
      accel=(-accel kvm -cpu host)
    fi
    ;;
  Darwin-arm64)
    accel=(-accel hvf -cpu host)
    ;;
esac

command_line=(
  qemu-system-aarch64
  -machine virt,gic-version=max
  "${accel[@]}"
  -smp 4
  -m "$memory"
  -bios "$firmware"
  -drive "if=none,id=cdrom,media=cdrom,format=raw,readonly=on,file=$iso"
  -device virtio-scsi-pci,id=scsi0
  -device scsi-cd,drive=cdrom,bus=scsi0.0
  -device virtio-gpu-pci
  -device qemu-xhci
  -device usb-kbd
  -device usb-tablet
  -nic user,model=virtio-net-pci
  -boot order=d,menu=on
  -display none
  -monitor none
  -serial stdio
  -no-reboot
)

printf 'firmware=%s\niso=%s\ntimeout=%s\ncommand=' \
  "$firmware" "$iso" "$timeout_seconds" > "$log"
printf '%q ' "${command_line[@]}" >> "$log"
printf '\n--- serial output ---\n' >> "$log"

set +e
timeout --signal=TERM --kill-after=10 "$timeout_seconds" \
  "${command_line[@]}" 2>&1 | tee -a "$log"
qemu_rc=${PIPESTATUS[0]}
set -e

if grep -Eqi \
  'Could not read from CDROM|No bootable device|Guest has not initialized the display|failed to load Boot|Synchronous Exception' \
  "$log"; then
  hg_die "QEMU reported a boot failure; inspect $log"
fi

kernel_evidence='EFI stub:|Booting Linux|Linux version [0-9]|Run /init as init process|Freeing unused kernel memory'
if ! grep -Eq "$kernel_evidence" "$log"; then
  hg_die "AArch64 UEFI did not produce Linux kernel-entry evidence (qemu rc=$qemu_rc); inspect $log"
fi

if [[ -n "$marker" ]] && ! grep -Fq "$marker" "$log"; then
  hg_die "required readiness marker was not observed: $marker"
fi

case "$qemu_rc" in
  0|124|137|143)
    ;;
  *)
    hg_warn "QEMU returned $qemu_rc after kernel evidence; retaining successful smoke classification"
    ;;
esac

hg_log "AArch64 UEFI reached the Linux kernel; log: $log"
