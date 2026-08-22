#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hg-arm64-common.sh
source "$SCRIPT_DIR/hg-arm64-common.sh"

usage() {
  cat <<'EOF'
Usage:
  hg-arm64-validate.sh --iso PATH [--report PATH] [--json PATH] [--keep-work]
  hg-arm64-validate.sh PATH

Validates ISO size, GPT/El Torito metadata, AArch64 EFI, ARM64 kernel,
initramfs, SquashFS extraction, dpkg architectures, and every ELF in rootfs.
EOF
}

iso=''
report=''
json=''
keep_work=0

while (($#)); do
  case "$1" in
    --iso)
      iso="${2:?missing value for --iso}"
      shift 2
      ;;
    --report)
      report="${2:?missing value for --report}"
      shift 2
      ;;
    --json)
      json="${2:?missing value for --json}"
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

[[ -n "$iso" ]] || hg_die 'an ISO path is required'
[[ -f "$iso" ]] || hg_die "ISO does not exist: $iso"
hg_require_cmd xorriso unsquashfs file readelf find sha256sum python3 strings

iso="$(hg_realpath "$iso")"
report="${report:-$iso.validation.md}"
json="${json:-$iso.validation.json}"
work="$(hg_make_workdir hg-arm64-validate)"
if [[ "$keep_work" -eq 0 ]]; then
  trap 'rm -rf "$work"' EXIT
else
  hg_log "keeping validation workspace: $work"
fi

iso_root="$work/iso"
rootfs="$work/rootfs"
mkdir -p "$iso_root" "$rootfs"
reasons="$work/reasons.txt"
checks="$work/checks.tsv"
foreign_elf="$work/foreign-elf.tsv"
foreign_packages="$work/foreign-packages.tsv"
: > "$reasons"
: > "$checks"
: > "$foreign_elf"
: > "$foreign_packages"

record_check() {
  local name="$1" status="$2" detail="$3"
  printf '%s\t%s\t%s\n' "$name" "$status" "${detail//$'\t'/ }" >> "$checks"
}

fail_check() {
  local name="$1" detail="$2"
  record_check "$name" FAIL "$detail"
  printf '%s: %s\n' "$name" "$detail" >> "$reasons"
}

pass_check() {
  record_check "$1" PASS "$2"
}

iso_size="$(stat -c '%s' "$iso")"
if ((iso_size >= 100 * 1024 * 1024)); then
  pass_check iso-size "$iso_size bytes"
else
  fail_check iso-size "$iso_size bytes; expected at least 100 MiB"
fi

iso_sha="$(hg_sha256 "$iso")"
pass_check iso-sha256 "$iso_sha"

set +e
xorriso -indev "$iso" -report_el_torito as_mkisofs \
  > "$work/el-torito.txt" 2> "$work/el-torito.stderr"
el_torito_rc=$?
xorriso -indev "$iso" -report_system_area plain \
  > "$work/system-area.txt" 2> "$work/system-area.stderr"
system_area_rc=$?
xorriso -osirrox on -indev "$iso" -extract / "$iso_root" \
  > "$work/extract.stdout" 2> "$work/extract.stderr"
extract_rc=$?
set -e

if [[ "$el_torito_rc" -eq 0 ]] && grep -Eqi 'efi|platform_id=0xef|-e ' "$work/el-torito.txt"; then
  pass_check el-torito-efi 'EFI boot catalog entry found'
else
  fail_check el-torito-efi "missing EFI El Torito evidence (rc=$el_torito_rc)"
fi

if [[ "$system_area_rc" -eq 0 ]] && grep -Eqi 'GPT|GUID Partition Table|Protective MBR' "$work/system-area.txt"; then
  pass_check gpt-system-area 'GPT/protective system-area evidence found'
else
  fail_check gpt-system-area "missing GPT system-area evidence (rc=$system_area_rc)"
fi

if [[ "$extract_rc" -eq 0 ]]; then
  pass_check iso-extraction 'xorriso extracted the complete ISO tree'
else
  fail_check iso-extraction "xorriso extraction failed (rc=$extract_rc)"
fi

bootaa64="$(find "$iso_root" -type f -iname 'BOOTAA64.EFI' -print -quit 2>/dev/null || true)"
if [[ -n "$bootaa64" ]]; then
  efi_description="$(file -b "$bootaa64")"
  if [[ "$efi_description" == *Aarch64* || "$efi_description" == *ARM64* ]]; then
    pass_check bootaa64 "$efi_description"
  else
    fail_check bootaa64 "not AArch64: $efi_description"
  fi
else
  fail_check bootaa64 'EFI/BOOT/BOOTAA64.EFI not found'
fi

x86_boot="$work/x86-boot-paths.txt"
find "$iso_root" \( \
  -iname 'BOOTX64.EFI' -o \
  -path '*/i386-pc/*' -o \
  -path '*/x86_64-efi/*' -o \
  -path '*/isolinux/*' -o \
  -iname 'isolinux.bin' \
\) -print | LC_ALL=C sort -u > "$x86_boot"
if [[ -s "$x86_boot" ]]; then
  fail_check x86-boot-remnants "$(wc -l < "$x86_boot") x86 boot paths remain"
else
  pass_check x86-boot-remnants 'none'
fi

kernel="$(hg_find_first "$iso_root" '*/live/vmlinuz' '*/live/vmlinuz-*' '*/casper/vmlinuz' '*/boot/vmlinuz-*' || true)"
if [[ -n "$kernel" ]]; then
  kernel_description="$(file -b "$kernel")"
  if [[ "$kernel_description" == *ARM64* || "$kernel_description" == *AArch64* ]] \
      || strings "$kernel" 2>/dev/null | grep -Eq 'Linux version|ARM64|AArch64'; then
    pass_check arm64-kernel "${kernel#"$iso_root"/}: $kernel_description"
  else
    fail_check arm64-kernel "unrecognized architecture: $kernel_description"
  fi
else
  fail_check arm64-kernel 'live kernel not found'
fi

initrd="$(hg_find_first "$iso_root" '*/live/initrd.img' '*/live/initrd*' '*/casper/initrd*' '*/boot/initrd*' || true)"
if [[ -n "$initrd" && -s "$initrd" ]]; then
  initrd_description="$(file -b "$initrd")"
  if command -v lsinitramfs >/dev/null 2>&1; then
    set +e
    lsinitramfs "$initrd" > "$work/initramfs.list" 2> "$work/initramfs.stderr"
    initrd_rc=$?
    set -e
    if [[ "$initrd_rc" -eq 0 && -s "$work/initramfs.list" ]]; then
      pass_check initramfs "${initrd#"$iso_root"/}: $initrd_description"
    else
      fail_check initramfs "lsinitramfs failed (rc=$initrd_rc): $initrd_description"
    fi
  else
    pass_check initramfs "nonempty payload; lsinitramfs unavailable: $initrd_description"
  fi
else
  fail_check initramfs 'live initramfs not found or empty'
fi

squashfs="$(hg_find_first "$iso_root" '*/live/filesystem.squashfs' '*/casper/filesystem.squashfs' '*/*.squashfs' || true)"
if [[ -n "$squashfs" ]]; then
  set +e
  unsquashfs -d "$rootfs" "$squashfs" \
    > "$work/unsquashfs.stdout" 2> "$work/unsquashfs.stderr"
  unsquashfs_rc=$?
  set -e
  if [[ "$unsquashfs_rc" -eq 0 && -d "$rootfs/etc" ]]; then
    pass_check squashfs-extraction "${squashfs#"$iso_root"/}"
  else
    fail_check squashfs-extraction "unsquashfs failed or rootfs incomplete (rc=$unsquashfs_rc)"
  fi
else
  fail_check squashfs-extraction 'filesystem.squashfs not found'
fi

if [[ -d "$rootfs/etc" ]]; then
  if hg_scan_foreign_elf "$rootfs" "$foreign_elf"; then
    pass_check foreign-elf '0 non-AArch64 ELF files'
  else
    fail_check foreign-elf "$(wc -l < "$foreign_elf") non-AArch64 ELF files"
  fi

  if hg_scan_dpkg_architectures "$rootfs" "$foreign_packages"; then
    pass_check foreign-packages '0 installed foreign-architecture packages'
  else
    fail_check foreign-packages "$(wc -l < "$foreign_packages") foreign package records"
  fi

  if [[ -f "$rootfs/var/lib/dpkg/arch" ]] \
      && grep -Evq '^(arm64|all|[[:space:]]*)$' "$rootfs/var/lib/dpkg/arch"; then
    fail_check dpkg-foreign-architectures 'foreign architecture registered in var/lib/dpkg/arch'
  else
    pass_check dpkg-foreign-architectures 'none registered'
  fi
fi

passed=true
[[ ! -s "$reasons" ]] || passed=false

python3 - "$iso" "$iso_size" "$iso_sha" "$checks" "$reasons" \
  "$foreign_elf" "$foreign_packages" "$x86_boot" "$json" "$report" "$passed" <<'PY'
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

(
    iso, iso_size, iso_sha, checks_path, reasons_path, foreign_elf_path,
    foreign_packages_path, x86_boot_path, json_path, report_path, passed,
) = sys.argv[1:]

def read_lines(path: str):
    p = Path(path)
    return p.read_text(encoding='utf-8', errors='replace').splitlines() if p.exists() else []

checks = []
with Path(checks_path).open(encoding='utf-8', newline='') as stream:
    for name, status, detail in csv.reader(stream, delimiter='\t'):
        checks.append({'name': name, 'status': status, 'detail': detail})

document = {
    'schema': 1,
    'generated_at': datetime.now(timezone.utc).isoformat(),
    'iso': iso,
    'iso_size': int(iso_size),
    'iso_sha256': iso_sha,
    'passed': passed == 'true',
    'checks': checks,
    'reasons': read_lines(reasons_path),
    'foreign_elf': read_lines(foreign_elf_path),
    'foreign_packages': read_lines(foreign_packages_path),
    'x86_boot_paths': read_lines(x86_boot_path),
}
Path(json_path).write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')

lines = [
    '# Hancom Gooroom 3.3 ARM64 ISO validation',
    '',
    f'- Generated: `{document["generated_at"]}`',
    f'- ISO: `{iso}`',
    f'- Bytes: `{iso_size}`',
    f'- SHA-256: `{iso_sha}`',
    f'- Result: **{"PASS" if document["passed"] else "FAIL"}**',
    '',
    '## Checks',
    '',
    '| Check | Result | Detail |',
    '|---|---|---|',
]
for check in checks:
    detail = check['detail'].replace('|', '\\|')
    lines.append(f'| `{check["name"]}` | **{check["status"]}** | {detail} |')
lines.extend(['', '## Failure reasons', ''])
if document['reasons']:
    lines.extend(f'- {reason}' for reason in document['reasons'])
else:
    lines.append('- None')
for title, key in (
    ('Foreign ELF evidence', 'foreign_elf'),
    ('Foreign package evidence', 'foreign_packages'),
    ('x86 boot remnants', 'x86_boot_paths'),
):
    lines.extend(['', f'## {title}', ''])
    values = document[key]
    if values:
        lines.append('```text')
        lines.extend(values)
        lines.append('```')
    else:
        lines.append('- None')
Path(report_path).write_text('\n'.join(lines) + '\n', encoding='utf-8')
PY

hg_log "validation report: $report"
hg_log "validation JSON: $json"
if [[ "$passed" == true ]]; then
  hg_log 'ISO validation passed'
  exit 0
fi
hg_die 'ISO validation failed; inspect the report and evidence files'
