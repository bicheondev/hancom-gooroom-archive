#!/usr/bin/env bash
set -Eeuo pipefail

HG_SOURCE_ISO_SHA256='ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a'
HG_SOURCE_ISO_BASENAME='Hancom-Gooroom-3.3-amd64.hybrid.iso'
HG_VOLUME_ID='HANCOM_GOOROOM_ARM64'

hg_log() {
  printf '[hg-arm64] %s\n' "$*" >&2
}

hg_warn() {
  printf '[hg-arm64] WARNING: %s\n' "$*" >&2
}

hg_die() {
  printf '[hg-arm64] ERROR: %s\n' "$*" >&2
  exit 1
}

hg_require_cmd() {
  local command_name
  for command_name in "$@"; do
    command -v "$command_name" >/dev/null 2>&1 \
      || hg_die "required command is unavailable: $command_name"
  done
}

hg_require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] \
    || hg_die 'this operation requires root privileges'
}

hg_sha256() {
  sha256sum "$1" | awk '{print $1}'
}

hg_realpath() {
  python3 - "$1" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
}

hg_make_workdir() {
  local prefix="${1:-hg-arm64}"
  mktemp -d -t "${prefix}.XXXXXXXX"
}

hg_file_is_elf() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  [[ "$(head -c 4 "$path" 2>/dev/null || true)" == $'\x7fELF' ]]
}

hg_elf_machine() {
  LC_ALL=C readelf -h "$1" 2>/dev/null \
    | awk -F: '/^[[:space:]]*Machine:/{sub(/^[[:space:]]+/, "", $2); print $2; exit}'
}

hg_scan_foreign_elf() {
  local root="$1"
  local output="$2"
  : > "$output"

  local path machine relative
  while IFS= read -r -d '' path; do
    hg_file_is_elf "$path" || continue
    machine="$(hg_elf_machine "$path")"
    case "$machine" in
      AArch64)
        ;;
      *)
        relative="${path#"$root"/}"
        printf '%s\t%s\n' "$relative" "${machine:-unknown}" >> "$output"
        ;;
    esac
  done < <(find "$root" -xdev -type f -print0)

  LC_ALL=C sort -u -o "$output" "$output"
  [[ ! -s "$output" ]]
}

hg_scan_dpkg_architectures() {
  local root="$1"
  local output="$2"
  local status_file="$root/var/lib/dpkg/status"
  : > "$output"

  [[ -f "$status_file" ]] || return 0

  awk '
    /^Package: / { package=$2 }
    /^Architecture: / {
      architecture=$2
      if (architecture != "arm64" && architecture != "all") {
        print package "\t" architecture
      }
    }
  ' "$status_file" | LC_ALL=C sort -u > "$output"

  [[ ! -s "$output" ]]
}

hg_assert_aarch64_pe() {
  local path="$1"
  local description
  description="$(file -b "$path")"
  [[ "$description" == *Aarch64* || "$description" == *ARM64* ]] \
    || hg_die "EFI executable is not AArch64: $path ($description)"
}

hg_assert_arm64_kernel() {
  local path="$1"
  local description
  description="$(file -b "$path")"
  if [[ "$description" == *ARM64* || "$description" == *AArch64* ]]; then
    return 0
  fi

  # Compressed Linux arm64 Image files are not consistently identified by file(1).
  if strings "$path" 2>/dev/null | grep -Eq 'Linux version|ARM64|AArch64'; then
    return 0
  fi

  hg_die "kernel does not contain recognizable ARM64 evidence: $path ($description)"
}

hg_find_first() {
  local root="$1"
  shift
  local pattern result
  for pattern in "$@"; do
    result="$(find "$root" -type f -path "$pattern" -print -quit 2>/dev/null || true)"
    if [[ -n "$result" ]]; then
      printf '%s\n' "$result"
      return 0
    fi
  done
  return 1
}

hg_write_sha256_sidecar() {
  local path="$1"
  (
    cd "$(dirname "$path")"
    sha256sum "$(basename "$path")" > "$(basename "$path").sha256"
  )
}
