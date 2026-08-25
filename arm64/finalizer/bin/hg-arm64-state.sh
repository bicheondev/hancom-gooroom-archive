#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hg-arm64-common.sh
source "$SCRIPT_DIR/hg-arm64-common.sh"

usage() {
  cat <<'EOF'
Usage:
  hg-arm64-state.sh --workspace PATH [--report PATH] [--json PATH]

Inventories ISO, SquashFS, AArch64 EFI, kernel, initramfs, and DEB candidates
without changing the workspace. The report chooses the next fail-closed step.
EOF
}

workspace=''
report=''
json=''

while (($#)); do
  case "$1" in
    --workspace)
      workspace="${2:?missing value for --workspace}"
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
    -h|--help)
      usage
      exit 0
      ;;
    *)
      hg_die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$workspace" ]] || hg_die '--workspace is required'
[[ -d "$workspace" ]] || hg_die "workspace is not a directory: $workspace"
hg_require_cmd find file sha256sum python3

workspace="$(hg_realpath "$workspace")"
report="${report:-$workspace/arm64-state-report.md}"
json="${json:-$workspace/arm64-state-report.json}"
mkdir -p "$(dirname "$report")" "$(dirname "$json")"

work="$(hg_make_workdir hg-arm64-state)"
trap 'rm -rf "$work"' EXIT
inventory="$work/inventory.tsv"
: > "$inventory"

record() {
  local kind="$1"
  local path="$2"
  local size sha description
  size="$(stat -c '%s' "$path" 2>/dev/null || stat -f '%z' "$path")"
  sha="$(hg_sha256 "$path")"
  description="$(file -b "$path" | tr '\t\n' '  ')"
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$kind" "${path#"$workspace"/}" "$size" "$sha" "$description" >> "$inventory"
}

while IFS= read -r -d '' path; do
  record iso "$path"
done < <(find "$workspace" -type f \( -iname '*.iso' -o -iname '*.img' \) -size +100M -print0)

while IFS= read -r -d '' path; do
  record squashfs "$path"
done < <(find "$workspace" -type f \( -name 'filesystem.squashfs' -o -name '*.squashfs' \) -print0)

while IFS= read -r -d '' path; do
  record efi "$path"
done < <(find "$workspace" -type f \( -iname 'BOOTAA64.EFI' -o -iname '*aa64*.efi' \) -print0)

while IFS= read -r -d '' path; do
  record kernel "$path"
done < <(find "$workspace" -type f \( -name 'vmlinuz*' -o -name 'Image' -o -name 'Image.gz' \) -print0)

while IFS= read -r -d '' path; do
  record initrd "$path"
done < <(find "$workspace" -type f \( -name 'initrd*' -o -name 'initramfs*' \) -print0)

while IFS= read -r -d '' path; do
  record deb "$path"
done < <(find "$workspace" -type f -name '*.deb' -print0)

LC_ALL=C sort -u -o "$inventory" "$inventory"

python3 - "$workspace" "$inventory" "$json" "$report" <<'PY'
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

workspace = Path(sys.argv[1])
inventory_path = Path(sys.argv[2])
json_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])

rows = []
with inventory_path.open(encoding='utf-8', newline='') as stream:
    for kind, path, size, sha256, description in csv.reader(stream, delimiter='\t'):
        rows.append({
            'kind': kind,
            'path': path,
            'size': int(size),
            'sha256': sha256,
            'description': description,
        })

counts = Counter(row['kind'] for row in rows)
arm64_efi = [
    row for row in rows
    if row['kind'] == 'efi'
    and ('Aarch64' in row['description'] or 'ARM64' in row['description'])
]
arm64_kernel = [
    row for row in rows
    if row['kind'] == 'kernel'
    and ('ARM64' in row['description'] or 'AArch64' in row['description'])
]
large_iso = [row for row in rows if row['kind'] == 'iso' and row['size'] >= 100 * 1024 * 1024]

if large_iso and arm64_efi and counts['squashfs'] and counts['initrd']:
    next_action = 'validate-existing-iso'
elif counts['squashfs'] and arm64_efi and counts['kernel'] and counts['initrd']:
    next_action = 'assemble-iso-from-existing-live-payloads'
elif counts['deb']:
    next_action = 'recover-arm64-offline-package-pool'
else:
    next_action = 'restore-build-inputs-or-rootfs'

document = {
    'schema': 1,
    'generated_at': datetime.now(timezone.utc).isoformat(),
    'workspace': str(workspace),
    'counts': dict(sorted(counts.items())),
    'next_action': next_action,
    'items': rows,
}
json_path.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')

lines = [
    '# Hancom Gooroom 3.3 ARM64 workspace state',
    '',
    f'- Generated: `{document["generated_at"]}`',
    f'- Workspace: `{workspace}`',
    f'- Next fail-closed action: **`{next_action}`**',
    '',
    '## Counts',
    '',
]
for kind in ('iso', 'squashfs', 'efi', 'kernel', 'initrd', 'deb'):
    lines.append(f'- `{kind}`: `{counts[kind]}`')
lines.extend(['', '## Inventory', '', '| Kind | Path | Bytes | SHA-256 | Identification |', '|---|---|---:|---|---|'])
for row in rows:
    description = row['description'].replace('|', '\\|')
    path = row['path'].replace('|', '\\|')
    lines.append(f'| {row["kind"]} | `{path}` | {row["size"]} | `{row["sha256"]}` | {description} |')
if not rows:
    lines.append('| — | No candidates found | 0 | — | — |')
report_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
PY

hg_log "wrote state report: $report"
hg_log "wrote machine-readable state: $json"
