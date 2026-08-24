#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

output="${1:-work/user-reference-release-source-recovery}"
timeout_seconds="${HANCOM_GOOROOM_RECOVERY_TIMEOUT:-30}"

gooroom_inrelease='arm64/locks/reference-iso-source-residue/latest/selected-text/rootfs___var__lib__apt__lists__update.hancomgooroom.com_gooroom_dists_gooroom-3.0_InRelease.txt'
hancom_inrelease='arm64/locks/reference-iso-source-residue/latest/selected-text/rootfs___var__lib__apt__lists__update.hancomgooroom.com_hancom_dists_hancom-3.0_InRelease.txt'

for path in \
  arm64/scripts/recover_exact_sources_from_reference_release.py \
  "$gooroom_inrelease" \
  "$hancom_inrelease"; do
  test -f "$path" || {
    echo "required file is missing: $path" >&2
    exit 2
  }
done

rm -rf "$output"
mkdir -p "$output"

set +e
python3 arm64/scripts/recover_exact_sources_from_reference_release.py \
  --gooroom-inrelease "$gooroom_inrelease" \
  --hancom-inrelease "$hancom_inrelease" \
  --output-dir "$output" \
  --timeout "$timeout_seconds"
recovery_rc=$?
set -e
printf '%s\n' "$recovery_rc" > "$output/user-recovery.exit-code"

bundle="${output%/}.tar.gz"
rm -f "$bundle" "$bundle.sha256"
tar -czf "$bundle" -C "$(dirname "$output")" "$(basename "$output")"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$bundle" > "$bundle.sha256"
else
  shasum -a 256 "$bundle" > "$bundle.sha256"
fi

printf '\nRecovery exit code: %s\n' "$recovery_rc"
printf 'Bundle: %s\n' "$bundle"
printf 'Checksum: %s\n' "$bundle.sha256"
if [ -f "$output/summary.json" ]; then
  printf '\nSummary:\n'
  cat "$output/summary.json"
fi

# Preserve the recovery result even when no exact index was found.  A nonzero
# exit code means the bundle contains negative evidence that is still useful.
exit 0
