#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 CONFIG_JSON OUTPUT_DIR" >&2
  exit 64
fi

CONFIG=$1
OUTPUT=$2
WORK=${RUNNER_TEMP:-/tmp}/hancom-gooroom-v3.3-inventory
ISO_DIR=$WORK/download
ISO_TREE=$WORK/iso-tree
ROOT_META=$WORK/root-meta

rm -rf "$WORK" "$OUTPUT"
mkdir -p "$ISO_DIR" "$ISO_TREE" "$ROOT_META" "$OUTPUT"

repo=$(jq -r '.release.repository' "$CONFIG")
tag=$(jq -r '.release.tag' "$CONFIG")
asset=$(jq -r '.release.asset' "$CONFIG")
expected_size=$(jq -r '.release.size_bytes' "$CONFIG")
expected_sha=$(jq -r '.release.sha256' "$CONFIG")
iso=$ISO_DIR/$asset

: "${GH_TOKEN:?GH_TOKEN is required to download the locked release asset}"
gh release download "$tag" --repo "$repo" --pattern "$asset" --dir "$ISO_DIR" --clobber

actual_size=$(stat -c '%s' "$iso")
actual_sha=$(sha256sum "$iso" | awk '{print $1}')
if [[ "$actual_size" != "$expected_size" ]]; then
  echo "fatal: ISO size mismatch: expected=$expected_size actual=$actual_size" >&2
  exit 1
fi
if [[ "$actual_sha" != "$expected_sha" ]]; then
  echo "fatal: ISO SHA-256 mismatch: expected=$expected_sha actual=$actual_sha" >&2
  exit 1
fi

cat > "$OUTPUT/iso-lock.json" <<EOF
{
  "asset": "$asset",
  "size_bytes": $actual_size,
  "sha256": "$actual_sha"
}
EOF

xorriso -osirrox on -indev "$iso" -extract / "$ISO_TREE" \
  >"$OUTPUT/xorriso-extract.log" 2>&1
xorriso -indev "$iso" -toc >"$OUTPUT/xorriso-toc.txt" 2>&1 || true
find "$ISO_TREE" -printf '%y\t%s\t%P\n' | LC_ALL=C sort >"$OUTPUT/iso-files.tsv"

mapfile -t squashfs_records < <(
  find "$ISO_TREE" -type f \( -iname '*.squashfs' -o -iname '*.sfs' \) \
    -printf '%s\t%p\n' | sort -rn
)
if ((${#squashfs_records[@]} == 0)); then
  echo "fatal: no SquashFS root filesystem found in ISO" >&2
  exit 1
fi
printf '%s\n' "${squashfs_records[@]}" >"$OUTPUT/squashfs-images.tsv"
squashfs=${squashfs_records[0]#*$'\t'}

unsquashfs -s "$squashfs" >"$OUTPUT/squashfs-superblock.txt"
unsquashfs -ll "$squashfs" >"$OUTPUT/squashfs-files.txt"

# Extract only package, release, APT, installer, and kernel metadata. The full
# amd64 rootfs is deliberately not propagated to later ARM64 build stages.
unsquashfs -no-progress -d "$ROOT_META" "$squashfs" \
  etc/os-release usr/lib/os-release etc/debian_version etc/issue \
  etc/apt var/lib/dpkg/status var/log/installer boot \
  >"$OUTPUT/unsquashfs-metadata.log" 2>&1 || true

status=$ROOT_META/var/lib/dpkg/status
if [[ ! -s "$status" ]]; then
  echo "fatal: /var/lib/dpkg/status was not recovered from the live rootfs" >&2
  exit 1
fi
cp "$status" "$OUTPUT/dpkg-status.amd64"
python3 tools/parse-dpkg-status.py "$status" "$OUTPUT"

{
  for candidate in "$ROOT_META/etc/os-release" "$ROOT_META/usr/lib/os-release"; do
    if [[ -f "$candidate" ]]; then
      echo "### ${candidate#$ROOT_META/}"
      cat "$candidate"
      echo
    fi
  done
  if [[ -f "$ROOT_META/etc/debian_version" ]]; then
    echo "### etc/debian_version"
    cat "$ROOT_META/etc/debian_version"
    echo
  fi
} >"$OUTPUT/release-metadata.txt"

{
  if [[ -f "$ROOT_META/etc/apt/sources.list" ]]; then
    echo "### etc/apt/sources.list"
    cat "$ROOT_META/etc/apt/sources.list"
    echo
  fi
  while IFS= read -r -d '' source_file; do
    echo "### ${source_file#$ROOT_META/}"
    cat "$source_file"
    echo
  done < <(find "$ROOT_META/etc/apt/sources.list.d" -type f -print0 2>/dev/null | sort -z)
} >"$OUTPUT/apt-sources.txt"

find "$ROOT_META/boot" -printf '%y\t%s\t%P\n' 2>/dev/null | LC_ALL=C sort \
  >"$OUTPUT/boot-files.tsv" || true

mkdir -p "$OUTPUT/iso-metadata"
while IFS= read -r -d '' metadata; do
  rel=${metadata#$ISO_TREE/}
  destination=$OUTPUT/iso-metadata/$rel
  mkdir -p "$(dirname "$destination")"
  cp -a "$metadata" "$destination"
done < <(
  find "$ISO_TREE" -type f \
    \( -path '*/.disk/*' -o -iname '*manifest*' -o -iname '*packages*' -o -iname '*filesystem.size*' \) \
    -size -20M -print0
)

python3 - "$CONFIG" "$OUTPUT" "$squashfs" <<'PY'
import json
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
out = Path(sys.argv[2])
squashfs = Path(sys.argv[3])
config = json.loads(config_path.read_text(encoding="utf-8"))
package_summary = json.loads((out / "package-summary.json").read_text(encoding="utf-8"))
iso_lock = json.loads((out / "iso-lock.json").read_text(encoding="utf-8"))
summary = {
    "schema": 1,
    "product": config["product"],
    "version": config["version"],
    "base_architecture": config["base_architecture"],
    "target_architecture": config["target_architecture"],
    "source_organizations": config["source_organizations"],
    "source_version_policy": config["source_version_policy"],
    "iso": iso_lock,
    "selected_rootfs_image": squashfs.name,
    "packages": package_summary,
}
(out / "inventory-summary.json").write_text(
    json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
PY

{
  echo "## Hancom Gooroom 3.3 AMD64 inventory"
  echo
  echo "* ISO SHA-256: \`$actual_sha\`"
  echo "* ISO size: \`$actual_size\` bytes"
  echo "* Selected rootfs: \`$(basename "$squashfs")\`"
  echo
  echo '```json'
  cat "$OUTPUT/package-summary.json"
  echo '```'
  echo
  echo "### Custom package hints"
  echo '```tsv'
  head -n 80 "$OUTPUT/custom-packages.amd64.tsv"
  echo '```'
} >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
