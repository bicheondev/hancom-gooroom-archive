#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 LOCK_JSON SOURCE_NAME OUTPUT_DIR" >&2
  echo "set HANCOM_GOOROOM_VENDOR_PACKAGES to a comma/space separated list" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
LOCK_JSON="$1"
SOURCE_NAME="$2"
OUTPUT_DIR="$3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_BUILDER="$SCRIPT_DIR/build_locked_source_arm64.sh"
LEGACY_WRAPPER="$SCRIPT_DIR/run_locked_source_arm64.sh"
SCHEMA_WRAPPER="$SCRIPT_DIR/run_locked_source_arm64_v4.sh"
COMPOSITE_HELPER="${HANCOM_GOOROOM_COMPOSITE_SOURCE_HELPER:-$SCRIPT_DIR/prepare_composite_source_chroot.sh}"
COMPONENT_LOCK_DIR="${HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR:-$SCRIPT_DIR/../locks/source-components}"
VENDOR_LOCK="${HANCOM_GOOROOM_VENDOR_LOCK:-$SCRIPT_DIR/../locks/vendor-binaries/vendor-binary-lock.json}"
VENDOR_PACKAGES_RAW="${HANCOM_GOOROOM_VENDOR_PACKAGES:-}"

for command in jq curl dpkg-deb dpkg-scanpackages sha256sum gzip python3 stat; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done
[ -f "$LOCK_JSON" ] || { echo "source lock not found: $LOCK_JSON" >&2; exit 69; }
[ -f "$BASE_BUILDER" ] || { echo "base builder not found: $BASE_BUILDER" >&2; exit 69; }
[ -f "$LEGACY_WRAPPER" ] || { echo "legacy compatibility wrapper not found: $LEGACY_WRAPPER" >&2; exit 69; }
[ -f "$SCHEMA_WRAPPER" ] || { echo "schema compatibility wrapper not found: $SCHEMA_WRAPPER" >&2; exit 69; }
[ -f "$COMPOSITE_HELPER" ] || { echo "composite source helper not found: $COMPOSITE_HELPER" >&2; exit 69; }
[ -d "$COMPONENT_LOCK_DIR" ] || { echo "source component lock directory not found: $COMPONENT_LOCK_DIR" >&2; exit 69; }
[ -f "$VENDOR_LOCK" ] || { echo "vendor binary lock not found: $VENDOR_LOCK" >&2; exit 69; }
[ -n "$VENDOR_PACKAGES_RAW" ] || usage

COMPOSITE_HELPER="$(readlink -f "$COMPOSITE_HELPER")"
COMPONENT_LOCK_DIR="$(readlink -f "$COMPONENT_LOCK_DIR")"
OUTPUT_DIR_ABS="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
VENDOR_REPO="$WORK_DIR/vendor-repo"
BUILDER_DIR="$WORK_DIR/builder"
EVIDENCE_LINES="$WORK_DIR/vendor-evidence.jsonl"
mkdir -p "$VENDOR_REPO" "$BUILDER_DIR"
: > "$EVIDENCE_LINES"

# Accept either commas or whitespace, reject all shell-significant package names,
# and de-duplicate deterministically.
mapfile -t VENDOR_PACKAGES < <(
  tr ',\t ' '\n\n\n' <<<"$VENDOR_PACKAGES_RAW" \
    | sed '/^$/d' \
    | LC_ALL=C sort -u
)
[ "${#VENDOR_PACKAGES[@]}" -gt 0 ] || usage

for package in "${VENDOR_PACKAGES[@]}"; do
  [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || {
    echo "invalid vendor package name: $package" >&2
    exit 2
  }

  matches="$(jq -c --arg package "$package" '[
    .packages[]
    | select(
        .package == $package
        and .status == "verified"
        and .architecture == "all"
      )
  ]' "$VENDOR_LOCK")"
  count="$(jq 'length' <<<"$matches")"
  [ "$count" -eq 1 ] || {
    echo "expected one verified Architecture: all lock for $package; found $count" >&2
    exit 2
  }
  entry="$(jq -c '.[0]' <<<"$matches")"

  version="$(jq -r '.version' <<<"$entry")"
  architecture="$(jq -r '.architecture' <<<"$entry")"
  url="$(jq -r '.url' <<<"$entry")"
  filename="$(jq -r '.local_filename' <<<"$entry")"
  expected_size="$(jq -r '.actual_size' <<<"$entry")"
  expected_sha256="$(jq -r '.actual_sha256' <<<"$entry")"
  index_package="$(jq -r '.selected.Package' <<<"$entry")"
  index_version="$(jq -r '.selected.Version' <<<"$entry")"
  index_architecture="$(jq -r '.selected.Architecture' <<<"$entry")"
  index_size="$(jq -r '.selected.Size' <<<"$entry")"
  index_sha256="$(jq -r '.selected.SHA256' <<<"$entry")"

  [ "$index_package" = "$package" ] || { echo "vendor index package mismatch" >&2; exit 3; }
  [ "$index_version" = "$version" ] || { echo "vendor index version mismatch" >&2; exit 3; }
  [ "$architecture" = all ] && [ "$index_architecture" = all ] || {
    echo "vendor dependency is not Architecture: all: $package" >&2
    exit 3
  }
  [ "$index_size" = "$expected_size" ] || { echo "vendor index size mismatch" >&2; exit 3; }
  [ "$index_sha256" = "$expected_sha256" ] || { echo "vendor index SHA256 mismatch" >&2; exit 3; }
  [[ "$filename" =~ ^[A-Za-z0-9][A-Za-z0-9+_.~-]*\.deb$ ]] || {
    echo "invalid locked vendor filename: $filename" >&2
    exit 3
  }
  case "$url" in
    http://update.hancomgooroom.com/*|https://update.hancomgooroom.com/*) ;;
    *) echo "unexpected vendor URL: $url" >&2; exit 3 ;;
  esac

  destination="$VENDOR_REPO/$filename"
  curl --fail --location --retry 5 --retry-all-errors \
    --connect-timeout 30 --max-time 600 \
    --output "$destination" "$url"
  actual_size="$(stat -c '%s' "$destination")"
  actual_sha256="$(sha256sum "$destination" | awk '{print $1}')"
  [ "$actual_size" = "$expected_size" ] || {
    echo "downloaded size mismatch for $package: $actual_size != $expected_size" >&2
    exit 4
  }
  [ "$actual_sha256" = "$expected_sha256" ] || {
    echo "downloaded SHA256 mismatch for $package" >&2
    exit 4
  }

  control_package="$(dpkg-deb -f "$destination" Package)"
  control_version="$(dpkg-deb -f "$destination" Version)"
  control_architecture="$(dpkg-deb -f "$destination" Architecture)"
  [ "$control_package" = "$package" ] || { echo "DEB package mismatch" >&2; exit 4; }
  [ "$control_version" = "$version" ] || { echo "DEB version mismatch" >&2; exit 4; }
  [ "$control_architecture" = all ] || { echo "DEB architecture mismatch" >&2; exit 4; }

  jq -n \
    --arg package "$package" \
    --arg version "$version" \
    --arg architecture "$architecture" \
    --arg url "$url" \
    --arg filename "$filename" \
    --arg sha256 "$actual_sha256" \
    --argjson size "$actual_size" \
    '{
      package: $package,
      version: $version,
      architecture: $architecture,
      url: $url,
      filename: $filename,
      size: $size,
      sha256: $sha256
    }' >> "$EVIDENCE_LINES"
done

(
  cd "$VENDOR_REPO"
  dpkg-scanpackages . /dev/null > Packages
  gzip -n -9 -c Packages > Packages.gz
  sha256sum ./*.deb Packages Packages.gz | LC_ALL=C sort -k2 > REPOSITORY-SHA256SUMS
)

# Preserve the checked-in generic builder and both compatibility layers. The
# v4 wrapper adapts the legacy asserted transformations to the current
# build-lock schema; calling the legacy wrapper directly would fail before the
# exact vendor repository is ever used.
cp "$BASE_BUILDER" "$BUILDER_DIR/build_locked_source_arm64.sh"
cp "$LEGACY_WRAPPER" "$BUILDER_DIR/run_locked_source_arm64.sh"
cp "$SCHEMA_WRAPPER" "$BUILDER_DIR/run_locked_source_arm64_v4.sh"
chmod +x "$BUILDER_DIR/"*.sh

python3 - "$BUILDER_DIR/build_locked_source_arm64.sh" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")

anchor = '''BOOTSTRAP_IMAGE="${HANCOM_GOOROOM_BOOTSTRAP_IMAGE:-arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"
'''
replacement = anchor + '''VENDOR_REPO="${HANCOM_GOOROOM_VENDOR_REPO:-}"
[ -d "$VENDOR_REPO" ] || {
  echo "verified local vendor repository is missing: $VENDOR_REPO" >&2
  exit 69
}
'''
if source.count(anchor) != 1:
    raise SystemExit(f"expected one bootstrap-image anchor, found {source.count(anchor)}")
source = source.replace(anchor, replacement)

chroot_anchor = '''cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"

mkdir -p "$ROOT/build/source" "$ROOT/build/output"
'''
chroot_replacement = '''cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"

mkdir -p "$ROOT/opt/hancom-gooroom-vendor-repo"
cp -a /vendor-repo/. "$ROOT/opt/hancom-gooroom-vendor-repo/"
cat > "$ROOT/etc/apt/sources.list.d/99hancom-gooroom-vendor-local.list" <<'EOF'
deb [trusted=yes] file:/opt/hancom-gooroom-vendor-repo ./
EOF

mkdir -p "$ROOT/build/source" "$ROOT/build/output"
'''
if source.count(chroot_anchor) != 1:
    raise SystemExit(f"expected one chroot-copy anchor, found {source.count(chroot_anchor)}")
source = source.replace(chroot_anchor, chroot_replacement)

docker_anchor = '''  --volume "$SOURCE_ROOT:/src:ro" \\
'''
docker_replacement = '''  --volume "$SOURCE_ROOT:/src:ro" \\
  --volume "$VENDOR_REPO:/vendor-repo:ro" \\
'''
if source.count(docker_anchor) != 1:
    raise SystemExit(f"expected one Docker source mount, found {source.count(docker_anchor)}")
source = source.replace(docker_anchor, docker_replacement)

path.write_text(source, encoding="utf-8")
PY

export HANCOM_GOOROOM_VENDOR_REPO="$VENDOR_REPO"
export HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR="$COMPONENT_LOCK_DIR"
export HANCOM_GOOROOM_COMPOSITE_SOURCE_HELPER="$COMPOSITE_HELPER"
"$BUILDER_DIR/run_locked_source_arm64_v4.sh" "$LOCK_JSON" "$SOURCE_NAME" "$OUTPUT_DIR_ABS"

jq -s \
  --arg source "$SOURCE_NAME" \
  --arg vendor_lock "$(readlink -f "$VENDOR_LOCK")" \
  '{
    schema: 1,
    policy: "exact-verified-architecture-all-vendor-build-dependencies",
    source: $source,
    vendor_lock: $vendor_lock,
    packages: .
  }' "$EVIDENCE_LINES" > "$OUTPUT_DIR_ABS/vendor-build-dependencies.json"

find "$OUTPUT_DIR_ABS" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 sha256sum \
  > "$OUTPUT_DIR_ABS/SHA256SUMS"
cat "$OUTPUT_DIR_ABS/vendor-build-dependencies.json"
