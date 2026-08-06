#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 LOCK_JSON SOURCE_NAME OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
LOCK_JSON="$1"
SOURCE_NAME="$2"
OUTPUT_DIR="$3"

for command in jq dpkg-deb file sha256sum find grep sort; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done

[ -f "$LOCK_JSON" ] || {
  echo "lock file not found: $LOCK_JSON" >&2
  exit 2
}
[ -d "$OUTPUT_DIR" ] || {
  echo "build output directory not found: $OUTPUT_DIR" >&2
  exit 2
}

entry="$(jq -ce --arg source "$SOURCE_NAME" '
  .sources[]
  | select(
      .source == $source
      and .role == "rebuild-arm64"
      and .status == "resolved"
      and .selected != null
      and (.selected.type // "git") == "git"
    )
' "$LOCK_JSON" | head -n1)"
[ -n "$entry" ] || {
  echo "No resolved Git ARM64 rebuild lock for $SOURCE_NAME" >&2
  exit 2
}

SOURCE_VERSION="$(jq -r '.source_version' <<<"$entry")"
COMMIT_SHA="$(jq -r '.selected.commit_sha' <<<"$entry")"
TREE_SHA="$(jq -r '.selected.tree_sha' <<<"$entry")"
mapfile -t EXPECTED_PACKAGES < <(jq -r '.binary_packages[]' <<<"$entry")

jq -e \
  --arg source "$SOURCE_NAME" \
  --arg version "$SOURCE_VERSION" '
    .source == $source
    and .source_version == $version
    and .target_architecture == "arm64"
    and .build_mode == "native-arm64-historical-chroot-binary-arch"
  ' "$OUTPUT_DIR/build-lock.json" >/dev/null

jq -e \
  --arg source "$SOURCE_NAME" \
  --arg version "$SOURCE_VERSION" \
  --arg commit "$COMMIT_SHA" \
  --arg tree "$TREE_SHA" '
    .source == $source
    and .source_version == $version
    and .commit_sha == $commit
    and .verified_commit_sha == $commit
    and .tree_sha == $tree
    and .verified_tree_sha == $tree
  ' "$OUTPUT_DIR/source-lock-evidence.json" >/dev/null

shopt -s nullglob
DEBS=("$OUTPUT_DIR"/*.deb)
[ "${#DEBS[@]}" -gt 0 ] || {
  echo "No DEB output was produced for $SOURCE_NAME" >&2
  exit 4
}

produced_packages=()
report_dir="$OUTPUT_DIR/file-reports"
mkdir -p "$report_dir"

for deb in "${DEBS[@]}"; do
  package="$(dpkg-deb -f "$deb" Package)"
  version="$(dpkg-deb -f "$deb" Version)"
  architecture="$(dpkg-deb -f "$deb" Architecture)"

  [ "$version" = "$SOURCE_VERSION" ] || {
    echo "version mismatch in $(basename "$deb"): $version != $SOURCE_VERSION" >&2
    exit 5
  }
  case "$architecture" in
    arm64|all) ;;
    *)
      echo "unexpected architecture in $(basename "$deb"): $architecture" >&2
      exit 5
      ;;
  esac

  root="$(mktemp -d)"
  dpkg-deb -x "$deb" "$root"
  report="$report_dir/$(basename "$deb").txt"
  find "$root" -type f -exec file -- '{}' + | sort > "$report"
  if grep -E \
      'ELF (32|64)-bit .* (x86-64|Intel 80386)|PE32(\+)? executable .* (x86-64|Intel 80386)' \
      "$report"; then
    echo "x86 executable leaked into $(basename "$deb")" >&2
    rm -rf "$root"
    exit 5
  fi
  rm -rf "$root"
  produced_packages+=("$package")
done

for expected in "${EXPECTED_PACKAGES[@]}"; do
  found=false
  for produced in "${produced_packages[@]}"; do
    if [ "$produced" = "$expected" ]; then
      found=true
      break
    fi
  done
  if [ "$found" != true ]; then
    echo "Expected binary package was not built: $expected" >&2
    exit 6
  fi
done

(
  cd "$OUTPUT_DIR"
  sha256sum --check SHA256SUMS
)

expected_json="$(printf '%s\n' "${EXPECTED_PACKAGES[@]}" | jq -Rsc 'split("\n")[:-1]')"
produced_json="$(printf '%s\n' "${produced_packages[@]}" | jq -Rsc 'split("\n")[:-1] | sort')"
cat > "$OUTPUT_DIR/verification-summary.json" <<EOF
{
  "schema": 1,
  "source": $(jq -Rn --arg value "$SOURCE_NAME" '$value'),
  "source_version": $(jq -Rn --arg value "$SOURCE_VERSION" '$value'),
  "commit_sha": $(jq -Rn --arg value "$COMMIT_SHA" '$value'),
  "tree_sha": $(jq -Rn --arg value "$TREE_SHA" '$value'),
  "expected_binary_packages": $expected_json,
  "produced_binary_packages": $produced_json,
  "deb_count": ${#DEBS[@]},
  "wrong_architecture_executable_count": 0,
  "verified": true
}
EOF

cat "$OUTPUT_DIR/verification-summary.json"
