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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-$SCRIPT_DIR/../locks/reference/amd64-reference.json}"
COMPONENT_LOCK_DIR="${HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR:-$SCRIPT_DIR/../locks/source-components}"
COMPONENT_LOCK="$COMPONENT_LOCK_DIR/$SOURCE_NAME.json"

for command in jq dpkg-deb file sha256sum find grep sort stat; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done

[ -f "$LOCK_JSON" ] || {
  echo "lock file not found: $LOCK_JSON" >&2
  exit 2
}
[ -f "$REFERENCE_JSON" ] || {
  echo "AMD64 reference lock not found: $REFERENCE_JSON" >&2
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
REPOSITORY="$(jq -r '.selected.repository_full_name' <<<"$entry")"
COMMIT_SHA="$(jq -r '.selected.commit_sha' <<<"$entry")"
TREE_SHA="$(jq -r '.selected.tree_sha' <<<"$entry")"

# dpkg-buildpackage -B produces only architecture-dependent binaries. A mixed
# source can also own Architecture: all packages; those are reused byte-for-byte
# from the independently verified AMD64 reference and are not expected here.
mapfile -t EXPECTED_PACKAGES < <(jq -r \
  --arg source "$SOURCE_NAME" \
  --arg version "$SOURCE_VERSION" '
    .packages[]
    | select(
        .source == $source
        and .source_version == $version
        and .architecture != "all"
      )
    | .package
  ' "$REFERENCE_JSON" | sort -u)
[ "${#EXPECTED_PACKAGES[@]}" -gt 0 ] || {
  echo "No architecture-dependent package is required for $SOURCE_NAME $SOURCE_VERSION" >&2
  exit 2
}

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
  --arg repository "$REPOSITORY" \
  --arg commit "$COMMIT_SHA" \
  --arg tree "$TREE_SHA" '
    .source == $source
    and .source_version == $version
    and .repository == $repository
    and .commit_sha == $commit
    and .verified_commit_sha == $commit
    and .tree_sha == $tree
    and .verified_tree_sha == $tree
  ' "$OUTPUT_DIR/source-lock-evidence.json" >/dev/null

expected_json="$(printf '%s\n' "${EXPECTED_PACKAGES[@]}" | jq -Rsc 'split("\n")[:-1] | sort')"
jq -e --argjson expected "$expected_json" '
  (.expected_binary_packages | sort) == $expected
  and .binary_package_policy == "AMD64 reference packages whose Architecture is not all"
' "$OUTPUT_DIR/build-lock.json" >/dev/null

SOURCE_COMPOSITION_MODE=git-only
UPSTREAM_SOURCE_JSON=null
if [ -f "$COMPONENT_LOCK" ]; then
  SOURCE_COMPOSITION_MODE=packaging-git-plus-exact-debian-orig
  [ -f "$OUTPUT_DIR/upstream-source-evidence.json" ] || {
    echo "composite source evidence is missing for $SOURCE_NAME" >&2
    exit 3
  }
  [ -f "$OUTPUT_DIR/upstream-source-members.tsv" ] || {
    echo "composite source member report is missing for $SOURCE_NAME" >&2
    exit 3
  }

  COMPONENT_LOCK_SHA256="$(sha256sum "$COMPONENT_LOCK" | awk '{print $1}')"
  UPSTREAM_SOURCE="$(jq -er '.upstream.source' "$COMPONENT_LOCK")"
  UPSTREAM_VERSION="$(jq -er '.upstream.version' "$COMPONENT_LOCK")"
  UPSTREAM_SNAPSHOT="$(jq -er '.upstream.snapshot' "$COMPONENT_LOCK")"
  UPSTREAM_SOURCE_JSON="$(jq -cn \
    --arg source "$UPSTREAM_SOURCE" \
    --arg version "$UPSTREAM_VERSION" \
    --arg snapshot "$UPSTREAM_SNAPSHOT" '
      {source: $source, version: $version, snapshot: $snapshot}
    ')"

  jq -e \
    --arg source "$SOURCE_NAME" \
    --arg version "$SOURCE_VERSION" \
    --arg repository "$REPOSITORY" \
    --arg commit "$COMMIT_SHA" \
    --arg tree "$TREE_SHA" \
    --arg lock_sha256 "$COMPONENT_LOCK_SHA256" \
    --arg snapshot "$UPSTREAM_SNAPSHOT" \
    --slurpfile component "$COMPONENT_LOCK" '
      .verified == true
      and .source == $source
      and .source_version == $version
      and .source_component_lock_sha256 == $lock_sha256
      and .packaging.repository_full_name == $repository
      and .packaging.commit_sha == $commit
      and .packaging.tree_sha == $tree
      and .upstream.source == $component[0].upstream.source
      and .upstream.version == $component[0].upstream.version
      and .upstream.files == $component[0].upstream.files
      and .upstream.required_paths == $component[0].upstream.required_paths
      and .upstream.verified_snapshot == $snapshot
      and .upstream.required_paths_verified == true
      and .composition == $component[0].composition
    ' "$OUTPUT_DIR/upstream-source-evidence.json" >/dev/null

  jq -e \
    --arg mode "$SOURCE_COMPOSITION_MODE" \
    --arg lock_sha256 "$COMPONENT_LOCK_SHA256" \
    --arg upstream_source "$UPSTREAM_SOURCE" \
    --arg upstream_version "$UPSTREAM_VERSION" '
      .source_composition.mode == $mode
      and .source_composition.source_component_lock_sha256 == $lock_sha256
      and .source_composition.upstream_source == $upstream_source
      and .source_composition.upstream_version == $upstream_version
    ' "$OUTPUT_DIR/build-lock.json" >/dev/null

  for key in dsc orig debian; do
    expected_name="$(jq -er --arg key "$key" '.upstream.files[$key].name' "$COMPONENT_LOCK")"
    expected_size="$(jq -er --arg key "$key" '.upstream.files[$key].size' "$COMPONENT_LOCK")"
    expected_sha256="$(jq -er --arg key "$key" '.upstream.files[$key].sha256' "$COMPONENT_LOCK")"
    awk -F '\t' \
      -v key="$key" \
      -v name="$expected_name" \
      -v size="$expected_size" \
      -v sha="$expected_sha256" '
        $1 == key && $2 == name && $3 == size && $4 == sha { found = 1 }
        END { exit found ? 0 : 1 }
      ' "$OUTPUT_DIR/upstream-source-members.tsv" || {
        echo "composite source member evidence mismatch for $key" >&2
        exit 3
      }
  done
else
  jq -e '.source_composition.mode == "git-only"' \
    "$OUTPUT_DIR/build-lock.json" >/dev/null
fi

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
    echo "Expected architecture-dependent package was not built: $expected" >&2
    exit 6
  fi
done

(
  cd "$OUTPUT_DIR"
  sha256sum --check SHA256SUMS
)

produced_json="$(printf '%s\n' "${produced_packages[@]}" | jq -Rsc 'split("\n")[:-1] | sort')"
cat > "$OUTPUT_DIR/verification-summary.json" <<EOF
{
  "schema": 3,
  "source": $(jq -Rn --arg value "$SOURCE_NAME" '$value'),
  "source_version": $(jq -Rn --arg value "$SOURCE_VERSION" '$value'),
  "commit_sha": $(jq -Rn --arg value "$COMMIT_SHA" '$value'),
  "tree_sha": $(jq -Rn --arg value "$TREE_SHA" '$value'),
  "source_composition_mode": $(jq -Rn --arg value "$SOURCE_COMPOSITION_MODE" '$value'),
  "upstream_source": $UPSTREAM_SOURCE_JSON,
  "expected_architecture_dependent_packages": $expected_json,
  "produced_binary_packages": $produced_json,
  "architecture_all_policy": "reuse exact verified AMD64 Architecture: all binaries",
  "deb_count": ${#DEBS[@]},
  "wrong_architecture_executable_count": 0,
  "verified": true
}
EOF

cat "$OUTPUT_DIR/verification-summary.json"
