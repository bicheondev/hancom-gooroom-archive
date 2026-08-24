#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 LOCK_JSON SOURCE_NAME OUTPUT_DIR" >&2
  echo "set HANCOM_GOOROOM_LOCAL_DEB_DIR and HANCOM_GOOROOM_LOCAL_SOURCE" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
LOCK_JSON="$1"
SOURCE_NAME="$2"
OUTPUT_DIR="$3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_BUILDER="$SCRIPT_DIR/build_locked_source_arm64_v2.sh"
REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-$SCRIPT_DIR/../locks/reference/amd64-reference.json}"
LOCAL_DEB_DIR="${HANCOM_GOOROOM_LOCAL_DEB_DIR:-}"
LOCAL_SOURCE_NAME="${HANCOM_GOOROOM_LOCAL_SOURCE:-}"
LOCAL_REQUIRED_PACKAGES_RAW="${HANCOM_GOOROOM_LOCAL_REQUIRED_PACKAGES:-}"
SOURCE_VERSION_RE='\(([^)]+)\)'

for command in \
  jq dpkg-deb dpkg-scanpackages sha256sum gzip python3 stat find \
  awk sort sed tr readlink; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done
[ -f "$LOCK_JSON" ] || {
  echo "source lock not found: $LOCK_JSON" >&2
  exit 69
}
[ -f "$BASE_BUILDER" ] || {
  echo "base builder not found: $BASE_BUILDER" >&2
  exit 69
}
[ -f "$REFERENCE_JSON" ] || {
  echo "AMD64 reference lock not found: $REFERENCE_JSON" >&2
  exit 69
}
[ -d "$LOCAL_DEB_DIR" ] || usage
[[ "$LOCAL_SOURCE_NAME" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || usage

LOCK_JSON="$(readlink -f "$LOCK_JSON")"
REFERENCE_JSON="$(readlink -f "$REFERENCE_JSON")"
LOCAL_DEB_DIR="$(readlink -f "$LOCAL_DEB_DIR")"
OUTPUT_DIR_ABS="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
LOCAL_REPO="$WORK_DIR/local-repo"
EVIDENCE_LINES="$WORK_DIR/local-evidence.jsonl"
mkdir -p "$LOCAL_REPO"
: > "$EVIDENCE_LINES"

local_entry="$(jq -c --arg source "$LOCAL_SOURCE_NAME" '
  .sources[]
  | select(.source == $source and .status == "resolved" and .selected != null)
' "$LOCK_JSON")"
[ "$(grep -c . <<<"$local_entry")" -eq 1 ] || {
  echo "expected one resolved exact source lock for local dependency $LOCAL_SOURCE_NAME" >&2
  exit 2
}
LOCAL_SOURCE_VERSION="$(jq -r '.source_version' <<<"$local_entry")"
LOCAL_REPOSITORY="$(jq -r '.selected.repository_full_name' <<<"$local_entry")"
LOCAL_COMMIT_SHA="$(jq -r '.selected.commit_sha' <<<"$local_entry")"
LOCAL_TREE_SHA="$(jq -r '.selected.tree_sha' <<<"$local_entry")"
[[ "$LOCAL_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "invalid local dependency repository: $LOCAL_REPOSITORY" >&2
  exit 2
}
[[ "$LOCAL_COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid local dependency commit" >&2
  exit 2
}
[[ "$LOCAL_TREE_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid local dependency tree" >&2
  exit 2
}

mapfile -d '' LOCAL_DEBS < <(
  find "$LOCAL_DEB_DIR" -maxdepth 1 -type f -name '*.deb' -print0 \
    | LC_ALL=C sort -z
)
[ "${#LOCAL_DEBS[@]}" -gt 0 ] || {
  echo "no local DEBs found in $LOCAL_DEB_DIR" >&2
  exit 2
}

for deb in "${LOCAL_DEBS[@]}"; do
  package="$(dpkg-deb -f "$deb" Package)"
  version="$(dpkg-deb -f "$deb" Version)"
  architecture="$(dpkg-deb -f "$deb" Architecture)"
  source_field="$(dpkg-deb -f "$deb" Source 2>/dev/null || true)"
  [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || {
    echo "invalid local DEB package name: $package" >&2
    exit 3
  }
  case "$architecture" in
    arm64|all) ;;
    *)
      echo "local dependency is not ARM64/all: $package $architecture" >&2
      exit 3
      ;;
  esac
  [ "$version" = "$LOCAL_SOURCE_VERSION" ] || {
    echo "local dependency version mismatch for $package: $version != $LOCAL_SOURCE_VERSION" >&2
    exit 3
  }

  if [ -z "$source_field" ]; then
    [ "$package" = "$LOCAL_SOURCE_NAME" ] || {
      echo "local DEB $package has no Source field and is not $LOCAL_SOURCE_NAME" >&2
      exit 3
    }
    declared_source="$package"
    declared_source_version="$version"
  else
    declared_source="${source_field%% *}"
    if [[ "$source_field" =~ $SOURCE_VERSION_RE ]]; then
      declared_source_version="${BASH_REMATCH[1]}"
    else
      declared_source_version="$version"
    fi
  fi
  [ "$declared_source" = "$LOCAL_SOURCE_NAME" ] || {
    echo "local DEB source mismatch for $package: $declared_source != $LOCAL_SOURCE_NAME" >&2
    exit 3
  }
  [ "$declared_source_version" = "$LOCAL_SOURCE_VERSION" ] || {
    echo "local DEB source version mismatch for $package" >&2
    exit 3
  }

  filename="$(basename "$deb")"
  [[ "$filename" =~ ^[A-Za-z0-9][A-Za-z0-9+_.~:-]*\.deb$ ]] || {
    echo "invalid local DEB filename: $filename" >&2
    exit 3
  }
  destination="$LOCAL_REPO/$filename"
  cp "$deb" "$destination"
  size="$(stat -c '%s' "$destination")"
  digest="$(sha256sum "$destination" | awk '{print $1}')"

  jq -n \
    --arg package "$package" \
    --arg version "$version" \
    --arg architecture "$architecture" \
    --arg source "$declared_source" \
    --arg source_version "$declared_source_version" \
    --arg filename "$filename" \
    --arg sha256 "$digest" \
    --argjson size "$size" '
      {
        package: $package,
        version: $version,
        architecture: $architecture,
        source: $source,
        source_version: $source_version,
        filename: $filename,
        size: $size,
        sha256: $sha256
      }
    ' >> "$EVIDENCE_LINES"
done

mapfile -t LOCAL_REQUIRED_PACKAGES < <(
  tr ',\t ' '\n\n\n' <<<"$LOCAL_REQUIRED_PACKAGES_RAW" \
    | sed '/^$/d' \
    | LC_ALL=C sort -u
)
for package in "${LOCAL_REQUIRED_PACKAGES[@]}"; do
  [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || {
    echo "invalid required local package: $package" >&2
    exit 3
  }
  jq -e --arg package "$package" 'select(.package == $package)' \
    "$EVIDENCE_LINES" >/dev/null || {
      echo "required local dependency package was not provided: $package" >&2
      exit 3
    }
done

(
  cd "$LOCAL_REPO"
  dpkg-scanpackages . /dev/null > Packages
  gzip -n -9 -c Packages > Packages.gz

  packages_sha256="$(sha256sum Packages | awk '{print $1}')"
  packages_size="$(stat -c '%s' Packages)"
  packages_gz_sha256="$(sha256sum Packages.gz | awk '{print $1}')"
  packages_gz_size="$(stat -c '%s' Packages.gz)"
  cat > Release <<EOF
Origin: Hancom Gooroom ARM64
Label: Hancom Gooroom ARM64
Suite: exact-local
Codename: exact-local
Date: Thu, 01 Jan 1970 00:00:00 UTC
Architectures: arm64 all
Components: main
Description: Exact locally built ARM64 dependencies
SHA256:
 $packages_sha256 $packages_size Packages
 $packages_gz_sha256 $packages_gz_size Packages.gz
EOF

  find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum \
    > SHA256SUMS
  sha256sum --check SHA256SUMS
)

# build_locked_source_arm64_v2.sh owns the repository-mount implementation.
# This wrapper only validates and materializes exact local DEBs, then supplies
# that immutable flat repository through the builder's public environment
# contract. No source-code anchor or disposable builder patch is involved.
export HANCOM_GOOROOM_REFERENCE_JSON="$REFERENCE_JSON"
export HANCOM_GOOROOM_DEPENDENCY_REPOSITORY="$LOCAL_REPO"
"$BASE_BUILDER" "$LOCK_JSON" "$SOURCE_NAME" "$OUTPUT_DIR_ABS"

# The v2 builder predates the common verifier's evidence-schema fields. Add
# the same immutable policy metadata emitted by the generic locked builder so
# this local-dependency path can be verified without weakening any gate.
BUILD_LOCK_TMP="$WORK_DIR/build-lock.json"
jq '
  .binary_package_policy = "AMD64 reference packages whose Architecture is not all"
  | .source_composition = {mode: "git-only"}
' "$OUTPUT_DIR_ABS/build-lock.json" > "$BUILD_LOCK_TMP"
mv "$BUILD_LOCK_TMP" "$OUTPUT_DIR_ABS/build-lock.json"

jq -e '
  .binary_package_policy == "AMD64 reference packages whose Architecture is not all"
  and .source_composition.mode == "git-only"
' "$OUTPUT_DIR_ABS/build-lock.json" >/dev/null

jq -s \
  --arg target_source "$SOURCE_NAME" \
  --arg source "$LOCAL_SOURCE_NAME" \
  --arg source_version "$LOCAL_SOURCE_VERSION" \
  --arg repository "$LOCAL_REPOSITORY" \
  --arg commit_sha "$LOCAL_COMMIT_SHA" \
  --arg tree_sha "$LOCAL_TREE_SHA" '
    {
      schema: 2,
      policy: "exact-locally-built-source-dependency-repository",
      injection_contract: "HANCOM_GOOROOM_DEPENDENCY_REPOSITORY",
      target_source: $target_source,
      dependency_source: {
        source: $source,
        source_version: $source_version,
        repository: $repository,
        commit_sha: $commit_sha,
        tree_sha: $tree_sha
      },
      packages: .
    }
  ' "$EVIDENCE_LINES" > "$OUTPUT_DIR_ABS/local-build-dependencies.json"

find "$OUTPUT_DIR_ABS" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 sha256sum \
  > "$OUTPUT_DIR_ABS/SHA256SUMS"
sha256sum --check "$OUTPUT_DIR_ABS/SHA256SUMS"
cat "$OUTPUT_DIR_ABS/local-build-dependencies.json"
