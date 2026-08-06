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
COMPAT_WRAPPER="$SCRIPT_DIR/run_locked_source_arm64.sh"
COMPOSITE_HELPER="${HANCOM_GOOROOM_COMPOSITE_SOURCE_HELPER:-$SCRIPT_DIR/prepare_composite_source_chroot.sh}"
COMPONENT_LOCK_DIR="${HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR:-$SCRIPT_DIR/../locks/source-components}"
LOCAL_DEB_DIR="${HANCOM_GOOROOM_LOCAL_DEB_DIR:-}"
LOCAL_SOURCE_NAME="${HANCOM_GOOROOM_LOCAL_SOURCE:-}"
LOCAL_REQUIRED_PACKAGES_RAW="${HANCOM_GOOROOM_LOCAL_REQUIRED_PACKAGES:-}"
SOURCE_VERSION_RE='\(([^)]+)\)'

for command in jq dpkg-deb dpkg-scanpackages sha256sum gzip python3 stat find; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done
[ -f "$LOCK_JSON" ] || { echo "source lock not found: $LOCK_JSON" >&2; exit 69; }
[ -f "$BASE_BUILDER" ] || { echo "base builder not found: $BASE_BUILDER" >&2; exit 69; }
[ -f "$COMPAT_WRAPPER" ] || { echo "compatibility wrapper not found: $COMPAT_WRAPPER" >&2; exit 69; }
[ -f "$COMPOSITE_HELPER" ] || { echo "composite helper not found: $COMPOSITE_HELPER" >&2; exit 69; }
[ -d "$COMPONENT_LOCK_DIR" ] || { echo "component lock directory not found: $COMPONENT_LOCK_DIR" >&2; exit 69; }
[ -d "$LOCAL_DEB_DIR" ] || usage
[[ "$LOCAL_SOURCE_NAME" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || usage

COMPOSITE_HELPER="$(readlink -f "$COMPOSITE_HELPER")"
COMPONENT_LOCK_DIR="$(readlink -f "$COMPONENT_LOCK_DIR")"
LOCAL_DEB_DIR="$(readlink -f "$LOCAL_DEB_DIR")"
OUTPUT_DIR_ABS="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
LOCAL_REPO="$WORK_DIR/local-repo"
BUILDER_DIR="$WORK_DIR/builder"
EVIDENCE_LINES="$WORK_DIR/local-evidence.jsonl"
mkdir -p "$LOCAL_REPO" "$BUILDER_DIR"
: > "$EVIDENCE_LINES"

local_entry="$(jq -c --arg source "$LOCAL_SOURCE_NAME" '
  .sources[]
  | select(.source == $source and .status == "resolved" and .selected != null)
' "$LOCK_JSON" | head -n1)"
[ -n "$local_entry" ] || {
  echo "No resolved exact source lock for local dependency source $LOCAL_SOURCE_NAME" >&2
  exit 2
}
LOCAL_SOURCE_VERSION="$(jq -r '.source_version' <<<"$local_entry")"
LOCAL_REPOSITORY="$(jq -r '.selected.repository_full_name' <<<"$local_entry")"
LOCAL_COMMIT_SHA="$(jq -r '.selected.commit_sha' <<<"$local_entry")"
LOCAL_TREE_SHA="$(jq -r '.selected.tree_sha' <<<"$local_entry")"
[[ "$LOCAL_COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid local dependency commit" >&2; exit 2; }
[[ "$LOCAL_TREE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid local dependency tree" >&2; exit 2; }

mapfile -d '' LOCAL_DEBS < <(
  find "$LOCAL_DEB_DIR" -maxdepth 1 -type f -name '*.deb' -print0 | LC_ALL=C sort -z
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
    *) echo "local dependency is not ARM64/all: $package $architecture" >&2; exit 3 ;;
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
  sha256sum ./*.deb Packages Packages.gz | LC_ALL=C sort -k2 > REPOSITORY-SHA256SUMS
)

# Patch a disposable copy of only the generic builder to mount the verified
# repository. The checked-in compatibility wrapper still performs the exact
# target Git commit/tree/version and AMD64-reference package gates unchanged.
cp "$BASE_BUILDER" "$BUILDER_DIR/build_locked_source_arm64_v2.sh"
cp "$COMPAT_WRAPPER" "$BUILDER_DIR/run_locked_source_arm64.sh"
chmod +x "$BUILDER_DIR/"*.sh

python3 - "$BUILDER_DIR/build_locked_source_arm64_v2.sh" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")

anchor = '''BOOTSTRAP_IMAGE="${HANCOM_GOOROOM_BOOTSTRAP_IMAGE:-arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"
'''
replacement = anchor + '''LOCAL_REPO="${HANCOM_GOOROOM_LOCAL_REPO:-}"
[ -d "$LOCAL_REPO" ] || {
  echo "verified local build repository is missing: $LOCAL_REPO" >&2
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

mkdir -p "$ROOT/opt/hancom-gooroom-local-build-repo"
cp -a /local-build-repo/. "$ROOT/opt/hancom-gooroom-local-build-repo/"
cat > "$ROOT/etc/apt/sources.list.d/98hancom-gooroom-local-build.list" <<'EOF'
deb [trusted=yes] file:/opt/hancom-gooroom-local-build-repo ./
EOF
cat > "$ROOT/etc/apt/preferences.d/98hancom-gooroom-local-build.pref" <<'EOF'
Package: *
Pin: origin ""
Pin-Priority: 1001
EOF

mkdir -p "$ROOT/build/source" "$ROOT/build/output"
'''
if source.count(chroot_anchor) != 1:
    raise SystemExit(f"expected one chroot-copy anchor, found {source.count(chroot_anchor)}")
source = source.replace(chroot_anchor, chroot_replacement)

docker_anchor = '''  --volume "$SOURCE_ROOT:/src:ro" \\
'''
docker_replacement = '''  --volume "$SOURCE_ROOT:/src:ro" \\
  --volume "$LOCAL_REPO:/local-build-repo:ro" \\
'''
if source.count(docker_anchor) != 1:
    raise SystemExit(f"expected one Docker source mount, found {source.count(docker_anchor)}")
source = source.replace(docker_anchor, docker_replacement)

path.write_text(source, encoding="utf-8")
PY

export HANCOM_GOOROOM_LOCAL_REPO="$LOCAL_REPO"
export HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR="$COMPONENT_LOCK_DIR"
export HANCOM_GOOROOM_COMPOSITE_SOURCE_HELPER="$COMPOSITE_HELPER"
"$BUILDER_DIR/run_locked_source_arm64.sh" "$LOCK_JSON" "$SOURCE_NAME" "$OUTPUT_DIR_ABS"

jq -s \
  --arg target_source "$SOURCE_NAME" \
  --arg source "$LOCAL_SOURCE_NAME" \
  --arg source_version "$LOCAL_SOURCE_VERSION" \
  --arg repository "$LOCAL_REPOSITORY" \
  --arg commit_sha "$LOCAL_COMMIT_SHA" \
  --arg tree_sha "$LOCAL_TREE_SHA" '
    {
      schema: 1,
      policy: "exact-locally-built-source-dependency-repository",
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
cat "$OUTPUT_DIR_ABS/local-build-dependencies.json"
