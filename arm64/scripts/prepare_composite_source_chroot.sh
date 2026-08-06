#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 PACKAGING_ROOT OUTPUT_DIR COMPONENT_LOCK" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
PACKAGING_ROOT="$1"
OUTPUT_DIR="$2"
COMPONENT_LOCK="$3"
COMPOSITE_ROOT=/build/composite-source
DOWNLOAD_DIR=/build/source-download

for command in jq apt-get sha1sum sha256sum stat tar dpkg-parsechangelog; do
  command -v "$command" >/dev/null || {
    echo "required composite-source command is missing: $command" >&2
    exit 69
  }
done

[ -d "$PACKAGING_ROOT/debian" ] || {
  echo "locked packaging root has no debian/ directory: $PACKAGING_ROOT" >&2
  exit 2
}
[ -f "$COMPONENT_LOCK" ] || {
  echo "source component lock not found: $COMPONENT_LOCK" >&2
  exit 2
}
mkdir -p "$OUTPUT_DIR"

LOCK_SOURCE="$(jq -er '.source' "$COMPONENT_LOCK")"
LOCK_SOURCE_VERSION="$(jq -er '.source_version' "$COMPONENT_LOCK")"
UPSTREAM_SOURCE="$(jq -er '.upstream.source' "$COMPONENT_LOCK")"
UPSTREAM_VERSION="$(jq -er '.upstream.version' "$COMPONENT_LOCK")"
LOCK_SNAPSHOT="$(jq -er '.upstream.snapshot' "$COMPONENT_LOCK")"

[ "$LOCK_SOURCE" = "${SOURCE_NAME:?SOURCE_NAME is required}" ] || {
  echo "component source mismatch: $LOCK_SOURCE != $SOURCE_NAME" >&2
  exit 2
}
PACKAGING_SOURCE="$(dpkg-parsechangelog -l"$PACKAGING_ROOT/debian/changelog" -S Source)"
PACKAGING_VERSION="$(dpkg-parsechangelog -l"$PACKAGING_ROOT/debian/changelog" -S Version)"
[ "$PACKAGING_SOURCE" = "$LOCK_SOURCE" ] || {
  echo "packaging source mismatch: $PACKAGING_SOURCE != $LOCK_SOURCE" >&2
  exit 2
}
[ "$PACKAGING_VERSION" = "$LOCK_SOURCE_VERSION" ] || {
  echo "packaging version mismatch: $PACKAGING_VERSION != $LOCK_SOURCE_VERSION" >&2
  exit 2
}
[ "$LOCK_SNAPSHOT" = "${SNAPSHOT:?SNAPSHOT is required}" ] || {
  echo "component snapshot mismatch: $LOCK_SNAPSHOT != $SNAPSHOT" >&2
  exit 2
}

rm -rf "$DOWNLOAD_DIR" "$COMPOSITE_ROOT"
mkdir -p "$DOWNLOAD_DIR" "$COMPOSITE_ROOT"
cd "$DOWNLOAD_DIR"

# The source index is authenticated through the dated Debian Release files.
# Every downloaded source member is then checked again against the independent
# immutable component lock before extraction.
apt-get source --download-only "${UPSTREAM_SOURCE}=${UPSTREAM_VERSION}"

verify_member() {
  local key="$1"
  local filename expected_size expected_sha1 expected_sha256
  filename="$(jq -er --arg key "$key" '.upstream.files[$key].name' "$COMPONENT_LOCK")"
  expected_size="$(jq -er --arg key "$key" '.upstream.files[$key].size' "$COMPONENT_LOCK")"
  expected_sha1="$(jq -er --arg key "$key" '.upstream.files[$key].sha1' "$COMPONENT_LOCK")"
  expected_sha256="$(jq -er --arg key "$key" '.upstream.files[$key].sha256' "$COMPONENT_LOCK")"

  [ -f "$filename" ] || {
    echo "downloaded source member is missing: $filename" >&2
    exit 3
  }
  local actual_size actual_sha1 actual_sha256
  actual_size="$(stat -c '%s' "$filename")"
  actual_sha1="$(sha1sum "$filename" | awk '{print $1}')"
  actual_sha256="$(sha256sum "$filename" | awk '{print $1}')"
  [ "$actual_size" = "$expected_size" ] || {
    echo "source member size mismatch for $filename: $actual_size != $expected_size" >&2
    exit 3
  }
  [ "$actual_sha1" = "$expected_sha1" ] || {
    echo "source member SHA-1 mismatch for $filename" >&2
    exit 3
  }
  [ "$actual_sha256" = "$expected_sha256" ] || {
    echo "source member SHA-256 mismatch for $filename" >&2
    exit 3
  }
  printf '%s\t%s\t%s\t%s\n' \
    "$key" "$filename" "$actual_size" "$actual_sha256" \
    >> "$OUTPUT_DIR/upstream-source-members.tsv"
}

: > "$OUTPUT_DIR/upstream-source-members.tsv"
verify_member dsc
verify_member orig
verify_member debian

ORIG_FILENAME="$(jq -er '.upstream.files.orig.name' "$COMPONENT_LOCK")"
FIRST_ENTRY="$(tar -tJf "$ORIG_FILENAME" | sed -n '1p')"
case "$FIRST_ENTRY" in
  */*) ;;
  *)
    echo "upstream archive does not have a removable top-level directory: $FIRST_ENTRY" >&2
    exit 3
    ;;
esac

tar --extract --xz --file "$ORIG_FILENAME" \
  --strip-components=1 \
  --no-same-owner \
  --no-same-permissions \
  --directory "$COMPOSITE_ROOT"

while IFS= read -r required_path; do
  [ -e "$COMPOSITE_ROOT/$required_path" ] || {
    echo "required upstream path is missing after extraction: $required_path" >&2
    exit 3
  }
done < <(jq -er '.upstream.required_paths[]' "$COMPONENT_LOCK")

# The Debian source archive is used only as a signed/hash-locked locator for
# the upstream tarball. The independently locked Gooroom packaging directory is
# the sole debian/ overlay and must never be replaced by Debian's debian.tar.xz.
rm -rf "$COMPOSITE_ROOT/debian"
cp -a "$PACKAGING_ROOT/debian" "$COMPOSITE_ROOT/debian"

COMPOSITE_SOURCE="$(dpkg-parsechangelog -l"$COMPOSITE_ROOT/debian/changelog" -S Source)"
COMPOSITE_VERSION="$(dpkg-parsechangelog -l"$COMPOSITE_ROOT/debian/changelog" -S Version)"
[ "$COMPOSITE_SOURCE" = "$LOCK_SOURCE" ]
[ "$COMPOSITE_VERSION" = "$LOCK_SOURCE_VERSION" ]

LOCK_SHA256="$(sha256sum "$COMPONENT_LOCK" | awk '{print $1}')"
ORIG_SHA256="$(jq -er '.upstream.files.orig.sha256' "$COMPONENT_LOCK")"
DSC_SHA256="$(jq -er '.upstream.files.dsc.sha256' "$COMPONENT_LOCK")"
DEBIAN_SHA256="$(jq -er '.upstream.files.debian.sha256' "$COMPONENT_LOCK")"

jq \
  --arg lock_sha256 "$LOCK_SHA256" \
  --arg snapshot "$SNAPSHOT" \
  --arg packaging_source "$PACKAGING_SOURCE" \
  --arg packaging_version "$PACKAGING_VERSION" \
  --arg dsc_sha256 "$DSC_SHA256" \
  --arg orig_sha256 "$ORIG_SHA256" \
  --arg debian_sha256 "$DEBIAN_SHA256" '
  {
    schema: 1,
    policy: .policy,
    source: .source,
    source_version: .source_version,
    source_component_lock_sha256: $lock_sha256,
    packaging: .packaging + {
      verified_source: $packaging_source,
      verified_version: $packaging_version
    },
    changelog_anchor: .changelog_anchor,
    upstream: .upstream + {
      verified_snapshot: $snapshot,
      verified_files: {
        dsc_sha256: $dsc_sha256,
        orig_sha256: $orig_sha256,
        debian_sha256: $debian_sha256
      },
      required_paths_verified: true
    },
    composition: .composition,
    composite_root: "/build/composite-source",
    verified: true
  }
' "$COMPONENT_LOCK" > "$OUTPUT_DIR/upstream-source-evidence.json"

cat "$OUTPUT_DIR/upstream-source-evidence.json"
