#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_BUILDER="$SCRIPT_DIR/build_locked_source_arm64.sh"
REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-$SCRIPT_DIR/../locks/reference/amd64-reference.json}"
COMPONENT_LOCK_DIR="${HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR:-$SCRIPT_DIR/../locks/source-components}"
COMPOSITE_HELPER="${HANCOM_GOOROOM_COMPOSITE_SOURCE_HELPER:-$SCRIPT_DIR/prepare_composite_source_chroot.sh}"

[ -f "$BASE_BUILDER" ] || {
  echo "base builder not found: $BASE_BUILDER" >&2
  exit 69
}
[ -f "$REFERENCE_JSON" ] || {
  echo "AMD64 reference lock not found: $REFERENCE_JSON" >&2
  exit 69
}
[ -d "$COMPONENT_LOCK_DIR" ] || {
  echo "source component lock directory not found: $COMPONENT_LOCK_DIR" >&2
  exit 69
}
[ -f "$COMPOSITE_HELPER" ] || {
  echo "composite source helper not found: $COMPOSITE_HELPER" >&2
  exit 69
}
export HANCOM_GOOROOM_REFERENCE_JSON="$(readlink -f "$REFERENCE_JSON")"
export HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR="$(readlink -f "$COMPONENT_LOCK_DIR")"
export HANCOM_GOOROOM_COMPOSITE_SOURCE_HELPER="$(readlink -f "$COMPOSITE_HELPER")"

PATCHED_BUILDER="$(mktemp)"
trap 'rm -f "$PATCHED_BUILDER"' EXIT

# Old Bullseye devscripts/equivs and rootful build containers have several
# compatibility quirks. Apply only asserted, deterministic transformations to
# the checked-in base builder; a changed base script stops instead of silently
# producing a different package.
python3 - "$BASE_BUILDER" "$PATCHED_BUILDER" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")

old_glob = "-name '*-build-deps_*.deb'"
new_glob = "-name '*-build-deps*.deb'"
if source.count(old_glob) != 1:
    raise SystemExit(
        f"expected exactly one strict build-deps glob, found {source.count(old_glob)}"
    )
source = source.replace(old_glob, new_glob)

old_command = """mk-build-deps --build-dep debian/control
DUMMY_PACKAGE=\"$(find . -maxdepth 1 -type f -name '*-build-deps*.deb' -print -quit)\"
[ -n \"$DUMMY_PACKAGE\" ]
"""
new_command = """set +e
mk-build-deps --build-dep debian/control
MK_BUILD_DEPS_RC=$?
set -e
DUMMY_PACKAGE=\"$(find . -maxdepth 1 -type f -name '*-build-deps*.deb' -print -quit)\"
if [ -z \"$DUMMY_PACKAGE\" ]; then
  echo \"mk-build-deps produced no dependency package (exit $MK_BUILD_DEPS_RC)\" >&2
  exit \"$MK_BUILD_DEPS_RC\"
fi
if [ \"$MK_BUILD_DEPS_RC\" -ne 0 ]; then
  echo \"mk-build-deps returned $MK_BUILD_DEPS_RC after creating $DUMMY_PACKAGE; continuing with explicit APT validation\" >&2
fi
"""
if source.count(old_command) != 1:
    raise SystemExit(
        f"expected exactly one mk-build-deps block, found {source.count(old_command)}"
    )
source = source.replace(old_command, new_command)

old_expected = '''EXPECTED_PACKAGES="$(jq -r '.binary_packages | join(" ")' <<<"$entry")"
'''
new_expected = '''EXPECTED_PACKAGES="$(jq -r '.binary_packages | join(" ")' <<<"$entry")"
REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-}"
COMPONENT_LOCK_DIR="${HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR:-}"
COMPOSITE_HELPER="${HANCOM_GOOROOM_COMPOSITE_SOURCE_HELPER:-}"
SOURCE_COMPONENT_LOCK=""
SOURCE_COMPONENT_LOCK_PRESENT=false
SOURCE_COMPONENT_LOCK_SHA256=""
SOURCE_COMPONENT_LOCK_MOUNT="$WORK_DIR/source-component-lock.json"
printf '{}\\n' > "$SOURCE_COMPONENT_LOCK_MOUNT"

[ -f "$COMPOSITE_HELPER" ] || {
  echo "composite source helper not found: $COMPOSITE_HELPER" >&2
  exit 2
}
if [ -n "$COMPONENT_LOCK_DIR" ] && [ -f "$COMPONENT_LOCK_DIR/$SOURCE_NAME.json" ]; then
  SOURCE_COMPONENT_LOCK="$(readlink -f "$COMPONENT_LOCK_DIR/$SOURCE_NAME.json")"
  jq -e \
    --arg source "$SOURCE_NAME" \
    --arg version "$SOURCE_VERSION" \
    --arg repository "$REPOSITORY" \
    --arg commit "$COMMIT_SHA" \
    --arg tree "$TREE_SHA" \
    --arg snapshot "$SNAPSHOT" '
      .source == $source
      and .source_version == $version
      and .packaging.repository_full_name == $repository
      and .packaging.commit_sha == $commit
      and .packaging.tree_sha == $tree
      and .upstream.snapshot == $snapshot
      and .composition.extract == "upstream.files.orig only"
    ' "$SOURCE_COMPONENT_LOCK" >/dev/null
  cp "$SOURCE_COMPONENT_LOCK" "$SOURCE_COMPONENT_LOCK_MOUNT"
  SOURCE_COMPONENT_LOCK_PRESENT=true
  SOURCE_COMPONENT_LOCK_SHA256="$(sha256sum "$SOURCE_COMPONENT_LOCK" | awk '{print $1}')"
fi

if [ -n "$REFERENCE_JSON" ]; then
  [ -f "$REFERENCE_JSON" ] || {
    echo "AMD64 reference lock not found: $REFERENCE_JSON" >&2
    exit 2
  }
  # dpkg-buildpackage -B intentionally emits architecture-dependent binaries
  # only. Architecture: all binaries from a mixed source are byte-reused from
  # the verified AMD64 reference and must not be falsely required here.
  EXPECTED_PACKAGES="$(jq -r \
    --arg source "$SOURCE_NAME" \
    --arg version "$SOURCE_VERSION" '
      [
        .packages[]
        | select(
            .source == $source
            and .source_version == $version
            and .architecture != "all"
          )
        | .package
      ]
      | unique
      | join(" ")
    ' "$REFERENCE_JSON")"
fi
[ -n "$EXPECTED_PACKAGES" ] || {
  echo "No architecture-dependent binary package is required for $SOURCE_NAME $SOURCE_VERSION" >&2
  exit 2
}
'''
if source.count(old_expected) != 1:
    raise SystemExit(
        f"expected exactly one binary-package policy line, found {source.count(old_expected)}"
    )
source = source.replace(old_expected, new_expected)

old_version_gate = '''[ "$DECLARED_VERSION" = "$SOURCE_VERSION" ] || {
  echo "version mismatch: $DECLARED_VERSION != $SOURCE_VERSION" >&2
  exit 3
}

cat > "$OUTPUT_DIR_ABS/source-lock-evidence.json" <<EOF
'''
new_version_gate = '''[ "$DECLARED_VERSION" = "$SOURCE_VERSION" ] || {
  echo "version mismatch: $DECLARED_VERSION != $SOURCE_VERSION" >&2
  exit 3
}

if [ "$SOURCE_COMPONENT_LOCK_PRESENT" = true ]; then
  if [ "$(jq -r '.packaging.layout' "$SOURCE_COMPONENT_LOCK")" = "debian-directory-only" ]; then
    TOP_LEVEL_ENTRIES="$(find "$SOURCE_ROOT" -mindepth 1 -maxdepth 1 -printf '%f\\n' | LC_ALL=C sort)"
    [ "$TOP_LEVEL_ENTRIES" = debian ] || {
      echo "packaging-only lock expected exactly debian/ at the Git tree root" >&2
      printf '%s\\n' "$TOP_LEVEL_ENTRIES" >&2
      exit 3
    }
  fi
  python3 - "$SOURCE_ROOT/debian/changelog" "$SOURCE_COMPONENT_LOCK" <<'PY_COMPONENT_ANCHOR'
import json
import re
import sys
from pathlib import Path

changelog = Path(sys.argv[1]).read_text(encoding="utf-8", errors="strict")
lock = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
headers = re.findall(r"^([^\\s]+) \\(([^)]+)\\) [^;]+; urgency=", changelog, re.MULTILINE)
anchor = lock["changelog_anchor"]
position = int(anchor["position"])
if position < 1 or len(headers) < position:
    raise SystemExit(f"changelog anchor position {position} is unavailable")
actual_source, actual_version = headers[position - 1]
if (actual_source, actual_version) != (anchor["source"], anchor["version"]):
    raise SystemExit(
        "changelog anchor mismatch: "
        f"{actual_source} {actual_version} != {anchor['source']} {anchor['version']}"
    )
PY_COMPONENT_ANCHOR
fi

cat > "$OUTPUT_DIR_ABS/source-lock-evidence.json" <<EOF
'''
if source.count(old_version_gate) != 1:
    raise SystemExit(
        f"expected exactly one source version gate, found {source.count(old_version_gate)}"
    )
source = source.replace(old_version_gate, new_version_gate)

old_inner_header = ''': "${SNAPSHOT:?SNAPSHOT is required}"
export DEBIAN_FRONTEND=noninteractive
'''
new_inner_header = ''': "${SNAPSHOT:?SNAPSHOT is required}"
: "${SOURCE_COMPONENT_LOCK_PRESENT:=false}"
export DEBIAN_FRONTEND=noninteractive
'''
if source.count(old_inner_header) != 1:
    raise SystemExit(
        f"expected exactly one inner build header, found {source.count(old_inner_header)}"
    )
source = source.replace(old_inner_header, new_inner_header)

old_root_sources = '''cat > "$ROOT/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
rm -f "$ROOT/etc/apt/sources.list.d/"*
'''
new_root_sources = '''cat > "$ROOT/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
if [ "$SOURCE_COMPONENT_LOCK_PRESENT" = true ]; then
  cat >> "$ROOT/etc/apt/sources.list" <<EOF
deb-src [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb-src [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb-src [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
fi
rm -f "$ROOT/etc/apt/sources.list.d/"*
'''
if source.count(old_root_sources) != 1:
    raise SystemExit(
        f"expected exactly one historical root source list, found {source.count(old_root_sources)}"
    )
source = source.replace(old_root_sources, new_root_sources)

old_root_copy = '''mkdir -p "$ROOT/build/source" "$ROOT/build/output"
cp -a /src/. "$ROOT/build/source/"
'''
new_root_copy = '''mkdir -p "$ROOT/build/source" "$ROOT/build/output"
cp -a /src/. "$ROOT/build/source/"
if [ "$SOURCE_COMPONENT_LOCK_PRESENT" = true ]; then
  cp /source-component-lock.json "$ROOT/build/source-component-lock.json"
  cp /prepare-composite-source.sh "$ROOT/build/prepare-composite-source.sh"
  chmod +x "$ROOT/build/prepare-composite-source.sh"
fi
'''
if source.count(old_root_copy) != 1:
    raise SystemExit(
        f"expected exactly one build-root source copy, found {source.count(old_root_copy)}"
    )
source = source.replace(old_root_copy, new_root_copy)

old_tools = '''  build-essential ca-certificates debhelper devscripts dpkg-dev \\
  equivs fakeroot gnupg xz-utils
'''
new_tools = '''  build-essential ca-certificates debhelper devscripts dpkg-dev \\
  equivs fakeroot gnupg jq xz-utils
'''
if source.count(old_tools) != 1:
    raise SystemExit(
        f"expected exactly one chroot tool install block, found {source.count(old_tools)}"
    )
source = source.replace(old_tools, new_tools)

old_build_root = '''cd /build/source
export SOURCE_DATE_EPOCH="$(dpkg-parsechangelog -S Date | date -f - +%s)"
'''
new_build_root = '''BUILD_SOURCE=/build/source
if [ "$SOURCE_COMPONENT_LOCK_PRESENT" = true ]; then
  /bin/bash /build/prepare-composite-source.sh \
    /build/source \
    /build/output \
    /build/source-component-lock.json
  BUILD_SOURCE=/build/composite-source
fi
cd "$BUILD_SOURCE"
export SOURCE_DATE_EPOCH="$(dpkg-parsechangelog -S Date | date -f - +%s)"
'''
if source.count(old_build_root) != 1:
    raise SystemExit(
        f"expected exactly one chroot build-source entry, found {source.count(old_build_root)}"
    )
source = source.replace(old_build_root, new_build_root)

old_options = '''export DEB_BUILD_OPTIONS="nocheck nodoc parallel=2"
export DEB_BUILD_PROFILES="pkg.nocheck nodoc"
'''
new_options = '''case "${SOURCE_NAME:-}" in
  p7zip)
    # p7zip-full.links validates and links DOC/MANUAL/style.css. The generic
    # nodoc optimization removes that file and breaks otherwise valid ARM64
    # packaging, so retain documentation for this exact source only.
    export DEB_BUILD_OPTIONS="nocheck parallel=2"
    export DEB_BUILD_PROFILES="pkg.nocheck"
    ;;
  *)
    export DEB_BUILD_OPTIONS="nocheck nodoc parallel=2"
    export DEB_BUILD_PROFILES="pkg.nocheck nodoc"
    ;;
esac
'''
if source.count(old_options) != 1:
    raise SystemExit(
        f"expected exactly one build-options block, found {source.count(old_options)}"
    )
source = source.replace(old_options, new_options)

old_docker_env = '''  --env "SNAPSHOT=$SNAPSHOT" \\
'''
new_docker_env = '''  --env "SNAPSHOT=$SNAPSHOT" \\
  --env "SOURCE_NAME=$SOURCE_NAME" \\
  --env "SOURCE_COMPONENT_LOCK_PRESENT=$SOURCE_COMPONENT_LOCK_PRESENT" \\
  --volume "$SOURCE_COMPONENT_LOCK_MOUNT:/source-component-lock.json:ro" \\
  --volume "$COMPOSITE_HELPER:/prepare-composite-source.sh:ro" \\
'''
if source.count(old_docker_env) != 1:
    raise SystemExit(
        f"expected exactly one Docker snapshot environment line, found {source.count(old_docker_env)}"
    )
source = source.replace(old_docker_env, new_docker_env)

old_copy = '''cp -av "$ROOT/build/output/." /out/ || true
exit "$BUILD_RC"
'''
new_copy = '''cp -av "$ROOT/build/output/." /out/ || true
# The rootful container may preserve root ownership on /out itself. The host
# runner must be able to append the immutable build lock and checksum manifest.
chmod -R a+rwX /out || true
exit "$BUILD_RC"
'''
if source.count(old_copy) != 1:
    raise SystemExit(
        f"expected exactly one chroot output copy block, found {source.count(old_copy)}"
    )
source = source.replace(old_copy, new_copy)

old_manifest_start = '''cat > "$OUTPUT_DIR_ABS/build-lock.json" <<EOF
'''
new_manifest_start = '''EXPECTED_PACKAGES_JSON="$(printf '%s\\n' $EXPECTED_PACKAGES | jq -Rsc 'split("\\n")[:-1]')"
if [ "$SOURCE_COMPONENT_LOCK_PRESENT" = true ]; then
  SOURCE_COMPOSITION_JSON="$(jq -cn \
    --arg mode "packaging-git-plus-exact-debian-orig" \
    --arg lock_sha256 "$SOURCE_COMPONENT_LOCK_SHA256" \
    --arg upstream_source "$(jq -r '.upstream.source' "$SOURCE_COMPONENT_LOCK")" \
    --arg upstream_version "$(jq -r '.upstream.version' "$SOURCE_COMPONENT_LOCK")" '
      {
        mode: $mode,
        source_component_lock_sha256: $lock_sha256,
        upstream_source: $upstream_source,
        upstream_version: $upstream_version
      }
    ')"
else
  SOURCE_COMPOSITION_JSON='{"mode":"git-only"}'
fi
cat > "$OUTPUT_DIR_ABS/build-lock.json" <<EOF
'''
if source.count(old_manifest_start) != 1:
    raise SystemExit(
        f"expected exactly one build-lock start, found {source.count(old_manifest_start)}"
    )
source = source.replace(old_manifest_start, new_manifest_start)

old_manifest_field = '''  "expected_binary_packages": $(jq -c '.binary_packages' <<<"$entry"),
'''
new_manifest_field = '''  "expected_binary_packages": $EXPECTED_PACKAGES_JSON,
  "binary_package_policy": "AMD64 reference packages whose Architecture is not all",
  "source_composition": $SOURCE_COMPOSITION_JSON,
'''
if source.count(old_manifest_field) != 1:
    raise SystemExit(
        f"expected exactly one build-lock expected-package field, found {source.count(old_manifest_field)}"
    )
source = source.replace(old_manifest_field, new_manifest_field)

Path(sys.argv[2]).write_text(source, encoding="utf-8")
PY

chmod +x "$PATCHED_BUILDER"
exec "$PATCHED_BUILDER" "$@"
