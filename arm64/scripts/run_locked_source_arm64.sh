#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_BUILDER="$SCRIPT_DIR/build_locked_source_arm64.sh"
REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-$SCRIPT_DIR/../locks/reference/amd64-reference.json}"

[ -f "$BASE_BUILDER" ] || {
  echo "base builder not found: $BASE_BUILDER" >&2
  exit 69
}
[ -f "$REFERENCE_JSON" ] || {
  echo "AMD64 reference lock not found: $REFERENCE_JSON" >&2
  exit 69
}
export HANCOM_GOOROOM_REFERENCE_JSON="$(readlink -f "$REFERENCE_JSON")"

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
