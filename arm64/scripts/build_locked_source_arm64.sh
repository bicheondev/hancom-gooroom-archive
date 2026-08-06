#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 LOCK_JSON SOURCE_NAME OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
LOCK_JSON="$1"
SOURCE_NAME="$2"
OUTPUT_DIR="$3"

command -v jq >/dev/null
command -v curl >/dev/null
command -v docker >/dev/null

mkdir -p "$OUTPUT_DIR"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

entry="$(jq -c --arg source "$SOURCE_NAME" '
  .sources[]
  | select(.source == $source and .status == "resolved" and .selected != null)
' "$LOCK_JSON" | head -n1)"
[ -n "$entry" ] || {
  echo "No resolved exact source lock for $SOURCE_NAME" >&2
  exit 2
}

SOURCE_VERSION="$(jq -r '.source_version' <<<"$entry")"
REPOSITORY="$(jq -r '.selected.repository_full_name' <<<"$entry")"
COMMIT_SHA="$(jq -r '.selected.commit_sha' <<<"$entry")"
TREE_SHA="$(jq -r '.selected.tree_sha' <<<"$entry")"
EXPECTED_PACKAGES="$(jq -r '.binary_packages | join(" ")' <<<"$entry")"

case "$SOURCE_VERSION" in
  *$'\n'*|*$'\r'*) echo "invalid version" >&2; exit 2 ;;
esac
case "$COMMIT_SHA" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) echo "invalid commit SHA: $COMMIT_SHA" >&2; exit 2 ;;
esac

ARCHIVE="$WORK_DIR/source.tar.gz"
SOURCE_ROOT="$WORK_DIR/source"
mkdir -p "$SOURCE_ROOT"

curl --fail --location --silent --show-error \
  --retry 5 --retry-all-errors \
  "https://codeload.github.com/${REPOSITORY}/tar.gz/${COMMIT_SHA}" \
  --output "$ARCHIVE"
ARCHIVE_SHA256="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
tar -xzf "$ARCHIVE" --strip-components=1 -C "$SOURCE_ROOT"

[ -f "$SOURCE_ROOT/debian/changelog" ] || {
  echo "debian/changelog missing from locked source" >&2
  exit 3
}

DECLARED_SOURCE="$(dpkg-parsechangelog -l"$SOURCE_ROOT/debian/changelog" -S Source)"
DECLARED_VERSION="$(dpkg-parsechangelog -l"$SOURCE_ROOT/debian/changelog" -S Version)"
[ "$DECLARED_SOURCE" = "$SOURCE_NAME" ] || {
  echo "source mismatch: $DECLARED_SOURCE != $SOURCE_NAME" >&2
  exit 3
}
[ "$DECLARED_VERSION" = "$SOURCE_VERSION" ] || {
  echo "version mismatch: $DECLARED_VERSION != $SOURCE_VERSION" >&2
  exit 3
}

cat > "$WORK_DIR/build-inside.sh" <<'INNER'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export DEB_BUILD_OPTIONS="nocheck parallel=2"
export DEB_BUILD_PROFILES="pkg.nocheck"

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates gnupg dirmngr curl xz-utils \
  build-essential devscripts equivs fakeroot dpkg-dev debhelper

cat > /etc/apt/sources.list <<'EOF'
deb [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/debian/20240331T235959Z/ bullseye main contrib non-free
deb [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/debian/20240331T235959Z/ bullseye-updates main contrib non-free
deb [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20240331T235959Z/ bullseye-security main contrib non-free
EOF
rm -f /etc/apt/sources.list.d/*
cat > /etc/apt/apt.conf.d/99snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
apt-get update

cd /src
mk-build-deps \
  --install \
  --remove \
  --tool 'apt-get -y --no-install-recommends -o Dpkg::Use-Pty=0' \
  debian/control

dpkg-buildpackage -us -uc -b -j2
mkdir -p /out
find .. -maxdepth 1 -type f \( -name '*.deb' -o -name '*.buildinfo' -o -name '*.changes' \) \
  -exec cp -v '{}' /out/ \;
INNER
chmod +x "$WORK_DIR/build-inside.sh"

# The container is natively arm64 from dpkg's point of view and executes through
# binfmt/QEMU on the amd64 GitHub runner. This avoids unreliable cross-build
# assumptions in old Debian packaging.
docker run --rm --platform linux/arm64 \
  --volume "$SOURCE_ROOT:/src:rw" \
  --volume "$WORK_DIR/build-inside.sh:/build-inside.sh:ro" \
  --volume "$(cd "$OUTPUT_DIR" && pwd):/out:rw" \
  arm64v8/debian:bullseye-slim \
  /bin/bash /build-inside.sh

shopt -s nullglob
DEBS=("$OUTPUT_DIR"/*.deb)
[ "${#DEBS[@]}" -gt 0 ] || {
  echo "No .deb output was produced" >&2
  exit 4
}

produced_packages=()
for deb in "${DEBS[@]}"; do
  package="$(dpkg-deb -f "$deb" Package)"
  version="$(dpkg-deb -f "$deb" Version)"
  architecture="$(dpkg-deb -f "$deb" Architecture)"
  [ "$version" = "$SOURCE_VERSION" ] || {
    echo "output version mismatch for $package: $version != $SOURCE_VERSION" >&2
    exit 5
  }
  case "$architecture" in
    arm64|all) ;;
    *) echo "unexpected output architecture for $package: $architecture" >&2; exit 5 ;;
  esac
  produced_packages+=("$package")
done

for expected in $EXPECTED_PACKAGES; do
  found=false
  for produced in "${produced_packages[@]}"; do
    if [ "$produced" = "$expected" ]; then found=true; break; fi
  done
  if [ "$found" != true ]; then
    echo "Expected binary package was not built: $expected" >&2
    exit 6
  fi
done

cat > "$OUTPUT_DIR/build-lock.json" <<EOF
{
  "schema": 1,
  "source": $(jq -Rn --arg v "$SOURCE_NAME" '$v'),
  "source_version": $(jq -Rn --arg v "$SOURCE_VERSION" '$v'),
  "repository": $(jq -Rn --arg v "$REPOSITORY" '$v'),
  "commit_sha": $(jq -Rn --arg v "$COMMIT_SHA" '$v'),
  "tree_sha": $(jq -Rn --arg v "$TREE_SHA" '$v'),
  "source_archive_sha256": $(jq -Rn --arg v "$ARCHIVE_SHA256" '$v'),
  "target_architecture": "arm64",
  "expected_binary_packages": $(jq -c '.binary_packages' <<<"$entry")
}
EOF

find "$OUTPUT_DIR" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > "$OUTPUT_DIR/SHA256SUMS"

cat "$OUTPUT_DIR/build-lock.json"
