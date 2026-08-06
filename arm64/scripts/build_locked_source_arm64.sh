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
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"

command -v jq >/dev/null
command -v curl >/dev/null
command -v docker >/dev/null
command -v dpkg-parsechangelog >/dev/null

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR_ABS="$(cd "$OUTPUT_DIR" && pwd)"
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
[[ "$COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid commit SHA: $COMMIT_SHA" >&2
  exit 2
}
[[ "$TREE_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid tree SHA: $TREE_SHA" >&2
  exit 2
}
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid Debian snapshot: $SNAPSHOT" >&2
  exit 2
}

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

: "${SNAPSHOT:?SNAPSHOT is required}"
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

# The Docker base tag moves over time. It is therefore used only as a tiny
# bootstrap host. The actual package is built inside a fresh ARM64 Bullseye
# rootfs reconstructed from the same dated Debian snapshot used by the package
# map, so current and historical library revisions never mix.
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates debootstrap xz-utils

ROOT=/snapshot-root
rm -rf "$ROOT"
mkdir -p "$ROOT"
deBootstrapLog=/tmp/debootstrap.log
if ! debootstrap \
  --arch=arm64 \
  --variant=buildd \
  --no-check-gpg \
  --include=ca-certificates \
  bullseye \
  "$ROOT" \
  "https://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
  >"$deBootstrapLog" 2>&1; then
  cat "$deBootstrapLog" >&2
  exit 20
fi
cat "$deBootstrapLog"

cat > "$ROOT/etc/apt/sources.list" <<EOF
deb [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
rm -f "$ROOT/etc/apt/sources.list.d/"*
cat > "$ROOT/etc/apt/apt.conf.d/99snapshot" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"

mkdir -p "$ROOT/build/source" "$ROOT/build/output"
cp -a /src/. "$ROOT/build/source/"

cat > "$ROOT/build/run-build.sh" <<'CHROOT'
#!/usr/bin/env bash
set -euo pipefail
export HOME=/root
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export DEB_BUILD_OPTIONS="nocheck parallel=2"
export DEB_BUILD_PROFILES="nodoc"

apt-get update
apt-get install -y --no-install-recommends \
  build-essential ca-certificates curl debhelper devscripts dpkg-dev \
  equivs fakeroot gnupg xz-utils

cd /build/source

# Build only architecture-dependent binaries. This deliberately excludes
# Build-Depends-Indep/documentation and mirrors what is needed to replace the
# AMD64 executables and shared libraries in the reference rootfs.
mk-build-deps \
  --build-dep \
  --install \
  --remove \
  --tool 'apt-get -y --no-install-recommends -o Dpkg::Use-Pty=0 -o Debug::pkgProblemResolver=yes' \
  debian/control

dpkg-checkbuilddeps -B
dpkg-buildpackage -us -uc -B -j2
find /build -maxdepth 1 -type f \
  \( -name '*.deb' -o -name '*.buildinfo' -o -name '*.changes' \) \
  -exec cp -v '{}' /build/output/ \;
CHROOT
chmod +x "$ROOT/build/run-build.sh"

cleanup_mounts() {
  umount -R "$ROOT/dev" 2>/dev/null || true
  umount "$ROOT/proc" 2>/dev/null || true
  umount "$ROOT/sys" 2>/dev/null || true
}
trap cleanup_mounts EXIT
mount --rbind /dev "$ROOT/dev"
mount --make-rslave "$ROOT/dev"
mount -t proc proc "$ROOT/proc"
mount -t sysfs sysfs "$ROOT/sys"

chroot "$ROOT" /bin/bash /build/run-build.sh
cp -av "$ROOT/build/output/." /out/
INNER
chmod +x "$WORK_DIR/build-inside.sh"

# The bootstrap container executes as ARM64 through binfmt/QEMU. --privileged is
# required only to mount proc/sys/dev inside the isolated historical chroot.
docker run --rm --privileged --platform linux/arm64 \
  --env "SNAPSHOT=$SNAPSHOT" \
  --volume "$SOURCE_ROOT:/src:ro" \
  --volume "$WORK_DIR/build-inside.sh:/build-inside.sh:ro" \
  --volume "$OUTPUT_DIR_ABS:/out:rw" \
  arm64v8/debian:bullseye-slim \
  /bin/bash /build-inside.sh

shopt -s nullglob
DEBS=("$OUTPUT_DIR_ABS"/*.deb)
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

cat > "$OUTPUT_DIR_ABS/build-lock.json" <<EOF
{
  "schema": 2,
  "source": $(jq -Rn --arg v "$SOURCE_NAME" '$v'),
  "source_version": $(jq -Rn --arg v "$SOURCE_VERSION" '$v'),
  "repository": $(jq -Rn --arg v "$REPOSITORY" '$v'),
  "commit_sha": $(jq -Rn --arg v "$COMMIT_SHA" '$v'),
  "tree_sha": $(jq -Rn --arg v "$TREE_SHA" '$v'),
  "source_archive_sha256": $(jq -Rn --arg v "$ARCHIVE_SHA256" '$v'),
  "target_architecture": "arm64",
  "debian_snapshot": $(jq -Rn --arg v "$SNAPSHOT" '$v'),
  "build_mode": "native-arm64-qemu-historical-chroot-binary-arch",
  "expected_binary_packages": $(jq -c '.binary_packages' <<<"$entry")
}
EOF

find "$OUTPUT_DIR_ABS" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > "$OUTPUT_DIR_ABS/SHA256SUMS"

cat "$OUTPUT_DIR_ABS/build-lock.json"
