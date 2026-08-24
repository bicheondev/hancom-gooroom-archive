#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 ARCH SOURCE_TAR OUTPUT_DIR [SNAPSHOT]" >&2
  exit 64
}

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || usage
ARCH="$1"
SOURCE_TAR="$(readlink -f "$2")"
OUTPUT_DIR="$(mkdir -p "$3" && cd "$3" && pwd)"
SNAPSHOT="${4:-20230730T235959Z}"
VERSION='0.3.1+grm3u1+han3u2'

case "$ARCH" in
  amd64|arm64) ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 64 ;;
esac
[ "$(id -u)" -eq 0 ] || {
  echo "this builder must run as root" >&2
  exit 77
}
[ -f "$SOURCE_TAR" ] || {
  echo "source archive not found: $SOURCE_TAR" >&2
  exit 69
}
for command in debootstrap chroot tar find dpkg-deb sha256sum; do
  command -v "$command" >/dev/null || {
    echo "required command missing: $command" >&2
    exit 69
  }
done

ROOTFS="$OUTPUT_DIR/rootfs"
rm -rf "$ROOTFS" "$OUTPUT_DIR/debs"
mkdir -p "$OUTPUT_DIR/debs"

debootstrap \
  --arch="$ARCH" \
  --variant=minbase \
  --include=ca-certificates \
  --no-check-gpg \
  bullseye \
  "$ROOTFS" \
  "https://snapshot.debian.org/archive/debian/$SNAPSHOT/" \
  2>&1 | tee "$OUTPUT_DIR/debootstrap.log"

cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/$SNAPSHOT bullseye main
EOF
cat > "$ROOTFS/etc/apt/apt.conf.d/99snapshot" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
Dpkg::Use-Pty "0";
EOF
mkdir -p "$ROOTFS/build/source"
tar -xf "$SOURCE_TAR" -C "$ROOTFS/build/source"
chown -R root:root "$ROOTFS/build/source"

set +e
chroot "$ROOTFS" /bin/bash -euxo pipefail -c '
  export DEBIAN_FRONTEND=noninteractive
  export DEB_BUILD_OPTIONS=nocheck
  export LC_ALL=C.UTF-8
  apt-get update
  apt-get install -y --no-install-recommends \
    build-essential devscripts dpkg-dev equivs git
  cd /build/source
  mk-build-deps \
    --install \
    --remove \
    --tool "apt-get -y --no-install-recommends" \
    debian/control
  dpkg-buildpackage -us -uc -b -j2
' 2>&1 | tee "$OUTPUT_DIR/build.log"
BUILD_RC=${PIPESTATUS[0]}
set -e
[ "$BUILD_RC" -eq 0 ] || exit "$BUILD_RC"

while IFS= read -r package; do
  cp "$package" "$OUTPUT_DIR/debs/"
done < <(
  find "$ROOTFS/build" -maxdepth 1 -type f \
    -name "*_${VERSION}_${ARCH}.deb" \
    | LC_ALL=C sort
)
[ -n "$(find "$OUTPUT_DIR/debs" -maxdepth 1 -type f -name '*.deb' -print -quit)" ] || {
  echo "build produced no $ARCH DEBs for $VERSION" >&2
  exit 2
}

main_count=0
for deb in "$OUTPUT_DIR"/debs/*.deb; do
  package="$(dpkg-deb -f "$deb" Package)"
  version="$(dpkg-deb -f "$deb" Version)"
  architecture="$(dpkg-deb -f "$deb" Architecture)"
  [ "$version" = "$VERSION" ] || {
    echo "wrong version in $deb: $version" >&2
    exit 3
  }
  [ "$architecture" = "$ARCH" ] || {
    echo "wrong architecture in $deb: $architecture" >&2
    exit 3
  }
  [ "$package" != gooroom-greeter ] || main_count=$((main_count + 1))
done
[ "$main_count" -eq 1 ] || {
  echo "expected exactly one gooroom-greeter package, got $main_count" >&2
  exit 3
}

(
  cd "$OUTPUT_DIR/debs"
  sha256sum ./*.deb > SHA256SUMS
  sha256sum --check SHA256SUMS
)
rm -rf "$ROOTFS"
