#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: build_recovered_source_archive_arm64.sh \
  <source-archive-dir> <local-deb-repository-dir> <output-dir> <source> <version>
EOF
}

if [[ $# -ne 5 ]]; then
  usage >&2
  exit 64
fi

SOURCE_ARCHIVE_DIR="$(realpath "$1")"
mkdir -p "$2" "$3"
LOCAL_REPO_DIR="$(realpath "$2")"
OUTPUT_DIR="$(realpath "$3")"
SOURCE_NAME="$4"
SOURCE_VERSION="$5"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
BUILD_JOBS="${HANCOM_GOOROOM_BUILD_JOBS:-3}"
# This image is only the immutable debootstrap carrier.  All packages used by
# dpkg-buildpackage are installed into a fresh rootfs from the locked snapshot.
BOOTSTRAP_IMAGE="${HANCOM_GOOROOM_BOOTSTRAP_IMAGE:-debian@sha256:f313b4bd62667092a59b3a664d7d3ab8b5e65f41675f48e81455a15dc5abe792}"

for command in docker dpkg-scanpackages sha256sum; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 69
  }
done

case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 host required; got $(uname -m)" >&2; exit 1 ;;
esac

if [[ ! -d "$SOURCE_ARCHIVE_DIR" ]]; then
  echo "source archive directory is missing: $SOURCE_ARCHIVE_DIR" >&2
  exit 66
fi
mapfile -t DSC_FILES < <(find "$SOURCE_ARCHIVE_DIR" -maxdepth 1 -type f -name '*.dsc' -print | sort)
if [[ ${#DSC_FILES[@]} -ne 1 ]]; then
  echo "exactly one .dsc is required in $SOURCE_ARCHIVE_DIR" >&2
  printf '%s\n' "${DSC_FILES[@]:-}" >&2
  exit 65
fi
DSC_NAME="$(basename "${DSC_FILES[0]}")"

find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
mkdir -p "$OUTPUT_DIR/logs" "$LOCAL_REPO_DIR"
chmod -R a+rX "$SOURCE_ARCHIVE_DIR" "$LOCAL_REPO_DIR"

# Regenerate a deterministic flat repository for all previously verified ARM64
# packages. An empty repository is valid; Debian snapshot dependencies may be
# sufficient for upstream-derived sources.
(
  cd "$LOCAL_REPO_DIR"
  find . -maxdepth 1 -type f -name '*.deb' -printf '%f\n' | LC_ALL=C sort \
    > .deb-files
  dpkg-scanpackages --multiversion . /dev/null > Packages
  gzip -n -9 -c Packages > Packages.gz
  sha256sum Packages Packages.gz > SHA256SUMS
)

SCRIPT_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$SCRIPT_DIR"
}
trap cleanup EXIT

cat > "$SCRIPT_DIR/bootstrap-build.sh" <<'BOOTSTRAP_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export TZ=UTC

mkdir -p /output/logs

# The carrier image is pinned by digest, but its installed package universe is
# deliberately not used for the build.  It supplies only debootstrap and TLS
# tooling, whose exact versions are recorded below.
apt-get update \
  > /output/logs/bootstrap-apt-update.stdout \
  2> /output/logs/bootstrap-apt-update.stderr
apt-get install -y --no-install-recommends \
  ca-certificates debootstrap xz-utils \
  > /output/logs/bootstrap-apt-install.stdout \
  2> /output/logs/bootstrap-apt-install.stderr
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  ca-certificates debootstrap xz-utils \
  > /output/logs/bootstrap-tool-versions.tsv

SNAPSHOT_DEBIAN="https://snapshot.debian.org/archive/debian/${SNAPSHOT}/"
SNAPSHOT_SECURITY="https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/"
printf '%s\n' "$SNAPSHOT_DEBIAN" > /output/logs/snapshot-debian-url.txt
printf '%s\n' "$SNAPSHOT_SECURITY" > /output/logs/snapshot-security-url.txt

rm -rf /snapshot-root
mkdir -p /snapshot-root
debootstrap \
  --arch=arm64 \
  --variant=minbase \
  --no-check-gpg \
  --include=ca-certificates \
  bullseye \
  /snapshot-root \
  "$SNAPSHOT_DEBIAN" \
  > /output/logs/debootstrap.stdout \
  2> /output/logs/debootstrap.stderr

mkdir -p \
  /snapshot-root/source \
  /snapshot-root/repo \
  /snapshot-root/output \
  /snapshot-root/build/logs \
  /snapshot-root/etc/apt/apt.conf.d \
  /snapshot-root/etc/apt/preferences.d
cp -a /source/. /snapshot-root/source/
cp -a /repo/. /snapshot-root/repo/
cp -L /etc/resolv.conf /snapshot-root/etc/resolv.conf

cat > /snapshot-root/etc/apt/apt.conf.d/99hancom-snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
Acquire::http::Timeout "60";
Acquire::https::Timeout "60";
APT::Get::Assume-Yes "true";
Dpkg::Options { "--force-confold"; };
EOF

cat > /snapshot-root/etc/apt/sources.list <<EOF
# Exact historical Debian dependency universe used by the ARM64 port.
deb [trusted=yes check-valid-until=no] ${SNAPSHOT_DEBIAN} bullseye main contrib non-free
deb-src [trusted=yes check-valid-until=no] ${SNAPSHOT_DEBIAN} bullseye main contrib non-free
deb [trusted=yes check-valid-until=no] ${SNAPSHOT_DEBIAN} bullseye-updates main contrib non-free
deb-src [trusted=yes check-valid-until=no] ${SNAPSHOT_DEBIAN} bullseye-updates main contrib non-free
deb [trusted=yes check-valid-until=no] ${SNAPSHOT_SECURITY} bullseye-security main contrib non-free
deb-src [trusted=yes check-valid-until=no] ${SNAPSHOT_SECURITY} bullseye-security main contrib non-free
deb [trusted=yes] file:/repo ./
EOF

cat > /snapshot-root/etc/apt/preferences.d/99hancom-snapshot <<'EOF'
Package: *
Pin: release n=bullseye
Pin-Priority: 1001

Package: *
Pin: release n=bullseye-updates
Pin-Priority: 1001

Package: *
Pin: release n=bullseye-security
Pin-Priority: 1001
EOF

cat > /snapshot-root/usr/sbin/policy-rc.d <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 0755 /snapshot-root/usr/sbin/policy-rc.d

cat > /snapshot-root/build-in-chroot.sh <<'CHROOT_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export TZ=UTC

mkdir -p /build/logs /output
rm -rf /var/lib/apt/lists/*
apt-get update \
  > /build/logs/snapshot-apt-update.stdout \
  2> /build/logs/snapshot-apt-update.stderr
apt-get install -y --no-install-recommends \
  apt-utils build-essential devscripts dpkg-dev equivs \
  fakeroot file git pkg-config python3 rsync xz-utils \
  > /build/logs/snapshot-build-tools.stdout \
  2> /build/logs/snapshot-build-tools.stderr

dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | LC_ALL=C sort > /build/logs/snapshot-installed-packages.tsv
apt-cache policy libc6 libc6-dev perl perl-base gpgv libtinfo6 libncursesw6 \
  > /build/logs/snapshot-critical-package-policy.txt

rm -rf /build/source-parent /build/src
mkdir -p /build/source-parent
cp -a /source/. /build/source-parent/

dpkg-source -x "/build/source-parent/${DSC_NAME}" /build/src \
  > /build/logs/dpkg-source.stdout \
  2> /build/logs/dpkg-source.stderr
test -f /build/src/debian/changelog
head -n1 /build/src/debian/changelog | tee /build/logs/changelog-head.txt
dpkg-parsechangelog -l/build/src/debian/changelog -S Source \
  | tee /build/logs/source.txt
dpkg-parsechangelog -l/build/src/debian/changelog -S Version \
  | tee /build/logs/version.txt
test "$(cat /build/logs/source.txt)" = "$SOURCE_NAME"
test "$(cat /build/logs/version.txt)" = "$SOURCE_VERSION"

cd /build/src
mk-build-deps \
  --install \
  --remove \
  --tool "apt-get -y --no-install-recommends --allow-downgrades -o Dpkg::Options::=--force-confold" \
  debian/control \
  > /build/logs/mk-build-deps.stdout \
  2> /build/logs/mk-build-deps.stderr

export DEB_BUILD_OPTIONS="nocheck nodoc parallel=${BUILD_JOBS}"
export DEB_BUILD_PROFILES="pkg.linux.nokerneldbg pkg.linux.nokerneldbginfo"
set +e
dpkg-buildpackage \
  --build=binary \
  --no-sign \
  --jobs-force="${BUILD_JOBS}" \
  > /build/logs/dpkg-buildpackage.stdout \
  2> /build/logs/dpkg-buildpackage.stderr
build_rc=$?
set -e
printf '%s\n' "$build_rc" > /build/logs/dpkg-buildpackage.exit-code

find /build -maxdepth 1 -type f \
  \( -name '*.deb' -o -name '*.changes' -o -name '*.buildinfo' \) \
  -exec cp -a {} /output/ \;
find /build/source-parent -maxdepth 1 -type f \
  -exec sha256sum {} \; > /build/logs/source-members.sha256
find /repo -maxdepth 1 -type f -name '*.deb' -printf '%f\n' \
  | LC_ALL=C sort > /build/logs/local-repository-debs.txt

if [[ "$build_rc" -ne 0 ]]; then
  exit "$build_rc"
fi
find /output -maxdepth 1 -type f -name '*.deb' -print -quit | grep -q .
CHROOT_SCRIPT
chmod 0755 /snapshot-root/build-in-chroot.sh

chroot /snapshot-root dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | LC_ALL=C sort > /output/logs/snapshot-minbase-packages.tsv

set +e
chroot /snapshot-root /usr/bin/env \
  SOURCE_NAME="$SOURCE_NAME" \
  SOURCE_VERSION="$SOURCE_VERSION" \
  DSC_NAME="$DSC_NAME" \
  BUILD_JOBS="$BUILD_JOBS" \
  /bin/bash /build-in-chroot.sh
build_rc=$?
set -e

cp -a /snapshot-root/build/logs/. /output/logs/ 2>/dev/null || true
cp -a /snapshot-root/output/. /output/ 2>/dev/null || true
printf '%s\n' "$build_rc" > /output/logs/snapshot-chroot.exit-code
exit "$build_rc"
BOOTSTRAP_SCRIPT
chmod 0755 "$SCRIPT_DIR/bootstrap-build.sh"

set +e
docker pull --platform linux/arm64 "$BOOTSTRAP_IMAGE" \
  > "$OUTPUT_DIR/logs/bootstrap-image-pull.stdout" \
  2> "$OUTPUT_DIR/logs/bootstrap-image-pull.stderr"
pull_rc=$?
if [[ "$pull_rc" -eq 0 ]]; then
  docker image inspect "$BOOTSTRAP_IMAGE" \
    > "$OUTPUT_DIR/logs/bootstrap-image-inspect.json"
  SOURCE_NAME="$SOURCE_NAME" \
  SOURCE_VERSION="$SOURCE_VERSION" \
  DSC_NAME="$DSC_NAME" \
  SNAPSHOT="$SNAPSHOT" \
  BUILD_JOBS="$BUILD_JOBS" \
  docker run --rm \
    --platform linux/arm64 \
    --network host \
    -e SOURCE_NAME \
    -e SOURCE_VERSION \
    -e DSC_NAME \
    -e SNAPSHOT \
    -e BUILD_JOBS \
    -v "$SCRIPT_DIR/bootstrap-build.sh:/bootstrap-build.sh:ro" \
    -v "$SOURCE_ARCHIVE_DIR:/source:ro" \
    -v "$LOCAL_REPO_DIR:/repo:ro" \
    -v "$OUTPUT_DIR:/output" \
    "$BOOTSTRAP_IMAGE" \
    /bin/bash /bootstrap-build.sh
  build_rc=$?
else
  build_rc="$pull_rc"
fi
set -e
printf '%s\n' "$build_rc" > "$OUTPUT_DIR/logs/outer-build.exit-code"

find "$OUTPUT_DIR" -maxdepth 2 -type f -printf '%P\t%s\n' \
  | LC_ALL=C sort > "$OUTPUT_DIR/output-inventory.tsv"
(
  cd "$OUTPUT_DIR"
  find . -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)

exit "$build_rc"
