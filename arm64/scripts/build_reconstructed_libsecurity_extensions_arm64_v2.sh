#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 1 ] || usage
OUTPUT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECONSTRUCTOR="${HANCOM_GOOROOM_XSM_RECONSTRUCTOR:-$SCRIPT_DIR/reconstruct_libsecurity_xsm_arm64_v2.py}"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
BOOTSTRAP_IMAGE="${HANCOM_GOOROOM_BOOTSTRAP_IMAGE:-arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"

PACKAGING_REPOSITORY="gooroom/gooroom-libsecurity-extensions"
PACKAGING_COMMIT="4990bab95ae1dcaa29f38836da83edfa0969ed73"
PACKAGING_TREE="e1dce97d3cd69331047c01940b2593a0eaf2307a"
SOURCE_VERSION="0.1.7+grm3u1"
FINAL_AMD64_COMMIT="40d69bd620b022aa4ecb6f7d968c87e7f8df5a28"
FINAL_AMD64_BLOB="416fbb7260c30d5075b1da6dd32aa8d81ef4a49f"
FINAL_AMD64_SHA256="d28c255bb00061b0df60f977e9c022a01e8d98e957b1cbcd145aaa3940aa37c8"
FINAL_AMD64_SIZE=27072

PUBLIC_REPOSITORY="ultract/X.org-Security-Module"
PUBLIC_COMMIT="fb0a3de9cab9b9f5b89aabd7943a5b5f13f37ab7"
PUBLIC_TREE="aef0ff9c73f625763b3822c7cfa7179799f26637"
PUBLIC_XSM_SHA256="6ba6fbf4468d0b7f72a15483c43226ffcf686a0cde95998a8bd117aad91d0ddb"
TARGET_MULTIARCH="aarch64-linux-gnu"

for command in git docker python3 sha256sum stat readlink tar jq dpkg-deb file readelf strings grep find awk; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done
[ -f "$RECONSTRUCTOR" ] || {
  echo "XSM reconstructor not found: $RECONSTRUCTOR" >&2
  exit 69
}
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid Debian snapshot: $SNAPSHOT" >&2
  exit 2
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 host required" >&2; exit 2 ;;
esac
case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) ;;
  *) echo "native ARM64 Docker daemon required" >&2; exit 2 ;;
esac

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(readlink -f "$OUTPUT_DIR")"
find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- '{}' +
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
PACKAGING_GIT="$WORK_DIR/packaging-git"
PUBLIC_GIT="$WORK_DIR/public-git"
PACKAGING_ROOT="$WORK_DIR/packaging"
PUBLIC_ROOT="$WORK_DIR/public"
RECONSTRUCTED_ROOT="$WORK_DIR/reconstructed"
INSIDE_SCRIPT="$WORK_DIR/build-inside.sh"
mkdir -p "$PACKAGING_GIT" "$PUBLIC_GIT" "$PACKAGING_ROOT" "$PUBLIC_ROOT" "$RECONSTRUCTED_ROOT"
export GIT_TERMINAL_PROMPT=0

fetch_exact_git_tree() {
  local repository="$1" commit="$2" tree="$3" destination="$4"
  git -C "$destination" init --quiet
  git -C "$destination" remote add origin "https://github.com/${repository}.git"
  git -C "$destination" -c protocol.version=2 fetch \
    --quiet --force --no-tags --depth=1 origin "$commit"
  local actual_commit actual_tree
  actual_commit="$(git -C "$destination" rev-parse FETCH_HEAD)"
  actual_tree="$(git -C "$destination" rev-parse 'FETCH_HEAD^{tree}')"
  [ "$actual_commit" = "$commit" ] || {
    echo "$repository commit mismatch: $actual_commit != $commit" >&2
    exit 3
  }
  [ "$actual_tree" = "$tree" ] || {
    echo "$repository tree mismatch: $actual_tree != $tree" >&2
    exit 3
  }
}

fetch_exact_git_tree "$PACKAGING_REPOSITORY" "$PACKAGING_COMMIT" "$PACKAGING_TREE" "$PACKAGING_GIT"
fetch_exact_git_tree "$PUBLIC_REPOSITORY" "$PUBLIC_COMMIT" "$PUBLIC_TREE" "$PUBLIC_GIT"

git -C "$PACKAGING_GIT" archive --format=tar "$PACKAGING_COMMIT" | tar -xf - -C "$PACKAGING_ROOT"
git -C "$PUBLIC_GIT" archive --format=tar "$PUBLIC_COMMIT" | tar -xf - -C "$PUBLIC_ROOT"

[ "$(git -C "$PACKAGING_GIT" rev-parse "$PACKAGING_COMMIT:lib/xsm.so")" = "$FINAL_AMD64_BLOB" ] || {
  echo "exact packaging tree does not contain the locked final AMD64 XSM blob" >&2
  exit 3
}
[ -f "$PACKAGING_ROOT/lib/xsm.so" ] || {
  echo "exact packaging tree has no lib/xsm.so" >&2
  exit 3
}
[ "$(stat -c '%s' "$PACKAGING_ROOT/lib/xsm.so")" = "$FINAL_AMD64_SIZE" ] || {
  echo "exact final AMD64 XSM size mismatch" >&2
  exit 3
}
[ "$(sha256sum "$PACKAGING_ROOT/lib/xsm.so" | awk '{print $1}')" = "$FINAL_AMD64_SHA256" ] || {
  echo "exact final AMD64 XSM SHA-256 mismatch" >&2
  exit 3
}
[ -f "$PUBLIC_ROOT/xsm.c" ] || {
  echo "immutable public source has no xsm.c" >&2
  exit 3
}
[ "$(sha256sum "$PUBLIC_ROOT/xsm.c" | awk '{print $1}')" = "$PUBLIC_XSM_SHA256" ] || {
  echo "immutable public xsm.c SHA-256 mismatch" >&2
  exit 3
}

python3 "$RECONSTRUCTOR" \
  "$PUBLIC_ROOT/xsm.c" \
  "$RECONSTRUCTED_ROOT/xsm.c" \
  "$RECONSTRUCTED_ROOT/reconstruction-manifest.json" \
  --target-multiarch "$TARGET_MULTIARCH" \
  > "$OUTPUT_DIR/reconstruction-generator.stdout.json"
cp "$RECONSTRUCTED_ROOT/reconstruction-manifest.json" "$OUTPUT_DIR/"
cp "$RECONSTRUCTED_ROOT/xsm.c" "$OUTPUT_DIR/reconstructed-xsm.c"

jq -e \
  --arg source_sha "$PUBLIC_XSM_SHA256" \
  --arg packaging_commit "$PACKAGING_COMMIT" \
  --arg final_sha "$FINAL_AMD64_SHA256" '
    .schema == 3
    and .source_status == "reconstructed-not-recovered-original-source"
    and .byte_identity_claimed == false
    and .published_source.xsm_c_sha256 == $source_sha
    and .exact_packaging.commit == $packaging_commit
    and .final_amd64_binary_evidence.sha256 == $final_sha
  ' "$OUTPUT_DIR/reconstruction-manifest.json" >/dev/null

cat > "$OUTPUT_DIR/source-lock-evidence.json" <<EOF
{
  "schema": 3,
  "source": "gooroom-libsecurity-extensions",
  "source_version": "$SOURCE_VERSION",
  "repository": "$PACKAGING_REPOSITORY",
  "commit_sha": "$PACKAGING_COMMIT",
  "verified_commit_sha": "$PACKAGING_COMMIT",
  "tree_sha": "$PACKAGING_TREE",
  "verified_tree_sha": "$PACKAGING_TREE",
  "public_implementation_repository": "$PUBLIC_REPOSITORY",
  "public_implementation_commit": "$PUBLIC_COMMIT",
  "public_implementation_tree": "$PUBLIC_TREE",
  "final_amd64_binary_commit": "$FINAL_AMD64_COMMIT",
  "final_amd64_binary_blob": "$FINAL_AMD64_BLOB",
  "final_amd64_binary_sha256": "$FINAL_AMD64_SHA256",
  "source_status": "binary-history-constrained-reconstruction"
}
EOF
printf '%s\n' "$BOOTSTRAP_IMAGE" > "$OUTPUT_DIR/bootstrap-image.txt"

cat > "$INSIDE_SCRIPT" <<'INNER'
#!/usr/bin/env bash
set -Eeuo pipefail

: "${SNAPSHOT:?SNAPSHOT is required}"
: "${SOURCE_VERSION:?SOURCE_VERSION is required}"
: "${HOST_UID:?HOST_UID is required}"
: "${HOST_GID:?HOST_GID is required}"
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
mkdir -p /out

finish() {
  chown -R "$HOST_UID:$HOST_GID" /out 2>/dev/null || true
}
cleanup_mounts() {
  umount -R /snapshot-root/dev 2>/dev/null || true
  umount /snapshot-root/proc 2>/dev/null || true
  umount /snapshot-root/sys 2>/dev/null || true
}
trap 'cleanup_mounts; finish' EXIT

[ "$(dpkg --print-architecture)" = arm64 ] || {
  echo "transport container is not ARM64" >&2
  exit 19
}
cat > /etc/apt/sources.list <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
rm -f /etc/apt/sources.list.d/*
cat > /etc/apt/apt.conf.d/99snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
apt-get update > /out/transport-apt-update.log 2>&1
apt-get install -y --no-install-recommends \
  ca-certificates debootstrap debian-archive-keyring xz-utils \
  > /out/transport-apt-install.log 2>&1

ROOT=/snapshot-root
rm -rf "$ROOT"
mkdir -p "$ROOT"
debootstrap \
  --arch=arm64 \
  --variant=buildd \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  --include=ca-certificates,debian-archive-keyring \
  bullseye \
  "$ROOT" \
  "http://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
  > /out/debootstrap.log 2>&1

cat > "$ROOT/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
rm -f "$ROOT/etc/apt/sources.list.d/"*
cp /etc/apt/apt.conf.d/99snapshot "$ROOT/etc/apt/apt.conf.d/99snapshot"
cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"
mkdir -p "$ROOT/build/packaging" "$ROOT/build/reconstructed" "$ROOT/build/output"
cp -a /packaging/. "$ROOT/build/packaging/"
cp -a /reconstructed/. "$ROOT/build/reconstructed/"

cat > "$ROOT/build/run-build.sh" <<'CHROOT'
#!/usr/bin/env bash
set -Eeuo pipefail
export HOME=/root
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export DEB_BUILD_OPTIONS="nocheck nodoc parallel=2"
export DEB_BUILD_PROFILES="pkg.nocheck nodoc"
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

apt-get update > /build/output/chroot-apt-update.log 2>&1
apt-get install -y --no-install-recommends \
  build-essential binutils ca-certificates debhelper dpkg-dev fakeroot file \
  libdbus-1-dev libdbus-glib-1-dev libgdk-pixbuf2.0-0 libjson-c-dev libnotify-dev libsystemd-dev pkg-config \
  python3 xserver-xorg-dev \
  > /build/output/chroot-apt-install.log 2>&1

dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | LC_ALL=C sort > /build/output/build-environment-packages.tsv
cd /build/packaging
[ "$(dpkg-parsechangelog -S Source)" = gooroom-libsecurity-extensions ]
[ "$(dpkg-parsechangelog -S Version)" = "$SOURCE_VERSION" ]

cp /build/reconstructed/xsm.c ./xsm-arm64-reconstructed.c
export SOURCE_DATE_EPOCH="$(dpkg-parsechangelog -S Date | date -f - +%s)"
pkg-config xorg-server --cflags --libs dbus-1,libnotify,json-c \
  > /build/output/pkg-config-command-line.txt

# Keep the historical link order. The pkg-config libraries precede the source,
# so Debian's --as-needed drops Xorg/DBus/systemd providers that the Xorg server
# supplies at load time. libdl remains after the source, matching the exact
# AMD64 binary's runtime dependency structure.
gcc $(pkg-config xorg-server --cflags --libs dbus-1,libnotify,json-c) \
  -DXACE -D_XSERVER64 -DX_REGISTRY_REQUEST \
  -DX_REGISTRY_RESOURCE -DCOMPOSITE \
  xsm-arm64-reconstructed.c -o lib/xsm.so \
  -shared -ldl -fPIC -s \
  > /build/output/xsm-compile.stdout.log \
  2> /build/output/xsm-compile.stderr.log

file lib/xsm.so > /build/output/prepackage-xsm.file.txt
readelf -hW lib/xsm.so > /build/output/prepackage-xsm.readelf.txt
readelf -dW lib/xsm.so > /build/output/prepackage-xsm.dynamic.txt
readelf -WsW lib/xsm.so > /build/output/prepackage-xsm.symbols.txt
strings -a -n 4 lib/xsm.so | LC_ALL=C sort -u \
  > /build/output/prepackage-xsm.strings.txt

python3 - <<'PY'
from pathlib import Path
import re

root = Path('/build/output')
readelf = (root / 'prepackage-xsm.readelf.txt').read_text(errors='replace')
if not re.search(r'^\s*Machine:\s*AArch64\s*$', readelf, re.MULTILINE):
    raise SystemExit('reconstructed XSM is not AArch64')

dynamic = (root / 'prepackage-xsm.dynamic.txt').read_text(errors='replace')
needed = re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic)
expected = {'libdl.so.2', 'libpthread.so.0', 'libc.so.6'}
if set(needed) != expected:
    raise SystemExit(f'unexpected reconstructed XSM NEEDED set: {needed!r}')

symbols = (root / 'prepackage-xsm.symbols.txt').read_text(errors='replace')
for symbol in ('xsmModuleData', 'dlopen', 'dlsym', 'dlclose',
               'dbus_message_new_signal', 'sd_journal_send_with_location'):
    if symbol not in symbols:
        raise SystemExit(f'required symbol absent from reconstructed XSM: {symbol}')

raw = Path('/build/packaging/lib/xsm.so').read_bytes()
for value in (
    b'/etc/gooroom/grac.d/user.rules',
    b'/etc/gooroom/grac.d/default.rules',
    b'/usr/lib/aarch64-linux-gnu/libjson-c.so.5',
    b'/kr/gooroom/GRACDEVD',
    b'kr.gooroom.GRACDEVD',
    b'grac_noti_forward',
    b'GRAC-EXT',
    b'GRMCODE=%s',
    b'screen_capture',
    b'/usr/libexec/at-spi2-registryd',
    b'/usr/bin/gnome-flashback',
    b'/usr/libexec/gnome-terminal-server',
    '040019:비인가된 행위(스크린캡쳐)가 탐지되어 차단하였습니다'.encode(),
    '040020:비인가된 행위(클립보드)가 탐지되어 차단하였습니다'.encode(),
):
    if value not in raw:
        raise SystemExit(f'required semantic byte string absent: {value!r}')
for forbidden in (
    b'/usr/lib/x86_64-linux-gnu/libjson-c.so.5',
    b'/etc/xsm/default.rules',
    b'XSM-LOG',
):
    if forbidden in raw:
        raise SystemExit(f'forbidden superseded byte string remains: {forbidden!r}')
PY

rm -f ../gooroom-libsecurity-extensions_*_arm64.deb \
      ../gooroom-libsecurity-extensions_*_arm64.buildinfo \
      ../gooroom-libsecurity-extensions_*_arm64.changes

dpkg-buildpackage -us -uc -B -j2 \
  > /build/output/dpkg-buildpackage.stdout.log \
  2> /build/output/dpkg-buildpackage.stderr.log
find /build -maxdepth 1 -type f \
  \( -name '*.deb' -o -name '*.buildinfo' -o -name '*.changes' \) \
  -exec cp -v '{}' /build/output/ \;
CHROOT
chmod +x "$ROOT/build/run-build.sh"
mount --rbind /dev "$ROOT/dev"
mount --make-rslave "$ROOT/dev"
mount -t proc proc "$ROOT/proc"
mount -t sysfs sysfs "$ROOT/sys"
set +e
chroot "$ROOT" /bin/bash /build/run-build.sh \
  > /out/chroot-build.stdout.log \
  2> /out/chroot-build.stderr.log
rc=$?
set -e
cp -a "$ROOT/build/output/." /out/ || true
exit "$rc"
INNER
chmod +x "$INSIDE_SCRIPT"

set +e
docker run --rm --privileged --platform linux/arm64 \
  --env "SNAPSHOT=$SNAPSHOT" \
  --env "SOURCE_VERSION=$SOURCE_VERSION" \
  --env "HOST_UID=$(id -u)" \
  --env "HOST_GID=$(id -g)" \
  --volume "$PACKAGING_ROOT:/packaging:ro" \
  --volume "$RECONSTRUCTED_ROOT:/reconstructed:ro" \
  --volume "$OUTPUT_DIR:/out" \
  --volume "$INSIDE_SCRIPT:/build-inside.sh:ro" \
  "$BOOTSTRAP_IMAGE" \
  /bin/bash /build-inside.sh \
  > "$OUTPUT_DIR/container.stdout.log" \
  2> "$OUTPUT_DIR/container.stderr.log"
BUILD_RC=$?
set -e
printf '%s\n' "$BUILD_RC" > "$OUTPUT_DIR/container.exit-code"
[ "$BUILD_RC" -eq 0 ] || {
  echo "reconstructed libsecurity package build failed: $BUILD_RC" >&2
  exit "$BUILD_RC"
}

shopt -s nullglob
DEBS=("$OUTPUT_DIR"/gooroom-libsecurity-extensions_*_arm64.deb)
[ "${#DEBS[@]}" -eq 1 ] || {
  echo "expected exactly one ARM64 package, found ${#DEBS[@]}" >&2
  exit 4
}
DEB="${DEBS[0]}"
[ "$(dpkg-deb -f "$DEB" Package)" = gooroom-libsecurity-extensions ]
[ "$(dpkg-deb -f "$DEB" Version)" = "$SOURCE_VERSION" ]
[ "$(dpkg-deb -f "$DEB" Architecture)" = arm64 ]

EXTRACTED="$WORK_DIR/extracted"
mkdir -p "$EXTRACTED"
dpkg-deb -x "$DEB" "$EXTRACTED"
PAYLOAD="$EXTRACTED/usr/lib/xorg/modules/extensions/xsm.so"
[ -f "$PAYLOAD" ] || {
  echo "packaged XSM payload is missing" >&2
  exit 5
}
file "$PAYLOAD" > "$OUTPUT_DIR/packaged-xsm.file.txt"
readelf -hW "$PAYLOAD" > "$OUTPUT_DIR/packaged-xsm.readelf.txt"
readelf -dW "$PAYLOAD" > "$OUTPUT_DIR/packaged-xsm.dynamic.txt"
readelf -WsW "$PAYLOAD" > "$OUTPUT_DIR/packaged-xsm.symbols.txt"
strings -a -n 4 "$PAYLOAD" | LC_ALL=C sort -u > "$OUTPUT_DIR/packaged-xsm.strings.txt"
find "$EXTRACTED" -type f -exec file -- '{}' + | LC_ALL=C sort \
  > "$OUTPUT_DIR/package-file-report.txt"
if grep -E \
  'ELF (32|64)-bit .* (x86-64|Intel 80386)|PE32(\+)? executable .* (x86-64|Intel 80386)' \
  "$OUTPUT_DIR/package-file-report.txt"; then
  echo "x86 executable leaked into reconstructed package" >&2
  exit 5
fi
grep -Eq '^ *Machine: +AArch64$' "$OUTPUT_DIR/packaged-xsm.readelf.txt"
grep -q 'xsmModuleData' "$OUTPUT_DIR/packaged-xsm.symbols.txt"
grep -Fq '/usr/lib/aarch64-linux-gnu/libjson-c.so.5' "$OUTPUT_DIR/packaged-xsm.strings.txt"
! grep -Fq '/usr/lib/x86_64-linux-gnu/libjson-c.so.5' "$OUTPUT_DIR/packaged-xsm.strings.txt"

PACKAGE_SHA256="$(sha256sum "$DEB" | awk '{print $1}')"
PACKAGE_SIZE="$(stat -c '%s' "$DEB")"
PAYLOAD_SHA256="$(sha256sum "$PAYLOAD" | awk '{print $1}')"
cat > "$OUTPUT_DIR/build-lock.json" <<EOF
{
  "schema": 4,
  "source": "gooroom-libsecurity-extensions",
  "source_version": "$SOURCE_VERSION",
  "target_architecture": "arm64",
  "build_mode": "native-arm64-binary-history-constrained-reconstruction",
  "source_status": "reconstructed-not-recovered-original-source",
  "byte_identity_claimed": false,
  "packaging": {
    "repository": "$PACKAGING_REPOSITORY",
    "commit": "$PACKAGING_COMMIT",
    "tree": "$PACKAGING_TREE"
  },
  "public_implementation": {
    "repository": "$PUBLIC_REPOSITORY",
    "commit": "$PUBLIC_COMMIT",
    "tree": "$PUBLIC_TREE",
    "xsm_c_sha256": "$PUBLIC_XSM_SHA256"
  },
  "final_amd64_binary": {
    "commit": "$FINAL_AMD64_COMMIT",
    "blob": "$FINAL_AMD64_BLOB",
    "sha256": "$FINAL_AMD64_SHA256",
    "size": $FINAL_AMD64_SIZE
  },
  "package": {
    "filename": "$(basename "$DEB")",
    "sha256": "$PACKAGE_SHA256",
    "size": $PACKAGE_SIZE,
    "architecture": "arm64"
  },
  "payload": {
    "path": "/usr/lib/xorg/modules/extensions/xsm.so",
    "sha256": "$PAYLOAD_SHA256",
    "machine": "AArch64"
  },
  "wrong_architecture_executable_count": 0,
  "verified": true
}
EOF

(
  cd "$OUTPUT_DIR"
  find . -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
  sha256sum --check SHA256SUMS
)
cat "$OUTPUT_DIR/build-lock.json"
