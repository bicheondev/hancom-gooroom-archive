#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 SOURCE_ARCHIVE_DIR SOURCE VERSION OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 4 ] || usage
ARCHIVE_DIR="$1"
SOURCE_NAME="$2"
SOURCE_VERSION="$3"
OUTPUT_DIR="$4"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
IMAGE="${HANCOM_GOOROOM_ARM64_BUILD_IMAGE:-arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"

case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 host required" >&2; exit 77 ;;
esac
command -v docker >/dev/null || {
  echo "docker is missing" >&2
  exit 69
}
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid snapshot timestamp: $SNAPSHOT" >&2
  exit 64
}

ARCHIVE_DIR="$(readlink -f "$ARCHIVE_DIR")"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(readlink -f "$OUTPUT_DIR")"
[ -d "$ARCHIVE_DIR" ] || {
  echo "source archive directory is missing: $ARCHIVE_DIR" >&2
  exit 66
}
LOCK="$ARCHIVE_DIR/source-archive-lock.json"
[ -f "$LOCK" ] || {
  echo "source archive lock is missing: $LOCK" >&2
  exit 66
}

python3 - "$ARCHIVE_DIR" "$SOURCE_NAME" "$SOURCE_VERSION" <<'PY'
from pathlib import Path
import hashlib
import json
import sys

root = Path(sys.argv[1])
source = sys.argv[2]
version = sys.argv[3]
lock = json.loads((root / 'source-archive-lock.json').read_text(encoding='utf-8'))
if lock.get('status') != 'resolved':
    raise SystemExit(f"source archive status is {lock.get('status')!r}")
if lock.get('source') != source or lock.get('version') != version:
    raise SystemExit('source archive identity mismatch')
records = [lock.get('dsc'), *lock.get('files', [])]
for record in records:
    if not isinstance(record, dict):
        raise SystemExit('invalid source file record')
    filename = record.get('filename')
    expected_size = record.get('size')
    expected_sha = record.get('sha256')
    if not filename or expected_size is None or not expected_sha:
        raise SystemExit(f'incomplete source file record: {record!r}')
    path = root / filename
    if not path.is_file():
        raise SystemExit(f'source file is missing: {filename}')
    if path.stat().st_size != int(expected_size):
        raise SystemExit(f'source file size mismatch: {filename}')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != expected_sha:
        raise SystemExit(f'source file sha256 mismatch: {filename}')
print(lock['dsc']['filename'])
PY

printf '%s\n' "$SOURCE_NAME" > "$OUTPUT_DIR/source-name.txt"
printf '%s\n' "$SOURCE_VERSION" > "$OUTPUT_DIR/source-version.txt"
printf '%s\n' "$SNAPSHOT" > "$OUTPUT_DIR/debian-snapshot.txt"
printf '%s\n' "$IMAGE" > "$OUTPUT_DIR/build-container-image.txt"
sha256sum "$LOCK" > "$OUTPUT_DIR/source-archive-lock.sha256"

INNER="$(mktemp)"
trap 'rm -f "$INNER"' EXIT
cat > "$INNER" <<'INNER_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_NAME="$1"
SOURCE_VERSION="$2"
SNAPSHOT="$3"
ROOT=/snapshot-root
INPUT=/input
HOST_OUT=/out

copy_partial() {
  set +e
  if [ -d "$ROOT/build/output" ]; then
    cp -a "$ROOT/build/output/." "$HOST_OUT/" 2>/dev/null || true
  fi
}
trap copy_partial EXIT

cat > /etc/apt/sources.list <<EOF
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
cat > /etc/apt/apt.conf.d/99snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "10";
Acquire::https::Timeout "45";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates debootstrap debian-archive-keyring xz-utils

rm -rf "$ROOT"
mkdir -p "$ROOT"
deBootstrapLog="$HOST_OUT/dsc-debootstrap.log"
deBootstrapUrl="https://snapshot.debian.org/archive/debian/${SNAPSHOT}/"
if ! debootstrap \
  --arch=arm64 \
  --variant=buildd \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  bullseye \
  "$ROOT" \
  "$deBootstrapUrl" \
  > "$deBootstrapLog" 2>&1; then
  cat "$deBootstrapLog" >&2
  exit 20
fi

cat > "$ROOT/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
cat > "$ROOT/etc/apt/apt.conf.d/99snapshot" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "10";
Acquire::https::Timeout "45";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"
printf '#!/bin/sh\nexit 101\n' > "$ROOT/usr/sbin/policy-rc.d"
chmod +x "$ROOT/usr/sbin/policy-rc.d"
mkdir -p "$ROOT/build/input" "$ROOT/build/output"
cp -a "$INPUT/." "$ROOT/build/input/"

cat > "$ROOT/root/build-exact-dsc.sh" <<'CHROOT_BUILD'
#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEB_BUILD_OPTIONS="nocheck parallel=2"
export DEB_BUILD_PROFILES="nocheck"

SOURCE_NAME="$1"
SOURCE_VERSION="$2"
cd /build
apt-get update
apt-get install -y --no-install-recommends \
  build-essential ca-certificates debhelper devscripts dpkg-dev equivs \
  fakeroot file git jq patchutils python3 xz-utils

dsc="$(find /build/input -maxdepth 1 -type f -name '*.dsc' -print -quit)"
[ -n "$dsc" ] || {
  echo 'no .dsc file was supplied' >&2
  exit 2
}
rm -rf /build/source
dpkg-source -x "$dsc" /build/source
actual_source="$(dpkg-parsechangelog -l/build/source/debian/changelog -SSource)"
actual_version="$(dpkg-parsechangelog -l/build/source/debian/changelog -SVersion)"
[ "$actual_source" = "$SOURCE_NAME" ] || {
  echo "source mismatch: $actual_source != $SOURCE_NAME" >&2
  exit 3
}
[ "$actual_version" = "$SOURCE_VERSION" ] || {
  echo "version mismatch: $actual_version != $SOURCE_VERSION" >&2
  exit 3
}
printf '%s\n' "$actual_source" > /build/output/declared-source.txt
printf '%s\n' "$actual_version" > /build/output/declared-version.txt

cd /build/source
rm -f ./*-build-deps*.deb
set +e
mk-build-deps --build-dep debian/control
mk_rc=$?
set -e
dummy="$(find . -maxdepth 1 -type f -name '*-build-deps*.deb' -print -quit)"
[ -n "$dummy" ] || {
  echo "mk-build-deps failed with code $mk_rc and produced no package" >&2
  exit 21
}
printf '%s\n' "$(basename "$dummy")" \
  > /build/output/build-dependency-metapackage.txt
apt-get -s install "./$(basename "$dummy")" \
  > /build/output/apt-solver-simulation.log
apt-get install -y "./$(basename "$dummy")"
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | sort > /build/output/build-environment-packages.tsv

dpkg-buildpackage -us -uc -B
find /build -maxdepth 1 -type f \
  \( -name '*.deb' -o -name '*.changes' -o -name '*.buildinfo' \) \
  ! -name '*-build-deps*.deb' \
  -exec cp -v '{}' /build/output/ ';'
CHROOT_BUILD
chmod +x "$ROOT/root/build-exact-dsc.sh"

set +e
chroot "$ROOT" /bin/bash /root/build-exact-dsc.sh \
  "$SOURCE_NAME" "$SOURCE_VERSION" \
  > >(tee "$HOST_OUT/dsc-chroot-build.log") \
  2> >(tee "$HOST_OUT/dsc-chroot-build.stderr.log" >&2)
build_rc=$?
set -e
copy_partial
exit "$build_rc"
INNER_SCRIPT
chmod +x "$INNER"

set +e
docker run --rm --privileged \
  --platform linux/arm64 \
  -v "$ARCHIVE_DIR:/input:ro" \
  -v "$OUTPUT_DIR:/out" \
  -v "$INNER:/runner:ro" \
  "$IMAGE" \
  /runner "$SOURCE_NAME" "$SOURCE_VERSION" "$SNAPSHOT" \
  2>&1 | tee "$OUTPUT_DIR/dsc-build-console.log"
rc="${PIPESTATUS[0]}"
set -e
if command -v sudo >/dev/null 2>&1; then
  sudo chown -R "$(id -u):$(id -g)" "$OUTPUT_DIR" || true
fi
printf '%s\n' "$rc" > "$OUTPUT_DIR/dsc-builder.exit-code"
if [ "$rc" != 0 ]; then
  exit "$rc"
fi
find "$OUTPUT_DIR" -maxdepth 1 -type f -name '*.deb' -print -quit | grep -q . || {
  echo "the exact .dsc build produced no Debian packages" >&2
  exit 22
}
