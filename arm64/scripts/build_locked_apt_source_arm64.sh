#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 APT_SOURCE_LOCK_JSON SOURCE OUTPUT_DIR" >&2
  exit 64
}
[ "$#" -eq 3 ] || usage

LOCK="$1"
SOURCE="$2"
OUTPUT="$3"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
BASE_IMAGE="${HANCOM_GOOROOM_ARM64_BUILD_IMAGE:-arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "a native ARM64 host is required" >&2; exit 77 ;;
esac
for command in docker jq curl sha256sum dpkg-deb stat python3; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid Debian snapshot timestamp: $SNAPSHOT" >&2
  exit 64
}

LOCK="$(readlink -f "$LOCK")"
rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"
OUTPUT="$(readlink -f "$OUTPUT")"
WORK="$(mktemp -d)"
INPUT="$WORK/input"
mkdir -p "$INPUT"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

jq -e --arg source "$SOURCE" '
  .sources[]
  | select(.source == $source)
  | select(.status == "resolved")
  | select(.selected.type == "apt-source")
  | select(.selected.declared_source == .source)
  | select(.selected.declared_version == .source_version)
' "$LOCK" > "$INPUT/source-lock-row.json"
[ "$(jq -s 'length' "$INPUT/source-lock-row.json")" = 1 ] || {
  echo "expected one resolved apt-source lock row for $SOURCE" >&2
  exit 2
}
SOURCE_VERSION="$(jq -r '.source_version' "$INPUT/source-lock-row.json")"

printf 'sha256\tbytes\tfilename\turl\n' > "$INPUT/SOURCE_FILES.tsv"
while IFS=$'\t' read -r expected_sha expected_size filename url; do
  [ -n "$filename" ]
  destination="$INPUT/$filename"
  curl --fail --location --retry 5 --retry-all-errors \
    --connect-timeout 30 --max-time 1800 \
    --output "$destination" "$url"
  actual_sha="$(sha256sum "$destination" | cut -d' ' -f1)"
  actual_size="$(stat -c '%s' "$destination")"
  [ "$actual_sha" = "$expected_sha" ] || {
    echo "source payload SHA-256 mismatch: $filename" >&2
    exit 3
  }
  [ "$actual_size" = "$expected_size" ] || {
    echo "source payload size mismatch: $filename" >&2
    exit 3
  }
  printf '%s\t%s\t%s\t%s\n' \
    "$actual_sha" "$actual_size" "$filename" "$url" \
    >> "$INPUT/SOURCE_FILES.tsv"
done < <(jq -r '
  .selected.files[]
  | [.sha256, (.size | tostring), .filename, .url]
  | @tsv
' "$INPUT/source-lock-row.json")
DSC="$(find "$INPUT" -maxdepth 1 -type f -name '*.dsc' -print -quit)"
[ -n "$DSC" ] || { echo "verified .dsc is absent" >&2; exit 3; }

cp "$LOCK" "$OUTPUT/apt-source-lock.used.json"
cp "$INPUT/source-lock-row.json" "$OUTPUT/source-lock-row.json"
cp "$INPUT/SOURCE_FILES.tsv" "$OUTPUT/SOURCE_FILES.tsv"
sha256sum "$OUTPUT/apt-source-lock.used.json" \
  "$OUTPUT/source-lock-row.json" \
  "$OUTPUT/SOURCE_FILES.tsv" \
  > "$OUTPUT/INPUT_LOCKSUMS.sha256"

BUILD_SCRIPT="$WORK/build-inside-snapshot.sh"
cat > "$BUILD_SCRIPT" <<'BUILD'
#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEB_BUILD_OPTIONS="nocheck parallel=2"
export DEB_BUILD_PROFILES=""
printf 'hancom-arm64-builder\n' > /etc/hostname
cat > /etc/hosts <<'EOF'
127.0.0.1 localhost
127.0.1.1 hancom-arm64-builder
::1 localhost ip6-localhost ip6-loopback
EOF
cat > /etc/apt/sources.list <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
cat > /etc/apt/apt.conf.d/99snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d
apt-get update
apt-get install -y --no-install-recommends \
  build-essential ca-certificates debhelper devscripts dpkg-dev equivs \
  fakeroot file git jq patchutils python3 xz-utils
mkdir -p /build/source
DSC="$(find /build/input -maxdepth 1 -type f -name '*.dsc' -print -quit)"
[ -n "$DSC" ]
dpkg-source -x "$DSC" /build/source
cd /build/source
actual_source="$(dpkg-parsechangelog -S Source)"
actual_version="$(dpkg-parsechangelog -S Version)"
[ "$actual_source" = "$SOURCE_NAME" ]
[ "$actual_version" = "$SOURCE_VERSION" ]

rm -f ./*-build-deps*.deb
set +e
mk-build-deps --build-dep debian/control
mk_rc=$?
set -e
DUMMY_PACKAGE="$(find . -maxdepth 1 -type f -name '*-build-deps*.deb' -print -quit)"
if [ -z "$DUMMY_PACKAGE" ]; then
  echo "mk-build-deps did not produce a dependency metapackage (exit $mk_rc)" >&2
  exit 21
fi
printf '%s\n' "${DUMMY_PACKAGE##*/}" > /build/output/build-dependency-metapackage.txt
apt-get -s install "./$DUMMY_PACKAGE" \
  > /build/output/apt-solver-simulation.log
apt-get install -y "./$DUMMY_PACKAGE"
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | sort > /build/output/build-environment-packages.tsv

dpkg-buildpackage --build=any --unsigned-source --unsigned-changes
find /build -maxdepth 1 -type f \
  \( -name '*.deb' -o -name '*.changes' -o -name '*.buildinfo' \) \
  -exec cp -v '{}' /build/output/ ';'
BUILD
chmod +x "$BUILD_SCRIPT"

# Bootstrap the exact historical build root inside a digest-pinned ARM64 image.
docker run --rm --platform linux/arm64 \
  -e SNAPSHOT="$SNAPSHOT" \
  -e SOURCE_NAME="$SOURCE" \
  -e SOURCE_VERSION="$SOURCE_VERSION" \
  -v "$INPUT:/host-input:ro" \
  -v "$OUTPUT:/host-output" \
  -v "$BUILD_SCRIPT:/host-build-script:ro" \
  "$BASE_IMAGE" \
  bash -s <<'CONTAINER'
set -Eeuo pipefail
cat > /etc/apt/sources.list <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main
EOF
cat > /etc/apt/apt.conf.d/99snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
Dpkg::Use-Pty "0";
EOF
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates debootstrap debian-archive-keyring xz-utils
ROOT=/snapshot-root
rm -rf "$ROOT"
deBootstrapLog=/host-output/debootstrap.log
deBootstrapMirror="http://snapshot.debian.org/archive/debian/${SNAPSHOT}/"
if ! debootstrap \
  --arch=arm64 \
  --variant=buildd \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  --include=ca-certificates,debian-archive-keyring \
  bullseye "$ROOT" "$deBootstrapMirror" \
  >"$deBootstrapLog" 2>&1; then
  cat "$deBootstrapLog" >&2
  exit 20
fi
mkdir -p "$ROOT/build/input" "$ROOT/build/output"
cp -a /host-input/. "$ROOT/build/input/"
cp /host-build-script "$ROOT/build/build.sh"
chmod +x "$ROOT/build/build.sh"
cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"
chroot "$ROOT" /usr/bin/env \
  SNAPSHOT="$SNAPSHOT" \
  SOURCE_NAME="$SOURCE_NAME" \
  SOURCE_VERSION="$SOURCE_VERSION" \
  /bin/bash /build/build.sh
cp -av "$ROOT/build/output/." /host-output/
chmod -R a+rX /host-output
CONTAINER

mapfile -t DEBS < <(find "$OUTPUT" -maxdepth 1 -type f -name '*.deb' | sort)
[ "${#DEBS[@]}" -gt 0 ] || { echo "no ARM64 DEB was built" >&2; exit 5; }

while IFS=$'\t' read -r package architecture; do
  [ "$architecture" = all ] && continue
  found=false
  for deb in "${DEBS[@]}"; do
    if [ "$(dpkg-deb -f "$deb" Package)" = "$package" ]; then
      test "$(dpkg-deb -f "$deb" Version)" = "$SOURCE_VERSION"
      test "$(dpkg-deb -f "$deb" Architecture)" = arm64
      found=true
      break
    fi
  done
  [ "$found" = true ] || {
    echo "expected native binary package was not built: $package" >&2
    exit 6
  }
done < <(jq -r '
  .binary_packages as $packages
  | .binary_architectures as $architectures
  | range(0; $packages | length) as $index
  | [$packages[$index], $architectures[$index]]
  | @tsv
' "$INPUT/source-lock-row.json")

for deb in "${DEBS[@]}"; do
  test "$(dpkg-deb -f "$deb" Version)" = "$SOURCE_VERSION"
  test "$(dpkg-deb -f "$deb" Architecture)" = arm64
  source_field="$(dpkg-deb -f "$deb" Source 2>/dev/null || true)"
  actual_source="${source_field%% *}"
  [ -n "$actual_source" ] || actual_source="$(dpkg-deb -f "$deb" Package)"
  [ "$actual_source" = "$SOURCE" ] || {
    echo "unexpected source field in $deb: $actual_source" >&2
    exit 7
  }
done

python3 "$SCRIPT_DIR/verify_deb_payload_machine.py" \
  --report "$OUTPUT/deb-payload-machine-report.json" \
  "${DEBS[@]}"

find "$OUTPUT" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > "$OUTPUT/SHA256SUMS"

jq -n \
  --arg status verified \
  --arg source "$SOURCE" \
  --arg source_version "$SOURCE_VERSION" \
  --arg architecture arm64 \
  --arg snapshot "$SNAPSHOT" \
  --arg base_image "$BASE_IMAGE" \
  --arg apt_source_lock_sha256 "$(sha256sum "$LOCK" | cut -d' ' -f1)" \
  --argjson deb_count "${#DEBS[@]}" \
  '{
    status: $status,
    source: $source,
    source_version: $source_version,
    architecture: $architecture,
    debian_snapshot: $snapshot,
    base_image: $base_image,
    apt_source_lock_sha256: $apt_source_lock_sha256,
    deb_count: $deb_count
  }' > "$OUTPUT/build-result.json"
