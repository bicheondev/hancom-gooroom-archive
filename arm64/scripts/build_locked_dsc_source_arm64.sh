#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 LOCK_JSON SOURCE_NAME OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
LOCK_JSON="$1"
SOURCE_NAME="$2"
OUTPUT_DIR="$3"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
BOOTSTRAP_IMAGE="${HANCOM_GOOROOM_BOOTSTRAP_IMAGE:-arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"
REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-arm64/locks/reference/amd64-reference.json}"
DEPENDENCY_REPOSITORY="${HANCOM_GOOROOM_DEPENDENCY_REPOSITORY:-}"
SOURCE_KEY_ASC="${HANCOM_GOOROOM_SOURCE_KEY_ASC:-arm64/keys/source-signing/gooroom-archive-public-keys.asc}"

for command in jq curl gpg gpgv docker dpkg-source dpkg-parsechangelog \
  dpkg-deb sha256sum gzip tar; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done
[ -f "$SOURCE_KEY_ASC" ] || {
  echo "trusted source-signing key bundle is missing: $SOURCE_KEY_ASC" >&2
  exit 70
}
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid Debian snapshot: $SNAPSHOT" >&2
  exit 64
}

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR_ABS="$(cd "$OUTPUT_DIR" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

entry="$(jq -c --arg source "$SOURCE_NAME" '
  .sources[]
  | select(
      .source == $source
      and .status == "resolved"
      and .selected != null
      and .selected.type == "dsc"
    )
' "$LOCK_JSON" | head -n1)"
[ -n "$entry" ] || {
  echo "No resolved exact signed DSC source lock for $SOURCE_NAME" >&2
  exit 2
}

SOURCE_VERSION="$(jq -r '.source_version' <<<"$entry")"
SIGNED_SOURCE="$(jq -r '.selected.signed_source // empty' <<<"$entry")"
SIGNED_VERSION="$(jq -r '.selected.signed_version // empty' <<<"$entry")"
SIGNATURE_VERIFIED="$(jq -r '.selected.signature_verified == true' <<<"$entry")"
[ "$SIGNED_SOURCE" = "$SOURCE_NAME" ]
[ "$SIGNED_VERSION" = "$SOURCE_VERSION" ]
[ "$SIGNATURE_VERIFIED" = true ]

if [ -n "${HANCOM_GOOROOM_REQUIRED_PACKAGES:-}" ]; then
  EXPECTED_PACKAGES="$HANCOM_GOOROOM_REQUIRED_PACKAGES"
elif [ -f "$REFERENCE_JSON" ]; then
  EXPECTED_PACKAGES="$(jq -r \
    --arg source "$SOURCE_NAME" \
    --arg version "$SOURCE_VERSION" '
      [
        .packages[]
        | select(
            .source == $source
            and .source_version == $version
            and .architecture == "amd64"
          )
        | .package
      ]
      | unique
      | sort
      | join(" ")
    ' "$REFERENCE_JSON")"
else
  EXPECTED_PACKAGES="$(jq -r '.binary_packages | join(" ")' <<<"$entry")"
fi
EXPECTED_PACKAGES_JSON="$(
  if [ -n "$EXPECTED_PACKAGES" ]; then
    printf '%s\n' $EXPECTED_PACKAGES | jq -Rsc 'split("\n")[:-1] | unique | sort'
  else
    printf '[]\n'
  fi
)"

DEPENDENCY_REPOSITORY_SHA256=""
if [ -n "$DEPENDENCY_REPOSITORY" ]; then
  DEPENDENCY_REPOSITORY="$(cd "$DEPENDENCY_REPOSITORY" && pwd)"
  test -f "$DEPENDENCY_REPOSITORY/Packages"
  test -f "$DEPENDENCY_REPOSITORY/Release"
  DEPENDENCY_REPOSITORY_SHA256="$(sha256sum "$DEPENDENCY_REPOSITORY/Packages" | awk '{print $1}')"
fi

SOURCE_BUNDLE="$WORK_DIR/source-bundle"
SOURCE_ROOT="$WORK_DIR/source"
mkdir -p "$SOURCE_BUNDLE" "$SOURCE_ROOT"

validate_filename() {
  local filename="$1"
  [[ "$filename" =~ ^[A-Za-z0-9][A-Za-z0-9.+:~_-]*$ ]] || {
    echo "unsafe source filename: $filename" >&2
    exit 3
  }
}

download_exact() {
  local filename="$1"
  local size="$2"
  local sha256="$3"
  local url="$4"
  validate_filename "$filename"
  [[ "$size" =~ ^[0-9]+$ ]]
  [[ "$sha256" =~ ^[0-9a-f]{64}$ ]]
  [[ "$url" =~ ^https?:// ]]
  local destination="$SOURCE_BUNDLE/$filename"
  local partial="$destination.partial"
  rm -f "$partial"
  curl --fail --location --silent --show-error \
    --retry 5 --retry-all-errors --connect-timeout 30 --max-time 900 \
    "$url" --output "$partial"
  test "$(stat -c '%s' "$partial")" = "$size"
  printf '%s  %s\n' "$sha256" "$partial" | sha256sum --check --strict
  mv "$partial" "$destination"
}

IFS=$'\t' read -r DSC_NAME DSC_SIZE DSC_SHA256 DSC_URL < <(
  jq -r '.selected.dsc | [.filename, (.size|tostring), .sha256, .url] | @tsv' \
    <<<"$entry"
)
download_exact "$DSC_NAME" "$DSC_SIZE" "$DSC_SHA256" "$DSC_URL"

mapfile -t payload_rows < <(
  jq -r '.selected.files[] | [.filename, (.size|tostring), .sha256, .url] | @tsv' \
    <<<"$entry"
)
test "${#payload_rows[@]}" -gt 0
for payload in "${payload_rows[@]}"; do
  IFS=$'\t' read -r filename size sha256 url <<<"$payload"
  [ "$filename" != "$DSC_NAME" ]
  download_exact "$filename" "$size" "$sha256" "$url"
done

find "$SOURCE_BUNDLE" -maxdepth 1 -type f ! -name SOURCE_BUNDLE.sha256 \
  -printf '%f\n' | sort \
  | while IFS= read -r filename; do
      printf '%s  %s\n' \
        "$(sha256sum "$SOURCE_BUNDLE/$filename" | awk '{print $1}')" \
        "$filename"
    done > "$SOURCE_BUNDLE/SOURCE_BUNDLE.sha256"
SOURCE_BUNDLE_MANIFEST_SHA256="$(sha256sum "$SOURCE_BUNDLE/SOURCE_BUNDLE.sha256" | awk '{print $1}')"

KEYRING="$WORK_DIR/source-signing.gpg"
gpg --batch --yes --dearmor --output "$KEYRING" "$SOURCE_KEY_ASC"
test -s "$KEYRING"
set +e
gpgv --keyring "$KEYRING" "$SOURCE_BUNDLE/$DSC_NAME" \
  > "$OUTPUT_DIR_ABS/gpgv-source.log" 2>&1
gpgv_rc=$?
set -e
cat "$OUTPUT_DIR_ABS/gpgv-source.log"
test "$gpgv_rc" = 0

set +e
dpkg-source -x "$SOURCE_BUNDLE/$DSC_NAME" "$SOURCE_ROOT" \
  > "$OUTPUT_DIR_ABS/dpkg-source-extract.log" 2>&1
dpkg_source_rc=$?
set -e
cat "$OUTPUT_DIR_ABS/dpkg-source-extract.log"
test "$dpkg_source_rc" = 0
[ -f "$SOURCE_ROOT/debian/changelog" ]

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

KEY_BUNDLE_SHA256="$(sha256sum "$SOURCE_KEY_ASC" | awk '{print $1}')"
cat > "$OUTPUT_DIR_ABS/source-lock-evidence.json" <<EOF
{
  "schema": 4,
  "source_type": "dsc",
  "source": $(jq -Rn --arg value "$SOURCE_NAME" '$value'),
  "source_version": $(jq -Rn --arg value "$SOURCE_VERSION" '$value'),
  "signed_source": $(jq -Rn --arg value "$SIGNED_SOURCE" '$value'),
  "signed_version": $(jq -Rn --arg value "$SIGNED_VERSION" '$value'),
  "dsc": $(jq -c '.selected.dsc' <<<"$entry"),
  "files": $(jq -c '.selected.files | sort_by(.filename)' <<<"$entry"),
  "dsc_signature_valid": true,
  "source_key_bundle_sha256": $(jq -Rn --arg value "$KEY_BUNDLE_SHA256" '$value'),
  "source_bundle_manifest_sha256": $(jq -Rn --arg value "$SOURCE_BUNDLE_MANIFEST_SHA256" '$value'),
  "dependency_repository_packages_sha256": $(jq -Rn --arg value "$DEPENDENCY_REPOSITORY_SHA256" '$value')
}
EOF
printf '%s\n' "$BOOTSTRAP_IMAGE" > "$OUTPUT_DIR_ABS/bootstrap-image.txt"
cp "$SOURCE_BUNDLE/SOURCE_BUNDLE.sha256" "$OUTPUT_DIR_ABS/"

cat > "$WORK_DIR/build-inside.sh" <<'INNER'
#!/usr/bin/env bash
set -Eeuo pipefail

: "${SNAPSHOT:?SNAPSHOT is required}"
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
mkdir -p /out

[ "$(dpkg --print-architecture)" = arm64 ] || {
  echo "bootstrap container is not ARM64" >&2
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
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates debootstrap debian-archive-keyring xz-utils

ROOT=/snapshot-root
rm -rf "$ROOT"
mkdir -p "$ROOT"
if ! debootstrap \
  --arch=arm64 \
  --variant=buildd \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  --include=ca-certificates,debian-archive-keyring \
  bullseye \
  "$ROOT" \
  "http://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
  > /out/debootstrap.log 2>&1; then
  cat /out/debootstrap.log >&2
  exit 20
fi
cat /out/debootstrap.log

cat > "$ROOT/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
rm -f "$ROOT/etc/apt/sources.list.d/"*
cat > "$ROOT/etc/apt/apt.conf.d/99snapshot" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"

if [ -f /dependency-repo/Packages ]; then
  mkdir -p "$ROOT/build-dependency-repo"
  cp -a /dependency-repo/. "$ROOT/build-dependency-repo/"
  cat > "$ROOT/etc/apt/sources.list.d/00-arm64-rebuild-dependencies.list" <<'EOF'
deb [trusted=yes] file:/build-dependency-repo ./
EOF
  cat > "$ROOT/etc/apt/preferences.d/00-arm64-rebuild-dependencies" <<'EOF'
Package: *
Pin: origin ""
Pin-Priority: 1001
EOF
fi

mkdir -p "$ROOT/build/source" "$ROOT/build/output"
cp -a /src/. "$ROOT/build/source/"

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
apt-get update
apt-get install -y --no-install-recommends \
  build-essential ca-certificates debhelper devscripts dpkg-dev \
  equivs fakeroot gnupg xz-utils

cd /build/source
export SOURCE_DATE_EPOCH="$(dpkg-parsechangelog -S Date | date -f - +%s)"
rm -f ./*-build-deps_*.deb
mk-build-deps --build-dep debian/control
DUMMY_PACKAGE="$(find . -maxdepth 1 -type f -name '*-build-deps_*.deb' -print -quit)"
[ -n "$DUMMY_PACKAGE" ]
dpkg-deb -f "$DUMMY_PACKAGE" Package Version Architecture Depends \
  > /build/output/build-dependency-metapackage.txt

set +e
apt-get -s --no-install-recommends \
  -o Debug::pkgProblemResolver=yes \
  install "$DUMMY_PACKAGE" \
  > /build/output/apt-solver-simulation.log 2>&1
SOLVER_RC=$?
set -e
cat /build/output/apt-solver-simulation.log
[ "$SOLVER_RC" -eq 0 ] || exit "$SOLVER_RC"

apt-get install -y --no-install-recommends \
  -o Debug::pkgProblemResolver=yes \
  "$DUMMY_PACKAGE"
dpkg-checkbuilddeps -B

dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | sort > /build/output/build-environment-packages.tsv
apt-cache policy > /build/output/apt-policy.txt

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

set +e
chroot "$ROOT" /bin/bash /build/run-build.sh \
  > >(tee /out/chroot-build.log) \
  2> >(tee /out/chroot-build.stderr.log >&2)
BUILD_RC=$?
set -e
cp -av "$ROOT/build/output/." /out/ || true
exit "$BUILD_RC"
INNER
chmod +x "$WORK_DIR/build-inside.sh"

docker_arguments=(
  --rm
  --privileged
  --platform linux/arm64
  --env "SNAPSHOT=$SNAPSHOT"
  --volume "$SOURCE_ROOT:/src:ro"
  --volume "$WORK_DIR/build-inside.sh:/build-inside.sh:ro"
  --volume "$OUTPUT_DIR_ABS:/out:rw"
)
if [ -n "$DEPENDENCY_REPOSITORY" ]; then
  docker_arguments+=(--volume "$DEPENDENCY_REPOSITORY:/dependency-repo:ro")
fi

docker run "${docker_arguments[@]}" \
  "$BOOTSTRAP_IMAGE" \
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
    echo "Expected architecture-dependent binary package was not built: $expected" >&2
    exit 6
  fi
done

cat > "$OUTPUT_DIR_ABS/build-lock.json" <<EOF
{
  "schema": 6,
  "source_type": "dsc",
  "source": $(jq -Rn --arg value "$SOURCE_NAME" '$value'),
  "source_version": $(jq -Rn --arg value "$SOURCE_VERSION" '$value'),
  "dsc": $(jq -c '.selected.dsc' <<<"$entry"),
  "source_files": $(jq -c '.selected.files | sort_by(.filename)' <<<"$entry"),
  "source_bundle_manifest_sha256": $(jq -Rn --arg value "$SOURCE_BUNDLE_MANIFEST_SHA256" '$value'),
  "source_key_bundle_sha256": $(jq -Rn --arg value "$KEY_BUNDLE_SHA256" '$value'),
  "bootstrap_image": $(jq -Rn --arg value "$BOOTSTRAP_IMAGE" '$value'),
  "target_architecture": "arm64",
  "debian_snapshot": $(jq -Rn --arg value "$SNAPSHOT" '$value'),
  "dependency_repository_packages_sha256": $(jq -Rn --arg value "$DEPENDENCY_REPOSITORY_SHA256" '$value'),
  "build_mode": "native-arm64-historical-chroot-binary-arch-from-exact-signed-dsc",
  "expected_binary_packages": $EXPECTED_PACKAGES_JSON,
  "produced_binary_packages": $(printf '%s\n' "${produced_packages[@]}" | jq -Rsc 'split("\n")[:-1] | unique | sort')
}
EOF

find "$OUTPUT_DIR_ABS" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | sort -z | xargs -0 sha256sum \
  > "$OUTPUT_DIR_ABS/SHA256SUMS"
cat "$OUTPUT_DIR_ABS/build-lock.json"
