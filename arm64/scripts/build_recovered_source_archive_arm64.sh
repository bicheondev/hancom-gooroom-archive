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
LOCAL_REPO_DIR="$(realpath "$2")"
OUTPUT_DIR="$(mkdir -p "$3" && realpath "$3")"
SOURCE_NAME="$4"
SOURCE_VERSION="$5"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
BUILD_JOBS="${HANCOM_GOOROOM_BUILD_JOBS:-3}"

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

rm -rf "$OUTPUT_DIR"/*
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

SOURCE_ARCHIVE_DIR="$SOURCE_ARCHIVE_DIR" \
LOCAL_REPO_DIR="$LOCAL_REPO_DIR" \
OUTPUT_DIR="$OUTPUT_DIR" \
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
  -v "$SOURCE_ARCHIVE_DIR:/source:ro" \
  -v "$LOCAL_REPO_DIR:/repo:ro" \
  -v "$OUTPUT_DIR:/output" \
  debian:bullseye-slim \
  bash -Eeuo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    export LC_ALL=C.UTF-8
    export LANG=C.UTF-8
    export TZ=UTC

    # bullseye-slim does not necessarily contain a CA trust store. Bootstrap it
    # from the image default HTTP repository before replacing the repository set
    # with HTTPS snapshot.debian.org. Keep both bootstrap and build dependency
    # installation explicitly noninteractive; DEBIAN_FRONTEND alone does not
    # answer apt-get confirmation prompts.
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates

    cat >/etc/apt/apt.conf.d/99hancom-snapshot <<EOF
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
Acquire::http::Timeout "60";
Acquire::https::Timeout "60";
APT::Get::Assume-Yes "true";
EOF

    cat >/etc/apt/sources.list <<EOF
# Exact historical Debian dependency universe used by the ARM64 port.
deb [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb-src [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
deb-src [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
deb [trusted=yes] file:/repo ./
EOF

    rm -rf /var/lib/apt/lists/*
    apt-get update
    apt-get install -y --no-install-recommends \
      apt-utils build-essential devscripts dpkg-dev equivs \
      fakeroot file git gnupg jq locales pkg-config python3 rsync xz-utils

    rm -rf /build
    mkdir -p /build/source-parent /build/logs
    cp -a /source/. /build/source-parent/

    dpkg-source -x "/build/source-parent/${DSC_NAME}" /build/src \
      > /build/logs/dpkg-source.stdout 2> /build/logs/dpkg-source.stderr
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
      --tool "apt-get -y --no-install-recommends -o Dpkg::Options::=--force-confold" \
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
    printf "%s\n" "$build_rc" > /build/logs/dpkg-buildpackage.exit-code

    cp -a /build/logs/. /output/logs/
    find /build -maxdepth 1 -type f \
      \( -name "*.deb" -o -name "*.changes" -o -name "*.buildinfo" \) \
      -exec cp -a {} /output/ \;
    find /build/source-parent -maxdepth 1 -type f \
      -exec sha256sum {} \; > /output/logs/source-members.sha256
    find /repo -maxdepth 1 -type f -name "*.deb" -printf "%f\n" \
      | LC_ALL=C sort > /output/logs/local-repository-debs.txt

    if [[ "$build_rc" -ne 0 ]]; then
      exit "$build_rc"
    fi
    find /output -maxdepth 1 -type f -name "*.deb" -print -quit | grep -q .
  '

find "$OUTPUT_DIR" -maxdepth 2 -type f -printf '%P\t%s\n' \
  | LC_ALL=C sort > "$OUTPUT_DIR/output-inventory.tsv"
(
  cd "$OUTPUT_DIR"
  find . -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)