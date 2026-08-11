#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: run_qtbase_grm3u1_reconstruction.sh <work-dir>

Required environment:
  GITHUB_REPOSITORY GH_TOKEN
Optional pinned inputs are documented below and have fail-closed defaults.
EOF
}

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 64
fi

WORK_DIR="$(mkdir -p "$1" && realpath "$1")"
REPO_ROOT="$(git rev-parse --show-toplevel)"

SOURCE_NAME="${SOURCE_NAME:-qtbase-opensource-src}"
BASE_VERSION="${BASE_VERSION:-5.15.2+dfsg-9}"
SECURITY_VERSION="${SECURITY_VERSION:-5.15.2+dfsg-9+deb11u1}"
TARGET_VERSION="${TARGET_VERSION:-5.15.2+dfsg-9+grm3u1}"
VENDOR_RUN_ID="${VENDOR_RUN_ID:-31097604490}"
VENDOR_ARTIFACT="${VENDOR_ARTIFACT:-hancom-gooroom-3.3-exact-vendor-debs}"
VENDOR_PACKAGE="${VENDOR_PACKAGE:-libqt5core5a}"
VENDOR_FILENAME="${VENDOR_FILENAME:-libqt5core5a_5.15.2+dfsg-9+grm3u1_amd64.deb}"
DEBIAN_SNAPSHOT="${DEBIAN_SNAPSHOT:-20230730T235959Z}"
DEBIAN_SECURITY_SNAPSHOT="${DEBIAN_SECURITY_SNAPSHOT:-20230802T000000Z}"

for command in docker dpkg-source dpkg-parsechangelog dscverify file gh jq python3 sha256sum; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 69
  }
done

if [[ -z "${GITHUB_REPOSITORY:-}" || -z "${GH_TOKEN:-}" ]]; then
  echo 'GITHUB_REPOSITORY and GH_TOKEN are required.' >&2
  exit 64
fi

case "$SOURCE_NAME:$BASE_VERSION:$SECURITY_VERSION:$TARGET_VERSION" in
  'qtbase-opensource-src:5.15.2+dfsg-9:5.15.2+dfsg-9+deb11u1:5.15.2+dfsg-9+grm3u1') ;;
  *) echo 'unexpected QtBase reconstruction identity' >&2; exit 65 ;;
esac

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"/{vendor-download,vendor,base-source,security-source,base-tree,security-tree,evidence,source-archive,artifact}

log_command() {
  local name="$1"
  shift
  set +e
  "$@" >"$WORK_DIR/evidence/${name}.stdout.txt" 2>"$WORK_DIR/evidence/${name}.stderr.txt"
  local rc=$?
  set -e
  printf '%s\n' "$rc" >"$WORK_DIR/evidence/${name}.exit-code"
  return "$rc"
}

fetch_source_archive() {
  local repository_kind="$1"
  local suite="$2"
  local snapshot="$3"
  local version="$4"
  local output="$5"
  local image="debian:bullseye-slim"

  mkdir -p "$output"
  docker run --rm \
    --network host \
    -e REPOSITORY_KIND="$repository_kind" \
    -e SUITE="$suite" \
    -e SNAPSHOT="$snapshot" \
    -e SOURCE_NAME="$SOURCE_NAME" \
    -e SOURCE_VERSION="$version" \
    -v "$output:/output" \
    "$image" \
    bash -Eeuo pipefail -c '
      export DEBIAN_FRONTEND=noninteractive
      export LC_ALL=C.UTF-8
      cat >/etc/apt/apt.conf.d/99hancom-snapshot <<EOF
Acquire::Check-Valid-Until "false";
Acquire::Retries "8";
Acquire::http::Timeout "90";
Acquire::https::Timeout "90";
APT::Get::Assume-Yes "true";
EOF
      case "$REPOSITORY_KIND" in
        debian)
          archive=debian
          ;;
        debian-security)
          archive=debian-security
          ;;
        *)
          echo "unsupported repository kind: $REPOSITORY_KIND" >&2
          exit 64
          ;;
      esac
      cat >/etc/apt/sources.list <<EOF
deb-src [trusted=yes check-valid-until=no] https://snapshot.debian.org/archive/${archive}/${SNAPSHOT}/ ${SUITE} main
EOF
      apt-get update
      apt-get install -y --no-install-recommends ca-certificates dpkg-dev
      cd /output
      apt-get source --download-only "${SOURCE_NAME}=${SOURCE_VERSION}"
    '
  sudo chown -R "$(id -u):$(id -g)" "$output"

  mapfile -t dscs < <(find "$output" -maxdepth 1 -type f -name '*.dsc' -print | sort)
  if [[ ${#dscs[@]} -ne 1 ]]; then
    echo "expected exactly one .dsc for $SOURCE_NAME $version; got ${#dscs[@]}" >&2
    find "$output" -maxdepth 1 -type f -printf '%f\t%s\n' >&2 || true
    exit 65
  fi
  printf '%s\n' "${dscs[0]}"
}

# Exact vendor binary authority.
gh run download "$VENDOR_RUN_ID" \
  --repo "$GITHUB_REPOSITORY" \
  --name "$VENDOR_ARTIFACT" \
  --dir "$WORK_DIR/vendor-download"

vendor="$(find "$WORK_DIR/vendor-download" -type f -name "$VENDOR_FILENAME" -print -quit)"
if [[ -z "$vendor" || ! -f "$vendor" ]]; then
  echo "exact vendor package not found in artifact: $VENDOR_FILENAME" >&2
  find "$WORK_DIR/vendor-download" -type f -printf '%P\t%s\n' >&2 || true
  exit 66
fi

vendor_lock="$REPO_ROOT/arm64/locks/vendor-binaries/vendor-binary-lock.json"
test -f "$vendor_lock"
record="$(
  jq -cer \
    --arg package "$VENDOR_PACKAGE" \
    --arg version "$TARGET_VERSION" \
    --arg architecture amd64 '
      [.packages[] | select(
        .package == $package
        and .version == $version
        and .architecture == $architecture
        and .status == "verified"
      )]
      | if length == 1 then .[0]
        else error("verified vendor lock is not unique") end
    ' "$vendor_lock"
)"
expected_sha="$(jq -er '.actual_sha256' <<<"$record")"
expected_size="$(jq -er '.actual_size' <<<"$record")"
expected_filename="$(jq -er '.local_filename' <<<"$record")"
test "$expected_filename" = "$VENDOR_FILENAME"
test "$(stat -c '%s' "$vendor")" = "$expected_size"
printf '%s  %s\n' "$expected_sha" "$vendor" | sha256sum --check --strict
cp "$vendor" "$WORK_DIR/vendor/$VENDOR_FILENAME"
printf '%s\n' "$record" | jq . >"$WORK_DIR/evidence/vendor-binary-lock-record.json"
sha256sum "$WORK_DIR/vendor/$VENDOR_FILENAME" >"$WORK_DIR/evidence/vendor-package.sha256"
rm -rf "$WORK_DIR/vendor-download"

# Signed Debian source inputs are both acquired from immutable snapshots.
base_dsc="$(fetch_source_archive debian bullseye "$DEBIAN_SNAPSHOT" "$BASE_VERSION" "$WORK_DIR/base-source")"
security_dsc="$(fetch_source_archive debian-security bullseye-security "$DEBIAN_SECURITY_SNAPSHOT" "$SECURITY_VERSION" "$WORK_DIR/security-source")"

log_command base-dscverify dscverify "$base_dsc"
log_command security-dscverify dscverify "$security_dsc"

log_command base-dpkg-source dpkg-source -x "$base_dsc" "$WORK_DIR/base-tree/source"
log_command security-dpkg-source dpkg-source -x "$security_dsc" "$WORK_DIR/security-tree/source"

base_changelog="$WORK_DIR/base-tree/source/debian/changelog"
security_changelog="$WORK_DIR/security-tree/source/debian/changelog"
test -f "$base_changelog"
test -f "$security_changelog"
test "$(dpkg-parsechangelog -l"$base_changelog" -S Source)" = "$SOURCE_NAME"
test "$(dpkg-parsechangelog -l"$base_changelog" -S Version)" = "$BASE_VERSION"
test "$(dpkg-parsechangelog -l"$security_changelog" -S Source)" = "$SOURCE_NAME"
test "$(dpkg-parsechangelog -l"$security_changelog" -S Version)" = "$SECURITY_VERSION"
head -n1 "$base_changelog" >"$WORK_DIR/evidence/base-changelog-head.txt"
head -n1 "$security_changelog" >"$WORK_DIR/evidence/security-changelog-head.txt"

patch="$WORK_DIR/security-tree/source/debian/patches/CVE-2022-25255.diff"
if [[ ! -f "$patch" ]]; then
  mapfile -t patch_candidates < <(
    grep -RIl --exclude=series -- 'CVE-2022-25255' \
      "$WORK_DIR/security-tree/source/debian/patches" 2>/dev/null | sort
  )
  if [[ ${#patch_candidates[@]} -ne 1 ]]; then
    echo "unable to resolve one canonical CVE-2022-25255 patch; got ${#patch_candidates[@]}" >&2
    printf '%s\n' "${patch_candidates[@]:-}" >&2
    exit 65
  fi
  patch="${patch_candidates[0]}"
fi
test -s "$patch"
cp "$patch" "$WORK_DIR/evidence/CVE-2022-25255.signed-debian.diff"
sha256sum "$patch" >"$WORK_DIR/evidence/CVE-2022-25255.signed-debian.diff.sha256"

(
  cd "$WORK_DIR/base-source"
  find . -maxdepth 1 -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) >"$WORK_DIR/evidence/base-source-download.sha256"
(
  cd "$WORK_DIR/security-source"
  find . -maxdepth 1 -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) >"$WORK_DIR/evidence/security-source-download.sha256"

python3 "$REPO_ROOT/arm64/scripts/reconstruct_qtbase_grm3u1.py" \
  --source-tree "$WORK_DIR/base-tree/source" \
  --base-source-dir "$WORK_DIR/base-source" \
  --base-dsc "$base_dsc" \
  --security-dsc "$security_dsc" \
  --vendor-deb "$WORK_DIR/vendor/$VENDOR_FILENAME" \
  --cve-patch "$patch" \
  --output-dir "$WORK_DIR/evidence" \
  --archive-output-dir "$WORK_DIR/source-archive"

jq -e '
  .source == "qtbase-opensource-src"
  and .source_version == "5.15.2+dfsg-9+grm3u1"
  and .source_status == "reconstructed-not-recovered-original-source"
  and .byte_identity_claimed == false
  and .promotion_allowed == false
  and .claims.only_vendor_declared_code_patch_added == true
  and .claims.lost_original_source_archive_recovered == false
  and .reconstruction.round_trip_verified == true
' "$WORK_DIR/evidence/authority.json" >/dev/null

mapfile -t reconstructed_dscs < <(find "$WORK_DIR/source-archive" -maxdepth 1 -type f -name '*.dsc' -print | sort)
test "${#reconstructed_dscs[@]}" -eq 1
reconstructed_dsc="${reconstructed_dscs[0]}"
rm -rf "$WORK_DIR/round-trip-tree"
log_command reconstructed-round-trip-dpkg-source \
  dpkg-source -x "$reconstructed_dsc" "$WORK_DIR/round-trip-tree"
test "$(dpkg-parsechangelog -l"$WORK_DIR/round-trip-tree/debian/changelog" -S Source)" = "$SOURCE_NAME"
test "$(dpkg-parsechangelog -l"$WORK_DIR/round-trip-tree/debian/changelog" -S Version)" = "$TARGET_VERSION"

mkdir -p "$WORK_DIR/artifact/source-archive" "$WORK_DIR/artifact/evidence"
cp -a "$WORK_DIR/source-archive/." "$WORK_DIR/artifact/source-archive/"
cp -a "$WORK_DIR/evidence/." "$WORK_DIR/artifact/evidence/"
(
  cd "$WORK_DIR/artifact"
  find . -type f ! -name LOCKSUMS.sha256 -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum >LOCKSUMS.sha256
  sha256sum --check --strict LOCKSUMS.sha256
)

jq -n \
  --arg source "$SOURCE_NAME" \
  --arg base_version "$BASE_VERSION" \
  --arg security_version "$SECURITY_VERSION" \
  --arg source_version "$TARGET_VERSION" \
  --arg reconstructed_dsc "$(basename "$reconstructed_dsc")" \
  --arg reconstructed_dsc_sha256 "$(sha256sum "$reconstructed_dsc" | awk '{print $1}')" \
  --arg authority_sha256 "$(sha256sum "$WORK_DIR/evidence/authority.json" | awk '{print $1}')" '
  {
    schema: 1,
    policy: "transparent-reconstruction-no-original-source-identity-claim",
    source: $source,
    base_version: $base_version,
    security_version: $security_version,
    source_version: $source_version,
    source_status: "reconstructed-not-recovered-original-source",
    reconstructed_dsc: $reconstructed_dsc,
    reconstructed_dsc_sha256: $reconstructed_dsc_sha256,
    authority_sha256: $authority_sha256,
    byte_identity_claimed: false,
    arm64_build_required: true,
    promotion_allowed: false,
    passed: true
  }
' >"$WORK_DIR/artifact/reconstruction-result.json"

printf '%s\n' "$(basename "$reconstructed_dsc")" >"$WORK_DIR/reconstructed-dsc-name.txt"
printf '%s\n' "$(sha256sum "$WORK_DIR/evidence/authority.json" | awk '{print $1}')" >"$WORK_DIR/authority-sha256.txt"

echo "QtBase reconstruction completed: $reconstructed_dsc"
