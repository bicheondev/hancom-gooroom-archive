#!/usr/bin/env bash
set -Eeuo pipefail

PACKAGE=gooroom-integration-applet
VERSION='0.3.1+grm3u1+han3u3'
TARGET_URL='https://update.hancomgooroom.com/hancom/pool/main/g/gooroom-integration-applet/gooroom-integration-applet_0.3.1+grm3u1+han3u3_amd64.deb'
TARGET_SHA256='1771ded81658d0e4bcce730ab69d162a1e58327cdabf1918c341cfbd02f495a9'
TARGET_SIZE=62392
PUBLIC_REPOSITORY='https://github.com/gooroom/gooroom-integration-applet.git'
BULLSEYE_DIGEST='sha256:99cdf7792e25416bd801861ccd8e2fb27fb527b25e8d9a8704ebc3ead2015675'
NIMF_VERSION='2023.06.30+grm3u1'
NIMF_COMMIT='583ad8b183db06a84c6b85a80fe132583566909d'
NIMF_AUTHORITY='arm64/locks/nimf-amd64-builddeps-v1/latest/authority.json'
HYBRID_LOCK_DIR='arm64/locks/gooroom-integration-applet-hybrid-search-v6/latest'
VERIFIER='arm64/scripts/verify_integration_applet_arm64_candidate_v1.py'
ROOT="${1:-work/integration-applet-native-arm64-v1}"

rm -rf "$ROOT"
mkdir -p "$ROOT"/{downloads,source,nimf-source,nimf-debs,build-debs,logs,verify,output,artifact}

write_failure_summary() {
  local rc="$1"
  local line="$2"
  mkdir -p "$ROOT/output" "$ROOT/artifact"
  jq -n \
    --arg source "$PACKAGE" --arg version "$VERSION" \
    --argjson exit_code "$rc" --arg failure_line "$line" '
      {
        schema:1,source:$source,version:$version,
        status:"native-build-infrastructure-failure",
        exit_code:$exit_code,failure_line:$failure_line,
        native_arm64_build_succeeded:false,
        native_arm64_candidate_verified:false,
        package_layer_promotion_allowed:false,
        iso_assembly_allowed:false,fail_closed:true,
        next_action:"inspect native ARM64 build artifact and repair the failed stage"
      }
    ' > "$ROOT/output/summary.json"
  cp "$ROOT/output/summary.json" "$ROOT/artifact/summary.json"
}

on_error() {
  local rc=$?
  local line="${BASH_LINENO[0]:-unknown}"
  trap - ERR
  write_failure_summary "$rc" "$line"
  find "$ROOT/artifact" -type f -printf '%P\t%s\n' | LC_ALL=C sort \
    > "$ROOT/artifact/FILE-INVENTORY.tsv" || true
  (
    cd "$ROOT/artifact"
    find . -type f ! -name LOCKSUMS.sha256 -print0 \
      | LC_ALL=C sort -z | xargs -0 sha256sum > LOCKSUMS.sha256
  ) || true
  exit "$rc"
}
trap on_error ERR

for command in \
  curl docker dpkg-buildpackage dpkg-deb git gresource jq python3 readelf sha256sum tar xz
 do
  command -v "$command" >/dev/null
 done

test -f "$VERIFIER"
test -f "$NIMF_AUTHORITY"
test -f "$HYBRID_LOCK_DIR/summary.json"
test -f "$HYBRID_LOCK_DIR/hybrid-lock.json"
test -f "$HYBRID_LOCK_DIR/closest-reconstruction.patch"
python3 -m py_compile "$VERIFIER"

jq -e '
  .schema == 1
  and .source == "gooroom-integration-applet"
  and .version == "0.3.1+grm3u1+han3u3"
  and .source_reconstruction_semantically_verified == true
  and .native_arm64_candidate_build_allowed == true
  and .package_layer_promotion_allowed == false
  and .iso_assembly_allowed == false
  and .fail_closed == true
' "$HYBRID_LOCK_DIR/summary.json" >/dev/null

jq -e '
  .schema == 1
  and (.base_commit_sha | test("^[0-9a-f]{40}$"))
  and (.source_blobs["src/gooroom-integration-applet.c"] | test("^[0-9a-f]{40}$"))
  and (.source_blobs["src/popup-window.c"] | test("^[0-9a-f]{40}$"))
  and (.source_blobs["modules/user/user-module.c"] | test("^[0-9a-f]{40}$"))
' "$HYBRID_LOCK_DIR/hybrid-lock.json" >/dev/null

curl --fail --show-error --location --retry 8 --retry-delay 2 \
  --retry-all-errors "$TARGET_URL" -o "$ROOT/downloads/target-amd64.deb"
test "$(stat -c '%s' "$ROOT/downloads/target-amd64.deb")" = "$TARGET_SIZE"
echo "$TARGET_SHA256  $ROOT/downloads/target-amd64.deb" | sha256sum --check --strict -
test "$(dpkg-deb -f "$ROOT/downloads/target-amd64.deb" Package)" = "$PACKAGE"
test "$(dpkg-deb -f "$ROOT/downloads/target-amd64.deb" Version)" = "$VERSION"
test "$(dpkg-deb -f "$ROOT/downloads/target-amd64.deb" Architecture)" = amd64

base_commit="$(jq -r '.base_commit_sha' "$HYBRID_LOCK_DIR/hybrid-lock.json")"
git clone "$PUBLIC_REPOSITORY" "$ROOT/source/tree"
git -C "$ROOT/source/tree" checkout --detach "$base_commit"
test "$(git -C "$ROOT/source/tree" rev-parse HEAD)" = "$base_commit"
git -C "$ROOT/source/tree" apply --check --binary \
  "$(pwd)/$HYBRID_LOCK_DIR/closest-reconstruction.patch"
git -C "$ROOT/source/tree" apply --binary \
  "$(pwd)/$HYBRID_LOCK_DIR/closest-reconstruction.patch"
test "$(dpkg-parsechangelog -l"$ROOT/source/tree/debian/changelog" -SVersion)" = "$VERSION"
git -C "$ROOT/source/tree" add -A
reconstructed_tree="$(git -C "$ROOT/source/tree" write-tree)"
git -C "$ROOT/source/tree" archive --format=tar "$reconstructed_tree" \
  > "$ROOT/source/reconstructed-source.tar"
xz -9e "$ROOT/source/reconstructed-source.tar"

# Locate the exact public Nimf commit without trusting an unverified repository label.
nimf_repository=
mapfile -t authority_repositories < <(
  jq -r '
    [
      .source_repository,
      .repository,
      .source_url,
      .source.repository,
      .source.url
    ] | .[]? | select(type == "string" and length > 0)
  ' "$NIMF_AUTHORITY" 2>/dev/null || true
)
repository_candidates=(
  "${authority_repositories[@]}"
  'https://github.com/gooroom/nimf.git'
  'https://github.com/hamonikr/nimf.git'
)
for repository in "${repository_candidates[@]}"; do
  [[ -n "$repository" ]] || continue
  rm -rf "$ROOT/nimf-source/tree"
  git init -q "$ROOT/nimf-source/tree"
  git -C "$ROOT/nimf-source/tree" remote add origin "$repository"
  if git -C "$ROOT/nimf-source/tree" fetch --depth=1 origin "$NIMF_COMMIT" \
      > "$ROOT/logs/nimf-fetch.log" 2>&1; then
    git -C "$ROOT/nimf-source/tree" checkout --detach FETCH_HEAD
    if [[ "$(git -C "$ROOT/nimf-source/tree" rev-parse HEAD)" == "$NIMF_COMMIT" ]]; then
      nimf_repository="$repository"
      break
    fi
  fi
done
test -n "$nimf_repository"
test "$(dpkg-parsechangelog -l"$ROOT/nimf-source/tree/debian/changelog" -SVersion)" = "$NIMF_VERSION"
printf '%s\n' "$nimf_repository" > "$ROOT/output/nimf-source-repository.txt"

# The pinned digest must resolve to a native ARM64 Bullseye userspace on this runner.
base_image="debian:bullseye@$BULLSEYE_DIGEST"
docker pull "$base_image"
test "$(docker run --rm "$base_image" dpkg --print-architecture)" = arm64
base_image_id="$(docker image inspect --format '{{.Id}}' "$base_image")"
printf '%s\n' "$base_image_id" > "$ROOT/output/base-image-id.txt"

# Build exact Nimf source natively for ARM64.
set +e
docker run --rm \
  -e DEBIAN_FRONTEND=noninteractive \
  -e DEB_BUILD_OPTIONS=nocheck \
  -e DEB_BUILD_MAINT_OPTIONS='hardening=+all reproducible=+fixfilepath' \
  -e LC_ALL=C.UTF-8 \
  -v "$(pwd)/$ROOT/nimf-source/tree:/build/source" \
  -v "$(pwd)/$ROOT/nimf-debs:/build/output" \
  "$base_image" bash -Eeuxo pipefail -c '
    apt-get update
    apt-get install -y --no-install-recommends \
      build-essential devscripts dpkg-dev equivs git libglib2.0-dev-bin
    cd /build/source
    mk-build-deps --install --remove \
      --tool "apt-get -o Acquire::Retries=6 -y --no-install-recommends" debian/control
    dpkg-buildpackage -us -uc -b -j2
    find /build -maxdepth 1 -type f -name "*.deb" -exec cp -v {} /build/output/ \;
  ' > "$ROOT/logs/nimf-build.log" 2>&1
nimf_build_rc=$?
set -e
printf '%s\n' "$nimf_build_rc" > "$ROOT/output/nimf-build.exit"
test "$nimf_build_rc" -eq 0

libnimf_deb=
nimf_dev_deb=
for deb in "$ROOT/nimf-debs"/*.deb; do
  package="$(dpkg-deb -f "$deb" Package)"
  case "$package" in
    libnimf1) libnimf_deb="$deb" ;;
    nimf-dev) nimf_dev_deb="$deb" ;;
  esac
done
test -n "$libnimf_deb"
test -n "$nimf_dev_deb"
for deb in "$libnimf_deb" "$nimf_dev_deb"; do
  test "$(dpkg-deb -f "$deb" Version)" = "$NIMF_VERSION"
  test "$(dpkg-deb -f "$deb" Architecture)" = arm64
done

# Build the semantically verified integration-applet source natively for ARM64.
source_date_epoch="$(
  date -u -d "$(dpkg-parsechangelog -l"$ROOT/source/tree/debian/changelog" -SDate)" +%s
)"
set +e
docker run --rm \
  -e DEBIAN_FRONTEND=noninteractive \
  -e DEB_BUILD_OPTIONS=nocheck \
  -e DEB_BUILD_MAINT_OPTIONS='hardening=+all reproducible=+fixfilepath' \
  -e SOURCE_DATE_EPOCH="$source_date_epoch" \
  -e LC_ALL=C.UTF-8 \
  -v "$(pwd)/$ROOT/source/tree:/build/source" \
  -v "$(pwd)/$ROOT/nimf-debs:/build/nimf-debs:ro" \
  -v "$(pwd)/$ROOT/build-debs:/build/output" \
  "$base_image" bash -Eeuxo pipefail -c '
    apt-get update
    apt-get install -y --no-install-recommends \
      build-essential devscripts dpkg-dev equivs git libglib2.0-dev-bin \
      /build/nimf-debs/libnimf1_*_arm64.deb \
      /build/nimf-debs/nimf-dev_*_arm64.deb
    cd /build/source
    mk-build-deps --install --remove \
      --tool "apt-get -o Acquire::Retries=6 -y --no-install-recommends" debian/control
    dpkg-buildpackage -us -uc -b -j2
    find /build -maxdepth 1 -type f -name "*.deb" -exec cp -v {} /build/output/ \;
  ' > "$ROOT/logs/integration-applet-build.log" 2>&1
build_rc=$?
set -e
printf '%s\n' "$build_rc" > "$ROOT/output/integration-applet-build.exit"
test "$build_rc" -eq 0

candidate_deb=
for deb in "$ROOT/build-debs"/*.deb; do
  if [[ "$(dpkg-deb -f "$deb" Package)" == "$PACKAGE" ]]; then
    candidate_deb="$deb"
  fi
done
test -n "$candidate_deb"
test "$(dpkg-deb -f "$candidate_deb" Version)" = "$VERSION"
test "$(dpkg-deb -f "$candidate_deb" Architecture)" = arm64
cp "$candidate_deb" "$ROOT/downloads/gooroom-integration-applet_${VERSION}_arm64.deb"
candidate_deb="$ROOT/downloads/gooroom-integration-applet_${VERSION}_arm64.deb"

python3 "$VERIFIER" \
  --target-deb "$ROOT/downloads/target-amd64.deb" \
  --candidate-deb "$candidate_deb" \
  --output "$ROOT/verify"

jq -e '
  .schema == 1
  and .source == "gooroom-integration-applet"
  and .version == "0.3.1+grm3u1+han3u3"
  and .candidate_control.Architecture == "arm64"
  and .all_candidate_elfs_aarch64 == true
  and .native_arm64_candidate_verified == true
  and .package_layer_promotion_allowed == false
  and .iso_assembly_allowed == false
  and .fail_closed == true
' "$ROOT/verify/summary.json" >/dev/null

candidate_sha="$(sha256sum "$candidate_deb" | awk '{print $1}')"
source_archive_sha="$(sha256sum "$ROOT/source/reconstructed-source.tar.xz" | awk '{print $1}')"
libnimf_sha="$(sha256sum "$libnimf_deb" | awk '{print $1}')"
nimf_dev_sha="$(sha256sum "$nimf_dev_deb" | awk '{print $1}')"

jq -n \
  --slurpfile verification "$ROOT/verify/summary.json" \
  --arg source "$PACKAGE" --arg version "$VERSION" \
  --arg target_sha256 "$TARGET_SHA256" \
  --arg candidate_sha256 "$candidate_sha" \
  --arg source_archive_sha256 "$source_archive_sha" \
  --arg reconstructed_tree_sha "$reconstructed_tree" \
  --arg base_image_digest "$BULLSEYE_DIGEST" \
  --arg base_image_id "$base_image_id" \
  --arg nimf_source_repository "$nimf_repository" \
  --arg nimf_source_commit "$NIMF_COMMIT" \
  --arg nimf_version "$NIMF_VERSION" \
  --arg libnimf1_sha256 "$libnimf_sha" \
  --arg nimf_dev_sha256 "$nimf_dev_sha" '
    {
      schema:1,source:$source,version:$version,
      target_amd64_deb_sha256:$target_sha256,
      candidate_arm64_deb_sha256:$candidate_sha256,
      reconstructed_source_archive_sha256:$source_archive_sha256,
      reconstructed_tree_sha:$reconstructed_tree_sha,
      build_userspace:{digest:$base_image_digest,image_id:$base_image_id,architecture:"arm64"},
      nimf:{repository:$nimf_source_repository,commit:$nimf_source_commit,
        version:$nimf_version,libnimf1_arm64_sha256:$libnimf1_sha256,
        nimf_dev_arm64_sha256:$nimf_dev_sha256},
      verification:$verification[0],
      native_arm64_build_succeeded:true,
      native_arm64_candidate_verified:$verification[0].native_arm64_candidate_verified,
      package_layer_promotion_allowed:false,
      iso_assembly_allowed:false,
      fail_closed:true,
      next_action:"integrate into a disposable ARM64 rootfs and run applet/session smoke tests"
    }
  ' > "$ROOT/output/summary.json"

cp "$ROOT/output/summary.json" "$ROOT/artifact/summary.json"
cp "$ROOT/verify/summary.json" "$ROOT/artifact/cross-architecture-verification.json"
cp "$ROOT/verify/non-elf-differences.json" "$ROOT/artifact/"
cp "$ROOT/verify/elf-comparison.json" "$ROOT/artifact/"
cp "$candidate_deb" "$ROOT/artifact/"
cp "$libnimf_deb" "$ROOT/artifact/"
cp "$nimf_dev_deb" "$ROOT/artifact/"
cp "$ROOT/source/reconstructed-source.tar.xz" "$ROOT/artifact/"
cp "$HYBRID_LOCK_DIR/hybrid-lock.json" "$ROOT/artifact/"
cp "$HYBRID_LOCK_DIR/closest-reconstruction.patch" "$ROOT/artifact/"
cp "$ROOT/logs/nimf-build.log" "$ROOT/artifact/"
cp "$ROOT/logs/integration-applet-build.log" "$ROOT/artifact/"
cp "$ROOT/output/nimf-source-repository.txt" "$ROOT/artifact/"
cp "$ROOT/output/base-image-id.txt" "$ROOT/artifact/"
find "$ROOT/artifact" -type f -printf '%P\t%s\n' | LC_ALL=C sort \
  > "$ROOT/artifact/FILE-INVENTORY.tsv"
(
  cd "$ROOT/artifact"
  find . -type f ! -name LOCKSUMS.sha256 -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum > LOCKSUMS.sha256
  sha256sum --check --strict LOCKSUMS.sha256
)
trap - ERR
jq '.' "$ROOT/output/summary.json"
