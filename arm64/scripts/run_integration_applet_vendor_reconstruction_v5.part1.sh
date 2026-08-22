#!/usr/bin/env bash
set -Eeuo pipefail

PACKAGE=gooroom-integration-applet
VERSION='0.3.1+grm3u1+han3u3'
REPOSITORY=gooroom/gooroom-integration-applet
CANDIDATE_COMMIT=bcca083b854e4a6c99e0bb69db4d4868e1210cdd
SNAPSHOT=20230730T235959Z
TARGET_URL='https://update.hancomgooroom.com/hancom/pool/main/g/gooroom-integration-applet/gooroom-integration-applet_0.3.1+grm3u1+han3u3_amd64.deb'
TARGET_SHA256=1771ded81658d0e4bcce730ab69d162a1e58327cdabf1918c341cfbd02f495a9
TARGET_SIZE=62392
NIMF_AUTHORITY=arm64/locks/nimf-amd64-builddeps-v1/latest/authority.json
DEBUG_AUTHORITY=arm64/locks/gooroom-integration-applet-vendor-source-debug-v7/latest/summary.json
ANALYZER=arm64/scripts/integration_applet_vendor_reconstruct.py
PATCHER=arm64/scripts/integration_applet_han3u3_patch_v5.py
WORK=${WORK:-work/integration-applet-v5}

rm -rf "$WORK"
mkdir -p "$WORK"/{downloads,deps,target-root,source-authority,build,comparison,aggregate,artifact}

sudo sed -Ei \
  's|http://azure\.archive\.ubuntu\.com/ubuntu/?|https://archive.ubuntu.com/ubuntu/|g;
   s|http://([a-z0-9.-]+\.)?archive\.ubuntu\.com/ubuntu/?|https://archive.ubuntu.com/ubuntu/|g;
   s|http://security\.ubuntu\.com/ubuntu/?|https://security.ubuntu.com/ubuntu/|g' \
  /etc/apt/sources.list /etc/apt/sources.list.d/*.list \
  /etc/apt/sources.list.d/*.sources 2>/dev/null || true
apt_options=(
  -o Acquire::Retries=4
  -o Acquire::http::Timeout=30
  -o Acquire::https::Timeout=30
  -o Acquire::ForceIPv4=true
  -o Dpkg::Use-Pty=0
)
timeout 15m sudo apt-get "${apt_options[@]}" update
timeout 15m sudo DEBIAN_FRONTEND=noninteractive apt-get "${apt_options[@]}" install -y --no-install-recommends \
  binutils ca-certificates curl debootstrap debian-archive-keyring dpkg-dev file gettext git jq \
  libglib2.0-bin python3 tar xz-utils
python3 -m py_compile "$ANALYZER" "$PATCHER"

jq -e '
  .schema == 2
  and .source == "gooroom-integration-applet"
  and .version == "0.3.1+grm3u1+han3u3"
  and .target_deb_sha256 == "1771ded81658d0e4bcce730ab69d162a1e58327cdabf1918c341cfbd02f495a9"
  and .exact_matching_debug_payload_recovered == true
  and .fail_closed == true
' "$DEBUG_AUTHORITY" >/dev/null

curl --fail --show-error --location --retry 8 --retry-delay 3 --retry-all-errors \
  "$TARGET_URL" -o "$WORK/downloads/target.deb"
test "$(stat -c '%s' "$WORK/downloads/target.deb")" = "$TARGET_SIZE"
echo "$TARGET_SHA256  $WORK/downloads/target.deb" | sha256sum --check --strict -
test "$(dpkg-deb -f "$WORK/downloads/target.deb" Package)" = "$PACKAGE"
test "$(dpkg-deb -f "$WORK/downloads/target.deb" Version)" = "$VERSION"
test "$(dpkg-deb -f "$WORK/downloads/target.deb" Architecture)" = amd64
dpkg-deb -x "$WORK/downloads/target.deb" "$WORK/target-root"

jq -e '
  .schema == 1
  and .source == "nimf"
  and .source_version == "2023.06.30+grm3u1"
  and .source_commit == "583ad8b183db06a84c6b85a80fe132583566909d"
  and (.packages | length) == 2
  and all(.packages[]; .architecture == "amd64")
' "$NIMF_AUTHORITY" >/dev/null
while IFS= read -r row; do
  file="$(jq -r '.filename' <<<"$row")"
  url="$(jq -r '.url' <<<"$row")"
  sha="$(jq -r '.sha256' <<<"$row")"
  size="$(jq -r '.size' <<<"$row")"
  package="$(jq -r '.package' <<<"$row")"
  curl --fail --show-error --location --retry 8 --retry-delay 2 --retry-all-errors \
    "$url" -o "$WORK/deps/$file"
  test "$(stat -c '%s' "$WORK/deps/$file")" = "$size"
  test "$(sha256sum "$WORK/deps/$file" | awk '{print $1}')" = "$sha"
  test "$(dpkg-deb -f "$WORK/deps/$file" Package)" = "$package"
  test "$(dpkg-deb -f "$WORK/deps/$file" Version)" = '2023.06.30+grm3u1'
  test "$(dpkg-deb -f "$WORK/deps/$file" Architecture)" = amd64
done < <(jq -c '.packages[]' "$NIMF_AUTHORITY")

git clone --filter=blob:none --no-checkout "https://github.com/$REPOSITORY.git" "$WORK/source"
git -C "$WORK/source" fetch --depth=1 origin "$CANDIDATE_COMMIT"
git -C "$WORK/source" checkout --detach "$CANDIDATE_COMMIT"
test "$(git -C "$WORK/source" rev-parse HEAD)" = "$CANDIDATE_COMMIT"
base_tree="$(git -C "$WORK/source" rev-parse HEAD^{tree})"

python3 "$ANALYZER" reconstruct \
  --source "$WORK/source" \
  --target-root "$WORK/target-root" \
  --output "$WORK/source-authority/base-reconstruction-report.json" \
  --version "$VERSION"
target_main="$(find "$WORK/target-root" -type f -name libgooroom-integration-applet.so -print -quit)"
test -n "$target_main"
python3 "$PATCHER" \
  --source "$WORK/source" \
  --target-main "$target_main" \
  --output "$WORK/source-authority/han3u3-patch-report.json"
test "$(dpkg-parsechangelog -l"$WORK/source/debian/changelog" -SVersion)" = "$VERSION"
grep -F 'theme_property_notified (NULL, NULL, NULL);' "$WORK/source/src/gooroom-integration-applet.c"
grep -F 'notify::gtk-icon-theme-name' "$WORK/source/src/goorom-integration-applet.c"
grep -F '/tmp/.cleanmode' "$WORK/source/src/popup-window.c"
grep -F 'gtk_widget_set_can_focus (priv->control, FALSE);' "$WORK/source/modules/datetime/datetime-module.c"
grep -F 'alias="style1.css"' "$WORK/source/src/gresource.xml"
grep -F 'alias="style2.css"' "$WORK/source/src/gresource.xml"

git -C "$WORK/source" add -A
reconstructed_tree="$(git -C "$WORK/source" write-tree)"
git -C "$WORK/source" diff --cached --binary --full-index > "$WORK/source-authority/reconstruction.patch"
test -s "$WORK/source-authority/reconstruction.patch"
git -C "$WORK/source" archive --format=tar "$reconstructed_tree" > "$WORK/source-authority/reconstructed-source.tar"
xz -9e "$WORK/source-authority/reconstructed-source.tar"
jq -n \
  --arg source "$PACKAGE" \
  --arg version "$VERSION" \
  --arg repository "$REPOSITORY" \
  --arg commit "$CANDIDATE_COMMIT" \
  --arg base_tree "$base_tree" \
  --arg reconstructed_tree "$reconstructed_tree" \
  --arg patch_sha256 "$(sha256sum "$WORK/source-authority/reconstruction.patch" | awk '{print $1}')" \
  --arg archive_sha256 "$(sha256sum "$WORK/source-authority/reconstructed-source.tar.xz" | awk '{print $1}')" \
  --arg target_sha256 "$TARGET_SHA256" \
  --arg debug_authority_sha256 "$(sha256sum "$DEBUG_AUTHORITY" | awk '{print $1}')" \
  --arg nimf_authority_sha256 "$(sha256sum "$NIMF_AUTHORITY" | awk '{print $1}')" '
  {
    schema: 2,
    source: $source,
    version: $version,
    repository: $repository,
    base_commit_sha: $commit,
    base_tree_sha: $base_tree,
    reconstructed_tree_sha: $reconstructed_tree,
    reconstruction_policy: "public-history-plus-exact-target-resources-plus-dwarf-guided-han3u3-code-v5",
    reconstruction_patch_sha256: $patch_sha256,
    source_archive_sha256: $archive_sha256,
    target_deb_sha256: $target_sha256,
    debug_authority_sha256: $debug_authority_sha256,
    nimf_authority_sha256: $nimf_authority_sha256
  }
' > "$WORK/source-authority/source-lock.json"

base="$(pwd)/$WORK"
rootfs="$base/build/rootfs"
timeout 30m sudo debootstrap \
  --arch=amd64 --variant=minbase --include=ca-certificates --no-check-gpg bullseye "$rootfs" \
  "https://snapshot.debian.org/archive/debian/$SNAPSHOT/" \
  2>&1 | tee "$base/build/debootstrap.log"
printf '%s\n' \
  "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/$SNAPSHOT bullseye main contrib non-free" \
  | sudo tee "$rootfs/etc/apt/sources.list" >/dev/null
printf '%s\n' \
  'Acquire::Check-Valid-Until "false";' \
  'Acquire::Retries "6";' \
  'Acquire::http::Timeout "45";' \
  'Acquire::https::Timeout "45";' \
  'Dpkg::Use-Pty "0";' \
  | sudo tee "$rootfs/etc/apt/apt.conf.d/99snapshot" >/dev/null
sudo cp /etc/resolv.conf "$rootfs/etc/resolv.conf"
sudo mkdir -p "$rootfs/build/source" "$rootfs/build/deps"
sudo tar -xJf "$base/source-authority/reconstructed-source.tar.xz" -C "$rootfs/build/source"
sudo cp "$base/deps"/*.deb "$rootfs/build/deps/"

timeout 90m sudo chroot "$rootfs" /bin/bash -Eeuxo pipefail -c '
  export DEBIAN_FRONTEND=noninteractive
  export DEB_BUILD_OPTIONS=nocheck
  export DEB_BUILD_MAINT_OPTIONS="hardening=+all reproducible=+fixfilepath"
  export LC_ALL=C.UTF-8
  apt-get update
  apt-get install -y --no-install-recommends build-essential devscripts dpkg-dev equivs git
  apt-get install -y /build/deps/libnimf1_2023.06.30+grm3u1_amd64.deb /build/deps/nimf-dev_2023.06.30+grm3u1_amd64.deb
  cd /build/source
  mk-build-deps --install --remove --tool "apt-get -o Acquire::Retries=6 -y --no-install-recommends" debian/control
  dpkg-buildpackage -us -uc -b -j2
' 2>&1 | tee "$base/build/build.log"

mkdir -p "$base/build/debs"
while IFS= read -r deb; do sudo cp "$deb" "$base/build/debs/"; done < <(
  sudo find "$rootfs/build" -maxdepth 1 -type f -name '*.deb' | LC_ALL=C sort
)
sudo chown -R "$(id -u):$(id -g)" "$base/build"
for deb in "$base/build/debs"/*.deb; do
  if [[ "$(dpkg-deb -f "$deb" Package)" == "$PACKAGE" ]]; then cp "$deb" "$base/downloads/candidate.deb"; fi
done
test -f "$base/downloads/candidate.deb"
test "$(dpkg-deb -f "$base/downloads/candidate.deb" Version)" = "$VERSION"