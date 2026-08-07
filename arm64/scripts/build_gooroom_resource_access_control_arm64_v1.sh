#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 1 ] || usage
OUTPUT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-$REPO_ROOT/arm64/locks/reference/amd64-reference.json}"
VERIFY_SCRIPT="$REPO_ROOT/arm64/scripts/verify_locked_arm64_build.sh"
LOCK_ROOT="$REPO_ROOT/arm64/locks"
XSM_EVIDENCE="$REPO_ROOT/arm64/locks/gooroom-libsecurity-extensions-arm64-build/latest"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
SNAPSHOT_URL="http://snapshot.debian.org/archive/debian/$SNAPSHOT/"

for command in jq git dpkg-parsechangelog debootstrap sha256sum file readelf dpkg-deb find sort awk sed grep sudo; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 build host required, got $(uname -m)" >&2; exit 65 ;;
esac

[ -f "$REFERENCE_JSON" ] || { echo "AMD64 reference lock is missing: $REFERENCE_JSON" >&2; exit 2; }
[ -x "$VERIFY_SCRIPT" ] || { echo "generic verifier is missing: $VERIFY_SCRIPT" >&2; exit 2; }
for file in summary.json verification-summary.json effective-source-lock.json authority.json; do
  [ -f "$XSM_EVIDENCE/$file" ] || {
    echo "verified XSM evidence is missing: $XSM_EVIDENCE/$file" >&2
    exit 2
  }
done
jq -e '
  .build_passed == true
  and .build_architecture == "arm64"
  and .xsm_module_machine == "AArch64"
  and .generic_locked_build_verifier_passed == true
  and .wrong_architecture_executable_count == 0
' "$XSM_EVIDENCE/summary.json" >/dev/null
jq -e '.verified == true and .wrong_architecture_executable_count == 0' \
  "$XSM_EVIDENCE/verification-summary.json" >/dev/null
jq -e '.source_build_outcome == "success" and .source_build_exit_code == "0"' \
  "$XSM_EVIDENCE/authority.json" >/dev/null

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
WORK_DIR="$OUTPUT_DIR/work"
SOURCE_DIR="$WORK_DIR/source"
XSM_SOURCE_DIR="$WORK_DIR/xsm-source"
CHROOT_DIR="$WORK_DIR/chroot"
EFFECTIVE_LOCK="$OUTPUT_DIR/effective-source-lock.json"
mkdir -p "$WORK_DIR"

SOURCE_NAME=""
for candidate in gooroom-resource-access-control resource-access-control; do
  if jq -e --arg source "$candidate" '.packages[] | select(.source == $source)' \
      "$REFERENCE_JSON" >/dev/null; then
    SOURCE_NAME="$candidate"
    break
  fi
done
if [ -z "$SOURCE_NAME" ]; then
  mapfile -t matches < <(jq -r '
    .packages[].source
    | select(test("(^|-)resource-access-control$"; "i"))
  ' "$REFERENCE_JSON" | sort -u)
  [ "${#matches[@]}" -eq 1 ] || {
    echo "unable to resolve one resource-access-control source" >&2
    printf '  %s\n' "${matches[@]:-<none>}" >&2
    exit 3
  }
  SOURCE_NAME="${matches[0]}"
fi

mapfile -t versions < <(jq -r --arg source "$SOURCE_NAME" '
  .packages[] | select(.source == $source) | .source_version
' "$REFERENCE_JSON" | sort -u)
[ "${#versions[@]}" -eq 1 ] || {
  echo "reference contains zero or multiple versions for $SOURCE_NAME" >&2
  printf '  %s\n' "${versions[@]:-<none>}" >&2
  exit 3
}
SOURCE_VERSION="${versions[0]}"

EXPECTED_ROWS_JSON="$(jq -cS --arg source "$SOURCE_NAME" --arg version "$SOURCE_VERSION" '
  [
    .packages[]
    | select(.source == $source and .source_version == $version)
    | {
        package: .package,
        reference_architecture: .architecture,
        expected_output_architecture: (if .architecture == "all" then "all" else "arm64" end)
      }
  ]
  | unique_by(.package)
  | sort_by(.package)
' "$REFERENCE_JSON")"
[ "$(jq 'length' <<<"$EXPECTED_ROWS_JSON")" -gt 0 ] || {
  echo "no reference binary packages found for $SOURCE_NAME $SOURCE_VERSION" >&2
  exit 3
}
mapfile -t EXPECTED_ARCH_PACKAGES < <(jq -r '
  .[] | select(.reference_architecture != "all") | .package
' <<<"$EXPECTED_ROWS_JSON")
EXPECTED_ARCH_PACKAGES_JSON="$(printf '%s\n' "${EXPECTED_ARCH_PACKAGES[@]:-}" \
  | jq -Rsc 'split("\n")[:-1] | map(select(length > 0)) | sort')"

LOCK_CANDIDATES=()
while IFS= read -r lock_file; do
  if jq -e --arg source "$SOURCE_NAME" --arg version "$SOURCE_VERSION" '
      .sources[]?
      | select(
          .source == $source
          and .source_version == $version
          and .role == "rebuild-arm64"
          and .status == "resolved"
          and .selected != null
          and (.selected.type // "git") == "git"
          and (.selected.repository_full_name | type == "string")
          and (.selected.commit_sha | type == "string")
          and (.selected.tree_sha | type == "string")
        )
    ' "$lock_file" >/dev/null 2>&1; then
    LOCK_CANDIDATES+=("$lock_file")
  fi
done < <(find "$LOCK_ROOT" -maxdepth 3 -type f -name '*.json' \
  ! -path '*/runs/*' ! -path '*/latest/*' | LC_ALL=C sort)
[ "${#LOCK_CANDIDATES[@]}" -gt 0 ] || {
  echo "no immutable resolved ARM64 source lock found for $SOURCE_NAME $SOURCE_VERSION" >&2
  exit 4
}
SOURCE_LOCK_PATH="${LOCK_CANDIDATES[0]}"
FIRST_ENTRY="$(jq -c --arg source "$SOURCE_NAME" --arg version "$SOURCE_VERSION" '
  first(.sources[] | select(
    .source == $source
    and .source_version == $version
    and .role == "rebuild-arm64"
    and .status == "resolved"
    and .selected != null
    and (.selected.type // "git") == "git"
  ))
' "$SOURCE_LOCK_PATH")"
FIRST_FINGERPRINT="$(jq -r '[.selected.repository_full_name,.selected.commit_sha,.selected.tree_sha] | @tsv' \
  <<<"$FIRST_ENTRY")"
for lock_file in "${LOCK_CANDIDATES[@]:1}"; do
  entry="$(jq -c --arg source "$SOURCE_NAME" --arg version "$SOURCE_VERSION" '
    first(.sources[] | select(
      .source == $source
      and .source_version == $version
      and .role == "rebuild-arm64"
      and .status == "resolved"
      and .selected != null
      and (.selected.type // "git") == "git"
    ))
  ' "$lock_file")"
  fingerprint="$(jq -r '[.selected.repository_full_name,.selected.commit_sha,.selected.tree_sha] | @tsv' \
    <<<"$entry")"
  [ "$fingerprint" = "$FIRST_FINGERPRINT" ] || {
    echo "conflicting immutable source locks found for $SOURCE_NAME" >&2
    printf '  %s\n' "${LOCK_CANDIDATES[@]}" >&2
    exit 4
  }
done
cp "$SOURCE_LOCK_PATH" "$EFFECTIVE_LOCK"
ENTRY="$FIRST_ENTRY"
REPOSITORY="$(jq -er '.selected.repository_full_name' <<<"$ENTRY")"
COMMIT_SHA="$(jq -er '.selected.commit_sha' <<<"$ENTRY")"
TREE_SHA="$(jq -er '.selected.tree_sha' <<<"$ENTRY")"
printf '%s\n' "$SOURCE_LOCK_PATH" > "$OUTPUT_DIR/source-lock-path.txt"
printf '%s\n' "$SNAPSHOT" > "$OUTPUT_DIR/debian-snapshot.txt"
printf '%s\n' "$SNAPSHOT_URL" > "$OUTPUT_DIR/debian-snapshot-url.txt"
printf '%s\n' "$EXPECTED_ROWS_JSON" | jq . > "$OUTPUT_DIR/expected-package-rows.json"

if [ -f "$REPO_ROOT/arm64/locks/source-components/$SOURCE_NAME.json" ]; then
  echo "composite source lock exists for $SOURCE_NAME; this v1 builder is deliberately git-only" >&2
  exit 5
fi

mkdir -p "$SOURCE_DIR"
git -C "$SOURCE_DIR" init -q
git -C "$SOURCE_DIR" remote add origin "https://github.com/$REPOSITORY.git"
git -C "$SOURCE_DIR" fetch --depth=1 origin "$COMMIT_SHA" \
  >"$OUTPUT_DIR/git-fetch.stdout.log" 2>"$OUTPUT_DIR/git-fetch.stderr.log"
git -C "$SOURCE_DIR" checkout --detach -q FETCH_HEAD
VERIFIED_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
VERIFIED_TREE="$(git -C "$SOURCE_DIR" rev-parse 'HEAD^{tree}')"
[ "$VERIFIED_COMMIT" = "$COMMIT_SHA" ] || { echo "commit verification failed" >&2; exit 6; }
[ "$VERIFIED_TREE" = "$TREE_SHA" ] || { echo "tree verification failed" >&2; exit 6; }
[ -f "$SOURCE_DIR/debian/changelog" ] || { echo "Debian changelog missing" >&2; exit 6; }
CHANGELOG_SOURCE="$(dpkg-parsechangelog -l"$SOURCE_DIR/debian/changelog" -SSource)"
CHANGELOG_VERSION="$(dpkg-parsechangelog -l"$SOURCE_DIR/debian/changelog" -SVersion)"
[ "$CHANGELOG_SOURCE" = "$SOURCE_NAME" ] || {
  echo "source-name mismatch: changelog=$CHANGELOG_SOURCE reference=$SOURCE_NAME" >&2; exit 6;
}
[ "$CHANGELOG_VERSION" = "$SOURCE_VERSION" ] || {
  echo "source-version mismatch: changelog=$CHANGELOG_VERSION reference=$SOURCE_VERSION" >&2; exit 6;
}

jq -n \
  --arg source "$SOURCE_NAME" --arg version "$SOURCE_VERSION" \
  --arg repository "$REPOSITORY" --arg commit "$COMMIT_SHA" --arg tree "$TREE_SHA" \
  --arg lock_path "$SOURCE_LOCK_PATH" --arg snapshot "$SNAPSHOT" '
  {
    schema: 1,
    source: $source,
    source_version: $version,
    repository: $repository,
    commit_sha: $commit,
    verified_commit_sha: $commit,
    tree_sha: $tree,
    verified_tree_sha: $tree,
    source_lock_origin: "project-source-resolution",
    source_lock_path: $lock_path,
    debian_snapshot: $snapshot,
    verified: true
  }
' > "$OUTPUT_DIR/source-provenance.json"
jq -n \
  --arg source "$SOURCE_NAME" --arg version "$SOURCE_VERSION" \
  --arg repository "$REPOSITORY" --arg commit "$COMMIT_SHA" --arg tree "$TREE_SHA" '
  {
    source: $source,
    source_version: $version,
    repository: $repository,
    commit_sha: $commit,
    verified_commit_sha: $commit,
    tree_sha: $tree,
    verified_tree_sha: $tree
  }
' > "$OUTPUT_DIR/source-lock-evidence.json"
jq -n \
  --arg source "$SOURCE_NAME" --arg version "$SOURCE_VERSION" --arg snapshot "$SNAPSHOT" \
  --argjson expected "$EXPECTED_ARCH_PACKAGES_JSON" '
  {
    schema: 1,
    source: $source,
    source_version: $version,
    target_architecture: "arm64",
    build_mode: "native-arm64-historical-chroot-binary-arch",
    debian_snapshot: $snapshot,
    expected_binary_packages: $expected,
    binary_package_policy: "AMD64 reference packages whose Architecture is not all",
    source_composition: {mode: "git-only"}
  }
' > "$OUTPUT_DIR/build-lock.json"

set +e
sudo debootstrap \
  --arch=arm64 --variant=minbase --include=ca-certificates,gnupg \
  bullseye "$CHROOT_DIR" "$SNAPSHOT_URL" \
  >"$OUTPUT_DIR/debootstrap.stdout.log" 2>"$OUTPUT_DIR/debootstrap.stderr.log"
DEBOOTSTRAP_RC=$?
set -e
printf '%s\n' "$DEBOOTSTRAP_RC" > "$OUTPUT_DIR/debootstrap.exit-code"
[ "$DEBOOTSTRAP_RC" -eq 0 ] || exit "$DEBOOTSTRAP_RC"

sudo mkdir -p "$CHROOT_DIR/build/src"
sudo cp -a "$SOURCE_DIR/." "$CHROOT_DIR/build/src/"
sudo cp -L /etc/resolv.conf "$CHROOT_DIR/etc/resolv.conf"
sudo tee "$CHROOT_DIR/etc/apt/sources.list" >/dev/null <<EOF
deb [check-valid-until=no] $SNAPSHOT_URL bullseye main
deb-src [check-valid-until=no] $SNAPSHOT_URL bullseye main
EOF
sudo tee "$CHROOT_DIR/etc/apt/apt.conf.d/99snapshot" >/dev/null <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
Acquire::http::No-Cache "true";
APT::Get::Assume-Yes "true";
EOF
cat > "$WORK_DIR/build-in-chroot.sh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
apt-get update
apt-get install -y --no-install-recommends \
  build-essential devscripts equivs fakeroot dpkg-dev debhelper \
  pkg-config ca-certificates file binutils
cd /build/src
mk-build-deps --install --remove \
  --tool 'apt-get -y --no-install-recommends' debian/control
export DEB_BUILD_OPTIONS="parallel=$(nproc)"
dpkg-buildpackage -b -us -uc
EOF
chmod 0755 "$WORK_DIR/build-in-chroot.sh"
sudo cp "$WORK_DIR/build-in-chroot.sh" "$CHROOT_DIR/build/build-in-chroot.sh"
sudo chmod 0755 "$CHROOT_DIR/build/build-in-chroot.sh"
set +e
sudo chroot "$CHROOT_DIR" /build/build-in-chroot.sh \
  >"$OUTPUT_DIR/build.stdout.log" 2>"$OUTPUT_DIR/build.stderr.log"
BUILD_RC=$?
set -e
printf '%s\n' "$BUILD_RC" > "$OUTPUT_DIR/build.exit-code"
[ "$BUILD_RC" -eq 0 ] || exit "$BUILD_RC"

find "$CHROOT_DIR/build" -maxdepth 1 -type f -name '*.deb' -print0 \
  | while IFS= read -r -d '' deb; do sudo cp "$deb" "$OUTPUT_DIR/"; done
sudo chown -R "$(id -u):$(id -g)" "$OUTPUT_DIR"
shopt -s nullglob
DEBS=("$OUTPUT_DIR"/*.deb)
[ "${#DEBS[@]}" -gt 0 ] || { echo "no binary package was produced" >&2; exit 7; }

: > "$OUTPUT_DIR/package-metadata.tsv"
: > "$OUTPUT_DIR/package-contents.txt"
: > "$OUTPUT_DIR/file-audit.txt"
PRODUCED_ROWS_FILE="$OUTPUT_DIR/produced-package-rows.jsonl"
: > "$PRODUCED_ROWS_FILE"
HELPER_PATHS_FILE="$OUTPUT_DIR/packaged-grac-noti-forward-paths.txt"
: > "$HELPER_PATHS_FILE"
RULE_PATHS_FILE="$OUTPUT_DIR/packaged-grac-rule-paths.txt"
: > "$RULE_PATHS_FILE"
WRONG_ARCH_COUNT=0

for deb in "${DEBS[@]}"; do
  package="$(dpkg-deb -f "$deb" Package)"
  version="$(dpkg-deb -f "$deb" Version)"
  architecture="$(dpkg-deb -f "$deb" Architecture)"
  printf '%s\t%s\t%s\t%s\n' "$(basename "$deb")" "$package" "$version" "$architecture" \
    >> "$OUTPUT_DIR/package-metadata.tsv"
  dpkg-deb -c "$deb" >> "$OUTPUT_DIR/package-contents.txt"
  [ "$version" = "$SOURCE_VERSION" ] || {
    echo "binary version mismatch: $package $version != $SOURCE_VERSION" >&2; exit 8;
  }
  jq -nc --arg package "$package" --arg architecture "$architecture" \
    '{package:$package,output_architecture:$architecture}' >> "$PRODUCED_ROWS_FILE"

  package_root="$WORK_DIR/extracted-$package"
  rm -rf "$package_root"
  mkdir -p "$package_root"
  dpkg-deb -x "$deb" "$package_root"
  find "$package_root" -type f -exec file -- '{}' + | LC_ALL=C sort \
    >> "$OUTPUT_DIR/file-audit.txt"
  if grep -E 'ELF (32|64)-bit .* (x86-64|Intel 80386)|PE32(\+)? executable .* (x86-64|Intel 80386)' \
      "$OUTPUT_DIR/file-audit.txt" >/dev/null; then
    WRONG_ARCH_COUNT=1
  fi
  while IFS= read -r -d '' helper; do
    printf '/%s\n' "${helper#"$package_root"/}" >> "$HELPER_PATHS_FILE"
  done < <(find "$package_root" \( -type f -o -type l \) -name grac_noti_forward -print0)
  while IFS= read -r -d '' rule; do
    printf '/%s\n' "${rule#"$package_root"/}" >> "$RULE_PATHS_FILE"
  done < <(find "$package_root" \( -type f -o -type l \) -path '*/etc/gooroom/grac.d/*' -print0)

done
[ "$WRONG_ARCH_COUNT" -eq 0 ] || {
  echo "x86 executable leaked into ARM64/architecture-all GRAC packages" >&2
  exit 8
}

jq -s 'unique_by(.package) | sort_by(.package)' "$PRODUCED_ROWS_FILE" \
  > "$OUTPUT_DIR/produced-package-rows.json"
EXPECTED_COMPARE="$(jq -cS '[.[] | {package,output_architecture:.expected_output_architecture}] | sort_by(.package)' \
  <<<"$EXPECTED_ROWS_JSON")"
PRODUCED_COMPARE="$(jq -cS 'sort_by(.package)' "$OUTPUT_DIR/produced-package-rows.json")"
[ "$EXPECTED_COMPARE" = "$PRODUCED_COMPARE" ] || {
  echo "produced GRAC package/architecture set differs from AMD64-reference mapping" >&2
  echo "expected: $EXPECTED_COMPARE" >&2
  echo "produced: $PRODUCED_COMPARE" >&2
  exit 9
}

LC_ALL=C sort -u -o "$HELPER_PATHS_FILE" "$HELPER_PATHS_FILE"
LC_ALL=C sort -u -o "$RULE_PATHS_FILE" "$RULE_PATHS_FILE"
mapfile -t PACKAGED_HELPER_PATHS < "$HELPER_PATHS_FILE"
[ "${#PACKAGED_HELPER_PATHS[@]}" -eq 1 ] || {
  echo "expected exactly one packaged grac_noti_forward provider, found ${#PACKAGED_HELPER_PATHS[@]}" >&2
  cat "$HELPER_PATHS_FILE" >&2
  exit 10
}
PACKAGED_HELPER_PATH="${PACKAGED_HELPER_PATHS[0]}"

XSM_REPOSITORY="$(jq -er '.repository' "$XSM_EVIDENCE/summary.json")"
XSM_COMMIT="$(jq -er '.commit_sha' "$XSM_EVIDENCE/summary.json")"
XSM_TREE="$(jq -er '.tree_sha' "$XSM_EVIDENCE/summary.json")"
mkdir -p "$XSM_SOURCE_DIR"
git -C "$XSM_SOURCE_DIR" init -q
git -C "$XSM_SOURCE_DIR" remote add origin "https://github.com/$XSM_REPOSITORY.git"
git -C "$XSM_SOURCE_DIR" fetch --depth=1 origin "$XSM_COMMIT" \
  >"$OUTPUT_DIR/xsm-git-fetch.stdout.log" 2>"$OUTPUT_DIR/xsm-git-fetch.stderr.log"
git -C "$XSM_SOURCE_DIR" checkout --detach -q FETCH_HEAD
[ "$(git -C "$XSM_SOURCE_DIR" rev-parse HEAD)" = "$XSM_COMMIT" ] || exit 11
[ "$(git -C "$XSM_SOURCE_DIR" rev-parse 'HEAD^{tree}')" = "$XSM_TREE" ] || exit 11

grep -RhoE --exclude-dir=.git '"/[^"[:space:]]*grac_noti_forward"' "$XSM_SOURCE_DIR" \
  | tr -d '"' | LC_ALL=C sort -u > "$OUTPUT_DIR/xsm-grac-noti-forward-consumer-paths.txt" || true
mapfile -t XSM_HELPER_PATHS < "$OUTPUT_DIR/xsm-grac-noti-forward-consumer-paths.txt"
[ "${#XSM_HELPER_PATHS[@]}" -eq 1 ] || {
  echo "expected exactly one literal grac_noti_forward consumer path in the locked XSM source" >&2
  cat "$OUTPUT_DIR/xsm-grac-noti-forward-consumer-paths.txt" >&2
  exit 12
}
XSM_HELPER_PATH="${XSM_HELPER_PATHS[0]}"
[ "$XSM_HELPER_PATH" = "$PACKAGED_HELPER_PATH" ] || {
  echo "XSM/GRAC helper path mismatch" >&2
  echo "XSM consumes: $XSM_HELPER_PATH" >&2
  echo "GRAC provides: $PACKAGED_HELPER_PATH" >&2
  exit 12
}

if grep -RFl --exclude-dir=.git '/etc/gooroom/grac.d/user.rules' "$XSM_SOURCE_DIR" \
    > "$OUTPUT_DIR/xsm-user-rules-consumer-files.txt"; then
  :
else
  echo "locked XSM source no longer exposes the expected GRAC user.rules contract" >&2
  exit 12
fi
grep -RFl --exclude-dir=.git '/etc/gooroom/grac.d/user.rules' "$SOURCE_DIR" \
  > "$OUTPUT_DIR/grac-user-rules-provider-source-files.txt" || true

(
  cd "$OUTPUT_DIR"
  find . -type f ! -path './work/*' ! -name SHA256SUMS \
    ! -name COMPLETE-SHA256SUMS ! -name summary.json ! -name verification-summary.json \
    -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
  sha256sum --check SHA256SUMS
)

GENERIC_VERIFIER_USED=false
if [ "${#EXPECTED_ARCH_PACKAGES[@]}" -gt 0 ]; then
  bash "$VERIFY_SCRIPT" "$EFFECTIVE_LOCK" "$SOURCE_NAME" "$OUTPUT_DIR" \
    > "$OUTPUT_DIR/generic-verifier.stdout.log" \
    2> "$OUTPUT_DIR/generic-verifier.stderr.log"
  jq -e '.verified == true and .wrong_architecture_executable_count == 0 and .deb_count > 0' \
    "$OUTPUT_DIR/verification-summary.json" >/dev/null
  GENERIC_VERIFIER_USED=true
else
  jq -n \
    --arg source "$SOURCE_NAME" --arg version "$SOURCE_VERSION" \
    --arg commit "$COMMIT_SHA" --arg tree "$TREE_SHA" \
    --argjson expected "$EXPECTED_COMPARE" --argjson produced "$PRODUCED_COMPARE" \
    --argjson deb_count "${#DEBS[@]}" '
    {
      schema: 3,
      source: $source,
      source_version: $version,
      commit_sha: $commit,
      tree_sha: $tree,
      source_composition_mode: "git-only",
      expected_architecture_dependent_packages: [],
      produced_binary_packages: ($produced | map(.package)),
      expected_full_package_mapping: $expected,
      produced_full_package_mapping: $produced,
      architecture_all_policy: "production corpus reuses exact verified AMD64 Architecture: all binaries; this source build validates structure and runtime contracts",
      deb_count: $deb_count,
      wrong_architecture_executable_count: 0,
      verified: true
    }
  ' > "$OUTPUT_DIR/verification-summary.json"
fi

jq -n \
  --arg source "$SOURCE_NAME" --arg version "$SOURCE_VERSION" \
  --arg repository "$REPOSITORY" --arg commit "$COMMIT_SHA" --arg tree "$TREE_SHA" \
  --arg snapshot "$SNAPSHOT" --arg helper "$PACKAGED_HELPER_PATH" \
  --arg xsm_helper "$XSM_HELPER_PATH" --argjson expected "$EXPECTED_COMPARE" \
  --argjson produced "$PRODUCED_COMPARE" --argjson deb_count "${#DEBS[@]}" \
  --argjson generic_verifier_used "$GENERIC_VERIFIER_USED" '
  {
    schema: 1,
    source: $source,
    source_version: $version,
    repository: $repository,
    commit_sha: $commit,
    tree_sha: $tree,
    debian_snapshot: $snapshot,
    build_architecture: "arm64",
    build_mode: "native-arm64-historical-chroot-full-binary",
    expected_package_mapping: $expected,
    produced_package_mapping: $produced,
    deb_count: $deb_count,
    packaged_grac_noti_forward_path: $helper,
    xsm_grac_noti_forward_consumer_path: $xsm_helper,
    xsm_grac_helper_path_contract_verified: true,
    xsm_user_rules_consumer_contract_present: true,
    generic_locked_build_verifier_used: $generic_verifier_used,
    wrong_architecture_executable_count: 0,
    build_passed: true
  }
' > "$OUTPUT_DIR/summary.json"

(
  cd "$OUTPUT_DIR"
  find . -type f ! -path './work/*' ! -name COMPLETE-SHA256SUMS -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum > COMPLETE-SHA256SUMS
  sha256sum --check COMPLETE-SHA256SUMS
)
cat "$OUTPUT_DIR/summary.json"
