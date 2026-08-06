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

for command in jq git docker dpkg-parsechangelog dpkg-deb sha256sum gzip tar; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR_ABS="$(cd "$OUTPUT_DIR" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
DEPENDENCY_REPOSITORY_COPY="$WORK_DIR/dependency-repository"
mkdir -p "$DEPENDENCY_REPOSITORY_COPY"
DEPENDENCY_REPOSITORY_PACKAGES_SHA256=""
if [ -n "$DEPENDENCY_REPOSITORY" ]; then
  [ -d "$DEPENDENCY_REPOSITORY" ] || {
    echo "dependency repository does not exist: $DEPENDENCY_REPOSITORY" >&2
    exit 69
  }
  for required in Packages Packages.gz Release; do
    [ -f "$DEPENDENCY_REPOSITORY/$required" ] || {
      echo "dependency repository is missing $required" >&2
      exit 69
    }
  done
  if [ -f "$DEPENDENCY_REPOSITORY/SHA256SUMS" ]; then
    (cd "$DEPENDENCY_REPOSITORY" && sha256sum --check SHA256SUMS)
  fi
  cp -a "$DEPENDENCY_REPOSITORY/." "$DEPENDENCY_REPOSITORY_COPY/"
  DEPENDENCY_REPOSITORY_PACKAGES_SHA256="$(
    sha256sum "$DEPENDENCY_REPOSITORY_COPY/Packages" | awk '{print $1}'
  )"
fi

entry="$(jq -c --arg source "$SOURCE_NAME" '
  .sources[]
  | select(.source == $source and .status == "resolved" and .selected != null)
' "$LOCK_JSON" | head -n1)"
[ -n "$entry" ] || {
  echo "No resolved exact source lock for $SOURCE_NAME" >&2
  exit 2
}

SOURCE_VERSION="$(jq -r '.source_version' <<<"$entry")"
SELECTED_TYPE="$(jq -r '.selected.type // "git"' <<<"$entry")"
REPOSITORY="$(jq -r '.selected.repository_full_name // empty' <<<"$entry")"
COMMIT_SHA="$(jq -r '.selected.commit_sha // empty' <<<"$entry")"
TREE_SHA="$(jq -r '.selected.tree_sha // empty' <<<"$entry")"
if [ -n "${HANCOM_GOOROOM_REQUIRED_PACKAGES:-}" ]; then
  EXPECTED_PACKAGES="$HANCOM_GOOROOM_REQUIRED_PACKAGES"
elif [ -f "$REFERENCE_JSON" ]; then
  EXPECTED_PACKAGES="$(jq -r \
    --arg source "$SOURCE_NAME" \
    --arg version "$SOURCE_VERSION" '
      [.packages[]
       | select(.source == $source
                and .source_version == $version
                and .architecture == "amd64")
       | .package]
      | unique | join(" ")
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

[ "$SELECTED_TYPE" = git ] || {
  echo "The Git package builder cannot consume source type: $SELECTED_TYPE" >&2
  exit 2
}
[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "invalid repository name: $REPOSITORY" >&2
  exit 2
}
case "$SOURCE_VERSION" in
  *$'\n'*|*$'\r'*) echo "invalid version" >&2; exit 2 ;;
esac
[[ "$COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid commit SHA: $COMMIT_SHA" >&2
  exit 2
}
[[ "$TREE_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid tree SHA: $TREE_SHA" >&2
  exit 2
}
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid Debian snapshot: $SNAPSHOT" >&2
  exit 2
}

# Verify the actual Git object before producing a deterministic source archive.
# A Codeload tarball alone cannot prove the locked tree and does not preserve
# gitlink/submodule semantics.
PROBE_REPO="$WORK_DIR/repository"
ARCHIVE="$WORK_DIR/source.tar.gz"
SOURCE_ROOT="$WORK_DIR/source"
mkdir -p "$PROBE_REPO" "$SOURCE_ROOT"
export GIT_TERMINAL_PROMPT=0

git -C "$PROBE_REPO" init --quiet
git -C "$PROBE_REPO" remote add origin "https://github.com/${REPOSITORY}.git"
git -C "$PROBE_REPO" -c protocol.version=2 fetch \
  --quiet --force --no-tags --depth=1 --filter=blob:none \
  origin "$COMMIT_SHA"

ACTUAL_COMMIT_SHA="$(git -C "$PROBE_REPO" rev-parse FETCH_HEAD)"
ACTUAL_TREE_SHA="$(git -C "$PROBE_REPO" rev-parse 'FETCH_HEAD^{tree}')"
[ "$ACTUAL_COMMIT_SHA" = "$COMMIT_SHA" ] || {
  echo "commit mismatch: $ACTUAL_COMMIT_SHA != $COMMIT_SHA" >&2
  exit 3
}
[ "$ACTUAL_TREE_SHA" = "$TREE_SHA" ] || {
  echo "tree mismatch: $ACTUAL_TREE_SHA != $TREE_SHA" >&2
  exit 3
}

GITLINKS="$WORK_DIR/gitlinks.tsv"
git -C "$PROBE_REPO" ls-tree -r FETCH_HEAD \
  | awk '$1 == "160000" { print }' > "$GITLINKS"
if [ -s "$GITLINKS" ]; then
  echo "locked source contains submodules without independent commit locks:" >&2
  cat "$GITLINKS" >&2
  exit 3
fi

git -C "$PROBE_REPO" archive --format=tar FETCH_HEAD \
  | gzip -n -9 > "$ARCHIVE"
ARCHIVE_SHA256="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
gzip -dc "$ARCHIVE" | tar -xf - -C "$SOURCE_ROOT"

[ -f "$SOURCE_ROOT/debian/changelog" ] || {
  echo "debian/changelog missing from locked source" >&2
  exit 3
}
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

cat > "$OUTPUT_DIR_ABS/source-lock-evidence.json" <<EOF
{
  "schema": 2,
  "source": $(jq -Rn --arg v "$SOURCE_NAME" '$v'),
  "source_version": $(jq -Rn --arg v "$SOURCE_VERSION" '$v'),
  "repository": $(jq -Rn --arg v "$REPOSITORY" '$v'),
  "commit_sha": $(jq -Rn --arg v "$COMMIT_SHA" '$v'),
  "tree_sha": $(jq -Rn --arg v "$TREE_SHA" '$v'),
  "verified_commit_sha": $(jq -Rn --arg v "$ACTUAL_COMMIT_SHA" '$v'),
  "verified_tree_sha": $(jq -Rn --arg v "$ACTUAL_TREE_SHA" '$v'),
  "deterministic_source_archive_sha256": $(jq -Rn --arg v "$ARCHIVE_SHA256" '$v')
}
EOF
printf '%s\n' "$BOOTSTRAP_IMAGE" > "$OUTPUT_DIR_ABS/bootstrap-image.txt"

cat > "$WORK_DIR/build-inside.sh" <<'INNER'
#!/usr/bin/env bash
set -Eeuo pipefail

: "${SNAPSHOT:?SNAPSHOT is required}"
: "${HOST_UID:?HOST_UID is required}"
: "${HOST_GID:?HOST_GID is required}"
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
mkdir -p /out

[ "$(dpkg --print-architecture)" = arm64 ] || {
  echo "bootstrap container is not ARM64" >&2
  exit 19
}

# Obtain debootstrap itself from the same immutable snapshot before creating the
# build root. The pinned Docker image is only a transport shell.
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

if [ -f /dependency-repository/Packages ]; then
  mkdir -p "$ROOT/opt/hancom-gooroom-dependency-repository"
  cp -a /dependency-repository/. \
    "$ROOT/opt/hancom-gooroom-dependency-repository/"
  cat > "$ROOT/etc/apt/sources.list.d/98hancom-gooroom-dependencies.list" <<'EOF'
deb [trusted=yes] file:/opt/hancom-gooroom-dependency-repository ./
EOF
  cat > "$ROOT/etc/apt/preferences.d/98hancom-gooroom-dependencies" <<'EOF'
Package: *
Pin: release o=Hancom Gooroom ARM64
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

# Build only architecture-dependent binaries. Generate the dependency dummy
# first, retain its exact Depends field, and run an APT simulation so a future
# failure names the unsatisfied package instead of merely deleting the dummy.
rm -f ./*-build-deps*.deb
mk-build-deps --build-dep debian/control
DUMMY_PACKAGE="$(find . -maxdepth 1 -type f -name '*-build-deps*.deb' -print -quit)"
if [ -z "$DUMMY_PACKAGE" ]; then
  echo "mk-build-deps did not produce a dependency metapackage" >&2
  find . -maxdepth 1 -type f -printf '%f\n' | sort >&2
  exit 21
fi
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
apt-cache policy systemd libsystemd0 libsystemd-dev policykit-1 libwacom-dev \
  > /build/output/key-build-dependency-policy.txt

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
chown -R "$HOST_UID:$HOST_GID" /out || true
exit "$BUILD_RC"
INNER
chmod +x "$WORK_DIR/build-inside.sh"

# On the native GitHub ARM64 runner this executes without emulation. Privileged
# mode is used only for proc/sys/dev mounts inside the dated build chroot.
docker run --rm --privileged --platform linux/arm64 \
  --env "SNAPSHOT=$SNAPSHOT" \
  --env "HOST_UID=$(id -u)" \
  --env "HOST_GID=$(id -g)" \
  --volume "$SOURCE_ROOT:/src:ro" \
  --volume "$DEPENDENCY_REPOSITORY_COPY:/dependency-repository:ro" \
  --volume "$WORK_DIR/build-inside.sh:/build-inside.sh:ro" \
  --volume "$OUTPUT_DIR_ABS:/out:rw" \
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
    echo "Expected binary package was not built: $expected" >&2
    exit 6
  fi
done

cat > "$OUTPUT_DIR_ABS/build-lock.json" <<EOF
{
  "schema": 5,
  "source": $(jq -Rn --arg v "$SOURCE_NAME" '$v'),
  "source_version": $(jq -Rn --arg v "$SOURCE_VERSION" '$v'),
  "repository": $(jq -Rn --arg v "$REPOSITORY" '$v'),
  "commit_sha": $(jq -Rn --arg v "$COMMIT_SHA" '$v'),
  "tree_sha": $(jq -Rn --arg v "$TREE_SHA" '$v'),
  "source_archive_sha256": $(jq -Rn --arg v "$ARCHIVE_SHA256" '$v'),
  "bootstrap_image": $(jq -Rn --arg v "$BOOTSTRAP_IMAGE" '$v'),
  "target_architecture": "arm64",
  "debian_snapshot": $(jq -Rn --arg v "$SNAPSHOT" '$v'),
  "build_mode": "native-arm64-historical-chroot-binary-arch",
  "expected_binary_packages": $EXPECTED_PACKAGES_JSON,
  "dependency_repository_packages_sha256": $(jq -Rn --arg v "$DEPENDENCY_REPOSITORY_PACKAGES_SHA256" '$v'),
  "produced_binary_packages": $(printf '%s\n' "${produced_packages[@]}" | jq -Rsc 'split("\n")[:-1] | unique | sort')
}
EOF

find "$OUTPUT_DIR_ABS" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > "$OUTPUT_DIR_ABS/SHA256SUMS"

cat "$OUTPUT_DIR_ABS/build-lock.json"
