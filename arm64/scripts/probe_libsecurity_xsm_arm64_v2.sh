#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 1 ] || usage
OUTPUT_DIR="$1"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
BOOTSTRAP_IMAGE="${HANCOM_GOOROOM_BOOTSTRAP_IMAGE:-arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"
IMPLEMENTATION_REPOSITORY="ultract/X.org-Security-Module"
IMPLEMENTATION_COMMIT="fb0a3de9cab9b9f5b89aabd7943a5b5f13f37ab7"
IMPLEMENTATION_TREE="aef0ff9c73f625763b3822c7cfa7179799f26637"

for command in git docker python3 sha256sum readlink; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid Debian snapshot: $SNAPSHOT" >&2
  exit 2
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *)
    echo "native ARM64 host required" >&2
    exit 2
    ;;
esac

docker_architecture="$(docker info --format '{{.Architecture}}')"
case "$docker_architecture" in
  aarch64|arm64) ;;
  *)
    echo "native ARM64 Docker daemon required: $docker_architecture" >&2
    exit 2
    ;;
esac

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(readlink -f "$OUTPUT_DIR")"
rm -rf "$OUTPUT_DIR"/*
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
SOURCE_ROOT="$WORK_DIR/source"
INSIDE_SCRIPT="$WORK_DIR/run-inside.sh"
mkdir -p "$SOURCE_ROOT"

export GIT_TERMINAL_PROMPT=0
git -C "$SOURCE_ROOT" init --quiet
git -C "$SOURCE_ROOT" remote add origin \
  "https://github.com/${IMPLEMENTATION_REPOSITORY}.git"
git -C "$SOURCE_ROOT" -c protocol.version=2 fetch \
  --quiet --force --no-tags --depth=1 origin "$IMPLEMENTATION_COMMIT"
actual_commit="$(git -C "$SOURCE_ROOT" rev-parse FETCH_HEAD)"
actual_tree="$(git -C "$SOURCE_ROOT" rev-parse 'FETCH_HEAD^{tree}')"
[ "$actual_commit" = "$IMPLEMENTATION_COMMIT" ] || {
  echo "implementation commit mismatch" >&2
  exit 3
}
[ "$actual_tree" = "$IMPLEMENTATION_TREE" ] || {
  echo "implementation tree mismatch" >&2
  exit 3
}
git -C "$SOURCE_ROOT" checkout --quiet --detach FETCH_HEAD
source_sha256="$(sha256sum "$SOURCE_ROOT/xsm.c" | awk '{print $1}')"

cat > "$OUTPUT_DIR/source-provenance.json" <<EOF
{
  "schema": 2,
  "repository": "$IMPLEMENTATION_REPOSITORY",
  "commit": "$IMPLEMENTATION_COMMIT",
  "tree": "$IMPLEMENTATION_TREE",
  "xsm_c_sha256": "$source_sha256",
  "debian_snapshot": "$SNAPSHOT",
  "bootstrap_image": "$BOOTSTRAP_IMAGE"
}
EOF

cat > "$INSIDE_SCRIPT" <<'INNER'
#!/usr/bin/env bash
set -Eeuo pipefail

: "${SNAPSHOT:?SNAPSHOT is required}"
: "${HOST_UID:?HOST_UID is required}"
: "${HOST_GID:?HOST_GID is required}"
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
mkdir -p /out

finish() {
  chown -R "$HOST_UID:$HOST_GID" /out 2>/dev/null || true
}
trap finish EXIT

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

set +e
apt-get update > /out/transport-apt-update.stdout.log \
  2> /out/transport-apt-update.stderr.log
transport_update_exit=$?
printf '%s\n' "$transport_update_exit" \
  > /out/transport-apt-update.exit-code
if [ "$transport_update_exit" -eq 0 ]; then
  apt-get install -y --no-install-recommends \
    ca-certificates debootstrap debian-archive-keyring xz-utils \
    > /out/transport-apt-install.stdout.log \
    2> /out/transport-apt-install.stderr.log
  transport_install_exit=$?
else
  transport_install_exit=125
fi
printf '%s\n' "$transport_install_exit" \
  > /out/transport-apt-install.exit-code
set -e
[ "$transport_update_exit" -eq 0 ] || exit "$transport_update_exit"
[ "$transport_install_exit" -eq 0 ] || exit "$transport_install_exit"

ROOT=/snapshot-root
rm -rf "$ROOT"
mkdir -p "$ROOT"
set +e
debootstrap \
  --arch=arm64 \
  --variant=buildd \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  --include=ca-certificates,debian-archive-keyring \
  bullseye \
  "$ROOT" \
  "http://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
  > /out/debootstrap.stdout.log 2> /out/debootstrap.stderr.log
debootstrap_exit=$?
printf '%s\n' "$debootstrap_exit" > /out/debootstrap.exit-code
set -e
[ "$debootstrap_exit" -eq 0 ] || exit "$debootstrap_exit"

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
mkdir -p "$ROOT/build/source" "$ROOT/build/output"
cp -a /source/. "$ROOT/build/source/"

cat > "$ROOT/build/run-probe.sh" <<'CHROOT'
#!/usr/bin/env bash
set -Eeuo pipefail
export HOME=/root
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

set +e
apt-get update > /build/output/chroot-apt-update.stdout.log \
  2> /build/output/chroot-apt-update.stderr.log
apt_update_exit=$?
printf '%s\n' "$apt_update_exit" \
  > /build/output/chroot-apt-update.exit-code
if [ "$apt_update_exit" -eq 0 ]; then
  apt-get install -y --no-install-recommends \
    build-essential pkg-config xserver-xorg-dev \
    libjson-c-dev libnotify-dev libdbus-1-dev libsystemd-dev \
    binutils file ca-certificates \
    > /build/output/chroot-apt-install.stdout.log \
    2> /build/output/chroot-apt-install.stderr.log
  apt_install_exit=$?
else
  apt_install_exit=125
fi
printf '%s\n' "$apt_install_exit" \
  > /build/output/chroot-apt-install.exit-code
set -e
[ "$apt_update_exit" -eq 0 ] || exit "$apt_update_exit"
[ "$apt_install_exit" -eq 0 ] || exit "$apt_install_exit"

cd /build/source
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | LC_ALL=C sort > /build/output/build-environment-packages.tsv
uname -a > /build/output/uname.txt
gcc --version > /build/output/gcc-version.txt
pkg-config --modversion xorg-server dbus-1 libnotify json-c \
  > /build/output/pkg-config-versions.txt
pkg-config --cflags xorg-server dbus-1 libnotify json-c \
  > /build/output/pkg-config-cflags.txt
pkg-config --libs xorg-server dbus-1 libnotify json-c \
  > /build/output/pkg-config-libs.txt

set +e
XDG_CURRENT_DESKTOP=GNOME bash -x ./build.sh \
  > /build/output/original-build.stdout.log \
  2> /build/output/original-build.stderr.log
original_exit=$?
printf '%s\n' "$original_exit" \
  > /build/output/original-build.exit-code
if [ -f xsm.so ]; then
  cp xsm.so /build/output/xsm-original-build.so
fi

rm -f xsm.so
gcc $(pkg-config --cflags xorg-server dbus-1 libnotify json-c) \
  -DXACE -D_XSERVER64 -DX_REGISTRY_REQUEST \
  -DX_REGISTRY_RESOURCE -DCOMPOSITE \
  xsm.c -o xsm.so -shared -ldl -fPIC -s \
  > /build/output/cflags-only-build.stdout.log \
  2> /build/output/cflags-only-build.stderr.log
cflags_only_exit=$?
printf '%s\n' "$cflags_only_exit" \
  > /build/output/cflags-only-build.exit-code
set -e

if [ -f xsm.so ]; then
  cp xsm.so /build/output/xsm-cflags-only-build.so
  file xsm.so > /build/output/xsm-cflags-only-build.file.txt
  readelf -hW xsm.so > /build/output/xsm-cflags-only-build.readelf.txt
  readelf -dW xsm.so > /build/output/xsm-cflags-only-build.dynamic.txt
  readelf -WsW xsm.so > /build/output/xsm-cflags-only-build.symbols.txt
  strings -a -n 4 xsm.so | LC_ALL=C sort -u \
    > /build/output/xsm-cflags-only-build.strings.txt
fi
exit 0
CHROOT
chmod +x "$ROOT/build/run-probe.sh"

cleanup_mounts() {
  umount -R "$ROOT/dev" 2>/dev/null || true
  umount "$ROOT/proc" 2>/dev/null || true
  umount "$ROOT/sys" 2>/dev/null || true
}
trap 'cleanup_mounts; finish' EXIT
mount --rbind /dev "$ROOT/dev"
mount --make-rslave "$ROOT/dev"
mount -t proc proc "$ROOT/proc"
mount -t sysfs sysfs "$ROOT/sys"

set +e
chroot "$ROOT" /bin/bash /build/run-probe.sh \
  > /out/chroot-probe.stdout.log \
  2> /out/chroot-probe.stderr.log
chroot_exit=$?
printf '%s\n' "$chroot_exit" > /out/chroot-probe.exit-code
set -e
cp -a "$ROOT/build/output/." /out/ || true
exit "$chroot_exit"
INNER
chmod +x "$INSIDE_SCRIPT"

set +e
docker run --rm --privileged --platform linux/arm64 \
  --env "SNAPSHOT=$SNAPSHOT" \
  --env "HOST_UID=$(id -u)" \
  --env "HOST_GID=$(id -g)" \
  --volume "$SOURCE_ROOT:/source:ro" \
  --volume "$OUTPUT_DIR:/out" \
  --volume "$INSIDE_SCRIPT:/run-inside.sh:ro" \
  "$BOOTSTRAP_IMAGE" \
  /bin/bash /run-inside.sh \
  > "$OUTPUT_DIR/container.stdout.log" \
  2> "$OUTPUT_DIR/container.stderr.log"
container_exit=$?
set -e
printf '%s\n' "$container_exit" > "$OUTPUT_DIR/container.exit-code"

OUTPUT_DIR="$OUTPUT_DIR" python3 - <<'PY'
import json
import os
import re
from pathlib import Path

root = Path(os.environ["OUTPUT_DIR"])

def number(name: str):
    path = root / name
    if not path.exists():
        return None
    value = path.read_text(encoding="utf-8", errors="replace").strip()
    return int(value) if value else None

readelf_path = root / "xsm-cflags-only-build.readelf.txt"
readelf = readelf_path.read_text(encoding="utf-8", errors="replace") if readelf_path.exists() else ""
machine_match = re.search(r"^\s*Machine:\s*(.+)$", readelf, re.MULTILINE)
machine = machine_match.group(1).strip() if machine_match else ""
binary = root / "xsm-cflags-only-build.so"
summary = {
    "schema": 2,
    "implementation_repository": "ultract/X.org-Security-Module",
    "implementation_commit": "fb0a3de9cab9b9f5b89aabd7943a5b5f13f37ab7",
    "implementation_tree": "aef0ff9c73f625763b3822c7cfa7179799f26637",
    "debian_snapshot": "20230730T235959Z",
    "bootstrap_image": "arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e",
    "container_exit_code": number("container.exit-code"),
    "transport_apt_update_exit_code": number("transport-apt-update.exit-code"),
    "transport_apt_install_exit_code": number("transport-apt-install.exit-code"),
    "debootstrap_exit_code": number("debootstrap.exit-code"),
    "chroot_apt_update_exit_code": number("chroot-apt-update.exit-code"),
    "chroot_apt_install_exit_code": number("chroot-apt-install.exit-code"),
    "chroot_probe_exit_code": number("chroot-probe.exit-code"),
    "original_build_exit_code": number("original-build.exit-code"),
    "cflags_only_build_exit_code": number("cflags-only-build.exit-code"),
    "original_binary_present": (root / "xsm-original-build.so").exists(),
    "cflags_only_binary_present": binary.exists(),
    "cflags_only_binary_machine": machine,
}
summary["probe_passed"] = (
    summary["cflags_only_build_exit_code"] == 0
    and binary.exists()
    and machine in {"AArch64", "ARM aarch64"}
)
(root / "summary.json").write_text(
    json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY

(
  cd "$OUTPUT_DIR"
  find . -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
  sha256sum --check SHA256SUMS
)
cat "$OUTPUT_DIR/summary.json"
