#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 PACKAGE_REPOSITORY MATERIALIZATION_JSON ROOTFS OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 4 ] || usage
PACKAGE_REPOSITORY="$1"
MATERIALIZATION_JSON="$2"
ROOTFS="$3"
OUTPUT_DIR="$4"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"

[ "$(id -u)" -eq 0 ] || {
  echo "root privileges are required" >&2
  exit 77
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 host required, got $(uname -m)" >&2; exit 78 ;;
esac
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "invalid snapshot timestamp: $SNAPSHOT" >&2
  exit 64
}

for command in jq python3 mmdebstrap chroot mount umount rsync dpkg-query; do
  command -v "$command" >/dev/null || {
    echo "required command missing: $command" >&2
    exit 69
  }
done
[ -f "$PACKAGE_REPOSITORY/Packages" ]
[ -f "$PACKAGE_REPOSITORY/Release" ]
[ -f "$MATERIALIZATION_JSON" ]
jq -e '.summary.repository_ready == true and .summary.blocked_count == 0' \
  "$MATERIALIZATION_JSON" >/dev/null

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
PACKAGE_REPOSITORY="$(cd "$PACKAGE_REPOSITORY" && pwd)"
MATERIALIZATION_JSON="$(cd "$(dirname "$MATERIALIZATION_JSON")" && pwd)/$(basename "$MATERIALIZATION_JSON")"
ROOTFS="$(mkdir -p "$ROOTFS" && cd "$ROOTFS" && pwd)"

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS" "$OUTPUT_DIR"

python3 - "$MATERIALIZATION_JSON" "$OUTPUT_DIR/install-specs.txt" <<'PY'
import json, sys
from pathlib import Path
manifest = json.loads(Path(sys.argv[1]).read_text())
packages = {}
for row in manifest.get('verified_packages', []):
    control = row.get('control') or {}
    package = control.get('package')
    version = control.get('version')
    architecture = control.get('architecture')
    if not package or not version or architecture not in {'arm64', 'all'}:
        raise SystemExit(f'invalid materialized package control: {control!r}')
    identity = (version, architecture)
    if package in packages and packages[package] != identity:
        raise SystemExit(f'conflicting versions for {package}: {packages[package]} and {identity}')
    packages[package] = identity
Path(sys.argv[2]).write_text(
    ''.join(f'{package}={identity[0]}\n' for package, identity in sorted(packages.items())),
    encoding='utf-8',
)
print(json.dumps({'package_count': len(packages)}, indent=2))
PY

test -s "$OUTPUT_DIR/install-specs.txt"
printf '%s\n' "$SNAPSHOT" > "$OUTPUT_DIR/debian-snapshot.txt"

# Bootstrap only a minimal ARM64 userspace from the dated Debian archive. The
# next transaction installs every materialized package with an explicit version
# from the local verified repository, replacing bootstrap versions as needed.
mmdebstrap \
  --mode=root \
  --architectures=arm64 \
  --variant=minbase \
  --aptopt='Acquire::Check-Valid-Until "false"' \
  --aptopt='Acquire::Retries "5"' \
  --aptopt='Dpkg::Use-Pty "0"' \
  bullseye \
  "$ROOTFS" \
  "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free" \
  "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free" \
  "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free" \
  2>&1 | tee "$OUTPUT_DIR/mmdebstrap.log"

mkdir -p \
  "$ROOTFS/mnt/hancom-packages" \
  "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" "$ROOTFS/run" \
  "$ROOTFS/tmp/hancom-arm64-build"
cp "$MATERIALIZATION_JSON" "$ROOTFS/tmp/hancom-arm64-build/materialization.json"
cp "$OUTPUT_DIR/install-specs.txt" "$ROOTFS/tmp/hancom-arm64-build/install-specs.txt"
cp -L /etc/resolv.conf "$ROOTFS/etc/resolv.conf"

cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb [trusted=yes] file:/mnt/hancom-packages ./
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
rm -f "$ROOTFS/etc/apt/sources.list.d/"*
cat > "$ROOTFS/etc/apt/apt.conf.d/99hancom-arm64-build" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
cat > "$ROOTFS/etc/apt/preferences.d/99hancom-local-exact" <<'EOF'
Package: *
Pin: origin ""
Pin-Priority: 1001
EOF
cat > "$ROOTFS/usr/sbin/policy-rc.d" <<'EOF'
#!/bin/sh
exit 101
EOF
chmod +x "$ROOTFS/usr/sbin/policy-rc.d"

mounted=()
cleanup() {
  set +e
  for target in "${mounted[@]}"; do
    umount -R "$target" 2>/dev/null || umount -l "$target" 2>/dev/null || true
  done
}
trap cleanup EXIT

mount --bind "$PACKAGE_REPOSITORY" "$ROOTFS/mnt/hancom-packages"
mounted=("$ROOTFS/mnt/hancom-packages")
mount -t proc proc "$ROOTFS/proc"
mounted=("$ROOTFS/proc" "${mounted[@]}")
mount -t sysfs sysfs "$ROOTFS/sys"
mounted=("$ROOTFS/sys" "${mounted[@]}")
mount --rbind /dev "$ROOTFS/dev"
mount --make-rslave "$ROOTFS/dev"
mounted=("$ROOTFS/dev" "${mounted[@]}")
mount --rbind /run "$ROOTFS/run"
mount --make-rslave "$ROOTFS/run"
mounted=("$ROOTFS/run" "${mounted[@]}")

cat > "$ROOTFS/tmp/hancom-arm64-build/install.sh" <<'CHROOT'
#!/bin/bash
set -Eeuo pipefail
export HOME=/root
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

[ "$(dpkg --print-architecture)" = arm64 ]
apt-get update
mapfile -t specs < /tmp/hancom-arm64-build/install-specs.txt
[ "${#specs[@]}" -gt 0 ]

# One solver transaction sees the full exact package set. Explicit versions
# prevent a newer snapshot package from silently replacing the AMD64 reference
# version. The local flat repository is trusted only because every file was
# already size/SHA-256/control-field verified by the materializer.
apt-get install -y \
  --allow-downgrades \
  --allow-change-held-packages \
  --no-install-recommends \
  -o Debug::pkgProblemResolver=yes \
  -o Dpkg::Options::=--force-confold \
  "${specs[@]}"

dpkg --configure -a
dpkg --audit

if command -v update-initramfs >/dev/null; then
  update-initramfs -u -k all
fi
if command -v ldconfig >/dev/null; then
  ldconfig
fi
if command -v update-ca-certificates >/dev/null; then
  update-ca-certificates
fi

dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  | sort > /tmp/hancom-arm64-build/installed-packages.tsv
apt-cache policy > /tmp/hancom-arm64-build/apt-policy.txt
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
CHROOT
chmod +x "$ROOTFS/tmp/hancom-arm64-build/install.sh"

set +e
chroot "$ROOTFS" /bin/bash /tmp/hancom-arm64-build/install.sh \
  > >(tee "$OUTPUT_DIR/package-install.log") \
  2> >(tee "$OUTPUT_DIR/package-install.stderr.log" >&2)
install_rc=$?
set -e
cp "$ROOTFS/tmp/hancom-arm64-build/installed-packages.tsv" \
  "$OUTPUT_DIR/installed-packages.tsv" 2>/dev/null || true
cp "$ROOTFS/tmp/hancom-arm64-build/apt-policy.txt" \
  "$OUTPUT_DIR/apt-policy.txt" 2>/dev/null || true
if [ "$install_rc" -ne 0 ]; then
  echo "exact package transaction failed with exit code $install_rc" >&2
  exit "$install_rc"
fi

rm -f "$ROOTFS/usr/sbin/policy-rc.d"
rm -f "$ROOTFS/etc/machine-id"
: > "$ROOTFS/etc/machine-id"
rm -f "$ROOTFS/var/lib/dbus/machine-id"
ln -s /etc/machine-id "$ROOTFS/var/lib/dbus/machine-id"
rm -f "$ROOTFS/etc/ssh/ssh_host_"* 2>/dev/null || true
rm -rf "$ROOTFS/tmp/hancom-arm64-build"
rm -f "$ROOTFS/etc/apt/apt.conf.d/99hancom-arm64-build"
rm -f "$ROOTFS/etc/apt/preferences.d/99hancom-local-exact"

cleanup
mounted=()
trap - EXIT

cat > "$OUTPUT_DIR/rootfs-build.json" <<EOF
{
  "schema": 1,
  "policy": "dated-minbase-plus-one-explicit-version-transaction",
  "architecture": "arm64",
  "debian_snapshot": $(jq -Rn --arg v "$SNAPSHOT" '$v'),
  "materialization_sha256": $(sha256sum "$MATERIALIZATION_JSON" | awk '{print "\""$1"\""}'),
  "local_packages_sha256": $(sha256sum "$PACKAGE_REPOSITORY/Packages" | awk '{print "\""$1"\""}')
}
EOF
cat "$OUTPUT_DIR/rootfs-build.json"
