#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 FINAL_REPOSITORY FINAL_AUTHORITY ROOTFS OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 4 ] || usage
FINAL_REPOSITORY="$1"
FINAL_AUTHORITY="$2"
ROOTFS="$3"
OUTPUT_DIR="$4"
SNAPSHOT_BASE="${HANCOM_GOOROOM_SNAPSHOT_BASE:-20230730T235959Z}"
SNAPSHOT_UPDATES="${HANCOM_GOOROOM_SNAPSHOT_UPDATES:-20240331T235959Z}"

[ "$(id -u)" -eq 0 ] || {
  echo "root privileges are required" >&2
  exit 77
}
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "native ARM64 host required, got $(uname -m)" >&2; exit 78 ;;
esac
for value in "$SNAPSHOT_BASE" "$SNAPSHOT_UPDATES"; do
  [[ "$value" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
    echo "invalid snapshot: $value" >&2
    exit 64
  }
done
for command in debootstrap chroot mount umount jq python3 dpkg-query sha256sum; do
  command -v "$command" >/dev/null || {
    echo "required command missing: $command" >&2
    exit 69
  }
done
[ -f "$FINAL_REPOSITORY/Packages" ]
[ -f "$FINAL_REPOSITORY/Release" ]
[ -f "$FINAL_AUTHORITY" ]
jq -e '.summary.final_repository_ready == true and .summary.blocker_count == 0' \
  "$FINAL_AUTHORITY" >/dev/null

FINAL_REPOSITORY="$(cd "$FINAL_REPOSITORY" && pwd)"
FINAL_AUTHORITY="$(cd "$(dirname "$FINAL_AUTHORITY")" && pwd)/$(basename "$FINAL_AUTHORITY")"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS" "$OUTPUT_DIR"
ROOTFS="$(cd "$ROOTFS" && pwd)"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

python3 - "$FINAL_AUTHORITY" "$OUTPUT_DIR/target-packages.json" "$OUTPUT_DIR/install-specs.txt" <<'PY'
import json, sys
from pathlib import Path

authority=json.loads(Path(sys.argv[1]).read_text())
packages={}
for route in authority.get('selected_routes',[]):
    package=route['target_package']; version=route['target_version']; architecture=route['target_architecture']
    if architecture not in {'arm64','all'}:
        raise SystemExit(f'invalid target architecture: {route}')
    identity=(version,architecture)
    if package in packages and packages[package]['identity'] != identity:
        raise SystemExit(f'conflicting target identities for {package}')
    packages.setdefault(package,{
        'identity':identity,
        'package':package,
        'version':version,
        'architecture':architecture,
        'routes':[],
    })['routes'].append(route)
rows=[{k:v for k,v in row.items() if k != 'identity'} for _,row in sorted(packages.items())]
Path(sys.argv[2]).write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n')
Path(sys.argv[3]).write_text(''.join(f"{row['package']}={row['version']}\n" for row in rows))
print(json.dumps({'target_package_count':len(rows)},indent=2))
PY
test -s "$OUTPUT_DIR/install-specs.txt"
cp "$FINAL_AUTHORITY" "$OUTPUT_DIR/final-package-authority.json"
sha256sum "$FINAL_AUTHORITY" "$FINAL_REPOSITORY/Packages" "$FINAL_REPOSITORY/Release" \
  > "$OUTPUT_DIR/input-locks.sha256"
printf '%s\n' "$SNAPSHOT_BASE" "$SNAPSHOT_UPDATES" \
  > "$OUTPUT_DIR/debian-snapshots.txt"

# Bootstrap is only a transport base. The following explicit-version
# transaction replaces its package set with the final package authority.
debootstrap \
  --arch=arm64 \
  --variant=minbase \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  --include=ca-certificates,debian-archive-keyring \
  bullseye "$ROOTFS" \
  "https://snapshot.debian.org/archive/debian/${SNAPSHOT_BASE}/" \
  2>&1 | tee "$OUTPUT_DIR/debootstrap.log"

mkdir -p \
  "$ROOTFS/mnt/final-repository" \
  "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" "$ROOTFS/run" \
  "$ROOTFS/tmp/hancom-gooroom-arm64-build"
cp "$OUTPUT_DIR/install-specs.txt" \
  "$ROOTFS/tmp/hancom-gooroom-arm64-build/install-specs.txt"
cp "$OUTPUT_DIR/target-packages.json" \
  "$ROOTFS/tmp/hancom-gooroom-arm64-build/target-packages.json"
cp -L /etc/resolv.conf "$ROOTFS/etc/resolv.conf"

cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb [trusted=yes] file:/mnt/final-repository ./
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT_BASE}/ bullseye main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT_BASE}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT_BASE}/ bullseye-security main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT_UPDATES}/ bullseye main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT_UPDATES}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT_UPDATES}/ bullseye-security main contrib non-free
EOF
rm -f "$ROOTFS/etc/apt/sources.list.d/"*
cat > "$ROOTFS/etc/apt/apt.conf.d/99hancom-gooroom-arm64-build" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "10";
Acquire::https::Timeout "45";
Acquire::http::Timeout "45";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
cat > "$ROOTFS/usr/sbin/policy-rc.d" <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 0755 "$ROOTFS/usr/sbin/policy-rc.d"

mounted=()
cleanup() {
  set +e
  for target in "${mounted[@]}"; do
    umount -R "$target" 2>/dev/null || umount -l "$target" 2>/dev/null || true
  done
}
trap cleanup EXIT
mount --bind "$FINAL_REPOSITORY" "$ROOTFS/mnt/final-repository"
mounted=("$ROOTFS/mnt/final-repository")
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

cat > "$ROOTFS/tmp/hancom-gooroom-arm64-build/install.sh" <<'CHROOT'
#!/usr/bin/env bash
set -Eeuo pipefail
export HOME=/root
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

[ "$(dpkg --print-architecture)" = arm64 ]
apt-get update
mapfile -t specs < /tmp/hancom-gooroom-arm64-build/install-specs.txt
[ "${#specs[@]}" -gt 0 ]

set +e
apt-get -s \
  --allow-downgrades \
  --allow-change-held-packages \
  --no-install-recommends \
  -o Debug::pkgProblemResolver=yes \
  install "${specs[@]}" \
  > /tmp/hancom-gooroom-arm64-build/apt-solver-simulation.log 2>&1
solver_rc=$?
set -e
cat /tmp/hancom-gooroom-arm64-build/apt-solver-simulation.log
[ "$solver_rc" -eq 0 ]

apt-get install -y \
  --allow-downgrades \
  --allow-change-held-packages \
  --no-install-recommends \
  -o Debug::pkgProblemResolver=yes \
  -o Dpkg::Options::=--force-confold \
  "${specs[@]}"
dpkg --configure -a
dpkg --audit

if command -v ldconfig >/dev/null; then ldconfig; fi
if command -v update-ca-certificates >/dev/null; then update-ca-certificates; fi
if command -v update-initramfs >/dev/null; then update-initramfs -u -k all; fi

dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  | sort > /tmp/hancom-gooroom-arm64-build/installed-packages.tsv
cp /var/log/apt/history.log \
  /tmp/hancom-gooroom-arm64-build/apt-history.log 2>/dev/null || true
cp /var/log/apt/term.log \
  /tmp/hancom-gooroom-arm64-build/apt-term.log 2>/dev/null || true
apt-cache policy > /tmp/hancom-gooroom-arm64-build/apt-policy.txt
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
CHROOT
chmod 0755 "$ROOTFS/tmp/hancom-gooroom-arm64-build/install.sh"

set +e
chroot "$ROOTFS" /bin/bash /tmp/hancom-gooroom-arm64-build/install.sh \
  > >(tee "$OUTPUT_DIR/package-install.log") \
  2> >(tee "$OUTPUT_DIR/package-install.stderr.log" >&2)
install_rc=$?
set -e
for name in \
  apt-solver-simulation.log installed-packages.tsv apt-history.log apt-term.log apt-policy.txt; do
  cp "$ROOTFS/tmp/hancom-gooroom-arm64-build/$name" "$OUTPUT_DIR/" 2>/dev/null || true
done
if [ "$install_rc" -ne 0 ]; then
  echo "final exact package transaction failed: $install_rc" >&2
  exit "$install_rc"
fi

rm -f "$ROOTFS/usr/sbin/policy-rc.d"
rm -rf "$ROOTFS/tmp/hancom-gooroom-arm64-build"
rm -f "$ROOTFS/etc/apt/apt.conf.d/99hancom-gooroom-arm64-build"
rm -f "$ROOTFS/etc/machine-id"
: > "$ROOTFS/etc/machine-id"
rm -f "$ROOTFS/var/lib/dbus/machine-id"
ln -s /etc/machine-id "$ROOTFS/var/lib/dbus/machine-id"
rm -f "$ROOTFS/etc/ssh/ssh_host_"* 2>/dev/null || true
rm -f "$ROOTFS/var/lib/systemd/random-seed"

cleanup
mounted=()
trap - EXIT

cat > "$OUTPUT_DIR/rootfs-build.json" <<EOF
{
  "schema": 2,
  "policy": "native-arm64-dated-minbase-plus-final-explicit-version-transaction",
  "architecture": "arm64",
  "snapshot_base": $(jq -Rn --arg v "$SNAPSHOT_BASE" '$v'),
  "snapshot_updates": $(jq -Rn --arg v "$SNAPSHOT_UPDATES" '$v'),
  "target_package_count": $(wc -l < "$OUTPUT_DIR/install-specs.txt"),
  "final_authority_sha256": $(sha256sum "$FINAL_AUTHORITY" | awk '{print "\""$1"\""}'),
  "repository_packages_sha256": $(sha256sum "$FINAL_REPOSITORY/Packages" | awk '{print "\""$1"\""}'),
  "repository_release_sha256": $(sha256sum "$FINAL_REPOSITORY/Release" | awk '{print "\""$1"\""}')
}
EOF
cat "$OUTPUT_DIR/rootfs-build.json"
