#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_SCRIPT="$SCRIPT_DIR/run_dsc_source_arm64.sh"
[ -f "$BASE_SCRIPT" ] || {
  echo "base .dsc builder is missing: $BASE_SCRIPT" >&2
  exit 69
}
PATCHED_SCRIPT="$(mktemp)"
trap 'rm -f "$PATCHED_SCRIPT"' EXIT

python3 - "$BASE_SCRIPT" "$PATCHED_SCRIPT" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
text = source.read_text(encoding='utf-8')

old_bootstrap = '''cat > /etc/apt/sources.list <<EOF
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
cat > /etc/apt/apt.conf.d/99snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "10";
Acquire::https::Timeout "45";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \\
  ca-certificates debootstrap debian-archive-keyring xz-utils
'''
new_bootstrap = '''# Install TLS and debootstrap from the image's signed base repository before
# switching any outer-container APT source to the historical HTTPS snapshot.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \\
  ca-certificates debootstrap debian-archive-keyring xz-utils
cat > /etc/apt/sources.list <<EOF
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
cat > /etc/apt/apt.conf.d/99snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "10";
Acquire::https::Timeout "45";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
'''

old_cleanup = '''copy_partial() {
  set +e
  if [ -d "$ROOT/build/output" ]; then
    cp -a "$ROOT/build/output/." "$HOST_OUT/" 2>/dev/null || true
  fi
}
trap copy_partial EXIT
'''
new_cleanup = '''MOUNTED=false
copy_partial() {
  set +e
  if [ -d "$ROOT/build/output" ]; then
    cp -a "$ROOT/build/output/." "$HOST_OUT/" 2>/dev/null || true
  fi
}
cleanup_inner() {
  set +e
  copy_partial
  if [ "$MOUNTED" = true ]; then
    umount -R "$ROOT/dev" 2>/dev/null || true
    umount "$ROOT/proc" 2>/dev/null || true
    umount "$ROOT/sys" 2>/dev/null || true
    umount -R "$ROOT/run" 2>/dev/null || true
  fi
}
trap cleanup_inner EXIT
'''

old_mount_point = '''mkdir -p "$ROOT/build/input" "$ROOT/build/output"
cp -a "$INPUT/." "$ROOT/build/input/"

cat > "$ROOT/root/build-exact-dsc.sh" <<'CHROOT_BUILD'
'''
new_mount_point = '''mkdir -p "$ROOT/build/input" "$ROOT/build/output"
cp -a "$INPUT/." "$ROOT/build/input/"
mount --rbind /dev "$ROOT/dev"
mount --make-rslave "$ROOT/dev"
mount -t proc proc "$ROOT/proc"
mount -t sysfs sysfs "$ROOT/sys"
mount --rbind /run "$ROOT/run"
mount --make-rslave "$ROOT/run"
MOUNTED=true

cat > "$ROOT/root/build-exact-dsc.sh" <<'CHROOT_BUILD'
'''

for old, new, label in (
    (old_bootstrap, new_bootstrap, 'outer bootstrap'),
    (old_cleanup, new_cleanup, 'cleanup'),
    (old_mount_point, new_mount_point, 'chroot mounts'),
):
    if text.count(old) != 1:
        raise SystemExit(
            f'refusing unexpected .dsc builder revision at {label}: count={text.count(old)}'
        )
    text = text.replace(old, new)

destination.write_text(text, encoding='utf-8')
PY
chmod +x "$PATCHED_SCRIPT"
exec "$PATCHED_SCRIPT" "$@"
