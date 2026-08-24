#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 ROOTFS OUTPUT_JSON" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
ROOTFS="$1"
OUTPUT_JSON="$2"

[ "$(id -u)" -eq 0 ] || {
  echo "root privileges are required" >&2
  exit 77
}
ROOTFS="$(cd "$ROOTFS" && pwd)"
mkdir -p "$(dirname "$OUTPUT_JSON")"
OUTPUT_JSON="$(cd "$(dirname "$OUTPUT_JSON")" && pwd)/$(basename "$OUTPUT_JSON")"

for path in \
  usr/local/sbin \
  etc/systemd/system/graphical.target.wants \
  usr/share/doc/hancom-gooroom-arm64; do
  mkdir -p "$ROOTFS/$path"
done

count_desktop_sessions() {
  local root="$1"
  local total=0
  local directory count
  for directory in \
    "$root/usr/share/xsessions" \
    "$root/usr/share/wayland-sessions"; do
    [ -d "$directory" ] || continue
    count="$(find "$directory" -maxdepth 1 -type f -name '*.desktop' -printf '.\n' | wc -l)"
    total=$((total + count))
  done
  printf '%s\n' "$total"
}

session_count="$(count_desktop_sessions "$ROOTFS")"
if [ "$session_count" -eq 0 ]; then
  echo 'No X11 or Wayland desktop session file exists in the final rootfs.' >&2
  exit 3
fi

if [ -x "$ROOTFS/usr/sbin/locale-gen" ]; then
  if [ -f "$ROOTFS/etc/locale.gen" ]; then
    sed -i -E 's/^# *ko_KR\.UTF-8 UTF-8/ko_KR.UTF-8 UTF-8/' "$ROOTFS/etc/locale.gen"
    if ! grep -Eq '^ko_KR\.UTF-8 UTF-8' "$ROOTFS/etc/locale.gen"; then
      printf 'ko_KR.UTF-8 UTF-8\n' >> "$ROOTFS/etc/locale.gen"
    fi
  else
    printf 'ko_KR.UTF-8 UTF-8\n' > "$ROOTFS/etc/locale.gen"
  fi
  chroot "$ROOTFS" /usr/sbin/locale-gen ko_KR.UTF-8
else
  echo 'locale-gen is not installed in the final rootfs.' >&2
  exit 3
fi
cat > "$ROOTFS/etc/default/locale" <<'EOF'
LANG=ko_KR.UTF-8
LANGUAGE=ko_KR:ko:en_US:en
LC_MESSAGES=ko_KR.UTF-8
EOF

find_display_manager_unit() {
  local link="$ROOTFS/etc/systemd/system/display-manager.service"
  if [ -L "$link" ]; then
    basename "$(readlink "$link")"
    return 0
  fi
  local unit
  for unit in gdm3.service gdm.service lightdm.service sddm.service; do
    if [ -f "$ROOTFS/lib/systemd/system/$unit" ] \
       || [ -f "$ROOTFS/usr/lib/systemd/system/$unit" ]; then
      printf '%s\n' "$unit"
      return 0
    fi
  done
  return 1
}

DISPLAY_MANAGER_UNIT="$(find_display_manager_unit)" || {
  echo 'No supported display-manager systemd unit exists in the final rootfs.' >&2
  exit 3
}
chroot "$ROOTFS" systemctl enable "$DISPLAY_MANAGER_UNIT"

unit_path=""
for candidate in \
  "/lib/systemd/system/$DISPLAY_MANAGER_UNIT" \
  "/usr/lib/systemd/system/$DISPLAY_MANAGER_UNIT"; do
  if [ -f "$ROOTFS$candidate" ]; then
    unit_path="$candidate"
    break
  fi
done
test -n "$unit_path"
if [ ! -L "$ROOTFS/etc/systemd/system/display-manager.service" ] \
   || [ "$(basename "$(readlink "$ROOTFS/etc/systemd/system/display-manager.service" 2>/dev/null || true)")" != "$DISPLAY_MANAGER_UNIT" ]; then
  rm -f "$ROOTFS/etc/systemd/system/display-manager.service"
  ln -s "$unit_path" "$ROOTFS/etc/systemd/system/display-manager.service"
fi

cat > "$ROOTFS/usr/local/sbin/hancom-gooroom-arm64-ci-marker" <<'EOF'
#!/bin/bash
set -Eeuo pipefail

final_marker='HANCOM_GOOROOM_3_3_ARM64_BOOT_OK'
display_marker='HANCOM_GOOROOM_3_3_ARM64_DISPLAY_MANAGER_OK'
locale_marker='HANCOM_GOOROOM_3_3_ARM64_KOREAN_LOCALE_OK'
session_marker='HANCOM_GOOROOM_3_3_ARM64_DESKTOP_SESSION_OK'

emit() {
  local value="$1"
  printf '%s\n' "$value" >/dev/console 2>/dev/null || true
  printf '%s\n' "$value" >/dev/ttyAMA0 2>/dev/null || true
  logger -t hancom-gooroom-arm64 "$value" 2>/dev/null || true
}

if ! locale -a 2>/dev/null | tr '[:upper:]' '[:lower:]' \
  | grep -Eq '^ko_kr\.(utf-?8|utf8)$'; then
  emit 'HANCOM_GOOROOM_3_3_ARM64_KOREAN_LOCALE_FAILED'
  exit 10
fi
emit "$locale_marker"

session_count=0
for directory in /usr/share/xsessions /usr/share/wayland-sessions; do
  [ -d "$directory" ] || continue
  count="$(find "$directory" -maxdepth 1 -type f -name '*.desktop' -printf '.\n' | wc -l)"
  session_count=$((session_count + count))
done
if [ "$session_count" -eq 0 ]; then
  emit 'HANCOM_GOOROOM_3_3_ARM64_DESKTOP_SESSION_FAILED'
  exit 11
fi
emit "$session_marker"

manager=''
for unit in display-manager.service gdm3.service gdm.service lightdm.service sddm.service; do
  if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q .; then
    manager="$unit"
    break
  fi
done
[ -n "$manager" ] || {
  emit 'HANCOM_GOOROOM_3_3_ARM64_DISPLAY_MANAGER_UNIT_MISSING'
  exit 12
}

for _ in $(seq 1 120); do
  if systemctl is-active --quiet "$manager"; then
    emit "$display_marker"
    emit "$final_marker"
    exit 0
  fi
  sleep 1
done

systemctl status "$manager" --no-pager >/dev/console 2>&1 || true
systemctl status "$manager" --no-pager >/dev/ttyAMA0 2>&1 || true
emit 'HANCOM_GOOROOM_3_3_ARM64_DISPLAY_MANAGER_FAILED'
exit 13
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/hancom-gooroom-arm64-ci-marker"

cat > "$ROOTFS/etc/systemd/system/hancom-gooroom-arm64-boot-marker.service" <<EOF
[Unit]
Description=Hancom Gooroom ARM64 graphical boot validation marker
ConditionVirtualization=vm
Wants=$DISPLAY_MANAGER_UNIT
After=$DISPLAY_MANAGER_UNIT systemd-user-sessions.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hancom-gooroom-arm64-ci-marker
RemainAfterExit=yes
TimeoutStartSec=150

[Install]
WantedBy=graphical.target
EOF
rm -f \
  "$ROOTFS/etc/systemd/system/multi-user.target.wants/hancom-gooroom-arm64-boot-marker.service"
ln -sfn ../hancom-gooroom-arm64-boot-marker.service \
  "$ROOTFS/etc/systemd/system/graphical.target.wants/hancom-gooroom-arm64-boot-marker.service"
chroot "$ROOTFS" systemctl set-default graphical.target

locale_count="$(chroot "$ROOTFS" locale -a | tr '[:upper:]' '[:lower:]' | grep -Ec '^ko_kr\.(utf-?8|utf8)$')"
test "$locale_count" -gt 0

jq -n \
  --arg display_manager_unit "$DISPLAY_MANAGER_UNIT" \
  --argjson desktop_session_count "$session_count" \
  --argjson korean_locale_count "$locale_count" \
  '{
    schema: 2,
    architecture: "arm64",
    boot_gate: "graphical-display-manager-korean-locale",
    display_manager_unit: $display_manager_unit,
    desktop_session_count: $desktop_session_count,
    korean_locale_count: $korean_locale_count,
    required_markers: [
      "HANCOM_GOOROOM_3_3_ARM64_KOREAN_LOCALE_OK",
      "HANCOM_GOOROOM_3_3_ARM64_DESKTOP_SESSION_OK",
      "HANCOM_GOOROOM_3_3_ARM64_DISPLAY_MANAGER_OK",
      "HANCOM_GOOROOM_3_3_ARM64_BOOT_OK"
    ]
  }' > "$OUTPUT_JSON"
cat "$OUTPUT_JSON"
