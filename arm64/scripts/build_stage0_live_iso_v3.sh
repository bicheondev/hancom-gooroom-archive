#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 REFERENCE_JSON VENDOR_LOCK_JSON VENDOR_DEB_DIR OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 4 ] || usage
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_SCRIPT="$SCRIPT_DIR/build_stage0_live_iso.sh"
REFERENCE_JSON="$1"
VENDOR_LOCK_JSON="$2"
VENDOR_DEB_DIR="$3"
OUTPUT_DIR="$4"

[ -f "$BASE_SCRIPT" ] || {
  echo "base stage-0 builder is missing: $BASE_SCRIPT" >&2
  exit 69
}
[ "${EUID:-$(id -u)}" -eq 0 ] || {
  echo "stage-0 v3 wrapper must run as root" >&2
  exit 77
}

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(readlink -f "$OUTPUT_DIR")"
PATCHED_SCRIPT="$(mktemp)"
trap 'rm -f "$PATCHED_SCRIPT"' EXIT

python3 - "$BASE_SCRIPT" "$PATCHED_SCRIPT" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
text = source.read_text(encoding="utf-8")

snapshot_url = "http://snapshot.debian.org"
snapshot_count = text.count(snapshot_url)
if snapshot_count < 2:
    raise SystemExit(
        "refusing to patch an unexpected stage-0 builder: "
        f"snapshot URL count={snapshot_count}"
    )
text = text.replace(snapshot_url, "https://snapshot.debian.org")

retry_needle = 'Acquire::Retries "5";'
if text.count(retry_needle) != 1:
    raise SystemExit("unexpected snapshot retry configuration")
text = text.replace(
    retry_needle,
    'Acquire::Retries "10";\n'
    'Acquire::https::Timeout "45";\n'
    'Acquire::http::Timeout "45";',
    1,
)

# arc-icon-theme is absent from the dated Debian ARM64 archive. Its exact
# Architecture: all vendor DEB is already hash/control/ELF checked and is
# applied through OVERLAY_ROOT after the Debian desktop transaction.
apt_vendor_line = (
    "  arc-icon-theme dconf-cli eog evince file-roller fonts-nanum "
    "fonts-noto-cjk \\\n"
)
apt_replacement_line = (
    "  dconf-cli eog evince file-roller fonts-nanum fonts-noto-cjk \\\n"
)
if text.count(apt_vendor_line) != 1:
    raise SystemExit("unexpected arc-icon-theme desktop package line")
text = text.replace(apt_vendor_line, apt_replacement_line, 1)

# Debian Bullseye's debootstrap root is merged-/usr: /bin, /sbin and /lib are
# receiver-side directory symlinks. A plain rsync of an overlay containing a
# physical lib/ directory replaces /lib -> usr/lib, hiding the ARM64 dynamic
# loader and making every dynamically linked program appear absent. Preserve
# those receiver symlinks and gate shell/loader execution on both sides of the
# overlay merge.
overlay_merge = 'rsync -aHAX "$OVERLAY_ROOT/" "$ROOTFS/"'
if text.count(overlay_merge) != 1:
    raise SystemExit("unexpected stage-0 overlay merge command")
overlay_merge_replacement = r'''MERGED_USR_AUDIT="$OUTPUT_DIR/stage0-merged-usr-overlay.tsv"
printf 'phase\tpath\ttype\ttarget\n' > "$MERGED_USR_AUDIT"
verify_merged_usr_overlay_boundary() {
  local phase="$1" merged_path path target
  for merged_path in bin sbin lib; do
    path="$ROOTFS/$merged_path"
    if [ ! -L "$path" ]; then
      printf '%s\t/%s\t%s\t%s\n' \
        "$phase" "$merged_path" "$(stat -c %F "$path" 2>/dev/null || printf missing)" "" \
        >> "$MERGED_USR_AUDIT"
      echo "merged-/usr invariant failed: /$merged_path is not a symlink during $phase" >&2
      return 23
    fi
    target="$(readlink "$path")"
    printf '%s\t/%s\tsymlink\t%s\n' \
      "$phase" "$merged_path" "$target" >> "$MERGED_USR_AUDIT"
    if [ "$target" != "usr/$merged_path" ]; then
      echo "merged-/usr invariant failed: /$merged_path -> $target during $phase" >&2
      return 23
    fi
  done
  if [ ! -x "$ROOTFS/bin/bash" ]; then
    echo "ARM64 bash is not executable during $phase" >&2
    return 23
  fi
  if [ ! -e "$ROOTFS/lib/ld-linux-aarch64.so.1" ]; then
    echo "ARM64 dynamic loader is missing during $phase" >&2
    return 23
  fi
  if ! chroot "$ROOTFS" /bin/bash -c 'exit 0'; then
    echo "ARM64 bash/loader execution gate failed during $phase" >&2
    return 23
  fi
  printf '%s\t/bin/bash\tchroot-executable\tok\n' \
    "$phase" >> "$MERGED_USR_AUDIT"
  printf '%s\t/lib/ld-linux-aarch64.so.1\tloader-visible\tok\n' \
    "$phase" >> "$MERGED_USR_AUDIT"
}

verify_merged_usr_overlay_boundary before-overlay
rsync -aHAX --keep-dirlinks "$OVERLAY_ROOT/" "$ROOTFS/"
verify_merged_usr_overlay_boundary after-overlay
if [ ! -f "$ROOTFS/lib/udev/rules.d/61-gnome-settings-daemon-rfkill.rules" ]; then
  echo "verified vendor /lib payload did not land through merged-/usr" >&2
  exit 23
fi
printf 'after-overlay\t/lib/udev/rules.d/61-gnome-settings-daemon-rfkill.rules\tpayload-visible\tok\n' \
  >> "$MERGED_USR_AUDIT"'''
text = text.replace(overlay_merge, overlay_merge_replacement, 1)

destination.write_text(text, encoding="utf-8")
PY
chmod +x "$PATCHED_SCRIPT"

TRACE_LOG="$OUTPUT_DIR/stage0-v3-trace.log"
TRACE_ERR="$OUTPUT_DIR/stage0-v3-trace.stderr.log"
set +e
bash -x "$PATCHED_SCRIPT" \
  "$REFERENCE_JSON" \
  "$VENDOR_LOCK_JSON" \
  "$VENDOR_DEB_DIR" \
  "$OUTPUT_DIR" \
  > >(tee "$TRACE_LOG") \
  2> >(tee "$TRACE_ERR" >&2)
builder_rc=$?
set -e

python3 - "$OUTPUT_DIR" "$builder_rc" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import json
import re
import sys

output = Path(sys.argv[1])
return_code = int(sys.argv[2])
pattern = re.compile(
    r"(?:^E:|error|failed|failure|unable|missing|not found|"
    r"no installation candidate|unmet depend|cannot|returned an error)",
    re.IGNORECASE,
)
files = []
error_lines = []
tails = []
for path in sorted(output.rglob("*")):
    if not path.is_file():
        continue
    files.append(
        {
            "path": str(path.relative_to(output)),
            "size": path.stat().st_size,
        }
    )
    if path.suffix.lower() not in {".log", ".txt", ".json", ".tsv"}:
        continue
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        continue
    matches = [
        {"line": index + 1, "text": line[:1000]}
        for index, line in enumerate(lines)
        if pattern.search(line)
    ]
    if matches:
        error_lines.append(
            {
                "path": str(path.relative_to(output)),
                "matches": matches[-80:],
            }
        )
    if return_code and lines:
        tails.append(
            {
                "path": str(path.relative_to(output)),
                "lines": [line[:1000] for line in lines[-80:]],
            }
        )

result = {
    "schema": "hancom-gooroom-arm64-stage0-wrapper-v3",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "status": "built" if return_code == 0 else "failed",
    "builder_exit_code": return_code,
    "transport_policy": {
        "snapshot_protocol": "https",
        "check_valid_until": False,
        "archive_signature_verification": "enabled",
        "retries": 10,
    },
    "vendor_overlay_policy": {
        "arc_icon_theme": "verified-architecture-all-overlay",
        "apt_vendor_package_request_removed": True,
        "merged_usr_receiver_symlinks": "preserved-and-gated",
        "rsync_keep_dirlinks": True,
    },
    "output_files": files,
    "diagnostic_matches": error_lines,
    "log_tails": tails[-12:] if return_code else [],
}
(output / "stage0-v3-wrapper-result.json").write_text(
    json.dumps(result, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
print(json.dumps(result, indent=2, ensure_ascii=False))
PY

exit "$builder_rc"
