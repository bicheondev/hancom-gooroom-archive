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
old = "http://snapshot.debian.org"
count = text.count(old)
if count < 2:
    raise SystemExit(
        f"refusing to patch an unexpected stage-0 builder: "
        f"snapshot URL count={count}"
    )
text = text.replace(old, "https://snapshot.debian.org")
needle = 'Acquire::Retries "5";'
if needle in text:
    text = text.replace(
        needle,
        'Acquire::Retries "10";\n'
        'Acquire::https::Timeout "45";\n'
        'Acquire::http::Timeout "45";',
        1,
    )
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
