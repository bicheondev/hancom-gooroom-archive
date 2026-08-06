#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 EFFECTIVE_SOURCE_LOCK_JSON SOURCE OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BASE_RUNNER="$SCRIPT_DIR/run_locked_source_arm64.sh"
VALIDATOR="$SCRIPT_DIR/validate_arm64_source_outputs_v3.py"
REFERENCE="$REPO_ROOT/arm64/locks/reference/amd64-reference.json"
LOCK_JSON="$1"
SOURCE_NAME="$2"
OUTPUT_DIR="$3"

for path in "$BASE_RUNNER" "$VALIDATOR" "$REFERENCE" "$LOCK_JSON"; do
  [ -f "$path" ] || {
    echo "required input is missing: $path" >&2
    exit 69
  }
done

mkdir -p "$(dirname "$OUTPUT_DIR")"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

set +e
"$BASE_RUNNER" "$LOCK_JSON" "$SOURCE_NAME" "$OUTPUT_DIR" 2>&1 | tee "$LOG"
legacy_rc="${PIPESTATUS[0]}"
set -e

mkdir -p "$OUTPUT_DIR" 2>/dev/null || true
if ! cp "$LOG" "$OUTPUT_DIR/legacy-run.log" 2>/dev/null; then
  if command -v sudo >/dev/null 2>&1; then
    sudo cp "$LOG" "$OUTPUT_DIR/legacy-run.log"
    sudo chown "$(id -u):$(id -g)" "$OUTPUT_DIR/legacy-run.log"
  else
    echo "cannot preserve legacy runner log in $OUTPUT_DIR" >&2
    exit 73
  fi
fi
printf '%s\n' "$legacy_rc" > "$OUTPUT_DIR/legacy-run.exit-code"

validator_args=(
  --lock "$LOCK_JSON"
  --reference "$REFERENCE"
  --source "$SOURCE_NAME"
  --output-dir "$OUTPUT_DIR"
)

case "$legacy_rc" in
  0)
    "$VALIDATOR" "${validator_args[@]}"
    ;;
  6)
    # The historical runner used exit 6 when any binary listed by the AMD64
    # source inventory was absent. A -B build correctly omits Architecture: all
    # binaries, so accept this one legacy code only after the exact reference
    # validator proves that every omitted package is an arch-all reuse input
    # and every native package exists at the exact locked version.
    "$VALIDATOR" "${validator_args[@]}" \
      --legacy-log "$OUTPUT_DIR/legacy-run.log"
    python3 - "$OUTPUT_DIR" "$SOURCE_NAME" "$legacy_rc" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import json
import sys

output = Path(sys.argv[1])
source = sys.argv[2]
legacy_rc = int(sys.argv[3])
result = {
    "schema": "hancom-gooroom-arm64-legacy-runner-acceptance-v3",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "source": source,
    "legacy_exit_code": legacy_rc,
    "status": "accepted-after-exact-reference-validation",
    "reason": (
        "the legacy runner required one or more Architecture: all binaries "
        "from a dpkg-buildpackage -B native build"
    ),
}
(output / "legacy-runner-acceptance-v3.json").write_text(
    json.dumps(result, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
PY
    ;;
  *)
    echo "locked ARM64 source runner failed with exit code $legacy_rc" >&2
    exit "$legacy_rc"
    ;;
esac
