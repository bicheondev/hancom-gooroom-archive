#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 EFFECTIVE_SOURCE_LOCK_JSON SOURCE OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEGACY_WRAPPER="$SCRIPT_DIR/run_locked_source_arm64.sh"

[ -f "$LEGACY_WRAPPER" ] || {
  echo "legacy locked-source wrapper not found: $LEGACY_WRAPPER" >&2
  exit 69
}

# Keep the generated wrapper beside the canonical scripts because the wrapper
# resolves its helpers relative to BASH_SOURCE[0]. A generic /tmp file would
# incorrectly look for build_locked_source_arm64.sh under /tmp.
PATCHED_WRAPPER="$(mktemp "$SCRIPT_DIR/.run_locked_source_arm64_v4.XXXXXX")"
trap 'rm -f "$PATCHED_WRAPPER"' EXIT

# The canonical wrapper was written against the original build-lock field,
# while build_locked_source_arm64.sh now emits EXPECTED_PACKAGES_JSON itself.
# Rewrite only that asserted patch block, preserving every other historical,
# source-composition, and package-specific compatibility transformation.
python3 - "$LEGACY_WRAPPER" "$PATCHED_WRAPPER" <<'PY'
from pathlib import Path
import sys

source_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
text = source_path.read_text(encoding="utf-8")
start_marker = "old_manifest_field = '''"
end_marker = "source = source.replace(old_manifest_field, new_manifest_field)\n"
start = text.find(start_marker)
if start < 0:
    raise SystemExit("stale build-lock patch block start was not found")
end = text.find(end_marker, start)
if end < 0:
    raise SystemExit("stale build-lock patch block end was not found")
end += len(end_marker)
block = text[start:end]
required = (
    "$(jq -c '.binary_packages' <<<\"$entry\")",
    '"binary_package_policy"',
    '"source_composition"',
)
missing = [token for token in required if token not in block]
if missing:
    raise SystemExit(
        "refusing to patch an unrecognized build-lock block; missing: "
        + ", ".join(missing)
    )
if text.find(start_marker, end) >= 0:
    raise SystemExit("more than one stale build-lock patch block was found")

replacement = """manifest_anchor = '''  \"expected_binary_packages\": $EXPECTED_PACKAGES_JSON,
'''
manifest_fields = manifest_anchor + '''  \"binary_package_policy\": \"AMD64 reference packages whose Architecture is not all\",
  \"source_composition\": $SOURCE_COMPOSITION_JSON,
'''
if source.count(manifest_anchor) != 1:
    raise SystemExit(
        f\"expected exactly one current build-lock expected-package field, found {source.count(manifest_anchor)}\"
    )
source = source.replace(manifest_anchor, manifest_fields)
"""
output_path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
PY

chmod +x "$PATCHED_WRAPPER"
exec "$PATCHED_WRAPPER" "$@"
