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

# Adapt the one stale source-component transformation in the historical
# wrapper to the current base builder. The legacy manifest transformation is
# already the exact adapter required by the current build-lock schema, so it is
# validated and retained rather than being replaced a second time.
python3 - "$LEGACY_WRAPPER" "$PATCHED_WRAPPER" <<'PY'
from pathlib import Path
import sys

source_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
text = source_path.read_text(encoding="utf-8")


def replace_asserted_block(
    value: str,
    *,
    start_marker: str,
    end_marker: str,
    required: tuple[str, ...],
    replacement: str,
    label: str,
) -> str:
    start = value.find(start_marker)
    if start < 0:
        raise SystemExit(f"{label} start was not found")
    end = value.find(end_marker, start)
    if end < 0:
        raise SystemExit(f"{label} end was not found")
    end += len(end_marker)
    block = value[start:end]
    missing = [token for token in required if token not in block]
    if missing:
        raise SystemExit(
            f"refusing to patch an unrecognized {label}; missing: "
            + ", ".join(missing)
        )
    if value.find(start_marker, end) >= 0:
        raise SystemExit(f"more than one {label} was found")
    return value[:start] + replacement + value[end:]


# The old wrapper inserted all source-component variables by replacing a
# fallback EXPECTED_PACKAGES assignment. The current builder reaches that line
# only when no reference manifest is present, leaving the variables unbound in
# normal exact-reference builds. Insert the component setup after the selected
# Git tree instead, where every required source-lock field and WORK_DIR exists.
component_replacement = r"""component_anchor = '''TREE_SHA="$(jq -r '.selected.tree_sha // empty' <<<"$entry")"
'''
component_setup = component_anchor + '''COMPONENT_LOCK_DIR="${HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR:-}"
COMPOSITE_HELPER="${HANCOM_GOOROOM_COMPOSITE_SOURCE_HELPER:-}"
SOURCE_COMPONENT_LOCK=""
SOURCE_COMPONENT_LOCK_PRESENT=false
SOURCE_COMPONENT_LOCK_SHA256=""
SOURCE_COMPONENT_LOCK_MOUNT="$WORK_DIR/source-component-lock.json"
printf '{}\\n' > "$SOURCE_COMPONENT_LOCK_MOUNT"

[ -f "$COMPOSITE_HELPER" ] || {
  echo "composite source helper not found: $COMPOSITE_HELPER" >&2
  exit 2
}
if [ -n "$COMPONENT_LOCK_DIR" ] && [ -f "$COMPONENT_LOCK_DIR/$SOURCE_NAME.json" ]; then
  SOURCE_COMPONENT_LOCK="$(readlink -f "$COMPONENT_LOCK_DIR/$SOURCE_NAME.json")"
  jq -e \\
    --arg source "$SOURCE_NAME" \\
    --arg version "$SOURCE_VERSION" \\
    --arg repository "$REPOSITORY" \\
    --arg commit "$COMMIT_SHA" \\
    --arg tree "$TREE_SHA" \\
    --arg snapshot "$SNAPSHOT" '
      .source == $source
      and .source_version == $version
      and .packaging.repository_full_name == $repository
      and .packaging.commit_sha == $commit
      and .packaging.tree_sha == $tree
      and .upstream.snapshot == $snapshot
      and .composition.extract == "upstream.files.orig only"
    ' "$SOURCE_COMPONENT_LOCK" >/dev/null
  cp "$SOURCE_COMPONENT_LOCK" "$SOURCE_COMPONENT_LOCK_MOUNT"
  SOURCE_COMPONENT_LOCK_PRESENT=true
  SOURCE_COMPONENT_LOCK_SHA256="$(sha256sum "$SOURCE_COMPONENT_LOCK" | awk '{print $1}')"
fi
'''
if source.count(component_anchor) != 1:
    raise SystemExit(
        f"expected exactly one selected-tree anchor, found {source.count(component_anchor)}"
    )
source = source.replace(component_anchor, component_setup)
"""
text = replace_asserted_block(
    text,
    start_marker="old_expected = '''",
    end_marker="source = source.replace(old_expected, new_expected)\n",
    required=(
        "SOURCE_COMPONENT_LOCK_PRESENT=false",
        ".architecture != \"all\"",
        ".composition.extract",
    ),
    replacement=component_replacement,
    label="stale expected-package/source-component patch block",
)

# The current base builder still emits the inline jq expression in
# expected_binary_packages. The checked-in legacy wrapper correctly replaces
# that field with EXPECTED_PACKAGES_JSON and appends the policy/composition
# evidence after defining both values. Validate this adapter fail-closed and
# leave it in place.
manifest_start = "old_manifest_field = '''"
manifest_end = "source = source.replace(old_manifest_field, new_manifest_field)\n"
start = text.find(manifest_start)
if start < 0:
    raise SystemExit("current build-lock manifest adapter start was not found")
end = text.find(manifest_end, start)
if end < 0:
    raise SystemExit("current build-lock manifest adapter end was not found")
end += len(manifest_end)
manifest_block = text[start:end]
required_manifest_tokens = (
    '"expected_binary_packages": $(jq -c',
    '"expected_binary_packages": $EXPECTED_PACKAGES_JSON',
    '"binary_package_policy"',
    '"source_composition"',
)
missing = [token for token in required_manifest_tokens if token not in manifest_block]
if missing:
    raise SystemExit(
        "refusing an unrecognized current build-lock manifest adapter; missing: "
        + ", ".join(missing)
    )
if text.find(manifest_start, end) >= 0:
    raise SystemExit("more than one current build-lock manifest adapter was found")

output_path.write_text(text, encoding="utf-8")
PY

chmod +x "$PATCHED_WRAPPER"
exec "$PATCHED_WRAPPER" "$@"
