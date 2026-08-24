#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 EFFECTIVE_LOCK_JSON SOURCE OUTPUT_DIR" >&2
  exit 64
}
[ "$#" -eq 3 ] || usage

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="$1"
SOURCE="$2"
OUTPUT="$3"
REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-$SCRIPT_DIR/../locks/reference/amd64-reference.json}"
FILTERED_LOCK="$(mktemp)"
trap 'rm -f "$FILTERED_LOCK"' EXIT

[ -f "$REFERENCE_JSON" ] || {
  echo "AMD64 reference lock not found: $REFERENCE_JSON" >&2
  exit 1
}

python3 "$SCRIPT_DIR/filter_arm64_binary_lock.py" \
  "$LOCK" "$SOURCE" "$FILTERED_LOCK" \
  --reference "$REFERENCE_JSON"

"$SCRIPT_DIR/verify_locked_arm64_build.sh" \
  "$FILTERED_LOCK" "$SOURCE" "$OUTPUT"

# Independently reconstruct the package-to-architecture mapping from the
# immutable AMD64 ISO reference lock. Prove that the filter changed only the
# selected source row's build-expectation fields and omitted only exact
# Architecture: all packages.
python3 - "$LOCK" "$FILTERED_LOCK" "$SOURCE" "$REFERENCE_JSON" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

full_path = Path(sys.argv[1])
filtered_path = Path(sys.argv[2])
source = sys.argv[3]
reference_path = Path(sys.argv[4])

full = json.loads(full_path.read_text(encoding="utf-8"))
filtered = json.loads(filtered_path.read_text(encoding="utf-8"))
reference_bytes = reference_path.read_bytes()
reference = json.loads(reference_bytes.decode("utf-8"))
reference_sha256 = hashlib.sha256(reference_bytes).hexdigest()


def rows_with_key(document):
    for key in ("sources", "packages", "entries"):
        value = document.get(key)
        if isinstance(value, list) and all(isinstance(item, dict) for item in value):
            return key, value
    raise SystemExit("source rows absent")


def require_string_list(value, label, allow_empty=False):
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise SystemExit(f"{label}: expected non-empty strings")
    if not allow_empty and not value:
        raise SystemExit(f"{label}: list is empty")
    return list(value)


full_key, full_rows = rows_with_key(full)
filtered_key, filtered_rows = rows_with_key(filtered)
if full_key != filtered_key:
    raise SystemExit(f"{source}: source-row container changed")
if len(full_rows) != len(filtered_rows):
    raise SystemExit(f"{source}: source-row count changed")

mutable_fields = {
    "binary_packages",
    "binary_architectures",
    "native_arm64_build_filter",
}
selected_before = None
selected_after = None
selected_count = 0

for index, (before_row, after_row) in enumerate(zip(full_rows, filtered_rows)):
    if before_row.get("source") != after_row.get("source"):
        raise SystemExit(f"{source}: source-row order/identity changed at index {index}")
    if before_row.get("source") != source:
        if before_row != after_row:
            raise SystemExit(
                f"{source}: unrelated source row changed: {before_row.get('source')}"
            )
        continue

    selected_count += 1
    selected_before = before_row
    selected_after = after_row
    immutable_before = {
        key: value for key, value in before_row.items() if key not in mutable_fields
    }
    immutable_after = {
        key: value for key, value in after_row.items() if key not in mutable_fields
    }
    if immutable_before != immutable_after:
        changed = sorted(
            key
            for key in set(immutable_before) | set(immutable_after)
            if immutable_before.get(key) != immutable_after.get(key)
        )
        raise SystemExit(f"{source}: immutable lock fields changed: {changed}")

if selected_count != 1 or selected_before is None or selected_after is None:
    raise SystemExit(f"{source}: expected exactly one source row, found {selected_count}")

# Prove that no top-level lock metadata changed outside the source-row list.
full_top = {key: value for key, value in full.items() if key != full_key}
filtered_top = {key: value for key, value in filtered.items() if key != filtered_key}
if full_top != filtered_top:
    changed = sorted(
        key
        for key in set(full_top) | set(filtered_top)
        if full_top.get(key) != filtered_top.get(key)
    )
    raise SystemExit(f"{source}: top-level lock metadata changed: {changed}")

source_version = selected_before.get("source_version")
if not isinstance(source_version, str) or not source_version:
    raise SystemExit(f"{source}: source_version is absent")

packages = require_string_list(
    selected_before.get("binary_packages"), f"{source}: binary_packages"
)
if len(packages) != len(set(packages)):
    raise SystemExit(f"{source}: binary_packages contains duplicates")
input_architectures = require_string_list(
    selected_before.get("binary_architectures"),
    f"{source}: binary_architectures",
)
if len(input_architectures) != len(set(input_architectures)):
    raise SystemExit(f"{source}: binary_architectures is not a source-level set")

reference_rows = reference.get("packages")
if not isinstance(reference_rows, list) or not all(
    isinstance(item, dict) for item in reference_rows
):
    raise SystemExit("AMD64 reference lock package rows absent")

resolved = []
for package in packages:
    matches = [
        item
        for item in reference_rows
        if item.get("source") == source
        and item.get("source_version") == source_version
        and item.get("package") == package
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"{source}: expected exactly one AMD64 reference row for {package}, "
            f"found {len(matches)}"
        )
    architecture = matches[0].get("architecture")
    if not isinstance(architecture, str) or not architecture:
        raise SystemExit(f"{source}: reference architecture absent for {package}")
    resolved.append({"package": package, "architecture": architecture})

reference_architectures = list(
    dict.fromkeys(item["architecture"] for item in resolved)
)
if set(input_architectures) != set(reference_architectures):
    raise SystemExit(
        f"{source}: architecture summary contradicts AMD64 reference rows"
    )

kept = [item for item in resolved if item["architecture"] != "all"]
omitted = [item for item in resolved if item["architecture"] == "all"]
if not kept:
    raise SystemExit(f"{source}: native ARM64 -B expectation became empty")

expected_packages = [item["package"] for item in kept]
actual_packages = require_string_list(
    selected_after.get("binary_packages"),
    f"{source}: filtered binary_packages",
)
if actual_packages != expected_packages:
    raise SystemExit(
        f"{source}: filtered package set differs from exact expectation: "
        f"expected={expected_packages!r} actual={actual_packages!r}"
    )

kept_architecture_set = {item["architecture"] for item in kept}
expected_architectures = [
    architecture
    for architecture in input_architectures
    if architecture in kept_architecture_set
]
actual_architectures = require_string_list(
    selected_after.get("binary_architectures"),
    f"{source}: filtered binary_architectures",
)
if actual_architectures != expected_architectures:
    raise SystemExit(
        f"{source}: filtered architecture summary differs from exact expectation"
    )

expected_metadata = {
    "policy": "dpkg-buildpackage--build=any",
    "architecture_resolution": "amd64-reference-lock",
    "reference_lock_sha256": reference_sha256,
    "input_binary_architectures": input_architectures,
    "kept_architecture_dependent": kept,
    "omitted_architecture_all": omitted,
}
if selected_after.get("native_arm64_build_filter") != expected_metadata:
    raise SystemExit(f"{source}: native ARM64 filter evidence is incomplete or altered")

print(
    json.dumps(
        {
            "source": source,
            "source_version": source_version,
            "architecture_dependent_rebuilt": kept,
            "architecture_all_not_rebuilt": omitted,
            "reference_lock_sha256": reference_sha256,
            "immutable_lock_fields_preserved": True,
        },
        sort_keys=True,
    )
)
PY
