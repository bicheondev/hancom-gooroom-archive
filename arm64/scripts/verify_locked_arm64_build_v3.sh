#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 EFFECTIVE_LOCK_JSON REFERENCE_JSON SOURCE OUTPUT_DIR" >&2
  exit 64
}
[ "$#" -eq 4 ] || usage

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="$1"
REFERENCE="$2"
SOURCE="$3"
OUTPUT="$4"
FILTERED_LOCK="$(mktemp)"
trap 'rm -f "$FILTERED_LOCK"' EXIT

python3 "$SCRIPT_DIR/filter_arm64_binary_lock_v2.py" \
  "$LOCK" "$REFERENCE" "$SOURCE" "$FILTERED_LOCK"

"$SCRIPT_DIR/verify_locked_arm64_build.sh" \
  "$FILTERED_LOCK" "$SOURCE" "$OUTPUT"

python3 - "$LOCK" "$FILTERED_LOCK" "$REFERENCE" "$SOURCE" <<'PY'
import json
import sys
from pathlib import Path

full = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
filtered = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
reference = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
source = sys.argv[4]


def rows(document):
    for key in ("sources", "packages", "entries"):
        value = document.get(key)
        if isinstance(value, list):
            return value
    raise SystemExit("source rows absent")


def row(document):
    matches = [item for item in rows(document) if item.get("source") == source]
    if len(matches) != 1:
        raise SystemExit(f"{source}: source-row cardinality changed")
    return matches[0]


before = row(full)
after = row(filtered)
for field in (
    "source",
    "source_version",
    "status",
    "selected",
    "repository_full_name",
    "commit_sha",
    "tree_sha",
    "declared_source",
    "declared_version",
):
    if field in before and before.get(field) != after.get(field):
        raise SystemExit(f"{source}: immutable lock field changed: {field}")

before_packages = before.get("binary_packages", [])
before_arches = before.get("binary_architectures", [])
after_packages = set(after.get("binary_packages", []))
if len(before_packages) != len(before_arches):
    raise SystemExit(f"{source}: malformed full source-lock package metadata")
removed = [
    (package, architecture)
    for package, architecture in zip(before_packages, before_arches)
    if package not in after_packages
]
if any(architecture != "all" for _, architecture in removed):
    raise SystemExit(f"{source}: an architecture-dependent package was filtered: {removed}")

inventory_all = {
    item.get("package")
    for item in reference.get("packages", [])
    if item.get("architecture") == "all"
}
missing = sorted(package for package, _ in removed if package not in inventory_all)
if missing:
    raise SystemExit(
        f"{source}: removed packages are not Architecture: all in the reference ISO: {missing}"
    )

print(
    json.dumps(
        {
            "source": source,
            "architecture_all_not_rebuilt": removed,
            "reference_iso_sha256": reference.get("reference_iso", {}).get("sha256"),
        }
    )
)
PY
