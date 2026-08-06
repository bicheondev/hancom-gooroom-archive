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
FILTERED_LOCK="$(mktemp)"
trap 'rm -f "$FILTERED_LOCK"' EXIT

python3 "$SCRIPT_DIR/filter_arm64_binary_lock.py" \
  "$LOCK" "$SOURCE" "$FILTERED_LOCK"

"$SCRIPT_DIR/verify_locked_arm64_build.sh" \
  "$FILTERED_LOCK" "$SOURCE" "$OUTPUT"

# Prove that every omitted expectation was Architecture: all in the immutable
# full lock. No version, source, repository, commit or tree field is changed.
python3 - "$LOCK" "$FILTERED_LOCK" "$SOURCE" <<'PY'
import json
import sys
from pathlib import Path

full = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
filtered = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
source = sys.argv[3]


def rows(document):
    for key in ("sources", "packages", "entries"):
        if isinstance(document.get(key), list):
            return document[key]
    raise SystemExit("source rows absent")


def row(document):
    matches = [item for item in rows(document) if item.get("source") == source]
    if len(matches) != 1:
        raise SystemExit(f"{source}: source-row cardinality changed")
    return matches[0]


before = row(full)
after = row(filtered)
for field in (
    "source", "source_version", "status", "selected", "repository_full_name",
    "commit_sha", "tree_sha", "declared_source", "declared_version",
):
    if field in before and before.get(field) != after.get(field):
        raise SystemExit(f"{source}: immutable lock field changed: {field}")

pairs = list(zip(before.get("binary_packages", []), before.get("binary_architectures", [])))
kept = set(after.get("binary_packages", []))
removed = [(package, arch) for package, arch in pairs if package not in kept]
if any(arch != "all" for _, arch in removed):
    raise SystemExit(f"{source}: an architecture-dependent package was filtered: {removed}")
print(json.dumps({"source": source, "architecture_all_not_rebuilt": removed}))
PY
