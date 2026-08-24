#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 LOCK_JSON SOURCE_NAME OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
LOCK_JSON="$1"
SOURCE_NAME="$2"
OUTPUT_DIR="$3"

for command in jq git tar dpkg-parsechangelog python3; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done
[ -f "$LOCK_JSON" ] || {
  echo "lock file not found: $LOCK_JSON" >&2
  exit 2
}
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

entry="$(jq -c --arg source "$SOURCE_NAME" '
  first(
    .sources[]
    | select(.source == $source and .status == "resolved" and .selected != null)
  ) // empty
' "$LOCK_JSON")"
[ -n "$entry" ] || {
  echo "No resolved exact source authority for $SOURCE_NAME" >&2
  exit 2
}

SOURCE_VERSION="$(jq -r '.source_version' <<<"$entry")"
SELECTED_TYPE="$(jq -r '.selected.type // "git"' <<<"$entry")"

if [ "$SELECTED_TYPE" != git ]; then
  exec bash arm64/scripts/build_locked_source_arm64_v5.sh \
    "$LOCK_JSON" "$SOURCE_NAME" "$OUTPUT_DIR"
fi

REPOSITORY="$(jq -r '.selected.repository_full_name // empty' <<<"$entry")"
COMMIT_SHA="$(jq -r '.selected.commit_sha // empty' <<<"$entry")"
TREE_SHA="$(jq -r '.selected.tree_sha // empty' <<<"$entry")"
[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "invalid repository name: $REPOSITORY" >&2
  exit 2
}
[[ "$COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid commit SHA: $COMMIT_SHA" >&2
  exit 2
}
[[ "$TREE_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid tree SHA: $TREE_SHA" >&2
  exit 2
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
PROBE_REPOSITORY="$WORK_DIR/repository"
SOURCE_ROOT="$WORK_DIR/source"
mkdir -p "$PROBE_REPOSITORY" "$SOURCE_ROOT"
export GIT_TERMINAL_PROMPT=0

git -C "$PROBE_REPOSITORY" init --quiet
git -C "$PROBE_REPOSITORY" remote add origin \
  "https://github.com/${REPOSITORY}.git"
git -C "$PROBE_REPOSITORY" -c protocol.version=2 fetch \
  --quiet --force --no-tags --depth=1 \
  origin "$COMMIT_SHA"

ACTUAL_COMMIT_SHA="$(git -C "$PROBE_REPOSITORY" rev-parse FETCH_HEAD)"
ACTUAL_TREE_SHA="$(git -C "$PROBE_REPOSITORY" rev-parse 'FETCH_HEAD^{tree}')"
[ "$ACTUAL_COMMIT_SHA" = "$COMMIT_SHA" ] || {
  echo "commit mismatch during prebuilt-payload preflight" >&2
  exit 3
}
[ "$ACTUAL_TREE_SHA" = "$TREE_SHA" ] || {
  echo "tree mismatch during prebuilt-payload preflight" >&2
  exit 3
}

git -C "$PROBE_REPOSITORY" archive --format=tar FETCH_HEAD \
  | tar -xf - -C "$SOURCE_ROOT"
[ -f "$SOURCE_ROOT/debian/changelog" ] || {
  echo "debian/changelog missing during prebuilt-payload preflight" >&2
  exit 3
}
DECLARED_SOURCE="$(
  dpkg-parsechangelog -l"$SOURCE_ROOT/debian/changelog" -S Source
)"
DECLARED_VERSION="$(
  dpkg-parsechangelog -l"$SOURCE_ROOT/debian/changelog" -S Version
)"
[ "$DECLARED_SOURCE" = "$SOURCE_NAME" ] || {
  echo "source mismatch during prebuilt-payload preflight" >&2
  exit 3
}
[ "$DECLARED_VERSION" = "$SOURCE_VERSION" ] || {
  echo "version mismatch during prebuilt-payload preflight" >&2
  exit 3
}

AUDIT="$OUTPUT_DIR/prebuilt-install-payload-audit.json"
set +e
python3 arm64/scripts/scan_prebuilt_install_payloads.py \
  --source-root "$SOURCE_ROOT" \
  --output "$AUDIT" \
  --source "$SOURCE_NAME" \
  --source-version "$SOURCE_VERSION" \
  --repository "$REPOSITORY" \
  --commit-sha "$COMMIT_SHA" \
  --tree-sha "$TREE_SHA"
AUDIT_RC=$?
set -e

case "$AUDIT_RC" in
  0)
    ;;
  86)
    cat > "$OUTPUT_DIR/source-recovery-required.json" <<EOF
{
  "schema": 1,
  "status": "source-recovery-required",
  "source": $(jq -Rn --arg value "$SOURCE_NAME" '$value'),
  "source_version": $(jq -Rn --arg value "$SOURCE_VERSION" '$value'),
  "repository_full_name": $(jq -Rn --arg value "$REPOSITORY" '$value'),
  "commit_sha": $(jq -Rn --arg value "$COMMIT_SHA" '$value'),
  "tree_sha": $(jq -Rn --arg value "$TREE_SHA" '$value'),
  "reason": "exact source tree installs a prebuilt non-ARM64 ELF payload",
  "audit_file": "prebuilt-install-payload-audit.json"
}
EOF
    echo "source-recovery-required: exact source installs prebuilt non-ARM64 ELF payloads" >&2
    jq '.summary, .foreign_elf_blockers' "$AUDIT" >&2
    exit 86
    ;;
  *)
    echo "prebuilt install-payload audit failed with exit code $AUDIT_RC" >&2
    exit "$AUDIT_RC"
    ;;
esac

exec bash arm64/scripts/build_locked_source_arm64_v5.sh \
  "$LOCK_JSON" "$SOURCE_NAME" "$OUTPUT_DIR"
