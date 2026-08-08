#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 INPUT_LOCK LINEAGE_LOCK OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
INPUT_LOCK="$1"
LINEAGE_LOCK="$2"
OUTPUT_DIR="$3"

: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

for command in \
  apt-get awk comm curl dpkg-buildpackage dpkg-deb dpkg-parsechangelog \
  find git gzip jq mk-build-deps python3 sha256sum sort stat tar unzip; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done

for required_file in "$INPUT_LOCK" "$LINEAGE_LOCK"; do
  [ -f "$required_file" ] || {
    echo "required lock does not exist: $required_file" >&2
    exit 66
  }
done

OUTPUT_DIR_ABS="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"
rm -rf "$OUTPUT_DIR_ABS"/*
WORK_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

INPUT_LOCK_SHA256="$(sha256sum "$INPUT_LOCK" | awk '{print $1}')"
EXPECTED_INPUT_LOCK_SHA256="$(jq -r '.target.input_lock_sha256' "$LINEAGE_LOCK")"
test "$INPUT_LOCK_SHA256" = "$EXPECTED_INPUT_LOCK_SHA256"

jq -e '
  .claims == {
    "source_status": "comparison-only",
    "reconstruction_status": "not-attempted",
    "byte_identity_claimed": false
  }
' "$INPUT_LOCK" >/dev/null
jq -e '
  .claims == {
    "source_status": "public-lineage-candidate",
    "reconstruction_status": "not-yet-built",
    "byte_identity_claimed": false
  }
' "$LINEAGE_LOCK" >/dev/null

ARTIFACT_ID="$(jq -r '.artifact.id' "$INPUT_LOCK")"
ARTIFACT_NAME="$(jq -r '.artifact.name' "$INPUT_LOCK")"
ARTIFACT_SIZE="$(jq -r '.artifact.size_in_bytes' "$INPUT_LOCK")"
ARTIFACT_DIGEST="$(jq -r '.artifact.digest | sub("^sha256:"; "")' "$INPUT_LOCK")"
ARTIFACT_RUN_ID="$(jq -r '.artifact.workflow_run_id' "$INPUT_LOCK")"
ARTIFACT_HEAD_BRANCH="$(jq -r '.artifact.head_branch' "$INPUT_LOCK")"
ARTIFACT_HEAD_SHA="$(jq -r '.artifact.head_sha' "$INPUT_LOCK")"
TARGET_URL="$(jq -r '.target.url' "$INPUT_LOCK")"
TARGET_FILENAME="$(jq -r '.target.filename' "$INPUT_LOCK")"
TARGET_SHA256="$(jq -r '.target.sha256' "$INPUT_LOCK")"
TARGET_PACKAGE="$(jq -r '.target.package' "$INPUT_LOCK")"
TARGET_VERSION="$(jq -r '.target.version' "$INPUT_LOCK")"
TARGET_ARCHITECTURE="$(jq -r '.target.architecture' "$INPUT_LOCK")"

CANDIDATE_REPOSITORY="$(jq -r '.public_candidate.repository' "$LINEAGE_LOCK")"
CANDIDATE_COMMIT="$(jq -r '.public_candidate.commit' "$LINEAGE_LOCK")"
CANDIDATE_TREE="$(jq -r '.public_candidate.tree' "$LINEAGE_LOCK")"
CANDIDATE_PARENT="$(jq -r '.public_candidate.parent' "$LINEAGE_LOCK")"
CANDIDATE_MESSAGE="$(jq -r '.public_candidate.message' "$LINEAGE_LOCK")"
CANDIDATE_CHANGE_ID="$(jq -r '.public_candidate.change_id' "$LINEAGE_LOCK")"
BASE_VERSION="$(jq -r '.public_base.version' "$LINEAGE_LOCK")"
TARGET_CHANGELOG_SHA256="$(jq -r '.target.changelog_sha256' "$LINEAGE_LOCK")"
TARGET_ICON_SHA256="$(jq -r '.target.icon_sha256' "$LINEAGE_LOCK")"

[[ "$ARTIFACT_ID" =~ ^[0-9]+$ ]]
[[ "$ARTIFACT_SIZE" =~ ^[0-9]+$ ]]
[[ "$ARTIFACT_RUN_ID" =~ ^[0-9]+$ ]]
[[ "$ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]]
[[ "$TARGET_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ "$ARTIFACT_HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$CANDIDATE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$CANDIDATE_TREE" =~ ^[0-9a-f]{40}$ ]]
[[ "$CANDIDATE_PARENT" =~ ^[0-9a-f]{40}$ ]]
[[ "$CANDIDATE_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]
test "$TARGET_ARCHITECTURE" = amd64

cp "$INPUT_LOCK" "$OUTPUT_DIR_ABS/input-lock.json"
cp "$LINEAGE_LOCK" "$OUTPUT_DIR_ABS/source-lineage-lock.json"

ARTIFACT_METADATA="$OUTPUT_DIR_ABS/artifact-metadata.json"
curl --fail --silent --show-error --location \
  --retry 4 --retry-all-errors \
  -H 'Accept: application/vnd.github+json' \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/artifacts/${ARTIFACT_ID}" \
  -o "$ARTIFACT_METADATA"

export \
  ARTIFACT_ID ARTIFACT_NAME ARTIFACT_SIZE ARTIFACT_DIGEST \
  ARTIFACT_RUN_ID ARTIFACT_HEAD_BRANCH ARTIFACT_HEAD_SHA
python3 - "$ARTIFACT_METADATA" <<'PY'
import json
import os
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "id": int(os.environ["ARTIFACT_ID"]),
    "name": os.environ["ARTIFACT_NAME"],
    "size_in_bytes": int(os.environ["ARTIFACT_SIZE"]),
    "digest": "sha256:" + os.environ["ARTIFACT_DIGEST"],
    "expired": False,
}
mismatch = {
    key: {"actual": data.get(key), "expected": value}
    for key, value in expected.items()
    if data.get(key) != value
}
run = data.get("workflow_run") or {}
run_expected = {
    "id": int(os.environ["ARTIFACT_RUN_ID"]),
    "head_branch": os.environ["ARTIFACT_HEAD_BRANCH"],
    "head_sha": os.environ["ARTIFACT_HEAD_SHA"],
}
run_mismatch = {
    key: {"actual": run.get(key), "expected": value}
    for key, value in run_expected.items()
    if run.get(key) != value
}
if mismatch or run_mismatch:
    raise SystemExit(
        f"artifact authority mismatch: metadata={mismatch}, run={run_mismatch}"
    )
PY

TARGET_DEB="$WORK_DIR/target.deb"
RETRIEVAL="direct-url"
if ! curl --fail --show-error --location \
    --retry 4 --retry-delay 2 --retry-all-errors \
    "$TARGET_URL" -o "$TARGET_DEB" \
    || ! echo "${TARGET_SHA256}  ${TARGET_DEB}" | sha256sum --check --strict; then
  RETRIEVAL="exact-artifact-fallback"
  rm -f "$TARGET_DEB"
  PACKAGE_POOL_ZIP="$WORK_DIR/package-pool.zip"
  curl --fail --silent --show-error --location \
    --retry 4 --retry-all-errors \
    -H 'Accept: application/vnd.github+json' \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/artifacts/${ARTIFACT_ID}/zip" \
    -o "$PACKAGE_POOL_ZIP"
  test "$(stat -c '%s' "$PACKAGE_POOL_ZIP")" = "$ARTIFACT_SIZE"
  echo "${ARTIFACT_DIGEST}  ${PACKAGE_POOL_ZIP}" | sha256sum --check --strict
  PACKAGE_POOL="$WORK_DIR/package-pool"
  mkdir -p "$PACKAGE_POOL"
  unzip -q "$PACKAGE_POOL_ZIP" -d "$PACKAGE_POOL"
  mapfile -t target_matches < <(
    find "$PACKAGE_POOL" -type f -name "$TARGET_FILENAME" -print
  )
  test "${#target_matches[@]}" -eq 1
  cp "${target_matches[0]}" "$TARGET_DEB"
fi

echo "${TARGET_SHA256}  ${TARGET_DEB}" | sha256sum --check --strict
test "$(dpkg-deb -f "$TARGET_DEB" Package)" = "$TARGET_PACKAGE"
test "$(dpkg-deb -f "$TARGET_DEB" Version)" = "$TARGET_VERSION"
test "$(dpkg-deb -f "$TARGET_DEB" Architecture)" = "$TARGET_ARCHITECTURE"
printf '%s\n' "$RETRIEVAL" > "$OUTPUT_DIR_ABS/retrieval.txt"
cp "$TARGET_DEB" "$OUTPUT_DIR_ABS/target.deb"

TARGET_ROOT="$WORK_DIR/target-root"
mkdir -p "$TARGET_ROOT"
dpkg-deb -x "$TARGET_DEB" "$TARGET_ROOT"
TARGET_CHANGELOG="$WORK_DIR/target-changelog"
TARGET_ICON="$WORK_DIR/target-icon.svg"
gzip -dc \
  "$TARGET_ROOT/usr/share/doc/gooroom-applauncher-applet/changelog.gz" \
  > "$TARGET_CHANGELOG"
cp \
  "$TARGET_ROOT/usr/share/icons/hicolor/scalable/apps/gooroom-applauncher-applet.svg" \
  "$TARGET_ICON"
echo "${TARGET_CHANGELOG_SHA256}  ${TARGET_CHANGELOG}" \
  | sha256sum --check --strict
echo "${TARGET_ICON_SHA256}  ${TARGET_ICON}" \
  | sha256sum --check --strict
cp "$TARGET_CHANGELOG" "$OUTPUT_DIR_ABS/target-changelog"
cp "$TARGET_ICON" "$OUTPUT_DIR_ABS/target-icon.svg"

SOURCE_DIR="$WORK_DIR/source"
git init -q "$SOURCE_DIR"
git -C "$SOURCE_DIR" remote add origin \
  "https://github.com/${CANDIDATE_REPOSITORY}.git"
git -C "$SOURCE_DIR" fetch --no-tags --depth=2 origin "$CANDIDATE_COMMIT"
git -C "$SOURCE_DIR" checkout -q --detach FETCH_HEAD

test "$(git -C "$SOURCE_DIR" rev-parse HEAD)" = "$CANDIDATE_COMMIT"
test "$(git -C "$SOURCE_DIR" rev-parse HEAD^{tree})" = "$CANDIDATE_TREE"
test "$(git -C "$SOURCE_DIR" rev-parse HEAD^1)" = "$CANDIDATE_PARENT"
test "$(git -C "$SOURCE_DIR" log -1 --format=%s)" = "$CANDIDATE_MESSAGE"
git -C "$SOURCE_DIR" log -1 --format=%B \
  | grep -Fx "Change-Id: ${CANDIDATE_CHANGE_ID}" >/dev/null

test "$(dpkg-parsechangelog -l"$SOURCE_DIR/debian/changelog" -SSource)" \
  = "$TARGET_PACKAGE"
test "$(dpkg-parsechangelog -l"$SOURCE_DIR/debian/changelog" -SVersion)" \
  = "$BASE_VERSION"

mapfile -t actual_changed_paths < <(
  git -C "$SOURCE_DIR" diff-tree --no-commit-id --name-only -r \
    "$CANDIDATE_COMMIT" | LC_ALL=C sort
)
mapfile -t expected_changed_paths < <(
  jq -r '.public_candidate.changed_paths | keys[]' "$LINEAGE_LOCK" \
    | LC_ALL=C sort
)
test "${#actual_changed_paths[@]}" -eq "${#expected_changed_paths[@]}"
diff -u \
  <(printf '%s\n' "${expected_changed_paths[@]}") \
  <(printf '%s\n' "${actual_changed_paths[@]}")

for path in "${expected_changed_paths[@]}"; do
  expected_blob="$(
    jq -r --arg path "$path" '.public_candidate.changed_paths[$path]' \
      "$LINEAGE_LOCK"
  )"
  actual_blob="$(git -C "$SOURCE_DIR" rev-parse "${CANDIDATE_COMMIT}:${path}")"
  test "$actual_blob" = "$expected_blob"
done

git -C "$SOURCE_DIR" diff --binary "$CANDIDATE_PARENT" "$CANDIDATE_COMMIT" \
  -- "${expected_changed_paths[@]}" \
  > "$OUTPUT_DIR_ABS/public-drag-drop.patch"

cp "$TARGET_CHANGELOG" "$SOURCE_DIR/debian/changelog"
cp "$TARGET_ICON" "$SOURCE_DIR/data/gooroom-applauncher-applet.svg"
test "$(dpkg-parsechangelog -l"$SOURCE_DIR/debian/changelog" -SVersion)" \
  = "$TARGET_VERSION"
echo "${TARGET_CHANGELOG_SHA256}  ${SOURCE_DIR}/debian/changelog" \
  | sha256sum --check --strict
echo "${TARGET_ICON_SHA256}  ${SOURCE_DIR}/data/gooroom-applauncher-applet.svg" \
  | sha256sum --check --strict

git -C "$SOURCE_DIR" diff --binary \
  > "$OUTPUT_DIR_ABS/target-payload-overlay.patch"

SOURCE_DATE_EPOCH="$(
  dpkg-parsechangelog -l"$SOURCE_DIR/debian/changelog" -STimestamp
)"
export SOURCE_DATE_EPOCH
RECONSTRUCTED_ARCHIVE="$OUTPUT_DIR_ABS/reconstructed-source.tar.gz"
tar --sort=name \
  --mtime="@${SOURCE_DATE_EPOCH}" \
  --owner=0 --group=0 --numeric-owner \
  --exclude=.git \
  -C "$SOURCE_DIR" -cf - . \
  | gzip -n -9 > "$RECONSTRUCTED_ARCHIVE"
RECONSTRUCTED_ARCHIVE_SHA256="$(
  sha256sum "$RECONSTRUCTED_ARCHIVE" | awk '{print $1}'
)"

export \
  CANDIDATE_REPOSITORY CANDIDATE_COMMIT CANDIDATE_TREE CANDIDATE_PARENT \
  CANDIDATE_MESSAGE CANDIDATE_CHANGE_ID TARGET_CHANGELOG_SHA256 \
  TARGET_ICON_SHA256 RECONSTRUCTED_ARCHIVE_SHA256 SOURCE_DATE_EPOCH
python3 - "$OUTPUT_DIR_ABS/source-evidence.json" <<'PY'
import json
import os
import sys
from pathlib import Path

record = {
    "schema": 1,
    "repository": os.environ["CANDIDATE_REPOSITORY"],
    "candidate_commit": os.environ["CANDIDATE_COMMIT"],
    "candidate_tree": os.environ["CANDIDATE_TREE"],
    "candidate_parent": os.environ["CANDIDATE_PARENT"],
    "candidate_message": os.environ["CANDIDATE_MESSAGE"],
    "candidate_change_id": os.environ["CANDIDATE_CHANGE_ID"],
    "changed_paths": [
        "src/applauncher-appitem.c",
        "src/applauncher-appitem.h",
        "src/applauncher-window.c",
    ],
    "overlay": {
        "changelog_sha256": os.environ["TARGET_CHANGELOG_SHA256"],
        "icon_sha256": os.environ["TARGET_ICON_SHA256"],
    },
    "source_date_epoch": int(os.environ["SOURCE_DATE_EPOCH"]),
    "reconstructed_source_archive_sha256": os.environ[
        "RECONSTRUCTED_ARCHIVE_SHA256"
    ],
}
Path(sys.argv[1]).write_text(
    json.dumps(record, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

apt-get update
pushd "$SOURCE_DIR" >/dev/null
mk-build-deps --install --remove \
  --tool 'apt-get -y --no-install-recommends' debian/control \
  2>&1 | tee "$OUTPUT_DIR_ABS/build-dependencies.log"
export DEB_BUILD_OPTIONS='nocheck parallel=2'
dpkg-buildpackage -us -uc -b \
  2>&1 | tee "$OUTPUT_DIR_ABS/build.log"
popd >/dev/null

mapfile -t rebuilt_matches < <(
  find "$WORK_DIR" -maxdepth 1 -type f \
    -name "${TARGET_PACKAGE}_${TARGET_VERSION}_amd64.deb" -print
)
test "${#rebuilt_matches[@]}" -eq 1
REBUILT_DEB="${rebuilt_matches[0]}"
test "$(dpkg-deb -f "$REBUILT_DEB" Package)" = "$TARGET_PACKAGE"
test "$(dpkg-deb -f "$REBUILT_DEB" Version)" = "$TARGET_VERSION"
test "$(dpkg-deb -f "$REBUILT_DEB" Architecture)" = amd64
cp "$REBUILT_DEB" "$OUTPUT_DIR_ABS/rebuilt.deb"

find "$WORK_DIR" -maxdepth 1 -type f \
  \( -name "${TARGET_PACKAGE}_${TARGET_VERSION}_*.buildinfo" \
     -o -name "${TARGET_PACKAGE}_${TARGET_VERSION}_*.changes" \
     -o -name "${TARGET_PACKAGE}-dbgsym_${TARGET_VERSION}_*.deb" \) \
  -exec cp {} "$OUTPUT_DIR_ABS/" \;

python3 "$(dirname "$0")/verify_gooroom_applauncher_lineage.py" \
  --target-deb "$TARGET_DEB" \
  --rebuilt-deb "$REBUILT_DEB" \
  --lineage-lock "$LINEAGE_LOCK" \
  --source-evidence "$OUTPUT_DIR_ABS/source-evidence.json" \
  --output-dir "$OUTPUT_DIR_ABS"
