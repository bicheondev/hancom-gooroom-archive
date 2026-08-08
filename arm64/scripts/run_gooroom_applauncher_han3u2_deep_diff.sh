#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 INPUT_LOCK OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
INPUT_LOCK="$1"
OUTPUT_DIR="$2"

: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

for command in \
  apt-get awk comm curl diff dpkg-buildpackage dpkg-deb \
  dpkg-parsechangelog find git gzip jq mk-build-deps nm objdump \
  python3 readelf sha256sum sort stat strings tar unzip; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 69
  }
done

[ -f "$INPUT_LOCK" ] || {
  echo "input lock does not exist: $INPUT_LOCK" >&2
  exit 66
}

OUTPUT_DIR_ABS="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"
rm -rf "$OUTPUT_DIR_ABS"/*
WORK_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

jq -e '
  .claims == {
    "source_status": "comparison-only",
    "reconstruction_status": "not-attempted",
    "byte_identity_claimed": false
  }
' "$INPUT_LOCK" >/dev/null || {
  echo "unsafe reconstruction claims in input lock" >&2
  exit 2
}

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
BASE_REPOSITORY="$(jq -r '.base_source.repository' "$INPUT_LOCK")"
BASE_VERSION="$(jq -r '.base_source.version' "$INPUT_LOCK")"
BASE_COMMIT="$(jq -r '.base_source.commit' "$INPUT_LOCK")"
BASE_TREE="$(jq -r '.base_source.tree' "$INPUT_LOCK")"

[[ "$ARTIFACT_ID" =~ ^[0-9]+$ ]] || { echo "invalid artifact id" >&2; exit 2; }
[[ "$ARTIFACT_SIZE" =~ ^[0-9]+$ ]] || { echo "invalid artifact size" >&2; exit 2; }
[[ "$ARTIFACT_RUN_ID" =~ ^[0-9]+$ ]] || { echo "invalid artifact run id" >&2; exit 2; }
[[ "$ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid artifact digest" >&2; exit 2; }
[[ "$TARGET_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid target digest" >&2; exit 2; }
[[ "$ARTIFACT_HEAD_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid artifact head SHA" >&2; exit 2; }
[[ "$BASE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid base commit" >&2; exit 2; }
[[ "$BASE_TREE" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid base tree" >&2; exit 2; }
[[ "$BASE_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "invalid base repository: $BASE_REPOSITORY" >&2
  exit 2
}

cp "$INPUT_LOCK" "$OUTPUT_DIR_ABS/input-lock.json"

ARTIFACT_METADATA="$OUTPUT_DIR_ABS/artifact-metadata.json"
curl --fail --silent --show-error --location \
  --retry 4 --retry-all-errors \
  -H 'Accept: application/vnd.github+json' \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/artifacts/${ARTIFACT_ID}" \
  -o "$ARTIFACT_METADATA"

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
  mapfile -t matches < <(find "$PACKAGE_POOL" -type f -name "$TARGET_FILENAME" -print)
  test "${#matches[@]}" -eq 1
  cp "${matches[0]}" "$TARGET_DEB"
fi

echo "${TARGET_SHA256}  ${TARGET_DEB}" | sha256sum --check --strict
test "$(dpkg-deb -f "$TARGET_DEB" Package)" = "$TARGET_PACKAGE"
test "$(dpkg-deb -f "$TARGET_DEB" Version)" = "$TARGET_VERSION"
test "$(dpkg-deb -f "$TARGET_DEB" Architecture)" = amd64
printf '%s\n' "$RETRIEVAL" > "$OUTPUT_DIR_ABS/retrieval.txt"
cp "$TARGET_DEB" "$OUTPUT_DIR_ABS/target.deb"

BASE_SOURCE="$WORK_DIR/base-source"
git init -q "$BASE_SOURCE"
git -C "$BASE_SOURCE" remote add origin "https://github.com/${BASE_REPOSITORY}.git"
git -C "$BASE_SOURCE" fetch --no-tags --depth=1 origin "$BASE_COMMIT"
git -C "$BASE_SOURCE" checkout -q --detach FETCH_HEAD
test "$(git -C "$BASE_SOURCE" rev-parse HEAD)" = "$BASE_COMMIT"
test "$(git -C "$BASE_SOURCE" rev-parse HEAD^{tree})" = "$BASE_TREE"
test "$(dpkg-parsechangelog -l"$BASE_SOURCE/debian/changelog" -SSource)" = "$TARGET_PACKAGE"
test "$(dpkg-parsechangelog -l"$BASE_SOURCE/debian/changelog" -SVersion)" = "$BASE_VERSION"
git -C "$BASE_SOURCE" archive --format=tar "$BASE_COMMIT" \
  | gzip -n -9 > "$OUTPUT_DIR_ABS/base-source.tar.gz"

apt-get update
pushd "$BASE_SOURCE" >/dev/null
mk-build-deps --install --remove \
  --tool 'apt-get -y --no-install-recommends' debian/control \
  2>&1 | tee "$OUTPUT_DIR_ABS/base-build-deps.log"
export DEB_BUILD_OPTIONS='nocheck parallel=2'
export SOURCE_DATE_EPOCH="$(dpkg-parsechangelog -STimestamp)"
dpkg-buildpackage -us -uc -b 2>&1 | tee "$OUTPUT_DIR_ABS/base-build.log"
popd >/dev/null

mapfile -t base_matches < <(
  find "$WORK_DIR" -maxdepth 1 -type f \
    -name "${TARGET_PACKAGE}_${BASE_VERSION}_amd64.deb" -print
)
test "${#base_matches[@]}" -eq 1
BASE_DEB="${base_matches[0]}"
test "$(dpkg-deb -f "$BASE_DEB" Package)" = "$TARGET_PACKAGE"
test "$(dpkg-deb -f "$BASE_DEB" Version)" = "$BASE_VERSION"
test "$(dpkg-deb -f "$BASE_DEB" Architecture)" = amd64
cp "$BASE_DEB" "$OUTPUT_DIR_ABS/base.deb"

BASE_ROOT="$OUTPUT_DIR_ABS/base-root"
TARGET_ROOT="$OUTPUT_DIR_ABS/target-root"
BASE_CONTROL="$OUTPUT_DIR_ABS/base-control"
TARGET_CONTROL="$OUTPUT_DIR_ABS/target-control"
mkdir -p "$BASE_ROOT" "$TARGET_ROOT" "$BASE_CONTROL" "$TARGET_CONTROL"
dpkg-deb -x "$BASE_DEB" "$BASE_ROOT"
dpkg-deb -x "$TARGET_DEB" "$TARGET_ROOT"
dpkg-deb -e "$BASE_DEB" "$BASE_CONTROL"
dpkg-deb -e "$TARGET_DEB" "$TARGET_CONTROL"

SO_PATH='usr/lib/x86_64-linux-gnu/gnome-panel/modules/libgooroom-applauncher-applet.so'
ICON_PATH='usr/share/icons/hicolor/scalable/apps/gooroom-applauncher-applet.svg'
CHANGELOG_PATH='usr/share/doc/gooroom-applauncher-applet/changelog.gz'

for side in base target; do
  if [ "$side" = base ]; then
    root="$BASE_ROOT"
  else
    root="$TARGET_ROOT"
  fi
  for required in "$SO_PATH" "$ICON_PATH" "$CHANGELOG_PATH"; do
    [ -f "$root/$required" ] || {
      echo "$side package is missing required path: $required" >&2
      find "$root" -type f -printf '%P\n' | sort >&2
      exit 3
    }
  done

  readelf -aW "$root/$SO_PATH" > "$OUTPUT_DIR_ABS/${side}.readelf.txt"
  nm -D --defined-only "$root/$SO_PATH" > "$OUTPUT_DIR_ABS/${side}.exports.txt"
  nm -D --undefined-only "$root/$SO_PATH" > "$OUTPUT_DIR_ABS/${side}.imports.txt"
  objdump -drwC -Mintel "$root/$SO_PATH" > "$OUTPUT_DIR_ABS/${side}.objdump.txt"
  objdump -s -j .rodata "$root/$SO_PATH" > "$OUTPUT_DIR_ABS/${side}.rodata.txt"
  strings -a -t x "$root/$SO_PATH" > "$OUTPUT_DIR_ABS/${side}.strings.txt"
  gzip -dc "$root/$CHANGELOG_PATH" > "$OUTPUT_DIR_ABS/${side}.changelog"
  cp "$root/$ICON_PATH" "$OUTPUT_DIR_ABS/${side}.icon.svg"
  awk '{print $NF}' "$OUTPUT_DIR_ABS/${side}.exports.txt" \
    | LC_ALL=C sort -u > "$OUTPUT_DIR_ABS/${side}.export-names.txt"
  awk '{print $NF}' "$OUTPUT_DIR_ABS/${side}.imports.txt" \
    | LC_ALL=C sort -u > "$OUTPUT_DIR_ABS/${side}.import-names.txt"
done

for symbol in dragsource_initialize applauncher_icon_get_path; do
  grep -Fxq "$symbol" "$OUTPUT_DIR_ABS/target.export-names.txt" || {
    echo "target ELF does not export expected Hancom symbol: $symbol" >&2
    exit 3
  }
  if grep -Fxq "$symbol" "$OUTPUT_DIR_ABS/base.export-names.txt"; then
    echo "public base unexpectedly exports Hancom-only symbol: $symbol" >&2
    exit 3
  fi
  objdump -drwC -Mintel --disassemble="$symbol" \
    "$TARGET_ROOT/$SO_PATH" > "$OUTPUT_DIR_ABS/target.${symbol}.objdump.txt"
done

readelf -Ws "$TARGET_ROOT/$SO_PATH" \
  | awk '$8 == "dragsource_initialize" || $8 == "applauncher_icon_get_path" {print}' \
  > "$OUTPUT_DIR_ABS/target.hancom-function-symbols.txt"
test "$(wc -l < "$OUTPUT_DIR_ABS/target.hancom-function-symbols.txt")" -eq 2

comm -13 "$OUTPUT_DIR_ABS/base.export-names.txt" "$OUTPUT_DIR_ABS/target.export-names.txt" \
  > "$OUTPUT_DIR_ABS/target-only-exports.txt"
comm -13 "$OUTPUT_DIR_ABS/base.import-names.txt" "$OUTPUT_DIR_ABS/target.import-names.txt" \
  > "$OUTPUT_DIR_ABS/target-only-imports.txt"
comm -23 "$OUTPUT_DIR_ABS/base.export-names.txt" "$OUTPUT_DIR_ABS/target.export-names.txt" \
  > "$OUTPUT_DIR_ABS/base-only-exports.txt"
comm -23 "$OUTPUT_DIR_ABS/base.import-names.txt" "$OUTPUT_DIR_ABS/target.import-names.txt" \
  > "$OUTPUT_DIR_ABS/base-only-imports.txt"

diff_capture() {
  local left="$1"
  local right="$2"
  local output="$3"
  local rc=0
  diff -u "$left" "$right" > "$output" || rc=$?
  [ "$rc" -le 1 ] || return "$rc"
}

diff_capture "$OUTPUT_DIR_ABS/base.changelog" "$OUTPUT_DIR_ABS/target.changelog" \
  "$OUTPUT_DIR_ABS/changelog.diff"
diff_capture "$OUTPUT_DIR_ABS/base.icon.svg" "$OUTPUT_DIR_ABS/target.icon.svg" \
  "$OUTPUT_DIR_ABS/icon.diff"
diff_capture "$OUTPUT_DIR_ABS/base.exports.txt" "$OUTPUT_DIR_ABS/target.exports.txt" \
  "$OUTPUT_DIR_ABS/exports.diff"
diff_capture "$OUTPUT_DIR_ABS/base.imports.txt" "$OUTPUT_DIR_ABS/target.imports.txt" \
  "$OUTPUT_DIR_ABS/imports.diff"
diff_capture "$OUTPUT_DIR_ABS/base.strings.txt" "$OUTPUT_DIR_ABS/target.strings.txt" \
  "$OUTPUT_DIR_ABS/strings.diff"
control_rc=0
diff -ruN "$BASE_CONTROL" "$TARGET_CONTROL" \
  > "$OUTPUT_DIR_ABS/control.diff" || control_rc=$?
[ "$control_rc" -le 1 ] || exit "$control_rc"

TARGET_ONLY_EXPORT_COUNT="$(wc -l < "$OUTPUT_DIR_ABS/target-only-exports.txt")"
TARGET_ONLY_IMPORT_COUNT="$(wc -l < "$OUTPUT_DIR_ABS/target-only-imports.txt")"
cat > "$OUTPUT_DIR_ABS/summary.md" <<EOF
# Gooroom applauncher Hancom deep-diff evidence

This is comparison-only evidence. It does not claim recovery of Hancom's exact source or byte-identical reconstruction.

- Target: \`${TARGET_PACKAGE} ${TARGET_VERSION} amd64\`
- Target SHA-256: \`${TARGET_SHA256}\`
- Public base: \`${BASE_REPOSITORY}@${BASE_COMMIT}\`
- Public base version: \`${BASE_VERSION}\`
- Public base tree: \`${BASE_TREE}\`
- Retrieval: \`${RETRIEVAL}\`
- Target-only dynamic exports: ${TARGET_ONLY_EXPORT_COUNT}
- Target-only dynamic imports: ${TARGET_ONLY_IMPORT_COUNT}
- Confirmed Hancom-only exports: \`dragsource_initialize\`, \`applauncher_icon_get_path\`

The required package paths were verified before extraction:

- \`${SO_PATH}\`
- \`${ICON_PATH}\`
- \`${CHANGELOG_PATH}\`
EOF

export ARTIFACT_ID ARTIFACT_NAME ARTIFACT_SIZE ARTIFACT_DIGEST
export ARTIFACT_RUN_ID ARTIFACT_HEAD_BRANCH ARTIFACT_HEAD_SHA
export TARGET_PACKAGE TARGET_VERSION TARGET_SHA256 TARGET_URL TARGET_FILENAME
export BASE_REPOSITORY BASE_VERSION BASE_COMMIT BASE_TREE RETRIEVAL
python3 - "$OUTPUT_DIR_ABS" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

out = Path(sys.argv[1])
files = {}
for path in sorted(p for p in out.rglob("*") if p.is_file() and p.name != "manifest.json"):
    rel = path.relative_to(out).as_posix()
    files[rel] = {
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
manifest = {
    "schema": 2,
    "audit_complete": True,
    "analysis_status": "deep-diff-collected",
    "authority": {
        "artifact": {
            "id": int(os.environ["ARTIFACT_ID"]),
            "name": os.environ["ARTIFACT_NAME"],
            "size_in_bytes": int(os.environ["ARTIFACT_SIZE"]),
            "digest": "sha256:" + os.environ["ARTIFACT_DIGEST"],
            "workflow_run_id": int(os.environ["ARTIFACT_RUN_ID"]),
            "head_branch": os.environ["ARTIFACT_HEAD_BRANCH"],
            "head_sha": os.environ["ARTIFACT_HEAD_SHA"],
        },
        "target": {
            "package": os.environ["TARGET_PACKAGE"],
            "version": os.environ["TARGET_VERSION"],
            "sha256": os.environ["TARGET_SHA256"],
            "url": os.environ["TARGET_URL"],
            "filename": os.environ["TARGET_FILENAME"],
            "retrieval": os.environ["RETRIEVAL"],
        },
        "base_source": {
            "repository": os.environ["BASE_REPOSITORY"],
            "version": os.environ["BASE_VERSION"],
            "commit": os.environ["BASE_COMMIT"],
            "tree": os.environ["BASE_TREE"],
        },
    },
    "claims": {
        "source_status": "comparison-only",
        "reconstruction_status": "not-attempted",
        "byte_identity_claimed": False,
    },
    "hancom_only_exports_required": [
        "applauncher_icon_get_path",
        "dragsource_initialize",
    ],
    "files": files,
}
(out / "manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

jq -e '
  .audit_complete == true and
  .analysis_status == "deep-diff-collected" and
  .claims.source_status == "comparison-only" and
  .claims.reconstruction_status == "not-attempted" and
  .claims.byte_identity_claimed == false
' "$OUTPUT_DIR_ABS/manifest.json" >/dev/null

echo "Deep-diff evidence written to $OUTPUT_DIR_ABS"
