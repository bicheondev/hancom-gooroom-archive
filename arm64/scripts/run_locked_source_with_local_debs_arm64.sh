#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 LOCK_JSON SOURCE_NAME OUTPUT_DIR LOCAL_DEB_DIR" >&2
  exit 64
}

[ "$#" -eq 4 ] || usage
LOCK_JSON="$1"
SOURCE_NAME="$2"
OUTPUT_DIR="$3"
LOCAL_DEB_DIR="$4"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_BUILDER="$SCRIPT_DIR/build_locked_source_arm64.sh"
COMMON_RUNNER="$SCRIPT_DIR/run_locked_source_arm64.sh"
REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-$SCRIPT_DIR/../locks/reference/amd64-reference.json}"
COMPONENT_LOCK_DIR="${HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR:-$SCRIPT_DIR/../locks/source-components}"
COMPOSITE_HELPER="${HANCOM_GOOROOM_COMPOSITE_SOURCE_HELPER:-$SCRIPT_DIR/prepare_composite_source_chroot.sh}"

for command in python3 jq dpkg-deb sha256sum find sort readlink; do
  command -v "$command" >/dev/null || {
    echo "required local-dependency build command is missing: $command" >&2
    exit 69
  }
done
for path in "$BASE_BUILDER" "$COMMON_RUNNER" "$REFERENCE_JSON" "$COMPOSITE_HELPER"; do
  [ -f "$path" ] || {
    echo "required build input is missing: $path" >&2
    exit 69
  }
done
[ -d "$COMPONENT_LOCK_DIR" ] || {
  echo "source component lock directory is missing: $COMPONENT_LOCK_DIR" >&2
  exit 69
}
[ -d "$LOCAL_DEB_DIR" ] || {
  echo "local dependency directory is missing: $LOCAL_DEB_DIR" >&2
  exit 2
}

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR_ABS="$(cd "$OUTPUT_DIR" && pwd)"
LOCAL_DEB_DIR_ABS="$(readlink -f "$LOCAL_DEB_DIR")"
REFERENCE_JSON="$(readlink -f "$REFERENCE_JSON")"
COMPONENT_LOCK_DIR="$(readlink -f "$COMPONENT_LOCK_DIR")"
COMPOSITE_HELPER="$(readlink -f "$COMPOSITE_HELPER")"

MANIFEST="$OUTPUT_DIR_ABS/local-build-dependencies.tsv"
printf 'package\tversion\tarchitecture\tsha256\tfilename\n' > "$MANIFEST"
count=0
while IFS= read -r -d '' deb; do
  package="$(dpkg-deb -f "$deb" Package)"
  version="$(dpkg-deb -f "$deb" Version)"
  architecture="$(dpkg-deb -f "$deb" Architecture)"
  case "$architecture" in
    arm64|all) ;;
    *)
      echo "local dependency has an invalid architecture: $deb ($architecture)" >&2
      exit 2
      ;;
  esac
  digest="$(sha256sum "$deb" | awk '{print $1}')"
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$package" "$version" "$architecture" "$digest" "$(basename "$deb")" \
    >> "$MANIFEST"
  count=$((count + 1))
done < <(find "$LOCAL_DEB_DIR_ABS" -maxdepth 1 -type f -name '*.deb' -print0 | sort -z)
[ "$count" -gt 0 ] || {
  echo "no .deb local dependencies were supplied" >&2
  exit 2
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cp "$BASE_BUILDER" "$WORK_DIR/build_locked_source_arm64.sh"
cp "$COMMON_RUNNER" "$WORK_DIR/run_locked_source_arm64.sh"
chmod +x "$WORK_DIR/build_locked_source_arm64.sh" "$WORK_DIR/run_locked_source_arm64.sh"

# Extend a private copy of the exact builder. The normal runner still applies
# all of its asserted compatibility transformations afterwards. Every insertion
# preserves the original anchor verbatim so a changed base builder fails closed.
python3 - "$WORK_DIR/build_locked_source_arm64.sh" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")

def insert_after(anchor: str, addition: str, label: str) -> None:
    global source
    if source.count(anchor) != 1:
        raise SystemExit(
            f"expected exactly one {label} anchor, found {source.count(anchor)}"
        )
    source = source.replace(anchor, anchor + addition)

insert_after(
    "trap 'rm -rf \"$WORK_DIR\"' EXIT\n",
    '''\nLOCAL_DEB_DIR_ABS="${HANCOM_GOOROOM_LOCAL_DEB_DIR:?local dependency directory is required}"
[ -d "$LOCAL_DEB_DIR_ABS" ] || {
  echo "local dependency directory is missing inside builder: $LOCAL_DEB_DIR_ABS" >&2
  exit 2
}
''',
    "host work-directory",
)

insert_after(
    'mkdir -p /out\n',
    '''\n: "${LOCAL_DEBS_PRESENT:?LOCAL_DEBS_PRESENT is required}"
[ "$LOCAL_DEBS_PRESENT" = true ] || {
  echo "local dependency mode was not enabled" >&2
  exit 2
}
''',
    "container output-directory",
)

insert_after(
    '''mkdir -p "$ROOT/build/source" "$ROOT/build/output"
cp -a /src/. "$ROOT/build/source/"
''',
    '''if [ "$LOCAL_DEBS_PRESENT" = true ]; then
  mkdir -p "$ROOT/build/local-debs"
  cp -a /local-debs/. "$ROOT/build/local-debs/"
fi
''',
    "historical-root source-copy",
)

insert_after(
    '''apt-get install -y --no-install-recommends \\
  build-essential ca-certificates debhelper devscripts dpkg-dev \\
  equivs fakeroot gnupg xz-utils
''',
    '''\nif [ -d /build/local-debs ]; then
  (
    cd /build/local-debs
    dpkg-scanpackages . /dev/null > Packages
    gzip -n -9 -c Packages > Packages.gz
  )
  cat > /etc/apt/sources.list.d/99-local-build-dependencies.list <<'EOF'
deb [trusted=yes] file:/build/local-debs ./
EOF
  apt-get update
  dpkg-deb -f /build/local-debs/*.deb Package Version Architecture \\
    > /build/output/local-build-dependency-control.txt
  apt-cache policy \\
    accountsservice libaccountsservice0 libaccountsservice-dev \\
    gir1.2-accountsservice-1.0 \\
    > /build/output/local-build-dependency-policy.txt
fi
''',
    "chroot build-tool installation",
)

insert_after(
    '  --env "SNAPSHOT=$SNAPSHOT" \\\n',
    '''  --env "LOCAL_DEBS_PRESENT=true" \\
  --volume "$LOCAL_DEB_DIR_ABS:/local-debs:ro" \\
''',
    "Docker snapshot environment",
)

path.write_text(source, encoding="utf-8")
PY

export HANCOM_GOOROOM_REFERENCE_JSON="$REFERENCE_JSON"
export HANCOM_GOOROOM_SOURCE_COMPONENT_LOCK_DIR="$COMPONENT_LOCK_DIR"
export HANCOM_GOOROOM_COMPOSITE_SOURCE_HELPER="$COMPOSITE_HELPER"
export HANCOM_GOOROOM_LOCAL_DEB_DIR="$LOCAL_DEB_DIR_ABS"

set +e
"$WORK_DIR/run_locked_source_arm64.sh" \
  "$LOCK_JSON" "$SOURCE_NAME" "$OUTPUT_DIR_ABS"
rc=$?
set -e
[ "$rc" -eq 0 ] || exit "$rc"

MANIFEST_SHA256="$(sha256sum "$MANIFEST" | awk '{print $1}')"
LOCAL_PACKAGES_JSON="$(python3 - "$MANIFEST" <<'PY'
import csv
import json
import sys
from pathlib import Path

with Path(sys.argv[1]).open(encoding="utf-8", newline="") as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))
print(json.dumps(rows, ensure_ascii=False, separators=(",", ":")))
PY
)"

temporary="$(mktemp)"
jq \
  --arg manifest_sha256 "$MANIFEST_SHA256" \
  --argjson packages "$LOCAL_PACKAGES_JSON" '
    . + {
      local_build_dependencies: {
        policy: "exact-local-deb-repository",
        manifest_sha256: $manifest_sha256,
        packages: $packages
      }
    }
  ' "$OUTPUT_DIR_ABS/build-lock.json" > "$temporary"
mv "$temporary" "$OUTPUT_DIR_ABS/build-lock.json"

find "$OUTPUT_DIR_ABS" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > "$OUTPUT_DIR_ABS/SHA256SUMS"

cat "$OUTPUT_DIR_ABS/build-lock.json"
