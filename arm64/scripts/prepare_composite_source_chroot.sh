#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 PACKAGING_ROOT OUTPUT_DIR COMPONENT_LOCK" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
PACKAGING_ROOT="$1"
OUTPUT_DIR="$2"
COMPONENT_LOCK="$3"
COMPOSITE_ROOT=/build/composite-source
DOWNLOAD_DIR=/build/source-download

for command in jq python3 sha1sum sha256sum stat tar dpkg-parsechangelog; do
  command -v "$command" >/dev/null || {
    echo "required composite-source command is missing: $command" >&2
    exit 69
  }
done

[ -d "$PACKAGING_ROOT/debian" ] || {
  echo "locked packaging root has no debian/ directory: $PACKAGING_ROOT" >&2
  exit 2
}
[ -f "$COMPONENT_LOCK" ] || {
  echo "source component lock not found: $COMPONENT_LOCK" >&2
  exit 2
}
mkdir -p "$OUTPUT_DIR"

LOCK_SOURCE="$(jq -er '.source' "$COMPONENT_LOCK")"
LOCK_SOURCE_VERSION="$(jq -er '.source_version' "$COMPONENT_LOCK")"
UPSTREAM_SOURCE="$(jq -er '.upstream.source' "$COMPONENT_LOCK")"
UPSTREAM_VERSION="$(jq -er '.upstream.version' "$COMPONENT_LOCK")"
LOCK_SNAPSHOT="$(jq -er '.upstream.snapshot' "$COMPONENT_LOCK")"
SNAPSHOT_FILE_BASE="$(jq -er '.upstream.content_addressed_base // "https://snapshot.debian.org/file"' "$COMPONENT_LOCK")"

[ "$LOCK_SOURCE" = "${SOURCE_NAME:?SOURCE_NAME is required}" ] || {
  echo "component source mismatch: $LOCK_SOURCE != $SOURCE_NAME" >&2
  exit 2
}
PACKAGING_SOURCE="$(dpkg-parsechangelog -l"$PACKAGING_ROOT/debian/changelog" -S Source)"
PACKAGING_VERSION="$(dpkg-parsechangelog -l"$PACKAGING_ROOT/debian/changelog" -S Version)"
[ "$PACKAGING_SOURCE" = "$LOCK_SOURCE" ] || {
  echo "packaging source mismatch: $PACKAGING_SOURCE != $LOCK_SOURCE" >&2
  exit 2
}
[ "$PACKAGING_VERSION" = "$LOCK_SOURCE_VERSION" ] || {
  echo "packaging version mismatch: $PACKAGING_VERSION != $LOCK_SOURCE_VERSION" >&2
  exit 2
}
[ "$LOCK_SNAPSHOT" = "${SNAPSHOT:?SNAPSHOT is required}" ] || {
  echo "component snapshot mismatch: $LOCK_SNAPSHOT != $SNAPSHOT" >&2
  exit 2
}
case "$SNAPSHOT_FILE_BASE" in
  https://snapshot.debian.org/file|http://snapshot.debian.org/file) ;;
  *)
    echo "unexpected snapshot content-addressed base: $SNAPSHOT_FILE_BASE" >&2
    exit 2
    ;;
esac

rm -rf "$DOWNLOAD_DIR" "$COMPOSITE_ROOT"
mkdir -p "$DOWNLOAD_DIR" "$COMPOSITE_ROOT"
cd "$DOWNLOAD_DIR"

# Suite source indexes retain one current source version per snapshot. A later
# snapshot can therefore still hold the exact files while no longer advertising
# the historical version to apt-get source. Fetch immutable Snapshot file
# objects by the independently locked SHA-1 identity, then enforce SHA-256 and
# size as a second, stronger gate before any extraction.
download_member() {
  local key="$1"
  local filename sha1 url
  filename="$(jq -er --arg key "$key" '.upstream.files[$key].name' "$COMPONENT_LOCK")"
  sha1="$(jq -er --arg key "$key" '.upstream.files[$key].sha1' "$COMPONENT_LOCK")"
  [[ "$filename" =~ ^[A-Za-z0-9][A-Za-z0-9+_.~:-]*$ ]] || {
    echo "invalid locked source filename: $filename" >&2
    exit 3
  }
  [[ "$sha1" =~ ^[0-9a-f]{40}$ ]] || {
    echo "invalid locked source SHA-1: $sha1" >&2
    exit 3
  }
  url="${SNAPSHOT_FILE_BASE}/${sha1}"
  python3 - "$url" "$filename" <<'PY_DOWNLOAD'
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

url, destination = sys.argv[1:]
path = Path(destination)
temporary = path.with_name(path.name + ".partial")
headers = {"User-Agent": "hancom-gooroom-arm64-exact-source/1"}
last_error = None
for attempt in range(5):
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=180) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        os.replace(temporary, path)
        break
    except (OSError, urllib.error.URLError) as error:
        last_error = error
        temporary.unlink(missing_ok=True)
        if attempt == 4:
            raise SystemExit(f"failed to download {url}: {error}")
        time.sleep(2 ** attempt)
else:
    raise SystemExit(f"failed to download {url}: {last_error}")
PY_DOWNLOAD
  printf '%s\t%s\t%s\n' "$key" "$filename" "$url" \
    >> "$OUTPUT_DIR/upstream-source-downloads.tsv"
}

verify_member() {
  local key="$1"
  local filename expected_size expected_sha1 expected_sha256
  filename="$(jq -er --arg key "$key" '.upstream.files[$key].name' "$COMPONENT_LOCK")"
  expected_size="$(jq -er --arg key "$key" '.upstream.files[$key].size' "$COMPONENT_LOCK")"
  expected_sha1="$(jq -er --arg key "$key" '.upstream.files[$key].sha1' "$COMPONENT_LOCK")"
  expected_sha256="$(jq -er --arg key "$key" '.upstream.files[$key].sha256' "$COMPONENT_LOCK")"

  [ -f "$filename" ] || {
    echo "downloaded source member is missing: $filename" >&2
    exit 3
  }
  local actual_size actual_sha1 actual_sha256
  actual_size="$(stat -c '%s' "$filename")"
  actual_sha1="$(sha1sum "$filename" | awk '{print $1}')"
  actual_sha256="$(sha256sum "$filename" | awk '{print $1}')"
  [ "$actual_size" = "$expected_size" ] || {
    echo "source member size mismatch for $filename: $actual_size != $expected_size" >&2
    exit 3
  }
  [ "$actual_sha1" = "$expected_sha1" ] || {
    echo "source member SHA-1 mismatch for $filename" >&2
    exit 3
  }
  [ "$actual_sha256" = "$expected_sha256" ] || {
    echo "source member SHA-256 mismatch for $filename" >&2
    exit 3
  }
  printf '%s\t%s\t%s\t%s\n' \
    "$key" "$filename" "$actual_size" "$actual_sha256" \
    >> "$OUTPUT_DIR/upstream-source-members.tsv"
}

: > "$OUTPUT_DIR/upstream-source-downloads.tsv"
: > "$OUTPUT_DIR/upstream-source-members.tsv"
for key in dsc orig debian; do
  download_member "$key"
  verify_member "$key"
done

DSC_FILENAME="$(jq -er '.upstream.files.dsc.name' "$COMPONENT_LOCK")"
python3 - "$DSC_FILENAME" "$COMPONENT_LOCK" <<'PY_DSC'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
lock = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
text = path.read_text(encoding="utf-8", errors="strict")

# Parse the RFC822 payload inside an optional clearsigned wrapper. Continuation
# lines are retained because Checksums-Sha256 is a multiline field.
lines = text.splitlines()
if lines and lines[0].startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
    try:
        blank = lines.index("")
    except ValueError as error:
        raise SystemExit("malformed clearsigned DSC") from error
    lines = lines[blank + 1:]
    for index, line in enumerate(lines):
        if line.startswith("-----BEGIN PGP SIGNATURE-----"):
            lines = lines[:index]
            break

fields = {}
current = None
for line in lines:
    if line.startswith((" ", "\t")) and current:
        fields[current] += "\n" + line.strip()
        continue
    match = re.match(r"^([A-Za-z0-9-]+):\s*(.*)$", line)
    if match:
        current = match.group(1)
        fields[current] = match.group(2)

expected_source = lock["upstream"]["source"]
expected_version = lock["upstream"]["version"]
if fields.get("Source") != expected_source:
    raise SystemExit(f"DSC source mismatch: {fields.get('Source')} != {expected_source}")
if fields.get("Version") != expected_version:
    raise SystemExit(f"DSC version mismatch: {fields.get('Version')} != {expected_version}")

checksums = {}
for row in fields.get("Checksums-Sha256", "").splitlines():
    parts = row.split()
    if len(parts) == 3:
        digest, size, name = parts
        checksums[name] = (digest, int(size))
for key in ("orig", "debian"):
    member = lock["upstream"]["files"][key]
    expected = (member["sha256"], int(member["size"]))
    actual = checksums.get(member["name"])
    if actual != expected:
        raise SystemExit(
            f"DSC checksum mismatch for {member['name']}: {actual} != {expected}"
        )
PY_DSC

ORIG_FILENAME="$(jq -er '.upstream.files.orig.name' "$COMPONENT_LOCK")"
FIRST_ENTRY="$(tar -tJf "$ORIG_FILENAME" | sed -n '1p')"
case "$FIRST_ENTRY" in
  */*) ;;
  *)
    echo "upstream archive does not have a removable top-level directory: $FIRST_ENTRY" >&2
    exit 3
    ;;
esac

tar --extract --xz --file "$ORIG_FILENAME" \
  --strip-components=1 \
  --no-same-owner \
  --no-same-permissions \
  --directory "$COMPOSITE_ROOT"

while IFS= read -r required_path; do
  [ -e "$COMPOSITE_ROOT/$required_path" ] || {
    echo "required upstream path is missing after extraction: $required_path" >&2
    exit 3
  }
done < <(jq -er '.upstream.required_paths[]' "$COMPONENT_LOCK")

# The Debian source archive is retained and hash-checked as independent
# provenance evidence only. The exact Gooroom Git commit supplies the sole
# debian/ overlay and must never be replaced by Debian's debian.tar.xz.
rm -rf "$COMPOSITE_ROOT/debian"
cp -a "$PACKAGING_ROOT/debian" "$COMPOSITE_ROOT/debian"

COMPOSITE_SOURCE="$(dpkg-parsechangelog -l"$COMPOSITE_ROOT/debian/changelog" -S Source)"
COMPOSITE_VERSION="$(dpkg-parsechangelog -l"$COMPOSITE_ROOT/debian/changelog" -S Version)"
[ "$COMPOSITE_SOURCE" = "$LOCK_SOURCE" ]
[ "$COMPOSITE_VERSION" = "$LOCK_SOURCE_VERSION" ]

LOCK_SHA256="$(sha256sum "$COMPONENT_LOCK" | awk '{print $1}')"
ORIG_SHA256="$(jq -er '.upstream.files.orig.sha256' "$COMPONENT_LOCK")"
DSC_SHA256="$(jq -er '.upstream.files.dsc.sha256' "$COMPONENT_LOCK")"
DEBIAN_SHA256="$(jq -er '.upstream.files.debian.sha256' "$COMPONENT_LOCK")"

jq \
  --arg lock_sha256 "$LOCK_SHA256" \
  --arg snapshot "$SNAPSHOT" \
  --arg file_base "$SNAPSHOT_FILE_BASE" \
  --arg packaging_source "$PACKAGING_SOURCE" \
  --arg packaging_version "$PACKAGING_VERSION" \
  --arg dsc_sha256 "$DSC_SHA256" \
  --arg orig_sha256 "$ORIG_SHA256" \
  --arg debian_sha256 "$DEBIAN_SHA256" '
  {
    schema: 2,
    policy: .policy,
    source: .source,
    source_version: .source_version,
    source_component_lock_sha256: $lock_sha256,
    packaging: .packaging + {
      verified_source: $packaging_source,
      verified_version: $packaging_version
    },
    changelog_anchor: .changelog_anchor,
    upstream: .upstream + {
      verified_snapshot: $snapshot,
      verified_content_addressed_base: $file_base,
      verified_dsc_identity: true,
      verified_files: {
        dsc_sha256: $dsc_sha256,
        orig_sha256: $orig_sha256,
        debian_sha256: $debian_sha256
      },
      required_paths_verified: true
    },
    composition: .composition,
    composite_root: "/build/composite-source",
    verified: true
  }
' "$COMPONENT_LOCK" > "$OUTPUT_DIR/upstream-source-evidence.json"

cat "$OUTPUT_DIR/upstream-source-evidence.json"
