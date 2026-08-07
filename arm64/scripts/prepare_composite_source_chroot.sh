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
# snapshot can therefore still hold exact files while no longer advertising the
# historical version to apt-get source. Prefer the immutable content-addressed
# object. If Snapshot's content object endpoint returns an error, try only the
# exact versioned pool URL already recorded in the component lock. Every
# candidate is accepted solely after size, SHA-1 and SHA-256 all match.
download_member() {
  local key="$1"
  local filename expected_size expected_sha1 expected_sha256 primary_url pool_url selected_url
  filename="$(jq -er --arg key "$key" '.upstream.files[$key].name' "$COMPONENT_LOCK")"
  expected_size="$(jq -er --arg key "$key" '.upstream.files[$key].size' "$COMPONENT_LOCK")"
  expected_sha1="$(jq -er --arg key "$key" '.upstream.files[$key].sha1' "$COMPONENT_LOCK")"
  expected_sha256="$(jq -er --arg key "$key" '.upstream.files[$key].sha256' "$COMPONENT_LOCK")"
  pool_url="$(jq -er --arg key "$key" '.upstream.files[$key].pool_url // ""' "$COMPONENT_LOCK")"

  [[ "$filename" =~ ^[A-Za-z0-9][A-Za-z0-9+_.~:-]*$ ]] || {
    echo "invalid locked source filename: $filename" >&2
    exit 3
  }
  [[ "$expected_size" =~ ^[0-9]+$ ]] || {
    echo "invalid locked source size: $expected_size" >&2
    exit 3
  }
  [[ "$expected_sha1" =~ ^[0-9a-f]{40}$ ]] || {
    echo "invalid locked source SHA-1: $expected_sha1" >&2
    exit 3
  }
  [[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid locked source SHA-256: $expected_sha256" >&2
    exit 3
  }

  primary_url="${SNAPSHOT_FILE_BASE}/${expected_sha1}"
  if [ -n "$pool_url" ]; then
    case "$pool_url" in
      https://snapshot.debian.org/archive/*|http://snapshot.debian.org/archive/*) ;;
      *)
        echo "unexpected locked Snapshot pool URL: $pool_url" >&2
        exit 3
        ;;
    esac
    python3 - "$pool_url" "$filename" <<'PY_POOL_URL'
import sys
from urllib.parse import unquote, urlparse

url, expected_name = sys.argv[1:]
parsed = urlparse(url)
actual_name = unquote(parsed.path.rsplit("/", 1)[-1])
if actual_name != expected_name:
    raise SystemExit(
        f"locked pool URL filename mismatch: {actual_name!r} != {expected_name!r}"
    )
PY_POOL_URL
  fi

  selected_url="$(
    python3 - \
      "$primary_url" \
      "$pool_url" \
      "$filename" \
      "$expected_size" \
      "$expected_sha1" \
      "$expected_sha256" <<'PY_DOWNLOAD'
import hashlib
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

primary_url, fallback_url, destination, size_raw, expected_sha1, expected_sha256 = sys.argv[1:]
expected_size = int(size_raw)
path = Path(destination)
temporary = path.with_name(path.name + ".partial")
headers = {"User-Agent": "hancom-gooroom-arm64-exact-source/2"}
urls = [primary_url]
if fallback_url and fallback_url != primary_url:
    urls.append(fallback_url)
errors = []

for url in urls:
    for attempt in range(5):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=180) as response, temporary.open("wb") as output:
                sha1 = hashlib.sha1()
                sha256 = hashlib.sha256()
                size = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    size += len(chunk)
            actual_sha1 = sha1.hexdigest()
            actual_sha256 = sha256.hexdigest()
            if size != expected_size:
                raise ValueError(f"size {size} != {expected_size}")
            if actual_sha1 != expected_sha1:
                raise ValueError(f"SHA-1 {actual_sha1} != {expected_sha1}")
            if actual_sha256 != expected_sha256:
                raise ValueError(f"SHA-256 {actual_sha256} != {expected_sha256}")
            os.replace(temporary, path)
            print(url)
            raise SystemExit(0)
        except (OSError, urllib.error.URLError, ValueError) as error:
            temporary.unlink(missing_ok=True)
            errors.append(f"{url} attempt {attempt + 1}: {error}")
            if attempt < 4:
                time.sleep(2 ** attempt)
            else:
                break

raise SystemExit("failed exact source download:\n" + "\n".join(errors))
PY_DOWNLOAD
  )"
  [ -n "$selected_url" ] || {
    echo "exact source downloader did not report a selected URL" >&2
    exit 3
  }
  printf '%s\t%s\t%s\t%s\n' \
    "$key" "$filename" "$primary_url" "$selected_url" \
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
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$key" "$filename" "$actual_size" "$actual_sha1" "$actual_sha256" \
    >> "$OUTPUT_DIR/upstream-source-members.tsv"
}

: > "$OUTPUT_DIR/upstream-source-downloads.tsv"
: > "$OUTPUT_DIR/upstream-source-members.tsv"
for key in dsc orig debian; do
  download_member "$key"
  verify_member "$key"
done

python3 - \
  "$OUTPUT_DIR/upstream-source-downloads.tsv" \
  "$OUTPUT_DIR/upstream-source-resolved-urls.json" <<'PY_RESOLVED_URLS'
import json
import sys
from pathlib import Path

source, destination = map(Path, sys.argv[1:])
records = []
for raw in source.read_text(encoding="utf-8").splitlines():
    if not raw:
        continue
    key, filename, primary_url, selected_url = raw.split("\t")
    records.append(
        {
            "key": key,
            "filename": filename,
            "primary_content_url": primary_url,
            "selected_url": selected_url,
            "used_locked_pool_fallback": selected_url != primary_url,
        }
    )
destination.write_text(
    json.dumps(records, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY_RESOLVED_URLS

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
  --slurpfile resolved_downloads "$OUTPUT_DIR/upstream-source-resolved-urls.json" \
  --arg lock_sha256 "$LOCK_SHA256" \
  --arg snapshot "$SNAPSHOT" \
  --arg file_base "$SNAPSHOT_FILE_BASE" \
  --arg packaging_source "$PACKAGING_SOURCE" \
  --arg packaging_version "$PACKAGING_VERSION" \
  --arg dsc_sha256 "$DSC_SHA256" \
  --arg orig_sha256 "$ORIG_SHA256" \
  --arg debian_sha256 "$DEBIAN_SHA256" '
  {
    schema: 3,
    policy: .policy,
    source: .source,
    source_version: .source_version,
    source_component_lock_sha256: $lock_sha256,
    packaging: (.packaging + {
      verified_source: $packaging_source,
      verified_version: $packaging_version
    }),
    changelog_anchor: .changelog_anchor,
    upstream: (.upstream + {
      verified_snapshot: $snapshot,
      verified_content_addressed_base: $file_base,
      resolved_downloads: $resolved_downloads[0],
      verified_dsc_identity: true,
      verified_files: {
        dsc_sha256: $dsc_sha256,
        orig_sha256: $orig_sha256,
        debian_sha256: $debian_sha256
      },
      required_paths_verified: true
    }),
    composition: .composition,
    composite_root: "/build/composite-source",
    verified: true
  }
' "$COMPONENT_LOCK" > "$OUTPUT_DIR/upstream-source-evidence.json"

cat "$OUTPUT_DIR/upstream-source-evidence.json"
