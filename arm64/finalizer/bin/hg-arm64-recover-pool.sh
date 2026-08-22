#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hg-arm64-common.sh
source "$SCRIPT_DIR/hg-arm64-common.sh"

usage() {
  cat <<'EOF'
Usage:
  hg-arm64-recover-pool.sh --input PATH --output PATH [--suite NAME]

Recursively scans DEB files, accepts only Architecture arm64/all, rejects foreign
architectures, detects tuple collisions, and generates a deterministic unsigned
APT repository plus complete evidence manifests.
EOF
}

input=''
output=''
suite='stable'

while (($#)); do
  case "$1" in
    --input)
      input="${2:?missing value for --input}"
      shift 2
      ;;
    --output)
      output="${2:?missing value for --output}"
      shift 2
      ;;
    --suite)
      suite="${2:?missing value for --suite}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      hg_die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$input" && -n "$output" ]] || hg_die '--input and --output are required'
[[ -d "$input" ]] || hg_die "input directory does not exist: $input"
hg_require_cmd dpkg-deb dpkg-scanpackages gzip sha256sum md5sum python3 find sort awk

input="$(hg_realpath "$input")"
output="$(hg_realpath "$output")"
[[ "$output" != "$input" ]] || hg_die 'output must not equal input'

work="$(hg_make_workdir hg-arm64-pool)"
trap 'rm -rf "$work"' EXIT
candidate_list="$work/candidates.list"
raw="$work/raw.tsv"
: > "$raw"
find "$input" -type f -name '*.deb' -print0 | LC_ALL=C sort -z > "$candidate_list"

candidate_count=0
while IFS= read -r -d '' deb; do
  candidate_count=$((candidate_count + 1))
  set +e
  package="$(dpkg-deb -f "$deb" Package 2>/dev/null)"
  package_rc=$?
  version="$(dpkg-deb -f "$deb" Version 2>/dev/null)"
  version_rc=$?
  architecture="$(dpkg-deb -f "$deb" Architecture 2>/dev/null)"
  architecture_rc=$?
  set -e

  size="$(stat -c '%s' "$deb")"
  sha="$(hg_sha256 "$deb")"
  relative="${deb#"$input"/}"

  if ((package_rc != 0 || version_rc != 0 || architecture_rc != 0)) \
      || [[ -z "$package" || -z "$version" || -z "$architecture" ]]; then
    printf 'invalid\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$relative" "$package" "$version" "$architecture" "$size" "$sha" >> "$raw"
    continue
  fi

  case "$architecture" in
    arm64|all)
      decision='accepted'
      ;;
    *)
      decision='foreign-architecture'
      ;;
  esac

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$decision" "$relative" "$package" "$version" "$architecture" "$size" "$sha" >> "$raw"
done < "$candidate_list"

rm -rf "$output"
mkdir -p "$output/pool" "$output/evidence" \
  "$output/dists/$suite/main/binary-arm64"

python3 - "$input" "$output" "$raw" <<'PY'
from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

input_root = Path(sys.argv[1])
output_root = Path(sys.argv[2])
raw_path = Path(sys.argv[3])

rows = []
with raw_path.open(encoding='utf-8', newline='') as stream:
    for decision, relative, package, version, architecture, size, sha256 in csv.reader(stream, delimiter='\t'):
        rows.append({
            'decision': decision,
            'source': relative,
            'package': package,
            'version': version,
            'architecture': architecture,
            'size': int(size),
            'sha256': sha256,
        })

by_tuple = defaultdict(list)
for row in rows:
    if row['decision'] == 'accepted':
        by_tuple[(row['package'], row['version'], row['architecture'])].append(row)

conflicts = []
accepted = []
for key, candidates in sorted(by_tuple.items()):
    hashes = {row['sha256'] for row in candidates}
    if len(hashes) != 1:
        for row in candidates:
            row['decision'] = 'tuple-conflict'
            conflicts.append(row)
        continue

    canonical = sorted(candidates, key=lambda row: row['source'])[0]
    package = canonical['package']
    first = package[0].lower() if package else '_'
    destination_dir = output_root / 'pool' / first / package
    destination_dir.mkdir(parents=True, exist_ok=True)
    source_path = input_root / canonical['source']
    destination_name = Path(canonical['source']).name
    destination = destination_dir / destination_name
    shutil.copy2(source_path, destination)

    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    if digest != canonical['sha256']:
        raise RuntimeError(f'copy hash mismatch for {canonical["source"]}')
    canonical = dict(canonical)
    canonical['pool_path'] = destination.relative_to(output_root).as_posix()
    canonical['duplicate_sources'] = sorted(row['source'] for row in candidates)
    accepted.append(canonical)

rejected = [row for row in rows if row['decision'] != 'accepted'] + conflicts
# Avoid recording accepted rows twice after conflict mutation.
rejected_by_identity = {(row['source'], row['sha256'], row['decision']): row for row in rejected}
rejected = [rejected_by_identity[key] for key in sorted(rejected_by_identity)]

manifest = {
    'schema': 1,
    'generated_at': datetime.now(timezone.utc).isoformat(),
    'input_root': str(input_root),
    'candidate_count': len(rows),
    'accepted_count': len(accepted),
    'rejected_count': len(rejected),
    'conflict_count': len(conflicts),
    'accepted_architectures': sorted({row['architecture'] for row in accepted}),
    'accepted': accepted,
    'rejected': rejected,
}
(output_root / 'evidence/manifest.json').write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + '\n',
    encoding='utf-8',
)

with (output_root / 'evidence/accepted.tsv').open('w', encoding='utf-8', newline='') as stream:
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(['package', 'version', 'architecture', 'size', 'sha256', 'pool_path', 'source'])
    for row in accepted:
        writer.writerow([
            row['package'], row['version'], row['architecture'], row['size'],
            row['sha256'], row['pool_path'], row['source'],
        ])

with (output_root / 'evidence/rejected.tsv').open('w', encoding='utf-8', newline='') as stream:
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(['decision', 'source', 'package', 'version', 'architecture', 'size', 'sha256'])
    for row in rejected:
        writer.writerow([
            row['decision'], row['source'], row['package'], row['version'],
            row['architecture'], row['size'], row['sha256'],
        ])

if conflicts:
    raise SystemExit(20)
if not accepted:
    raise SystemExit(21)
PY
python_status=$?
if [[ "$python_status" -eq 20 ]]; then
  hg_die "package/version/architecture tuple conflicts were found; see $output/evidence/rejected.tsv"
elif [[ "$python_status" -eq 21 ]]; then
  hg_die 'no arm64 or all packages were recovered'
elif [[ "$python_status" -ne 0 ]]; then
  hg_die "pool recovery failed with status $python_status"
fi

(
  cd "$output"
  dpkg-scanpackages -m pool /dev/null \
    > "dists/$suite/main/binary-arm64/Packages"
  gzip -n -9 -c "dists/$suite/main/binary-arm64/Packages" \
    > "dists/$suite/main/binary-arm64/Packages.gz"
)

python3 - "$output" "$suite" <<'PY'
from __future__ import annotations

import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
suite = sys.argv[2]
dist = root / 'dists' / suite
indexed = [
    dist / 'main/binary-arm64/Packages',
    dist / 'main/binary-arm64/Packages.gz',
]

def digest(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    h.update(path.read_bytes())
    return h.hexdigest()

lines = [
    'Origin: Hancom Gooroom ARM64 recovery',
    'Label: Hancom Gooroom ARM64 recovery',
    f'Suite: {suite}',
    f'Codename: {suite}',
    f'Date: {datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")}',
    'Architectures: arm64',
    'Components: main',
    'Description: Recovered ARM64 and architecture-independent packages',
    'MD5Sum:',
]
for path in indexed:
    relative = path.relative_to(dist).as_posix()
    lines.append(f' {digest(path, "md5")} {path.stat().st_size:16d} {relative}')
lines.append('SHA256:')
for path in indexed:
    relative = path.relative_to(dist).as_posix()
    lines.append(f' {digest(path, "sha256")} {path.stat().st_size:16d} {relative}')
(dist / 'Release').write_text('\n'.join(lines) + '\n', encoding='utf-8')

all_files = sorted(path for path in root.rglob('*') if path.is_file() and path.name != 'SHA256SUMS')
with (root / 'SHA256SUMS').open('w', encoding='utf-8') as stream:
    for path in all_files:
        stream.write(f'{digest(path, "sha256")}  {path.relative_to(root).as_posix()}\n')
PY

# Final fail-closed assertions.
if awk -F '\t' 'NR > 1 && $3 != "arm64" && $3 != "all" { bad=1 } END { exit bad ? 0 : 1 }' \
  "$output/evidence/accepted.tsv"; then
  hg_die 'foreign architecture escaped into accepted.tsv'
fi

grep -q '^Package: ' "$output/dists/$suite/main/binary-arm64/Packages" \
  || hg_die 'generated Packages index is empty'

hg_log "recovered package pool: $output"
hg_log "input candidates: $candidate_count"
hg_log "accepted packages: $(awk 'END {print NR-1}' "$output/evidence/accepted.tsv")"
hg_log "rejected packages: $(awk 'END {print NR-1}' "$output/evidence/rejected.tsv")"
