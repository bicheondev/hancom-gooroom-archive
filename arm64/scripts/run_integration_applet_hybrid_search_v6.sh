#!/usr/bin/env bash
set -Eeuo pipefail

PACKAGE=gooroom-integration-applet
VERSION='0.3.1+grm3u1+han3u3'
PUBLIC_REPOSITORY='https://github.com/gooroom/gooroom-integration-applet.git'
TARGET_URL='https://update.hancomgooroom.com/hancom/pool/main/g/gooroom-integration-applet/gooroom-integration-applet_0.3.1+grm3u1+han3u3_amd64.deb'
TARGET_SHA256='1771ded81658d0e4bcce730ab69d162a1e58327cdabf1918c341cfbd02f495a9'
TARGET_SIZE=62392
BULLSEYE_DIGEST='sha256:99cdf7792e25416bd801861ccd8e2fb27fb527b25e8d9a8704ebc3ead2015675'
NIMF_AUTHORITY='arm64/locks/nimf-amd64-builddeps-v1/latest/authority.json'
V5C_SUMMARY='arm64/locks/gooroom-integration-applet-history-search-v5c/latest/summary.json'
V4_SUMMARY='arm64/locks/gooroom-integration-applet-han3u3-vendor-reconstruction-v4/latest/summary.json'
GENERATOR='arm64/scripts/generate_integration_applet_hybrid_candidates_v6.py'
ANALYZER='arm64/scripts/integration_applet_vendor_reconstruct.py'
ROOT="${1:-work/integration-applet-hybrid-v6}"

rm -rf "$ROOT"
mkdir -p "$ROOT"/{downloads,deps,target-root,public,candidates,output,artifact,image}

write_failure_summary() {
  local rc="$1"
  local line="$2"
  mkdir -p "$ROOT/output" "$ROOT/artifact"
  jq -n \
    --arg source "$PACKAGE" \
    --arg version "$VERSION" \
    --argjson exit_code "$rc" \
    --arg failure_line "$line" '
      {
        schema: 1,
        source: $source,
        version: $version,
        status: "infrastructure-failure",
        exit_code: $exit_code,
        failure_line: $failure_line,
        source_reconstruction_semantically_verified: false,
        native_arm64_candidate_build_allowed: false,
        package_layer_promotion_allowed: false,
        iso_assembly_allowed: false,
        fail_closed: true,
        next_action: "inspect hybrid-search artifact and repair the failed infrastructure stage"
      }
    ' > "$ROOT/output/summary.json"
  cp "$ROOT/output/summary.json" "$ROOT/artifact/summary.json"
}

on_error() {
  local rc=$?
  local line="${BASH_LINENO[0]:-unknown}"
  trap - ERR
  write_failure_summary "$rc" "$line"
  find "$ROOT/artifact" -type f -printf '%P\t%s\n' | LC_ALL=C sort \
    > "$ROOT/artifact/FILE-INVENTORY.tsv" || true
  (
    cd "$ROOT/artifact"
    find . -type f ! -name LOCKSUMS.sha256 -print0 \
      | LC_ALL=C sort -z | xargs -0 sha256sum > LOCKSUMS.sha256
  ) || true
  exit "$rc"
}
trap on_error ERR

for command in \
  binutils curl docker dpkg-buildpackage dpkg-deb git jq objcopy objdump \
  python3 readelf sha256sum tar xz
 do
  command -v "$command" >/dev/null
 done

test -f "$GENERATOR"
test -f "$ANALYZER"
test -f "$NIMF_AUTHORITY"
python3 -m py_compile "$GENERATOR" "$ANALYZER"

jq -e '
  .schema == 1
  and .source == "nimf"
  and .source_version == "2023.06.30+grm3u1"
  and .source_commit == "583ad8b183db06a84c6b85a80fe132583566909d"
  and (.packages | length) == 2
  and all(.packages[]; .architecture == "amd64")
  and ([.packages[].package] | sort) == ["libnimf1", "nimf-dev"]
' "$NIMF_AUTHORITY" >/dev/null

curl --fail --show-error --location --retry 8 --retry-delay 2 \
  --retry-all-errors "$TARGET_URL" -o "$ROOT/downloads/target.deb"
test "$(stat -c '%s' "$ROOT/downloads/target.deb")" = "$TARGET_SIZE"
echo "$TARGET_SHA256  $ROOT/downloads/target.deb" | sha256sum --check --strict -
test "$(dpkg-deb -f "$ROOT/downloads/target.deb" Package)" = "$PACKAGE"
test "$(dpkg-deb -f "$ROOT/downloads/target.deb" Version)" = "$VERSION"
test "$(dpkg-deb -f "$ROOT/downloads/target.deb" Architecture)" = amd64
dpkg-deb -x "$ROOT/downloads/target.deb" "$ROOT/target-root"

jq -c '.packages[]' "$NIMF_AUTHORITY" | while IFS= read -r row; do
  filename="$(jq -r '.filename' <<<"$row")"
  url="$(jq -r '.url' <<<"$row")"
  expected_sha="$(jq -r '.sha256' <<<"$row")"
  expected_size="$(jq -r '.size' <<<"$row")"
  expected_package="$(jq -r '.package' <<<"$row")"
  curl --fail --show-error --location --retry 8 --retry-delay 2 \
    --retry-all-errors "$url" -o "$ROOT/deps/$filename"
  test "$(stat -c '%s' "$ROOT/deps/$filename")" = "$expected_size"
  test "$(sha256sum "$ROOT/deps/$filename" | awk '{print $1}')" = "$expected_sha"
  test "$(dpkg-deb -f "$ROOT/deps/$filename" Package)" = "$expected_package"
  test "$(dpkg-deb -f "$ROOT/deps/$filename" Version)" = '2023.06.30+grm3u1'
  test "$(dpkg-deb -f "$ROOT/deps/$filename" Architecture)" = amd64
done

git clone --mirror "$PUBLIC_REPOSITORY" "$ROOT/public/repository.git"

base_commit=
if [[ -f "$V5C_SUMMARY" ]]; then
  base_commit="$(jq -r '.closest_candidate.candidate_commit_sha // empty' "$V5C_SUMMARY")"
fi
if [[ -z "$base_commit" && -f "$V4_SUMMARY" ]]; then
  base_commit="$(jq -r '.closest_candidate.candidate_commit_sha // empty' "$V4_SUMMARY")"
fi
if [[ ! "$base_commit" =~ ^[0-9a-f]{40}$ ]]; then
  base_commit='bcca083b854e4a6c99e0bb69db4d4868e1210cdd'
fi
git -C "$ROOT/public/repository.git" cat-file -e "$base_commit^{commit}"

matrix="$(
  python3 "$GENERATOR" \
    --repository "$ROOT/public/repository.git" \
    --base-commit "$base_commit" \
    --output "$ROOT/output/discovery.json" \
    --limit 12 \
    | tail -1
)"
jq -e '
  (.include | type) == "array"
  and (.include | length) >= 3
  and (.include | length) <= 12
  and all(.include[];
    (.label | test("^[a-z0-9-]+$"))
    and (.base_commit | test("^[0-9a-f]{40}$"))
    and (.applet_blob | test("^[0-9a-f]{40}$"))
    and (.popup_blob | test("^[0-9a-f]{40}$"))
    and (.user_blob | test("^[0-9a-f]{40}$"))
  )
' <<<"$matrix" >/dev/null
printf '%s\n' "$matrix" > "$ROOT/output/matrix.json"

# Build one immutable userspace image and reuse it for every bounded candidate.
git clone --shared --no-checkout "$ROOT/public/repository.git" "$ROOT/image/source"
git -C "$ROOT/image/source" checkout --detach "$base_commit"
cp "$ROOT/image/source/debian/control" "$ROOT/image/debian-control"
mkdir -p "$ROOT/image/nimf-deps"
cp "$ROOT/deps"/*.deb "$ROOT/image/nimf-deps/"
cat > "$ROOT/image/Dockerfile" <<EOF
FROM debian:bullseye@$BULLSEYE_DIGEST
COPY nimf-deps/ /tmp/nimf-deps/
COPY debian-control /tmp/debian-control
RUN set -Eeux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential devscripts dpkg-dev equivs git libglib2.0-dev-bin \
      /tmp/nimf-deps/libnimf1_2023.06.30+grm3u1_amd64.deb \
      /tmp/nimf-deps/nimf-dev_2023.06.30+grm3u1_amd64.deb; \
    test "\$(dpkg-query -W -f='\${Version}' libnimf1)" = '2023.06.30+grm3u1'; \
    test "\$(dpkg-query -W -f='\${Version}' nimf-dev)" = '2023.06.30+grm3u1'; \
    cd /tmp; \
    mk-build-deps --install --remove \
      --tool 'apt-get -o Acquire::Retries=6 -y --no-install-recommends' \
      /tmp/debian-control; \
    rm -rf /var/lib/apt/lists/* /tmp/nimf-deps /tmp/gooroom-integration-applet-build-deps_*
EOF
image='hancom-gooroom/integration-applet-hybrid-v6:bullseye'
docker build --pull=false --tag "$image" "$ROOT/image"
image_id="$(docker image inspect --format '{{.Id}}' "$image")"
printf '%s\n' "$image_id" > "$ROOT/output/build-image-id.txt"

while IFS= read -r row; do
  label="$(jq -r '.label' <<<"$row")"
  candidate="$ROOT/candidates/$label"
  source="$candidate/source"
  mkdir -p "$candidate"/{build,debs,comparison,source-authority,artifact}

  git clone --shared --no-checkout "$ROOT/public/repository.git" "$source"
  git -C "$source" checkout --detach "$base_commit"

  applet_blob="$(jq -r '.applet_blob' <<<"$row")"
  popup_blob="$(jq -r '.popup_blob' <<<"$row")"
  user_blob="$(jq -r '.user_blob' <<<"$row")"
  git -C "$ROOT/public/repository.git" cat-file blob "$applet_blob" \
    > "$source/src/gooroom-integration-applet.c"
  git -C "$ROOT/public/repository.git" cat-file blob "$popup_blob" \
    > "$source/src/popup-window.c"
  git -C "$ROOT/public/repository.git" cat-file blob "$user_blob" \
    > "$source/modules/user/user-module.c"

  jq -n \
    --arg label "$label" --arg base_commit "$base_commit" \
    --arg applet_blob "$applet_blob" --arg popup_blob "$popup_blob" \
    --arg user_blob "$user_blob" --arg build_image_id "$image_id" \
    --arg discovery_score "$(jq -r '.discovery_score' <<<"$row")" '
      {
        schema:1,candidate_label:$label,base_commit_sha:$base_commit,
        source_blobs:{
          "src/gooroom-integration-applet.c":$applet_blob,
          "src/popup-window.c":$popup_blob,
          "modules/user/user-module.c":$user_blob},
        discovery_score:($discovery_score|tonumber),build_image_id:$build_image_id
      }
    ' > "$candidate/source-authority/hybrid-lock.json"

  python3 "$ANALYZER" reconstruct \
    --source "$source" \
    --target-root "$ROOT/target-root" \
    --output "$candidate/source-authority/reconstruction-report.json" \
    --version "$VERSION"
  test "$(dpkg-parsechangelog -l"$source/debian/changelog" -SVersion)" = "$VERSION"

  git -C "$source" add -A
  reconstructed_tree="$(git -C "$source" write-tree)"
  git -C "$source" diff --cached --binary --full-index \
    > "$candidate/source-authority/reconstruction.patch"
  test -s "$candidate/source-authority/reconstruction.patch"
  git -C "$source" archive --format=tar "$reconstructed_tree" \
    > "$candidate/source-authority/reconstructed-source.tar"
  xz -9e "$candidate/source-authority/reconstructed-source.tar"

  source_date_epoch="$(date -u -d "$(dpkg-parsechangelog -l"$source/debian/changelog" -SDate)" +%s)"
  set +e
  docker run --rm \
    -e DEBIAN_FRONTEND=noninteractive \
    -e DEB_BUILD_OPTIONS=nocheck \
    -e DEB_BUILD_MAINT_OPTIONS='hardening=+all reproducible=+fixfilepath' \
    -e SOURCE_DATE_EPOCH="$source_date_epoch" \
    -e LC_ALL=C.UTF-8 \
    -v "$(pwd)/$source:/build/source" \
    -v "$(pwd)/$candidate/debs:/build/output" \
    "$image" bash -Eeuxo pipefail -c '
      cd /build/source
      dpkg-buildpackage -us -uc -b -j2
      find /build -maxdepth 1 -type f -name "*.deb" -exec cp -v {} /build/output/ \;
    ' > "$candidate/build/build.log" 2>&1
  build_rc=$?
  set -e
  printf '%s\n' "$build_rc" > "$candidate/build/build.exit"

  candidate_deb=
  if [[ "$build_rc" -eq 0 ]]; then
    for deb in "$candidate/debs"/*.deb; do
      if [[ "$(dpkg-deb -f "$deb" Package)" == "$PACKAGE" ]]; then
        candidate_deb="$deb"
      fi
    done
  fi

  comparison_complete=false
  if [[ -n "$candidate_deb" ]]; then
    test "$(dpkg-deb -f "$candidate_deb" Version)" = "$VERSION"
    test "$(dpkg-deb -f "$candidate_deb" Architecture)" = amd64
    python3 "$ANALYZER" compare \
      --target-deb "$ROOT/downloads/target.deb" \
      --candidate-deb "$candidate_deb" \
      --output "$candidate/comparison" \
      --version "$VERSION" \
      --candidate-label "$label" \
      --candidate-commit "$base_commit"
    comparison_complete=true
  fi

  candidate_sha=
  if [[ -n "$candidate_deb" ]]; then
    candidate_sha="$(sha256sum "$candidate_deb" | awk '{print $1}')"
  fi
  jq -n \
    --arg label "$label" --arg base_commit "$base_commit" \
    --argjson build_exit "$build_rc" \
    --arg comparison_complete "$comparison_complete" \
    --arg candidate_deb_sha256 "$candidate_sha" \
    --arg build_image_id "$image_id" '
      {
        schema:1,candidate_label:$label,base_commit_sha:$base_commit,
        build_exit:$build_exit,build_succeeded:($build_exit==0),
        comparison_complete:($comparison_complete=="true"),
        candidate_deb_sha256:$candidate_deb_sha256,
        build_image_id:$build_image_id,fail_closed:true
      }
    ' > "$candidate/artifact/probe-summary.json"
  cp -a "$candidate/source-authority" "$candidate/artifact/"
  cp -a "$candidate/comparison" "$candidate/artifact/" || true
  cp "$candidate/build/build.exit" "$candidate/artifact/"
  cp "$candidate/build/build.log" "$candidate/artifact/"
  [[ -z "$candidate_deb" ]] || cp "$candidate_deb" "$candidate/artifact/candidate.deb"
  find "$candidate/artifact" -type f -printf '%P\t%s\n' | LC_ALL=C sort \
    > "$candidate/artifact/FILE-INVENTORY.tsv"
  (
    cd "$candidate/artifact"
    find . -type f ! -name LOCKSUMS.sha256 -print0 \
      | LC_ALL=C sort -z | xargs -0 sha256sum > LOCKSUMS.sha256
    sha256sum --check --strict LOCKSUMS.sha256
  )
  sudo rm -rf "$source" "$candidate/debs"
done < <(jq -c '.include[]' "$ROOT/output/matrix.json")

python3 - "$ROOT" <<'PY'
from __future__ import annotations
import json
import shutil
import sys
from pathlib import Path

root = Path(sys.argv[1])
output = root / 'output'
artifact = root / 'artifact'
rows = []
failed = []

for probe_path in sorted((root / 'candidates').glob('*/artifact/probe-summary.json')):
    candidate_artifact = probe_path.parent
    probe = json.loads(probe_path.read_text(encoding='utf-8'))
    comparison_path = candidate_artifact / 'comparison/summary.json'
    if not probe.get('comparison_complete') or not comparison_path.exists():
        failed.append(probe)
        continue
    comparison = json.loads(comparison_path.read_text(encoding='utf-8'))
    rank = comparison.get('comparison_rank')
    if not isinstance(rank, list) or not rank:
        failed.append({**probe, 'reason': 'missing-comparison-rank'})
        continue
    hybrid_lock = json.loads(
        (candidate_artifact / 'source-authority/hybrid-lock.json').read_text(encoding='utf-8')
    )
    rows.append((tuple(rank), comparison.get('candidate_label', ''), probe, comparison, hybrid_lock, candidate_artifact))

rows.sort(key=lambda row: (row[0], row[1]))
ranked = []
for rank, _, probe, comparison, hybrid, _ in rows:
    ranked.append({
        'candidate_label': comparison.get('candidate_label'),
        'base_commit_sha': hybrid.get('base_commit_sha'),
        'source_blobs': hybrid.get('source_blobs'),
        'discovery_score': hybrid.get('discovery_score'),
        'comparison_rank': list(rank),
        'different_resource_count': comparison.get('different_resource_count'),
        'different_dynamic_function_count': comparison.get('different_dynamic_function_count'),
        'different_allocated_section_count': comparison.get('different_allocated_section_count'),
        'non_elf_difference_count': comparison.get('non_elf_difference_count'),
        'main_different_functions': (comparison.get('main_elf') or {}).get('different_dynamic_function_count'),
        'nimf_different_functions': (comparison.get('nimf_elf') or {}).get('different_dynamic_function_count'),
        'target_only_strings': {
            'main': (comparison.get('main_elf') or {}).get('target_only_strings', []),
            'nimf': (comparison.get('nimf_elf') or {}).get('target_only_strings', []),
        },
    })

if rows:
    _, _, _, closest, closest_hybrid, closest_artifact = rows[0]
    closest_row = ranked[0]
    semantic = (
        closest.get('different_resource_count') == 0
        and closest.get('different_dynamic_function_count') == 0
        and closest.get('non_elf_difference_count') == 0
    )
    allocated_exact = semantic and closest.get('different_allocated_section_count') == 0
    copies = (
        ('comparison/summary.json', 'closest-comparison.json'),
        ('comparison/different-functions.tsv', 'different-functions.tsv'),
        ('source-authority/hybrid-lock.json', 'hybrid-lock.json'),
        ('source-authority/reconstruction-report.json', 'reconstruction-report.json'),
        ('source-authority/reconstruction.patch', 'closest-reconstruction.patch'),
        ('source-authority/reconstructed-source.tar.xz', 'closest-source.tar.xz'),
        ('candidate.deb', 'closest-candidate-amd64.deb'),
    )
    for source_name, destination_name in copies:
        source = closest_artifact / source_name
        if source.exists():
            shutil.copy2(source, artifact / destination_name)
else:
    closest_row = None
    semantic = False
    allocated_exact = False

summary = {
    'schema': 1,
    'source': 'gooroom-integration-applet',
    'version': '0.3.1+grm3u1+han3u3',
    'search_generation': 'hybrid-v6',
    'selection_policy': 'bounded-diverse-public-file-blob-combinations-plus-exact-vendor-visible-inputs',
    'candidate_count': len(rows) + len(failed),
    'completed_candidate_count': len(rows),
    'failed_candidate_count': len(failed),
    'closest_candidate': closest_row,
    'ranked_candidates': ranked,
    'failed_candidates': failed,
    'source_reconstruction_semantically_verified': semantic,
    'allocated_runtime_sections_exact': allocated_exact,
    'native_arm64_candidate_build_allowed': semantic,
    'package_layer_promotion_allowed': False,
    'iso_assembly_allowed': False,
    'fail_closed': True,
    'next_action': (
        'build and verify the recovered source natively for ARM64'
        if semantic
        else 'use the closest hybrid and exact DWARF to reconstruct remaining private functions'
    ),
}
(output / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
shutil.copy2(output / 'summary.json', artifact / 'summary.json')
shutil.copy2(output / 'discovery.json', artifact / 'discovery.json')
shutil.copy2(output / 'matrix.json', artifact / 'matrix.json')
shutil.copy2(output / 'build-image-id.txt', artifact / 'build-image-id.txt')
PY

find "$ROOT/artifact" -type f -printf '%P\t%s\n' | LC_ALL=C sort \
  > "$ROOT/artifact/FILE-INVENTORY.tsv"
(
  cd "$ROOT/artifact"
  find . -type f ! -name LOCKSUMS.sha256 -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum > LOCKSUMS.sha256
  sha256sum --check --strict LOCKSUMS.sha256
)
cp "$ROOT/output/summary.json" "$ROOT/output/final-summary.json"
trap - ERR
jq '.' "$ROOT/output/summary.json"
