#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 EFFECTIVE_LOCK SOURCE OUTPUT_DIR" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
LOCK_JSON="$1"
SOURCE_NAME="$2"
OUTPUT_DIR="$3"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"
REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-arm64/locks/reference/amd64-reference.json}"
BOOTSTRAP_IMAGE="${HANCOM_GOOROOM_BOOTSTRAP_IMAGE:-arm64v8/debian:bullseye-slim@sha256:4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"

for command in jq python3 docker dpkg-source dpkg-parsechangelog dpkg-deb sha256sum; do
  command -v "$command" >/dev/null || {
    echo "required command missing: $command" >&2
    exit 69
  }
done
[ -f "$LOCK_JSON" ]
[ -f "$REFERENCE_JSON" ]
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

entry="$(jq -ce --arg source "$SOURCE_NAME" '
  .sources[]
  | select(
      .source == $source
      and .role == "rebuild-arm64"
      and .status == "resolved"
      and .selected.type == "dsc"
      and .selected.signature_valid == true
    )
' "$LOCK_JSON" | head -n1)"
[ -n "$entry" ] || {
  echo "No exact signed DSC rebuild lock for $SOURCE_NAME" >&2
  exit 2
}
SOURCE_VERSION="$(jq -r '.source_version' <<<"$entry")"
DSC_URL="$(jq -r '.selected.url' <<<"$entry")"
DSC_NAME="$(jq -r '.selected.dsc_name' <<<"$entry")"
DSC_SHA256="$(jq -r '.selected.dsc_sha256' <<<"$entry")"
DSC_SIZE="$(jq -r '.selected.dsc_size' <<<"$entry")"

EXPECTED_MAP="$(jq -c \
  --arg source "$SOURCE_NAME" \
  --arg version "$SOURCE_VERSION" '
    .packages
    | map(select(
        .source == $source
        and .source_version == $version
        and .architecture == "amd64"
      ))
    | map({key:.package,value:.version})
    | from_entries
  ' "$REFERENCE_JSON")"
EXPECTED_PACKAGES="$(jq -r 'keys | join(" ")' <<<"$EXPECTED_MAP")"
[ -n "$EXPECTED_PACKAGES" ] || {
  echo "No architecture-dependent AMD64 reference packages for $SOURCE_NAME" >&2
  exit 2
}

SOURCE_FILES="$WORK_DIR/source-files"
SOURCE_ROOT="$WORK_DIR/source-root"
mkdir -p "$SOURCE_FILES" "$SOURCE_ROOT"
printf '%s\n' "$entry" > "$OUTPUT_DIR/source-lock-entry.json"

python3 - "$OUTPUT_DIR/source-lock-entry.json" "$SOURCE_FILES" <<'PY'
from pathlib import Path
import hashlib, json, sys, time, urllib.error, urllib.request

entry = json.loads(Path(sys.argv[1]).read_text())
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
selected = entry['selected']
items = [{
    'name': selected['dsc_name'],
    'url': selected['url'],
    'size': int(selected['dsc_size']),
    'sha256': selected['dsc_sha256'].lower(),
}]
for component in selected['components']:
    items.append({
        'name': component['name'],
        'url': component['url'],
        'size': int(component['size']),
        'sha256': component['sha256'].lower(),
    })
records = []
for item in items:
    destination = out / Path(item['name']).name
    error = None
    for attempt in range(1, 6):
        digest = hashlib.sha256(); size = 0
        try:
            request = urllib.request.Request(item['url'], headers={
                'User-Agent': 'hancom-gooroom-arm64-dsc-builder-v2/1'
            })
            with urllib.request.urlopen(request, timeout=240) as response, destination.open('wb') as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk: break
                    handle.write(chunk); digest.update(chunk); size += len(chunk)
            actual = digest.hexdigest()
            if size != item['size']:
                raise RuntimeError(f"size {size} != {item['size']}")
            if actual != item['sha256']:
                raise RuntimeError(f"sha256 {actual} != {item['sha256']}")
            records.append({**item, 'actual_size': size, 'actual_sha256': actual, 'attempts': attempt})
            break
        except Exception as exc:
            error = f'{type(exc).__name__}: {exc}'
            destination.unlink(missing_ok=True)
            if attempt < 5: time.sleep(2 ** (attempt - 1))
    else:
        raise SystemExit(f"failed to download {item['url']}: {error}")
Path(sys.argv[2], 'download-evidence.json').write_text(json.dumps(records, indent=2) + '\n')
PY
cp "$SOURCE_FILES/download-evidence.json" "$OUTPUT_DIR/"

test "$(stat -c '%s' "$SOURCE_FILES/$DSC_NAME")" = "$DSC_SIZE"
printf '%s  %s\n' "$DSC_SHA256" "$SOURCE_FILES/$DSC_NAME" | sha256sum --check --strict

dpkg-source -x "$SOURCE_FILES/$DSC_NAME" "$SOURCE_ROOT" \
  > "$OUTPUT_DIR/dpkg-source-extract.log" 2>&1
DECLARED_SOURCE="$(dpkg-parsechangelog -l"$SOURCE_ROOT/debian/changelog" -S Source)"
DECLARED_VERSION="$(dpkg-parsechangelog -l"$SOURCE_ROOT/debian/changelog" -S Version)"
[ "$DECLARED_SOURCE" = "$SOURCE_NAME" ]
[ "$DECLARED_VERSION" = "$SOURCE_VERSION" ]

cat > "$OUTPUT_DIR/source-lock-evidence.json" <<EOF
{
  "schema": 1,
  "source": $(jq -Rn --arg v "$SOURCE_NAME" '$v'),
  "source_version": $(jq -Rn --arg v "$SOURCE_VERSION" '$v'),
  "provenance": "vendor-apt-exact-signed-dsc",
  "dsc_url": $(jq -Rn --arg v "$DSC_URL" '$v'),
  "dsc_name": $(jq -Rn --arg v "$DSC_NAME" '$v'),
  "dsc_sha256": $(jq -Rn --arg v "$DSC_SHA256" '$v'),
  "dsc_size": $DSC_SIZE,
  "signature_verified_by_recovery_lock": true,
  "declared_source": $(jq -Rn --arg v "$DECLARED_SOURCE" '$v'),
  "declared_version": $(jq -Rn --arg v "$DECLARED_VERSION" '$v')
}
EOF
printf '%s\n' "$BOOTSTRAP_IMAGE" > "$OUTPUT_DIR/bootstrap-image.txt"

cat > "$WORK_DIR/build-inside.sh" <<'INNER'
#!/usr/bin/env bash
set -Eeuo pipefail
: "${SNAPSHOT:?}"
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
mkdir -p /out
[ "$(dpkg --print-architecture)" = arm64 ]

cat > /etc/apt/sources.list <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
rm -f /etc/apt/sources.list.d/*
cat > /etc/apt/apt.conf.d/99snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates debootstrap debian-archive-keyring xz-utils

ROOT=/snapshot-root
rm -rf "$ROOT"; mkdir -p "$ROOT"
debootstrap \
  --arch=arm64 --variant=buildd \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  --include=ca-certificates,debian-archive-keyring \
  bullseye "$ROOT" \
  "http://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
  > /out/debootstrap.log 2>&1
cat > "$ROOT/etc/apt/sources.list" <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
cat > "$ROOT/etc/apt/apt.conf.d/99snapshot" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
APT::Get::Assume-Yes "true";
Dpkg::Use-Pty "0";
EOF
cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"
mkdir -p "$ROOT/build/source" "$ROOT/build/output"
cp -a /src/. "$ROOT/build/source/"

cat > "$ROOT/build/run-build.sh" <<'CHROOT'
#!/usr/bin/env bash
set -Eeuo pipefail
export HOME=/root LANG=C.UTF-8 LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true
export DEB_BUILD_OPTIONS="nocheck nodoc parallel=2"
export DEB_BUILD_PROFILES="pkg.nocheck nodoc"
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d
apt-get update
apt-get install -y --no-install-recommends \
  build-essential ca-certificates debhelper devscripts dpkg-dev \
  equivs fakeroot gnupg xz-utils
cd /build/source
export SOURCE_DATE_EPOCH="$(dpkg-parsechangelog -S Date | date -f - +%s)"
rm -f ./*-build-deps*.deb
mk-build-deps --build-dep debian/control
DUMMY="$(find . -maxdepth 1 -type f -name '*-build-deps*.deb' -print -quit)"
[ -n "$DUMMY" ]
dpkg-deb -f "$DUMMY" Package Version Architecture Depends \
  > /build/output/build-dependency-metapackage.txt
set +e
apt-get -s --no-install-recommends -o Debug::pkgProblemResolver=yes \
  install "$DUMMY" > /build/output/apt-solver-simulation.log 2>&1
solver_rc=$?
set -e
cat /build/output/apt-solver-simulation.log
[ "$solver_rc" -eq 0 ]
apt-get install -y --no-install-recommends \
  -o Debug::pkgProblemResolver=yes "$DUMMY"
dpkg-checkbuilddeps -B
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
  | sort > /build/output/build-environment-packages.tsv
dpkg-buildpackage -us -uc -B -j2
find /build -maxdepth 1 -type f \
  \( -name '*.deb' -o -name '*.buildinfo' -o -name '*.changes' \) \
  -exec cp -v '{}' /build/output/ \;
CHROOT
chmod +x "$ROOT/build/run-build.sh"
cleanup() {
  umount -R "$ROOT/dev" 2>/dev/null || true
  umount "$ROOT/proc" 2>/dev/null || true
  umount "$ROOT/sys" 2>/dev/null || true
}
trap cleanup EXIT
mount --rbind /dev "$ROOT/dev"; mount --make-rslave "$ROOT/dev"
mount -t proc proc "$ROOT/proc"
mount -t sysfs sysfs "$ROOT/sys"
set +e
chroot "$ROOT" /bin/bash /build/run-build.sh \
  > >(tee /out/chroot-build.log) \
  2> >(tee /out/chroot-build.stderr.log >&2)
rc=$?
set -e
cp -av "$ROOT/build/output/." /out/ || true
exit "$rc"
INNER
chmod +x "$WORK_DIR/build-inside.sh"

docker run --rm --privileged --platform linux/arm64 \
  --env "SNAPSHOT=$SNAPSHOT" \
  --volume "$SOURCE_ROOT:/src:ro" \
  --volume "$WORK_DIR/build-inside.sh:/build-inside.sh:ro" \
  --volume "$OUTPUT_DIR:/out:rw" \
  "$BOOTSTRAP_IMAGE" /bin/bash /build-inside.sh

shopt -s nullglob
DEBS=("$OUTPUT_DIR"/*.deb)
[ "${#DEBS[@]}" -gt 0 ] || { echo "No DEB outputs" >&2; exit 4; }
produced=()
for deb in "${DEBS[@]}"; do
  package="$(dpkg-deb -f "$deb" Package)"
  version="$(dpkg-deb -f "$deb" Version)"
  architecture="$(dpkg-deb -f "$deb" Architecture)"
  case "$architecture" in arm64|all) ;; *) exit 5 ;; esac
  expected="$(jq -r --arg package "$package" '.[$package] // empty' <<<"$EXPECTED_MAP")"
  if [ -n "$expected" ] && [ "$version" != "$expected" ]; then
    echo "$package version $version != $expected" >&2
    exit 5
  fi
  produced+=("$package")
done
for expected in $EXPECTED_PACKAGES; do
  printf '%s\n' "${produced[@]}" | grep -Fxq "$expected" || {
    echo "Expected native package missing: $expected" >&2
    exit 6
  }
done

cat > "$OUTPUT_DIR/build-lock.json" <<EOF
{
  "schema": 1,
  "source": $(jq -Rn --arg v "$SOURCE_NAME" '$v'),
  "source_version": $(jq -Rn --arg v "$SOURCE_VERSION" '$v'),
  "provenance": "vendor-apt-exact-signed-dsc",
  "dsc_sha256": $(jq -Rn --arg v "$DSC_SHA256" '$v'),
  "target_architecture": "arm64",
  "debian_snapshot": $(jq -Rn --arg v "$SNAPSHOT" '$v'),
  "bootstrap_image": $(jq -Rn --arg v "$BOOTSTRAP_IMAGE" '$v'),
  "expected_binary_versions": $EXPECTED_MAP,
  "produced_binary_packages": $(printf '%s\n' "${produced[@]}" | jq -Rsc 'split("\n")[:-1] | unique | sort')
}
EOF
find "$OUTPUT_DIR" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | sort -z | xargs -0 sha256sum > "$OUTPUT_DIR/SHA256SUMS"
cat "$OUTPUT_DIR/build-lock.json"
