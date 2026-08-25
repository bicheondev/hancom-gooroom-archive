#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/bin"

fail() {
  printf '[selftest] FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf '[selftest] PASS: %s\n' "$*" >&2
}

required=(
  hg-arm64-common.sh
  hg-arm64-state.sh
  hg-arm64-recover-pool.sh
  hg-arm64-finalize.sh
  hg-arm64-validate.sh
  hg-arm64-qemu-smoke.sh
)

for name in "${required[@]}"; do
  [[ -f "$BIN/$name" ]] || fail "missing $name"
  bash -n "$BIN/$name" || fail "bash syntax: $name"
done
pass 'all Bash programs parse'

for name in \
  hg-arm64-state.sh \
  hg-arm64-recover-pool.sh \
  hg-arm64-finalize.sh \
  hg-arm64-validate.sh \
  hg-arm64-qemu-smoke.sh
do
  bash "$BIN/$name" --help >/dev/null || fail "--help smoke: $name"
done
pass 'all public programs expose a non-destructive help path'

for command_name in dpkg-deb dpkg-scanpackages gzip sha256sum md5sum python3 file readelf; do
  command -v "$command_name" >/dev/null 2>&1 \
    || fail "missing test dependency: $command_name"
done

work="$(mktemp -d -t hg-arm64-selftest.XXXXXXXX)"
trap 'rm -rf "$work"' EXIT
input="$work/input"
output="$work/output"
mkdir -p "$input"

make_deb() {
  local package="$1" version="$2" architecture="$3" payload="$4" destination="$5"
  local root="$work/pkg-${package}-${architecture}-${RANDOM}"
  mkdir -p "$root/DEBIAN" "$root/usr/share/$package"
  cat > "$root/DEBIAN/control" <<EOF
Package: $package
Version: $version
Architecture: $architecture
Maintainer: ARM64 finalizer self-test <noreply@example.invalid>
Description: synthetic package for deterministic pool recovery tests
EOF
  printf '%s\n' "$payload" > "$root/usr/share/$package/payload.txt"
  dpkg-deb --build --root-owner-group "$root" "$destination" >/dev/null
}

make_deb demo-arm64 1.0 arm64 arm64 "$input/demo-arm64_1.0_arm64.deb"
make_deb demo-all 1.0 all all "$input/demo-all_1.0_all.deb"
make_deb demo-amd64 1.0 amd64 amd64 "$input/demo-amd64_1.0_amd64.deb"

bash "$BIN/hg-arm64-recover-pool.sh" \
  --input "$input" \
  --output "$output" \
  --suite selftest

accepted_count="$(awk 'END {print NR-1}' "$output/evidence/accepted.tsv")"
rejected_count="$(awk 'END {print NR-1}' "$output/evidence/rejected.tsv")"
[[ "$accepted_count" -eq 2 ]] || fail "expected 2 accepted packages, got $accepted_count"
[[ "$rejected_count" -eq 1 ]] || fail "expected 1 rejected package, got $rejected_count"
grep -F $'demo-arm64\t1.0\tarm64' "$output/evidence/accepted.tsv" >/dev/null \
  || fail 'arm64 package was not accepted'
grep -F $'demo-all\t1.0\tall' "$output/evidence/accepted.tsv" >/dev/null \
  || fail 'all package was not accepted'
grep -F $'foreign-architecture\tdemo-amd64_1.0_amd64.deb' "$output/evidence/rejected.tsv" >/dev/null \
  || fail 'amd64 package was not rejected'
grep -q '^Package: demo-arm64$' "$output/dists/selftest/main/binary-arm64/Packages" \
  || fail 'Packages index lacks demo-arm64'
grep -q '^Package: demo-all$' "$output/dists/selftest/main/binary-arm64/Packages" \
  || fail 'Packages index lacks demo-all'
(
  cd "$output"
  sha256sum --check --strict SHA256SUMS >/dev/null
) || fail 'package pool SHA256SUMS verification'
pass 'arm64/all packages accepted and amd64 package rejected'

conflict_input="$work/conflict-input"
mkdir -p "$conflict_input/a" "$conflict_input/b"
make_deb collision 1.0 arm64 first "$conflict_input/a/collision_1.0_arm64.deb"
make_deb collision 1.0 arm64 second "$conflict_input/b/collision_1.0_arm64.deb"
set +e
bash "$BIN/hg-arm64-recover-pool.sh" \
  --input "$conflict_input" \
  --output "$work/conflict-output" \
  > "$work/conflict.stdout" 2> "$work/conflict.stderr"
conflict_rc=$?
set -e
[[ "$conflict_rc" -ne 0 ]] || fail 'different payloads for one package tuple were not rejected'
pass 'tuple collision fails closed'

# shellcheck source=../bin/hg-arm64-common.sh
source "$BIN/hg-arm64-common.sh"
foreign_root="$work/foreign-root"
mkdir -p "$foreign_root/usr/bin"
cp /bin/true "$foreign_root/usr/bin/foreign-true"
if hg_scan_foreign_elf "$foreign_root" "$work/foreign.tsv"; then
  fail 'host ELF unexpectedly passed as AArch64'
fi
[[ -s "$work/foreign.tsv" ]] || fail 'foreign ELF evidence was not recorded'
pass 'foreign ELF scanner fails closed'

printf '[selftest] ALL TESTS PASSED\n'
