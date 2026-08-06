#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 PACKAGE_REPOSITORY RECOVERY_JSON ROOTFS OUTPUT_DIR" >&2
  exit 64
}
[ "$#" -eq 4 ] || usage
REPOSITORY="$1"
RECOVERY_JSON="$2"
ROOTFS="$3"
OUTPUT_DIR="$4"
SNAPSHOT="${HANCOM_GOOROOM_DEBIAN_SNAPSHOT:-20230730T235959Z}"

[ "$(id -u)" -eq 0 ] || { echo 'root required' >&2; exit 77; }
case "$(uname -m)" in aarch64|arm64) ;; *) echo 'native ARM64 required' >&2; exit 78;; esac
for command in jq mmdebstrap chroot mount umount dpkg-query python3; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 69; }
done

REPOSITORY="$(cd "$REPOSITORY" && pwd)"
RECOVERY_JSON="$(cd "$(dirname "$RECOVERY_JSON")" && pwd)/$(basename "$RECOVERY_JSON")"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"
ROOTFS="$(cd "$ROOTFS" && pwd)"

jq -e '
  .summary.repository_ready == true
  and .summary.blocker_count == 0
  and (.summary.selected_package_count + .summary.excluded_package_count == .summary.reference_package_count)
' "$RECOVERY_JSON" >/dev/null
[ -f "$REPOSITORY/Packages" ]

python3 - "$RECOVERY_JSON" "$OUTPUT_DIR/install-specs.txt" "$OUTPUT_DIR/expected.json" <<'PY'
import json,sys
from pathlib import Path
doc=json.loads(Path(sys.argv[1]).read_text())
expected={}
for row in doc.get('selected',[]):
    package=row['target_package']
    candidate=row['candidate']
    version=candidate['version']
    architecture=candidate['architecture']
    current=expected.get(package)
    identity=(version,architecture)
    if current and tuple(current)!=identity:
        raise SystemExit(f'conflicting identity for {package}: {current} vs {identity}')
    expected[package]=list(identity)
Path(sys.argv[2]).write_text(''.join(f'{p}={v[0]}\n' for p,v in sorted(expected.items())))
Path(sys.argv[3]).write_text(json.dumps(expected,indent=2)+'\n')
print(json.dumps({'install_spec_count':len(expected)},indent=2))
PY

test -s "$OUTPUT_DIR/install-specs.txt"
mmdebstrap \
  --mode=root \
  --architectures=arm64 \
  --variant=minbase \
  --aptopt='Acquire::Check-Valid-Until "false"' \
  --aptopt='Acquire::Retries "5"' \
  bullseye "$ROOTFS" \
  "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free" \
  2>&1 | tee "$OUTPUT_DIR/mmdebstrap.log"

mkdir -p "$ROOTFS/mnt/exact-packages" "$ROOTFS/tmp/exact-rootfs" \
  "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" "$ROOTFS/run"
cp "$RECOVERY_JSON" "$ROOTFS/tmp/exact-rootfs/recovery.json"
cp "$OUTPUT_DIR/install-specs.txt" "$ROOTFS/tmp/exact-rootfs/install-specs.txt"
cp "$OUTPUT_DIR/expected.json" "$ROOTFS/tmp/exact-rootfs/expected.json"
rm -f "$ROOTFS/etc/resolv.conf"
cp -L /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb [trusted=yes] file:/mnt/exact-packages ./
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bullseye-security main contrib non-free
EOF
rm -f "$ROOTFS/etc/apt/sources.list.d/"*
cat > "$ROOTFS/etc/apt/apt.conf.d/99exact-arm64" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
Dpkg::Use-Pty "0";
EOF
cat > "$ROOTFS/usr/sbin/policy-rc.d" <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 0755 "$ROOTFS/usr/sbin/policy-rc.d"

cat > "$ROOTFS/tmp/exact-rootfs/install.sh" <<'CHROOT'
#!/bin/bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
apt-get update
mapfile -t specs < /tmp/exact-rootfs/install-specs.txt
[ "${#specs[@]}" -gt 0 ]
apt-get install -y --allow-downgrades --allow-change-held-packages \
  -o Debug::pkgProblemResolver=yes "${specs[@]}"
dpkg --configure -a
dpkg --audit
if command -v update-initramfs >/dev/null; then update-initramfs -u -k all; fi
ldconfig
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  | sort > /tmp/exact-rootfs/installed.tsv
apt-cache policy > /tmp/exact-rootfs/apt-policy.txt
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
CHROOT
chmod 0755 "$ROOTFS/tmp/exact-rootfs/install.sh"

mounted=()
cleanup() {
  set +e
  for target in "${mounted[@]}"; do
    umount -R "$target" 2>/dev/null || umount -l "$target" 2>/dev/null || true
  done
}
trap cleanup EXIT
mount --bind "$REPOSITORY" "$ROOTFS/mnt/exact-packages"; mounted=("$ROOTFS/mnt/exact-packages")
mount -t proc proc "$ROOTFS/proc"; mounted=("$ROOTFS/proc" "${mounted[@]}")
mount -t sysfs sysfs "$ROOTFS/sys"; mounted=("$ROOTFS/sys" "${mounted[@]}")
mount --rbind /dev "$ROOTFS/dev"; mount --make-rslave "$ROOTFS/dev"; mounted=("$ROOTFS/dev" "${mounted[@]}")
mount --rbind /run "$ROOTFS/run"; mount --make-rslave "$ROOTFS/run"; mounted=("$ROOTFS/run" "${mounted[@]}")
set +e
chroot "$ROOTFS" /bin/bash /tmp/exact-rootfs/install.sh \
  > >(tee "$OUTPUT_DIR/install.log") \
  2> >(tee "$OUTPUT_DIR/install.stderr.log" >&2)
rc=$?
set -e
cp "$ROOTFS/tmp/exact-rootfs/installed.tsv" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$ROOTFS/tmp/exact-rootfs/apt-policy.txt" "$OUTPUT_DIR/" 2>/dev/null || true
[ "$rc" -eq 0 ] || exit "$rc"
cleanup; mounted=(); trap - EXIT

python3 - "$ROOTFS" "$OUTPUT_DIR/expected.json" "$OUTPUT_DIR/rootfs-verification.json" <<'PY'
import json,os,struct,sys
from pathlib import Path
root=Path(sys.argv[1]);expected=json.loads(Path(sys.argv[2]).read_text())
status=(root/'var/lib/dpkg/status').read_text(errors='replace')
stanzas=[];current={};key=None
for line in status.splitlines()+['']:
    if not line.strip():
        if current:stanzas.append(current)
        current={};key=None;continue
    if line[:1].isspace():
        if key:current[key]+='\n'+line[1:]
    elif ':' in line:
        key,value=line.split(':',1);current[key]=value.lstrip()
installed={s['Package']:(s.get('Version',''),s.get('Architecture','')) for s in stanzas if s.get('Status')=='install ok installed' and s.get('Package')}
missing=[];mismatch=[]
for package,(version,arch) in expected.items():
    if package not in installed:missing.append(package)
    elif installed[package]!=(version,arch):mismatch.append({'package':package,'expected':[version,arch],'installed':list(installed[package])})
def elf(path):
    try:data=path.open('rb').read(20)
    except:return None
    if len(data)<20 or data[:4]!=b'\x7fELF':return None
    return struct.unpack('<H' if data[5]==1 else '>H',data[18:20])[0]
x86=[];foreign=[];machines={}
for directory,_,files in os.walk(root,followlinks=False):
    rel=Path(directory).relative_to(root)
    if rel.parts and rel.parts[0] in {'proc','sys','dev','run','mnt'}:continue
    for filename in files:
        p=Path(directory)/filename
        if p.is_symlink():continue
        machine=elf(p)
        if machine is None:continue
        name={3:'i386',40:'arm32',62:'x86_64',183:'aarch64',247:'bpf'}.get(machine,str(machine));machines[name]=machines.get(name,0)+1
        row={'path':str(p.relative_to(root)),'machine':name,'size':p.stat().st_size}
        if machine in {3,62}:x86.append(row)
        elif machine not in {0,183,247}:foreign.append(row)
kernels=sorted(str(p.relative_to(root)) for p in (root/'boot').glob('vmlinuz-*')) if (root/'boot').exists() else []
initrds=sorted(str(p.relative_to(root)) for p in (root/'boot').glob('initrd.img-*')) if (root/'boot').exists() else []
result={'schema':1,'expected_count':len(expected),'installed_count':len(installed),'missing':missing,'mismatches':mismatch,'extra_dependency_packages':sorted(set(installed)-set(expected)),'elf_machine_counts':machines,'x86_elf':x86,'foreign_elf':foreign,'kernels':kernels,'initrds':initrds,'passed':not missing and not mismatch and not x86 and not foreign and bool(kernels) and bool(initrds)}
Path(sys.argv[3]).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
if not result['passed']:raise SystemExit(2)
PY

rm -f "$ROOTFS/usr/sbin/policy-rc.d"
rm -rf "$ROOTFS/tmp/exact-rootfs"
rm -f "$ROOTFS/etc/machine-id"; : > "$ROOTFS/etc/machine-id"
rm -f "$ROOTFS/var/lib/dbus/machine-id"; ln -s /etc/machine-id "$ROOTFS/var/lib/dbus/machine-id"
rm -f "$ROOTFS/etc/ssh/ssh_host_"* "$ROOTFS/var/lib/systemd/random-seed" 2>/dev/null || true
cat > "$OUTPUT_DIR/rootfs-build.json" <<EOF
{
  "schema": 1,
  "policy": "recovered-exact-package-pool-plus-arm64-dependency-closure",
  "architecture": "arm64",
  "debian_snapshot": $(jq -Rn --arg v "$SNAPSHOT" '$v'),
  "recovery_sha256": $(sha256sum "$RECOVERY_JSON" | awk '{print "\""$1"\""}'),
  "packages_index_sha256": $(sha256sum "$REPOSITORY/Packages" | awk '{print "\""$1"\""}')
}
EOF
