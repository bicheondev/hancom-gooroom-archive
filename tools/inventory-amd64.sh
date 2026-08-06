#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: inventory-amd64.sh <amd64.iso> <output-dir> [work-dir]

Extracts a Hancom Gooroom AMD64 ISO and creates a deterministic inventory used
as the version and architecture baseline for the ARM64 port.
EOF
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage >&2
  exit 64
fi

ISO_PATH="$(realpath "$1")"
OUT_DIR="$(mkdir -p "$2" && realpath "$2")"
WORK_DIR="${3:-$(mktemp -d)}"
mkdir -p "$WORK_DIR"
WORK_DIR="$(realpath "$WORK_DIR")"
ISO_TREE="$WORK_DIR/iso"
ROOTFS="$WORK_DIR/rootfs"

for command in xorriso unsquashfs dpkg-query file sha256sum python3 jq; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 69
  }
done

if [[ ! -f "$ISO_PATH" ]]; then
  echo "ISO does not exist: $ISO_PATH" >&2
  exit 66
fi

rm -rf "$ISO_TREE" "$ROOTFS"
mkdir -p "$ISO_TREE" "$ROOTFS" "$OUT_DIR/apt" "$OUT_DIR/iso-manifests"

ISO_SHA256="$(sha256sum "$ISO_PATH" | awk '{print $1}')"
ISO_SIZE="$(stat -c '%s' "$ISO_PATH")"
printf '%s  %s\n' "$ISO_SHA256" "$(basename "$ISO_PATH")" > "$OUT_DIR/SHA256SUMS"
printf '%s\n' "$ISO_SIZE" > "$OUT_DIR/iso-size-bytes.txt"

# xorriso extraction works without loop mounting and therefore also works on
# restricted CI runners.
xorriso -osirrox on -indev "$ISO_PATH" -extract / "$ISO_TREE" \
  >"$OUT_DIR/xorriso-extract.log" 2>&1

xorriso -indev "$ISO_PATH" -report_el_torito as_mkisofs \
  >"$OUT_DIR/iso-eltorito.txt" 2>&1 || true
xorriso -indev "$ISO_PATH" -report_system_area plain \
  >"$OUT_DIR/iso-system-area.txt" 2>&1 || true

(
  cd "$ISO_TREE"
  find . -printf '%y\t%s\t%P\n' | LC_ALL=C sort
) > "$OUT_DIR/iso-layout.tsv"

# Preserve small package/installer manifests already present on the ISO.
while IFS= read -r -d '' manifest; do
  relative="${manifest#"$ISO_TREE"/}"
  safe_name="${relative//\//__}"
  cp -a "$manifest" "$OUT_DIR/iso-manifests/$safe_name"
done < <(
  find "$ISO_TREE" -type f \
    \( -iname '*filesystem*.manifest*' \
       -o -iname '*filesystem*.packages*' \
       -o -iname '*package*.list*' \
       -o -path '*/.disk/*' \
       -o -path '*/isolinux/*.cfg' \
       -o -path '*/boot/grub/*.cfg' \) \
    -size -16M -print0
)

mapfile -d '' SQUASHFS_CANDIDATES < <(
  find "$ISO_TREE" -type f \
    \( -name '*.squashfs' -o -name 'filesystem.squashfs' \) \
    -print0
)

if [[ ${#SQUASHFS_CANDIDATES[@]} -eq 0 ]]; then
  echo "no SquashFS root filesystem found in ISO" >&2
  exit 65
fi

SQUASHFS_PATH=""
for candidate in "${SQUASHFS_CANDIDATES[@]}"; do
  if [[ "$candidate" == */live/filesystem.squashfs ]]; then
    SQUASHFS_PATH="$candidate"
    break
  fi
done

if [[ -z "$SQUASHFS_PATH" ]]; then
  # Select the largest image when the conventional live path is absent.
  SQUASHFS_PATH="$(
    for candidate in "${SQUASHFS_CANDIDATES[@]}"; do
      printf '%s\t%s\n' "$(stat -c '%s' "$candidate")" "$candidate"
    done | sort -nr | head -n1 | cut -f2-
  )"
fi

printf '%s\n' "${SQUASHFS_PATH#"$ISO_TREE"/}" > "$OUT_DIR/squashfs-path.txt"
unsquashfs -s "$SQUASHFS_PATH" > "$OUT_DIR/squashfs-superblock.txt"
sudo unsquashfs -no-progress -d "$ROOTFS" "$SQUASHFS_PATH" \
  >"$OUT_DIR/unsquashfs.log" 2>&1

for release_file in etc/os-release usr/lib/os-release etc/debian_version etc/lsb-release; do
  if [[ -f "$ROOTFS/$release_file" ]]; then
    mkdir -p "$OUT_DIR/rootfs-release/$(dirname "$release_file")"
    cp -a "$ROOTFS/$release_file" "$OUT_DIR/rootfs-release/$release_file"
  fi
done

if [[ ! -f "$ROOTFS/var/lib/dpkg/status" ]]; then
  echo "root filesystem has no dpkg status database" >&2
  exit 65
fi

cp -a "$ROOTFS/var/lib/dpkg/status" "$OUT_DIR/dpkg-status"

# Use dpkg-query against the extracted package database. The Source field is
# retained exactly as recorded by the AMD64 build and is later normalized by
# resolve-source-lock.py.
dpkg-query --admindir="$ROOTFS/var/lib/dpkg" -W \
  -f='${binary:Package}\t${Version}\t${Architecture}\t${Source}\t${db:Status-Abbrev}\n' \
  | LC_ALL=C sort > "$OUT_DIR/packages.tsv"

awk -F '\t' 'BEGIN { IGNORECASE=1 }
  $1 ~ /(gooroom|hancom|hnc|hoffice|ahnlab)/ || $4 ~ /(gooroom|hancom|hnc|hoffice|ahnlab)/
' "$OUT_DIR/packages.tsv" > "$OUT_DIR/custom-packages.tsv"

if [[ -d "$ROOTFS/etc/apt" ]]; then
  cp -a "$ROOTFS/etc/apt/." "$OUT_DIR/apt/"
fi

if command -v chroot >/dev/null 2>&1 && [[ -x "$ROOTFS/usr/bin/apt-cache" ]]; then
  sudo chroot "$ROOTFS" /usr/bin/apt-cache policy \
    > "$OUT_DIR/apt-policy.txt" 2>&1 || true
fi

if [[ -d "$ROOTFS/boot" ]]; then
  (
    cd "$ROOTFS"
    find boot -maxdepth 3 -printf '%y\t%s\t%p\n' | LC_ALL=C sort
  ) > "$OUT_DIR/rootfs-boot-layout.tsv"
  while IFS= read -r -d '' boot_file; do
    printf '%s\t' "${boot_file#"$ROOTFS"}"
    file -b "$boot_file"
  done < <(find "$ROOTFS/boot" -type f -print0) \
    > "$OUT_DIR/rootfs-boot-file-types.tsv"
fi

# Copy installer logs/configuration when present. This is useful for detecting
# the exact live-build and installer layout without storing the full rootfs.
for source_dir in var/log/installer etc/live config; do
  if [[ -e "$ROOTFS/$source_dir" ]]; then
    mkdir -p "$OUT_DIR/rootfs-metadata/$(dirname "$source_dir")"
    cp -a "$ROOTFS/$source_dir" "$OUT_DIR/rootfs-metadata/$source_dir"
  fi
done

ROOTFS="$ROOTFS" OUT_DIR="$OUT_DIR" ISO_SHA256="$ISO_SHA256" ISO_SIZE="$ISO_SIZE" \
python3 <<'PY'
from __future__ import annotations

import csv
import json
import os
import pathlib
import re
from collections import Counter, defaultdict

root = pathlib.Path(os.environ["ROOTFS"])
out = pathlib.Path(os.environ["OUT_DIR"])

MACHINES = {
    0: "none",
    2: "sparc",
    3: "i386",
    8: "mips",
    20: "powerpc",
    21: "powerpc64",
    40: "arm",
    50: "ia64",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}

# Build a file-to-package map from dpkg's authoritative *.list files.
owners: dict[str, list[str]] = defaultdict(list)
info_dir = root / "var/lib/dpkg/info"
if info_dir.is_dir():
    for list_file in sorted(info_dir.glob("*.list")):
        package = list_file.name[:-5]
        try:
            lines = list_file.read_text(errors="surrogateescape").splitlines()
        except OSError:
            continue
        for path in lines:
            if path:
                owners[path].append(package)

machine_counts: Counter[str] = Counter()
package_machines: dict[str, Counter[str]] = defaultdict(Counter)
elf_rows: list[tuple[str, str, int, str]] = []

for base, dirs, files in os.walk(root):
    dirs.sort()
    files.sort()
    for name in files:
        path = pathlib.Path(base) / name
        try:
            if path.is_symlink():
                continue
            with path.open("rb") as fh:
                header = fh.read(20)
        except (OSError, PermissionError):
            continue
        if len(header) < 20 or header[:4] != b"\x7fELF":
            continue
        elf_class = {1: 32, 2: 64}.get(header[4], 0)
        byteorder = {1: "little", 2: "big"}.get(header[5])
        if not byteorder:
            machine = "invalid-endian"
        else:
            machine_id = int.from_bytes(header[18:20], byteorder)
            machine = MACHINES.get(machine_id, f"machine-{machine_id}")
        rel = "/" + str(path.relative_to(root))
        package = ",".join(sorted(owners.get(rel, [])))
        machine_counts[machine] += 1
        if package:
            for pkg in package.split(","):
                package_machines[pkg][machine] += 1
        elf_rows.append((rel, machine, elf_class, package))

with (out / "elf-binaries.tsv").open("w", newline="") as fh:
    writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
    writer.writerow(["path", "machine", "class", "package"])
    writer.writerows(elf_rows)

with (out / "elf-package-summary.tsv").open("w", newline="") as fh:
    writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
    writer.writerow(["package", "machine", "count"])
    for package in sorted(package_machines):
        for machine, count in sorted(package_machines[package].items()):
            writer.writerow([package, machine, count])

# Parse the generated package inventory for high-level counts.
package_rows = []
with (out / "packages.tsv").open(newline="") as fh:
    for row in csv.reader(fh, delimiter="\t"):
        if len(row) < 5:
            continue
        package_rows.append(
            {
                "package": row[0],
                "version": row[1],
                "architecture": row[2],
                "source_raw": row[3],
                "status": row[4],
            }
        )

arch_counts = Counter(row["architecture"] for row in package_rows)
custom_re = re.compile(r"(?:gooroom|hancom|hnc|hoffice|ahnlab)", re.I)
custom = [
    row
    for row in package_rows
    if custom_re.search(row["package"] + " " + row["source_raw"])
]

os_release = {}
for candidate in (root / "etc/os-release", root / "usr/lib/os-release"):
    if candidate.is_file():
        for line in candidate.read_text(errors="replace").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            os_release[key] = value.strip().strip('"')
        break

summary = {
    "schema": 1,
    "iso": {
        "sha256": os.environ["ISO_SHA256"],
        "size_bytes": int(os.environ["ISO_SIZE"]),
    },
    "os_release": os_release,
    "installed_package_count": len(package_rows),
    "package_architecture_counts": dict(sorted(arch_counts.items())),
    "custom_package_count": len(custom),
    "custom_packages": custom,
    "elf_machine_counts": dict(sorted(machine_counts.items())),
}

(out / "inventory.json").write_text(
    json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
)
PY

# Keep the output deterministic and avoid root-owned artifact files.
sudo chown -R "$(id -u):$(id -g)" "$OUT_DIR"
find "$OUT_DIR" -type f -exec chmod u+rw,go+r {} +

echo "Inventory written to $OUT_DIR"
