#!/usr/bin/env python3
"""Build a real, boot-tested Hancom Gooroom 3.3 ARM64 stage0 ISO.

This stage deliberately does not claim package-for-package equivalence. It uses
an ARM64 Debian Bullseye live base and overlays only architecture-neutral files
from the SHA-256-pinned Hancom Gooroom 3.3 AMD64 reference. Every copied regular
file is inspected for ELF machine type; x86 ELF is never copied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


REFERENCE_SHA256 = "ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a"
REFERENCE_SIZE = 1566277632
SNAPSHOT = "20230730T235959Z"

OVERLAY_ROOTS = (
    "etc/skel",
    "etc/xdg",
    "etc/dconf",
    "etc/gdm3",
    "etc/lightdm",
    "etc/plymouth",
    "usr/local/share",
    "usr/share/backgrounds",
    "usr/share/desktop-base",
    "usr/share/gnome-background-properties",
    "usr/share/gooroom",
    "usr/share/hancom",
    "usr/share/icons",
    "usr/share/pixmaps",
    "usr/share/plymouth",
    "usr/share/sounds",
    "usr/share/themes",
    "var/lib/AccountsService/icons",
    "var/lib/AccountsService/users",
)

EXCLUDED_RELATIVE_PREFIXES = (
    "etc/xdg/autostart/at-spi",
    "etc/xdg/autostart/orca",
)


class BuildError(RuntimeError):
    pass


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    process = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        check=False,
        env=env,
    )
    if check and process.returncode:
        output = process.stdout[-12000:] if capture and process.stdout else ""
        raise BuildError(
            f"command failed ({process.returncode}): {' '.join(command)}\n{output}"
        )
    return process


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elf_machine(path: Path) -> int | None:
    try:
        with path.open("rb") as handle:
            header = handle.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    if header[5] == 1:
        return struct.unpack("<H", header[18:20])[0]
    if header[5] == 2:
        return struct.unpack(">H", header[18:20])[0]
    return -1


def copy_metadata(source: Path, destination: Path) -> None:
    info = source.lstat()
    if not destination.is_symlink():
        os.chmod(destination, stat.S_IMODE(info.st_mode), follow_symlinks=False)
    try:
        os.chown(destination, info.st_uid, info.st_gid, follow_symlinks=False)
    except PermissionError:
        pass


def iter_tree(reference: Path, relative_root: str) -> Iterable[tuple[Path, str]]:
    source_root = reference / relative_root
    if not source_root.exists() and not source_root.is_symlink():
        return
    yield source_root, relative_root
    if source_root.is_file() or source_root.is_symlink():
        return
    for root, directories, files in os.walk(source_root, topdown=True, followlinks=False):
        root_path = Path(root)
        retained = []
        for directory in directories:
            path = root_path / directory
            relative = str(path.relative_to(reference))
            if path.is_symlink():
                yield path, relative
            else:
                retained.append(directory)
                yield path, relative
        directories[:] = retained
        for filename in sorted(files):
            path = root_path / filename
            yield path, str(path.relative_to(reference))


def apply_overlay(reference: Path, target: Path, evidence_path: Path) -> dict[str, Any]:
    copied: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    seen: set[str] = set()

    for root in OVERLAY_ROOTS:
        for source, relative in iter_tree(reference, root):
            relative = relative.strip("/")
            if relative in seen:
                continue
            seen.add(relative)
            if any(
                relative == prefix or relative.startswith(prefix + "/")
                for prefix in EXCLUDED_RELATIVE_PREFIXES
            ):
                skipped.append({"path": relative, "reason": "explicit-exclusion"})
                continue
            destination = target / relative
            info = source.lstat()
            if stat.S_ISDIR(info.st_mode):
                destination.mkdir(parents=True, exist_ok=True)
                copy_metadata(source, destination)
                copied.append({"path": relative, "type": "directory"})
                continue
            if stat.S_ISLNK(info.st_mode):
                link_target = os.readlink(source)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    if destination.is_dir() and not destination.is_symlink():
                        shutil.rmtree(destination)
                    else:
                        destination.unlink()
                os.symlink(link_target, destination)
                copied.append(
                    {"path": relative, "type": "symlink", "target": link_target}
                )
                continue
            if not stat.S_ISREG(info.st_mode):
                skipped.append({"path": relative, "reason": "special-file"})
                continue
            machine = elf_machine(source)
            if machine is not None:
                # The reference is AMD64. Even AArch64-looking payloads must be
                # independently sourced and locked rather than trusted as an overlay.
                rejected.append(
                    {
                        "path": relative,
                        "reason": "ELF-payload-not-architecture-neutral",
                        "machine": machine,
                        "size": info.st_size,
                        "sha256": sha256_file(source),
                    }
                )
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and destination.is_dir():
                shutil.rmtree(destination)
            shutil.copyfile(source, destination)
            copy_metadata(source, destination)
            copied.append(
                {
                    "path": relative,
                    "type": "file",
                    "size": info.st_size,
                    "sha256": sha256_file(source),
                }
            )

    summary = {
        "schema": 1,
        "policy": "architecture-neutral-reference-overlay-only",
        "roots": list(OVERLAY_ROOTS),
        "copied_entry_count": len(copied),
        "copied_file_count": sum(row["type"] == "file" for row in copied),
        "copied_bytes": sum(row.get("size", 0) for row in copied),
        "rejected_elf_count": len(rejected),
        "skipped_count": len(skipped),
    }
    evidence = {
        "summary": summary,
        "copied": copied,
        "rejected_elf": rejected,
        "skipped": skipped,
    }
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def write_chroot_finalizer(rootfs: Path) -> Path:
    script = rootfs / "tmp/stage0-v6-finalize.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(
        r'''#!/bin/bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d

cat >/etc/apt/sources.list <<'EOF'
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20230730T235959Z/ bullseye main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20230730T235959Z/ bullseye-updates main contrib non-free
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20230730T235959Z/ bullseye-security main contrib non-free
EOF
cat >/etc/apt/apt.conf.d/99snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
Dpkg::Use-Pty "0";
EOF
apt-get update
apt-get install -y --no-install-recommends \
  systemd-sysv linux-image-arm64 initramfs-tools live-boot live-config \
  locales sudo network-manager openssh-client ca-certificates curl wget \
  xserver-xorg xserver-xorg-video-all xserver-xorg-input-all \
  gdm3 gnome-session gnome-shell gnome-control-center \
  gnome-terminal nautilus file-roller eog evince gedit \
  gnome-system-monitor gnome-calculator gnome-screenshot \
  policykit-1 dbus-x11 udisks2 upower \
  fonts-noto-cjk fonts-noto-color-emoji fonts-dejavu-core \
  plymouth plymouth-themes desktop-base adwaita-icon-theme \
  linux-cpupower pciutils usbutils less vim-tiny

echo 'ko_KR.UTF-8 UTF-8' >/etc/locale.gen
locale-gen
update-locale LANG=ko_KR.UTF-8
printf 'hancom-gooroom\n' >/etc/hostname
cat >/etc/hosts <<'EOF'
127.0.0.1 localhost
127.0.1.1 hancom-gooroom
::1 localhost ip6-localhost ip6-loopback
EOF

mkdir -p /etc/live/config.conf.d
cat >/etc/live/config.conf.d/99-hancom-gooroom-stage0.conf <<'EOF'
LIVE_HOSTNAME="hancom-gooroom"
LIVE_USERNAME="gooroom"
LIVE_USER_FULLNAME="Hancom Gooroom Live User"
LIVE_LOCALES="ko_KR.UTF-8"
LIVE_KEYBOARD_LAYOUTS="kr"
EOF

mkdir -p /usr/local/sbin /etc/systemd/system/graphical.target.wants
cat >/usr/local/sbin/hancom-gooroom-stage0-marker <<'EOF'
#!/bin/sh
printf '%s\n' 'HANCOM_GOOROOM_3_3_ARM64_STAGE0_V6_BOOT_OK' >/dev/console 2>/dev/null || true
printf '%s\n' 'HANCOM_GOOROOM_3_3_ARM64_STAGE0_V6_BOOT_OK' >/dev/ttyAMA0 2>/dev/null || true
if systemctl is-active --quiet display-manager.service; then
  printf '%s\n' 'HANCOM_GOOROOM_3_3_ARM64_STAGE0_V6_GRAPHICAL_OK' >/dev/console 2>/dev/null || true
  printf '%s\n' 'HANCOM_GOOROOM_3_3_ARM64_STAGE0_V6_GRAPHICAL_OK' >/dev/ttyAMA0 2>/dev/null || true
fi
EOF
chmod 0755 /usr/local/sbin/hancom-gooroom-stage0-marker
cat >/etc/systemd/system/hancom-gooroom-stage0-marker.service <<'EOF'
[Unit]
Description=Hancom Gooroom ARM64 stage0 CI marker
After=display-manager.service graphical.target
Wants=display-manager.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for n in $(seq 1 60); do systemctl is-active --quiet display-manager.service && break; sleep 2; done; exec /usr/local/sbin/hancom-gooroom-stage0-marker'
RemainAfterExit=yes

[Install]
WantedBy=graphical.target
EOF
ln -sfn ../hancom-gooroom-stage0-marker.service \
  /etc/systemd/system/graphical.target.wants/hancom-gooroom-stage0-marker.service
systemctl set-default graphical.target

if command -v glib-compile-schemas >/dev/null; then
  glib-compile-schemas /usr/share/glib-2.0/schemas || true
fi
if command -v update-desktop-database >/dev/null; then
  update-desktop-database /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null; then
  find /usr/share/icons -mindepth 1 -maxdepth 1 -type d -exec test -f '{}/index.theme' ';' -print \
    | while read -r theme; do gtk-update-icon-cache -f -t "$theme" || true; done
fi
fc-cache -f || true
ldconfig
update-initramfs -u -k all

dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  | sort >/tmp/stage0-v6-packages.tsv
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
rm -f /usr/sbin/policy-rc.d
rm -f /etc/machine-id
: >/etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id
rm -f /etc/ssh/ssh_host_* /var/lib/systemd/random-seed 2>/dev/null || true
''',
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def mount_chroot(rootfs: Path) -> list[Path]:
    mounts: list[Path] = []
    for name in ("proc", "sys", "dev", "run"):
        (rootfs / name).mkdir(parents=True, exist_ok=True)
    run(["mount", "-t", "proc", "proc", str(rootfs / "proc")])
    mounts.append(rootfs / "proc")
    run(["mount", "-t", "sysfs", "sysfs", str(rootfs / "sys")])
    mounts.append(rootfs / "sys")
    run(["mount", "--rbind", "/dev", str(rootfs / "dev")])
    run(["mount", "--make-rslave", str(rootfs / "dev")])
    mounts.append(rootfs / "dev")
    run(["mount", "--rbind", "/run", str(rootfs / "run")])
    run(["mount", "--make-rslave", str(rootfs / "run")])
    mounts.append(rootfs / "run")
    return mounts


def unmount_all(mounts: list[Path]) -> None:
    for path in reversed(mounts):
        run(["umount", "-R", str(path)], check=False)
        run(["umount", "-l", str(path)], check=False)


def build_iso(rootfs: Path, output_iso: Path, evidence: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="stage0-v6-iso-") as temporary:
        work = Path(temporary)
        iso_root = work / "iso"
        (iso_root / "live").mkdir(parents=True)
        (iso_root / "boot/grub").mkdir(parents=True)
        (iso_root / ".disk").mkdir(parents=True)

        kernels = sorted((rootfs / "boot").glob("vmlinuz-*"))
        initrds = sorted((rootfs / "boot").glob("initrd.img-*"))
        if not kernels or not initrds:
            raise BuildError("ARM64 kernel or initramfs missing from rootfs")
        shutil.copyfile(kernels[-1], iso_root / "live/vmlinuz")
        shutil.copyfile(initrds[-1], iso_root / "live/initrd.img")

        run(
            [
                "mksquashfs",
                str(rootfs),
                str(iso_root / "live/filesystem.squashfs"),
                "-noappend",
                "-comp",
                "xz",
                "-b",
                "1M",
                "-Xdict-size",
                "100%",
                "-all-root",
                "-all-time",
                "0",
                "-mkfs-time",
                "0",
                "-processors",
                str(max(1, os.cpu_count() or 1)),
            ]
        )
        size = sum(
            path.stat().st_size
            for path in rootfs.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        (iso_root / "live/filesystem.size").write_text(str(size) + "\n")
        (iso_root / ".disk/info").write_text(
            "Hancom Gooroom 3.3 ARM64 stage0 v6\n", encoding="utf-8"
        )

        grub_cfg = r'''set default=0
set timeout=5
set timeout_style=menu

menuentry "Hancom Gooroom 3.3 ARM64 stage0 v6" {
  linux /live/vmlinuz boot=live components quiet splash locales=ko_KR.UTF-8 keyboard-layouts=kr console=tty0 console=ttyAMA0,115200
  initrd /live/initrd.img
}
menuentry "Hancom Gooroom 3.3 ARM64 stage0 v6 (serial diagnostics)" {
  linux /live/vmlinuz boot=live components systemd.unit=graphical.target console=ttyAMA0,115200
  initrd /live/initrd.img
}
'''
        (iso_root / "boot/grub/grub.cfg").write_text(grub_cfg, encoding="utf-8")
        embedded = work / "embedded.cfg"
        embedded.write_text(
            "search --no-floppy --label --set=root HGOOROOM33A64\n"
            "set prefix=($root)/boot/grub\n"
            "configfile /boot/grub/grub.cfg\n",
            encoding="utf-8",
        )
        boot_efi = work / "BOOTAA64.EFI"
        run(
            [
                "grub-mkstandalone",
                "-O",
                "arm64-efi",
                "--modules=part_gpt part_msdos fat iso9660 normal linux configfile search search_label all_video gfxterm font echo test",
                "--locales=",
                "--themes=",
                "-o",
                str(boot_efi),
                f"boot/grub/grub.cfg={embedded}",
            ]
        )
        efi_img = iso_root / "boot/grub/efi.img"
        run(["truncate", "-s", "32M", str(efi_img)])
        run(["mkfs.vfat", "-F", "16", "-n", "HGOOROOMEFI", str(efi_img)])
        run(["mmd", "-i", str(efi_img), "::/EFI", "::/EFI/BOOT"])
        run(
            [
                "mcopy",
                "-i",
                str(efi_img),
                str(boot_efi),
                "::/EFI/BOOT/BOOTAA64.EFI",
            ]
        )

        output_iso.parent.mkdir(parents=True, exist_ok=True)
        run(
            [
                "xorriso",
                "-as",
                "mkisofs",
                "-r",
                "-J",
                "-joliet-long",
                "-V",
                "HGOOROOM33A64",
                "-o",
                str(output_iso),
                "-e",
                "boot/grub/efi.img",
                "-no-emul-boot",
                "-isohybrid-gpt-basdat",
                str(iso_root),
            ]
        )

        efi_file = run(["file", "-b", str(boot_efi)], capture=True).stdout.strip()
        if "aarch64" not in efi_file.lower() and "arm64" not in efi_file.lower():
            raise BuildError(f"BOOTAA64.EFI is not AArch64: {efi_file}")
        evidence.update(
            {
                "kernel": kernels[-1].name,
                "initrd": initrds[-1].name,
                "bootaa64_file": efi_file,
                "iso_size": output_iso.stat().st_size,
                "iso_sha256": sha256_file(output_iso),
                "squashfs_size": (iso_root / "live/filesystem.squashfs").stat().st_size,
            }
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-iso", type=Path, required=True)
    parser.add_argument("--output-iso", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("root privileges are required")
    machine = os.uname().machine
    if machine not in {"aarch64", "arm64"}:
        raise SystemExit(f"native ARM64 host required, got {machine}")
    if args.reference_iso.stat().st_size != REFERENCE_SIZE:
        raise BuildError("reference ISO size mismatch")
    actual_reference_sha = sha256_file(args.reference_iso)
    if actual_reference_sha != REFERENCE_SHA256:
        raise BuildError(
            f"reference ISO SHA-256 mismatch: {actual_reference_sha} != {REFERENCE_SHA256}"
        )

    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    iso_root = args.work_dir / "reference-iso"
    reference_rootfs = args.work_dir / "reference-rootfs"
    rootfs = args.work_dir / "arm64-rootfs"
    for path in (iso_root, reference_rootfs, rootfs):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)

    run(
        [
            "xorriso",
            "-osirrox",
            "on",
            "-indev",
            str(args.reference_iso),
            "-extract",
            "/",
            str(iso_root),
        ]
    )
    squashfs = next(iter(iso_root.rglob("filesystem.squashfs")), None)
    if squashfs is None:
        raise BuildError("reference filesystem.squashfs was not found")
    run(["unsquashfs", "-d", str(reference_rootfs), str(squashfs)])

    run(
        [
            "mmdebstrap",
            "--mode=root",
            "--architectures=arm64",
            "--variant=minbase",
            '--aptopt=Acquire::Check-Valid-Until "false"',
            '--aptopt=Acquire::Retries "5"',
            "bullseye",
            str(rootfs),
            f"deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/{SNAPSHOT}/ bullseye main contrib non-free",
            f"deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/{SNAPSHOT}/ bullseye-updates main contrib non-free",
            f"deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/{SNAPSHOT}/ bullseye-security main contrib non-free",
        ]
    )

    shutil.copyfile("/etc/resolv.conf", rootfs / "etc/resolv.conf")
    write_chroot_finalizer(rootfs)
    mounts = mount_chroot(rootfs)
    try:
        process = run(
            ["chroot", str(rootfs), "/bin/bash", "/tmp/stage0-v6-finalize.sh"],
            check=False,
            capture=True,
        )
        (args.evidence_dir / "chroot-finalize.log").write_text(
            process.stdout or "", encoding="utf-8"
        )
        if process.returncode:
            raise BuildError(
                f"ARM64 rootfs finalizer failed ({process.returncode})\n"
                + (process.stdout or "")[-12000:]
            )
        package_evidence = rootfs / "tmp/stage0-v6-packages.tsv"
        if package_evidence.exists():
            shutil.copyfile(
                package_evidence, args.evidence_dir / "installed-packages.tsv"
            )
    finally:
        unmount_all(mounts)

    overlay_summary = apply_overlay(
        reference_rootfs,
        rootfs,
        args.evidence_dir / "reference-overlay.json",
    )

    # Regenerate caches after the architecture-neutral reference overlay.
    mounts = mount_chroot(rootfs)
    try:
        command = (
            "set -e; "
            "glib-compile-schemas /usr/share/glib-2.0/schemas || true; "
            "update-desktop-database /usr/share/applications || true; "
            "fc-cache -f || true; ldconfig; update-initramfs -u -k all"
        )
        process = run(
            ["chroot", str(rootfs), "/bin/bash", "-lc", command],
            check=False,
            capture=True,
        )
        (args.evidence_dir / "post-overlay-cache.log").write_text(
            process.stdout or "", encoding="utf-8"
        )
        if process.returncode:
            raise BuildError("post-overlay cache/initramfs regeneration failed")
    finally:
        unmount_all(mounts)

    # Audit the completed rootfs and reject any x86 ELF that could have entered
    # through either Debian installation or reference overlay.
    machine_counts: dict[str, int] = {}
    x86: list[dict[str, Any]] = []
    for path in rootfs.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        machine_value = elf_machine(path)
        if machine_value is None:
            continue
        name = {3: "i386", 62: "x86_64", 183: "aarch64", 247: "bpf"}.get(
            machine_value, str(machine_value)
        )
        machine_counts[name] = machine_counts.get(name, 0) + 1
        if machine_value in {3, 62}:
            x86.append(
                {
                    "path": str(path.relative_to(rootfs)),
                    "machine": name,
                    "size": path.stat().st_size,
                }
            )
    rootfs_audit = {
        "schema": 1,
        "elf_machine_counts": dict(sorted(machine_counts.items())),
        "x86_elf_count": len(x86),
        "x86_elf": x86,
        "passed": len(x86) == 0 and machine_counts.get("aarch64", 0) > 0,
    }
    (args.evidence_dir / "rootfs-elf-audit.json").write_text(
        json.dumps(rootfs_audit, indent=2) + "\n", encoding="utf-8"
    )
    if not rootfs_audit["passed"]:
        raise BuildError(
            f"rootfs ELF audit failed: {len(x86)} x86 files; "
            f"machines={machine_counts}"
        )

    evidence: dict[str, Any] = {
        "schema": 1,
        "status": "stage0-not-final-equivalence",
        "reference_iso": {
            "size": REFERENCE_SIZE,
            "sha256": REFERENCE_SHA256,
        },
        "debian_snapshot": SNAPSHOT,
        "overlay_summary": overlay_summary,
        "rootfs_elf_audit": rootfs_audit,
    }
    build_iso(rootfs, args.output_iso, evidence)
    (args.evidence_dir / "stage0-v6-build.json").write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_iso.with_suffix(args.output_iso.suffix + ".sha256")).write_text(
        f"{evidence['iso_sha256']}  {args.output_iso.name}\n", encoding="utf-8"
    )
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as error:
        print(f"BUILD ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
