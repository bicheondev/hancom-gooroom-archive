# Hancom Gooroom 3.3 ARM64 — user handoff tasks

This file lists only work that requires the user's network, private/local files,
physical hardware, or human contact. Automated repository analysis, source
verification, builds, package promotion, and ISO assembly remain in CI.

## 1. Run exact source recovery from a different network

Use this only when GitHub Actions cannot reach the live repository or an archive
snapshot. The helper uses the signed 2023 `InRelease` evidence extracted from
the exact reference ISO and accepts only byte-identical files.

```bash
git clone https://github.com/bicheondev/hancom-gooroom-archive.git
cd hancom-gooroom-archive
git checkout arm64-port
chmod +x arm64/scripts/user_recover_reference_sources.sh
HANCOM_GOOROOM_RECOVERY_TIMEOUT=45 \
  arm64/scripts/user_recover_reference_sources.sh
```

Return these two generated files:

```text
work/user-reference-release-source-recovery.tar.gz
work/user-reference-release-source-recovery.tar.gz.sha256
```

Do not rename, edit, recompress, or remove files inside the recovery directory.
Negative evidence is useful even if the summary reports zero recovered sources.

### Exact signed source-index identities

```text
Gooroom gooroom-3.0, dated 2023-07-29
main/source/Sources.gz
size    51094
sha256  09e1abccac1bcd86a430318caab0f0c68224f42a567b8cee7bcf308ed7f4a166

main/source/Sources
size    333374
sha256  d9fb9527dd6dd52f7ecd4ff60762355ee55cd54c5623e2bb316b917065232131

Hancom hancom-3.0, dated 2023-08-01
main/source/Sources.gz
size    7142
sha256  5898f493b7ae9c750dbd11c80325bde5a3778357500d9acda24cc6e4e41c6a58

main/source/Sources
size    25799
sha256  314db75129531a1ca348dce3c66dce865ed6b364b54cb5264696a9cbfcc8bfd1
```

A file with a different size or SHA-256 is not accepted, even if it contains the
same package version strings.

## 2. Check an old installed Hancom Gooroom system or backup

This task is useful if an old 3.3 installation, disk image, VM, backup, or APT
cache exists. Copy matching files without modifying them.

```bash
sudo find \
  /var/lib/apt/lists \
  /var/cache/apt \
  /var/cache/pbuilder \
  /var/cache/sbuild \
  /var/cache/apt-cacher-ng \
  /srv/apt-cacher-ng \
  -type f \
  \( -name 'Sources' -o -name 'Sources.gz' -o -name 'Sources.xz' \
     -o -name '*.dsc' -o -name '*.orig.tar.*' -o -name '*.debian.tar.*' \
     -o -name '*.diff.gz' \) \
  -print 2>/dev/null
```

Especially valuable files contain one of these exact versions:

```text
gnome-flashback             3.38.0-2+grm3u2+han3u4
gooroom-dockbarx-applet     0.3.1+grm3u1+han3u1
gooroom-guide               0.5.3+grm3u1+han3u1
gooroom-integration-applet  0.3.1+grm3u1+han3u3
gooroom-session-manager     0.3.9+grm3u1+han3u2
linux                       5.10.179-1+grm3u1
qtbase-opensource-src       5.15.2+dfsg-9+grm3u1
```

Package the files while preserving names and bytes:

```bash
tar -czf hancom-gooroom-3.3-source-residue.tar.gz <matching paths>
sha256sum hancom-gooroom-3.3-source-residue.tar.gz \
  > hancom-gooroom-3.3-source-residue.tar.gz.sha256
```

On macOS, use `shasum -a 256` instead of `sha256sum`.

## 3. Request the exact corresponding source archives

Human contact may recover files that are no longer public. Ask Hancom/Gooroom
for the Debian source package members (`.dsc`, `.orig.tar.*`, and
`.debian.tar.*` or `.diff.gz`) corresponding to the seven versions above.
Specify that binary packages alone are not sufficient and that original file
names and checksums must be preserved.

Suggested message:

> 한컴구름 3.3 AMD64 배포본에 포함된 GPL/LGPL 계열 패키지를 ARM64에서
> 재현 검증하기 위해, 아래 정확 버전의 Debian 소스 패키지 원본이
> 필요합니다. 각 버전의 `.dsc`, `.orig.tar.*`, `.debian.tar.*` 또는
> `.diff.gz` 파일을 원래 파일명과 체크섬 그대로 제공해 주시기 바랍니다.
> 바이너리 DEB나 다른 버전의 소스로는 대체할 수 없습니다.

Append the seven-version list from section 2.

## 4. Physical ARM64 boot and device testing

This starts only after CI produces a bootable ISO. CI can inspect AArch64 ELF,
package metadata, SquashFS, and UEFI layout, but it cannot verify a physical
keyboard, display, Wi-Fi device, audio device, suspend/resume, installer disk
write, or first boot.

Record the following when a candidate ISO is available:

```text
hardware model and firmware version
ISO SHA-256
USB-writing tool and version
UEFI boot result
live-session login result
installer start and completion
first installed-system boot
Ethernet/Wi-Fi, audio, display, keyboard, touchpad
shutdown, reboot, suspend/resume
journalctl -b output for any failure
```

Do not test installation on a disk containing unbacked-up data.
