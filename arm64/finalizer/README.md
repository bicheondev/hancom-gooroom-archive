# Hancom Gooroom 3.3 ARM64 finalizer

This directory contains fail-closed tooling for turning a verified AArch64 live root filesystem into a UEFI-bootable Hancom Gooroom 3.3 ISO.

## Trust boundary

The tools do not claim that an ISO is complete merely because `xorriso` produced a file. Promotion requires all of the following:

1. the source Hancom Gooroom 3.3 ISO matches the locked SHA-256;
2. the live root filesystem contains no AMD64/i386 ELF payloads;
3. the generated ISO contains an AArch64 `EFI/BOOT/BOOTAA64.EFI`;
4. kernel, initramfs, and SquashFS payloads can be extracted and inspected;
5. the ISO passes `hg-arm64-validate.sh`;
6. AArch64 UEFI reaches the Linux kernel under QEMU or UTM.

The locked source ISO digest is:

```text
ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a  Hancom-Gooroom-3.3-amd64.hybrid.iso
```

## Programs

- `bin/hg-arm64-state.sh`: inventory existing build products and choose the next fail-closed step.
- `bin/hg-arm64-recover-pool.sh`: recover a deterministic offline APT pool containing only `arm64` and `all` packages.
- `bin/hg-arm64-finalize.sh`: assemble a UEFI-only AArch64 hybrid ISO from verified inputs.
- `bin/hg-arm64-validate.sh`: inspect the ISO, unpack SquashFS, and reject foreign ELF or package architectures.
- `bin/hg-arm64-qemu-smoke.sh`: boot the ISO with AArch64 UEFI and require evidence that Linux was entered.
- `tests/selftest.sh`: syntax and synthetic package-pool checks.

## Typical sequence

```bash
sudo ./bin/hg-arm64-state.sh --workspace /srv/hancom-gooroom-arm64

./bin/hg-arm64-recover-pool.sh \
  --input /srv/hancom-gooroom-arm64 \
  --output /srv/hancom-gooroom-arm64/recovered-pool

sudo ./bin/hg-arm64-finalize.sh \
  --source-iso /srv/iso/Hancom-Gooroom-3.3-amd64.hybrid.iso \
  --rootfs /srv/hancom-gooroom-arm64/rootfs \
  --apt-pool /srv/hancom-gooroom-arm64/recovered-pool \
  --output /srv/hancom-gooroom-arm64/Hancom-Gooroom-3.3-arm64.hybrid.iso

sudo ./bin/hg-arm64-qemu-smoke.sh \
  /srv/hancom-gooroom-arm64/Hancom-Gooroom-3.3-arm64.hybrid.iso
```

Use `--live-only` only when intentionally producing a live environment without the original offline installer package pool. The finalizer otherwise rejects an AMD64 pool rather than silently shipping a partially installable image.
