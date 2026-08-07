# ARM64 XSM + GRAC security-stack status

Status: **PASS**

This gate covers the coupled Xorg security extension and Gooroom Resource Access Control runtime path. It does not claim that every remaining security-deferred source, the complete ARM64 package corpus, or the final ISO has passed.

## Locked inputs

- `arm64/locks/gooroom-libsecurity-extensions-arm64-build/latest`
- `arm64/locks/gooroom-resource-access-control-arm64-build/latest`
- `arm64/locks/xsm-grac-security-stack-arm64/latest`

Each `latest` directory is copied from an immutable workflow-run directory and contains its own `SHA256SUMS` and workflow authority.

## Enforced results

1. The exact locked `gooroom-libsecurity-extensions` source builds natively on an AArch64 runner in the dated Debian Bullseye snapshot.
2. The resulting Xorg module is an AArch64 shared object at `/usr/lib/xorg/modules/extensions/xsm.so`.
3. Its Debian package name and version are checked against the locked Hancom Gooroom 3.3 AMD64 reference.
4. The generic locked-build verifier reports no x86 or i386 executable leakage.
5. The exact locked Gooroom Resource Access Control source is built and its complete package/architecture mapping is checked against the AMD64 reference. Production still follows the existing rule that `Architecture: all` packages are reused byte-for-byte.
6. The XSM consumer path and GRAC provider path for `grac_noti_forward` are identical.
7. The XSM-side `/etc/gooroom/grac.d/user.rules` runtime contract remains present.
8. The aggregate two-component gate reports `security_stack_passed: true` and `wrong_architecture_executable_count: 0`.

## Deliberately not credited yet

- Installation of the verified package set into the final ARM64 root filesystem
- Xorg module load inside the final desktop session
- Live clipboard, screenshot, screencast, session-recording, notification-forwarding, and GRAC allow/deny behavior
- Full SquashFS audit and AArch64 UEFI ISO boot after this security-stack integration
- Any other security-deferred source not named by this gate

## Next integration gate

Rebuild or retrieve the exact verified package outputs inside the final corpus workflow, install them together with the byte-identical `Architecture: all` payload, boot the final Xorg desktop, and exercise the XSM-to-GRAC notification and rule path before crediting the final security milestone.
