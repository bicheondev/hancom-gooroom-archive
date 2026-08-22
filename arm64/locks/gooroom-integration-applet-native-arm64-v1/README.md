# Native ARM64 integration-applet candidate v1

This stage runs only after the hybrid-source authority proves zero vendor
resource, normalized dynamic-function, and non-ELF differences on AMD64.

The source is then rebuilt in a native ARM64 Bullseye userspace. Nimf is also
rebuilt from its locked public commit for ARM64 before the integration applet is
built. Cross-architecture verification normalizes the multiarch directory and
requires exact non-ELF payloads, exact embedded resources, equal exported symbol
sets, equal `DT_NEEDED` sets, and AArch64 ELF64 for every candidate ELF.

A passing result is only a native package candidate. Package-layer promotion,
rootfs integration, and ISO assembly remain disabled.
