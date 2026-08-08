# Verified reconstructed source overlays

This directory contains fail-closed source authorities reconstructed only when the exact shipped source version is absent from the public repository history.

An entry may be promoted into `source-locks.json` only after all of the following gates pass:

1. The exact AMD64 package and its checksum are locked.
2. The package changelog identifies the missing vendor delta.
3. The delta is recovered from public commit or Change-Id evidence, or is reconstructed under binary-constrained fail-closed checks when no complete public patch survives.
4. The reconstructed source is built independently for AMD64 in the locked historical Debian environment.
5. The rebuilt package passes exact non-ELF payload comparison and structural ELF, ABI, resource, relocation, symbol, and DWARF equivalence checks against the shipped AMD64 package. When raw ELF bytes differ, every differing byte must be confined to explicitly audited nondeterministic metadata such as GNU Build ID and its mechanically derived `.gnu_debuglink`.
6. The same immutable source archive builds natively for ARM64.
7. Every produced executable ELF is verified as AArch64 and every DEB identity is locked.

`source-locks.json` is merged over the ordinary exact-source lock only by `finalize_effective_source_authority.py`. Entries remain separate from ordinary Git commits so reconstructed provenance cannot be mistaken for a public exact-version tag.

## Current promoted sources

### `gooroom-applauncher-applet` `0.4.0+grm3u1+han3u2`

- base repository: `gooroom/gooroom-applauncher-applet`
- public base commit: `f2b5bf5909289796360a64526110d55e41c6f41f`
- public direct-child drag-and-drop commit: `20a1b11b624099bf9522f2de7104f4bf776e0a2e`
- reconstructed tree: `9b0cacfee8fb3118e4c497e590e2a310d8bc5c29`
- source archive SHA-256: `d92d75a144924fe84c5d2ccfa9794ccec7125f1640c00aaf3fffc783c6c877e7`
- exact target AMD64 DEB SHA-256: `97d4ad82497333615de5eea8fa4d64fd9538f000dccaee5acb1f6f26f44edc00`
- strict AMD64 source verification run: `31251842558`
- verified native ARM64 build run: `31268447673`
- raw-byte identity claim: `false`
- functional ELF identity: `true`; the only raw ELF differences are GNU Build ID and `.gnu_debuglink` metadata

### `gooroom-greeter` `0.3.1+grm3u1+han3u2`

- base repository: `hancom-io/gooroom-greeter`
- base commit: `886f8b6c5cd35117fd5a2d31896e4f9818400960`
- reconstructed tree: `007aea315dd41a4ca878589957ba10baa71353b8`
- source archive SHA-256: `b7f832cdc417ec0f669f2d07db987c57dbb6e1039f4b4ccc4137aacf67b36c6d`
- verified native ARM64 build run: `31228368554`
