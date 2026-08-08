# Verified reconstructed source overlays

This directory contains fail-closed source authorities reconstructed only when the exact shipped source version is absent from the public repository history.

An entry may be promoted into `source-locks.json` only after all of the following gates pass:

1. The exact AMD64 package and its checksum are locked.
2. The package changelog identifies the missing vendor delta.
3. The delta is recovered from public commit or Change-Id evidence.
4. The reconstructed source is built independently for AMD64 in the locked historical Debian environment.
5. The rebuilt package passes exact non-ELF payload comparison and structural ELF, ABI, resource, relocation, symbol, and DWARF equivalence checks against the shipped AMD64 package.
6. The same immutable source archive builds natively for ARM64.
7. Every produced executable ELF is verified as AArch64 and every DEB identity is locked.

`source-locks.json` is merged over the ordinary exact-source lock only by `merge_reconstructed_source_locks.py`. Entries remain separate from ordinary Git commits so reconstructed provenance cannot be mistaken for a public exact-version tag.

Current promoted source:

- `gooroom-greeter` `0.3.1+grm3u1+han3u2`
  - base repository: `hancom-io/gooroom-greeter`
  - base commit: `886f8b6c5cd35117fd5a2d31896e4f9818400960`
  - reconstructed tree: `007aea315dd41a4ca878589957ba10baa71353b8`
  - source archive SHA-256: `b7f832cdc417ec0f669f2d07db987c57dbb6e1039f4b4ccc4137aacf67b36c6d`
  - verified build run: `31228368554`
