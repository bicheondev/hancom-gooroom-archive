# Hancom delta audit: gooroom-applauncher-applet

Comparison-only evidence; missing Hancom source is not claimed as recovered.

- Source status: `comparison-only`
- Reconstruction status: `not-attempted`
- Byte identity claimed: `false`
- Target SHA-256: `97d4ad82497333615de5eea8fa4d64fd9538f000dccaee5acb1f6f26f44edc00`
- Public commit: `f2b5bf5909289796360a64526110d55e41c6f41f`
- Public tree: `946068a768ee6d648a79a3a8c294dcbdc64992df`

## Counts

- Target-only: 0
- Base-only: 0
- Changed common: 3
- Non-ELF changes: 2
- ELF semantic changes: 1
- Symlink changes: 0
- Control changes: 3

## Interpretation gate

Every material payload and ELF delta must be explained before reconstruction or ARM64 promotion. `audit_complete` does not mean source recovery.

## Target-only paths

None.

## Base-only paths

None.

## Changed common paths

- `usr/lib/x86_64-linux-gnu/gnome-panel/modules/libgooroom-applauncher-applet.so`
- `usr/share/doc/gooroom-applauncher-applet/changelog.gz`
- `usr/share/icons/hicolor/scalable/apps/gooroom-applauncher-applet.svg`
