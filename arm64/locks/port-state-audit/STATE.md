# Hancom Gooroom 3.3 ARM64 port state

Generated: `2026-08-06T10:33:00.450914Z`
Status: **in-progress**

## Reference fidelity

- AMD64 reference ISO SHA-256: `ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a`
- Reference binary packages: `1279`
- Exact vendor binaries verified: `123`
- Exact vendor binaries unresolved: `0`

## Exact source and native builds

- Effective source rows: `74`
- Exact Git sources: `55`
- Native source rows: `54`
- Passed native source builds: `0`
- Failed native source builds: `0`
- Resolved but not yet built: `43`

## Boot gates

- Minimal ARM64 UEFI proof: `missing`
- Stage-0 desktop ARM64 UEFI: `missing`

## Current blockers

- **unresolved-native-source**: 11
  - `gnome-flashback`, `gooroom-applauncher-applet`, `gooroom-dockbarx-applet`, `gooroom-greeter`, `gooroom-guide`, `gooroom-integration-applet`, `gooroom-session-manager`, `linux`, `linux-signed-amd64`, `nimf`, `qtbase-opensource-src`
- **resolved-native-source-not-yet-built**: 43
  - `accountsservice`, `celluloid`, `cups-pk-helper`, `dpkg`, `eog`, `file-roller`, `gdebi`, `gedit`, `gnome-bluetooth`, `gnome-control-center`, `gnome-panel`, `gnome-screenshot`, `gnome-settings-daemon`, `gooroom-browser`, `gooroom-dockbarx`, `gooroom-indicator-applet`, `gooroom-libsecurity-extensions`, `gooroom-logout`, `gooroom-notice-applet`, `gooroom-notifyd`, `gooroom-resource-access-control`, `gooroom-security-status-tools`, `gooroom-showdesktop-applet`, `gooroom-software`, `gtk+2.0`, `gtk+3.0`, `hancom-toolkit`, `hancom-viewer-installer`, `hancomgrm-adjustments-utils`, `libnma`, `lightdm`, `live-config`, `metacity`, `mousetweaks`, `nautilus`, `network-manager`, `network-manager-applet`, `p7zip`, `pam-gooroom`, `policykit-1`, `synaptic`, `system-config-printer`, `yelp`
- **minimal-arm64-uefi-boot-not-passed**
- **stage0-desktop-arm64-uefi-boot-not-passed**

> This dashboard reports only committed, checksum-backed evidence. It does not label the final ISO complete until every native source and both ARM64 UEFI boot gates pass.
