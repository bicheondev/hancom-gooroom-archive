# User handoff: exact Hancom Gooroom source material

Run `./USER_RECOVER_EXACT_SOURCES.sh` on a machine or network that can reach the old Hancom Gooroom repository or an authenticated archive.

A downloaded file is accepted only when both byte size and SHA-256 match the signed repository authority.
Do not substitute a similarly named Debian source package or a newer/older Git commit.

Files still requiring browser or private-network retrieval:
- `gooroom-Sources.gz` — CI could not retrieve the locked bytes.
- `hancom-Sources.gz` — CI could not retrieve the locked bytes.
- `gnome-flashback` — No byte-identical InRelease-locked Sources stanza was recovered in CI.
- `gooroom-dockbarx-applet` — No byte-identical InRelease-locked Sources stanza was recovered in CI.
- `gooroom-guide` — No byte-identical InRelease-locked Sources stanza was recovered in CI.
- `gooroom-integration-applet` — No byte-identical InRelease-locked Sources stanza was recovered in CI.
- `gooroom-session-manager` — No byte-identical InRelease-locked Sources stanza was recovered in CI.
- `linux` — No byte-identical InRelease-locked Sources stanza was recovered in CI.
- `qtbase-opensource-src` — No byte-identical InRelease-locked Sources stanza was recovered in CI.
