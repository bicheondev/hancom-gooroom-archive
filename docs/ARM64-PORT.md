# Hancom Gooroom 3.3 ARM64 port

This branch rebuilds Hancom Gooroom 3.3 for `arm64`; it does not convert or
binary-translate the `amd64` filesystem.

## Non-negotiable version invariant

The archived `amd64` ISO is the sole version authority. Before an upstream
repository under `hancomgooroom`, `hancom-io`, or `gooroom` may enter the ARM64
build, its Debian source-package version must exactly equal the source version
recorded in the installed package database of the reference ISO.

Newer, older, approximate, branch-name-only, and unverified matches are rejected.
A source lock must record the repository, immutable commit SHA, the version read
from `debian/changelog`, and the matching AMD64 source-package version.

The initial workflow stage verifies the ISO byte size and SHA-256, extracts the
installed package database, and publishes the resulting inventory as a workflow
artifact. Source resolution and the native ARM64 build are added only after that
inventory has been inspected.
