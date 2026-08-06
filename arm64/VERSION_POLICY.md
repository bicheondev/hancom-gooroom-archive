# Hancom Gooroom 3.3 ARM64 version policy

The AMD64 installation image is the sole version authority for this port.

Reference image:

- File: `Hancom-Gooroom-3.3-amd64.hybrid.iso`
- Size: `1566277632` bytes
- SHA-256: `ba3ac40c66c255bccb53b7e5e8bbe1fdee6cec93a63669d1f4c9d75555d7644a`

## Fail-closed rules

1. Every installed AMD64 package is inventoried from `/var/lib/dpkg/status` inside the image's live SquashFS.
2. Debian/Ubuntu binary substitutions are accepted only when the package name and Debian version compare equal to the AMD64 reference, except for an explicitly reviewed architecture-only binNMU suffix.
3. Source builds from `hancomgooroom`, `hancom-io`, or `gooroom` are accepted only when a commit's `debian/changelog` declares the exact `Source` and `Version` recorded in the AMD64 inventory.
4. Branch names such as `hancom-3.0` or `gooroom-3.0` are discovery hints, not version proof.
5. A missing, ambiguous, newer, or older source match stops the build. It must never silently fall back to a default branch or the latest commit.
6. Every accepted source is locked by organization, repository, full commit SHA, declared source version, tree hash, and archive SHA-256.
7. The final ARM64 root filesystem is audited against the AMD64 package lock. Every difference must be listed in a reviewed exception manifest with one of: `arch-rebuild`, `arch-replace`, `arch-omit`, or `config-only`.
8. The release workflow refuses to publish an ISO if any package or source lock is unresolved.

The generated files under `arm64/locks/` are machine-produced evidence. Do not edit them manually.
