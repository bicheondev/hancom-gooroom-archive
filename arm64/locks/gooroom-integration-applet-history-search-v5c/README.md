# Integration applet history search v5c

This search rebuilds a bounded set of public source snapshots selected from
release commits, ref tips, and the icon-theme and clean-mode code history. For
every candidate it overlays the exact vendor changelog, embedded GResources,
icons, and message catalogs, then builds with the locked Bullseye image and
locked Nimf packages.

Ranking compares non-ELF payloads, exact resources, normalized dynamic
functions, and allocated ELF sections. It does not ignore allocated runtime
content. A semantic source match may open only the native ARM64 candidate-build
gate; package promotion and ISO assembly remain closed.
