# Integration applet public-history search v5b

This authority searches a bounded set of public `gooroom-integration-applet`
source trees selected from release commits, ref tips, and commits that changed
the icon-theme or clean-mode code paths identified by exact vendor DWARF.

Each candidate is rebuilt only after overlaying the exact target changelog,
GResources, icons, and message catalogs. The build uses the locked Bullseye
base image and the repository's SHA-256-locked `libnimf1` and `nimf-dev`
packages.

The ranking compares:

- package filesystem and non-ELF payloads;
- exact embedded GResources;
- normalized dynamic-function disassembly;
- allocated ELF sections.

No allocated runtime section is ignored. A non-allocated `.shstrtab` policy
from the earlier reconstruction authority is not used to declare a history
candidate equivalent here.

Even an exact semantic source match only permits a native ARM64 candidate
build. Package-layer promotion and ISO assembly remain disabled until the
native ARM64 package and complete image gates pass.
