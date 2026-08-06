#!/usr/bin/env python3
"""Fix Debian epoch handling in exact ARM64 download URI validation.

`apt-get --print-uris download` chooses a local output filename containing the
Debian epoch (for example `attr_1%3a2.4...deb`), while the repository pool object
and Packages `Filename` correctly omit the epoch (`attr_2.4...deb`). The asset
identity must therefore compare the URL path basename to Packages Filename. The
APT-reported SHA256 digest is also required to equal the Packages SHA256.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()

    text = args.target.read_text(encoding="utf-8")
    import_anchor = "from typing import Any\n"
    import_replacement = import_anchor + "from urllib.parse import unquote, urlparse\n"
    if "from urllib.parse import unquote, urlparse" not in text:
        if text.count(import_anchor) != 1:
            raise SystemExit("typing import anchor was not unique")
        text = text.replace(import_anchor, import_replacement, 1)

    old = '''    if Path(uri["download_filename"]).name != Path(filename).name:
        return None, "APT URI filename differs from Packages Filename basename"
    source_name, source_version = record_source(record, package_name)
'''
    new = '''    pool_basename = Path(unquote(urlparse(uri["url"]).path)).name
    if pool_basename != Path(filename).name:
        return None, (
            "APT URI pool basename differs from Packages Filename basename: "
            f"{pool_basename} != {Path(filename).name}"
        )
    apt_digest = str(uri["apt_digest"])
    if not apt_digest.startswith("SHA256:"):
        return None, f"APT URI did not provide a SHA256 digest: {apt_digest}"
    if apt_digest.removeprefix("SHA256:").lower() != sha256:
        return None, "APT URI SHA256 differs from Packages SHA256"
    source_name, source_version = record_source(record, package_name)
'''
    if old not in text and "pool_basename = Path(unquote(urlparse" in text:
        print("epoch-aware URI validation already installed")
        args.target.write_text(text, encoding="utf-8")
        return 0
    if text.count(old) != 1:
        raise SystemExit(f"expected one local-filename comparison, found {text.count(old)}")
    args.target.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"updated {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
