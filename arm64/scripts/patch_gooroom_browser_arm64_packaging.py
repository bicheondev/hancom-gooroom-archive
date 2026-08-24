#!/usr/bin/env python3
"""Apply one asserted ARM64-only compatibility edit to the build wrapper.

The exact Gooroom packaging tree installs debian/setups/chrome_crashpad_handler,
a prebuilt downstream payload.  The same exact Chromium build already produces
out/Release/chrome_crashpad_handler.  On ARM64 the native strip tool rejects the
prebuilt payload before the package can be verified.  This helper changes only
the ephemeral build wrapper so dh_install selects the handler produced by that
same locked source build.  The checked-in source/component locks are untouched.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

OLD = '''cd "$BUILD_SOURCE"
export SOURCE_DATE_EPOCH="$(dpkg-parsechangelog -S Date | date -f - +%s)"
'''

NEW = '''cd "$BUILD_SOURCE"

if [ "${SOURCE_NAME:-}" = "gooroom-browser" ]; then
  host_arch="$(dpkg-architecture -qDEB_HOST_ARCH)"
  [ "$host_arch" = arm64 ] || {
    echo "gooroom-browser compatibility edit is ARM64-only, got: $host_arch" >&2
    exit 3
  }

  manifest=debian/gooroom-browser.install
  original='debian/setups/chrome_crashpad_handler usr/lib/gooroom-browser'
  replacement='out/Release/chrome_crashpad_handler usr/lib/gooroom-browser'
  original_payload=debian/setups/chrome_crashpad_handler

  [ -f "$manifest" ] || {
    echo "exact Gooroom browser install manifest is missing: $manifest" >&2
    exit 3
  }
  [ -f "$original_payload" ] || {
    echo "locked downstream crashpad payload is missing: $original_payload" >&2
    exit 3
  }

  original_count="$(grep -Fxc "$original" "$manifest" || true)"
  replacement_count="$(grep -Fxc "$replacement" "$manifest" || true)"
  [ "$original_count" -eq 1 ] || {
    echo "expected exactly one locked crashpad install source, found: $original_count" >&2
    exit 3
  }
  [ "$replacement_count" -eq 0 ] || {
    echo "native crashpad install source was already present unexpectedly" >&2
    exit 3
  }

  awk -v old="$original" -v new="$replacement" '
    $0 == old { print new; replaced += 1; next }
    { print }
    END { if (replaced != 1) exit 42 }
  ' "$manifest" > "$manifest.arm64"
  mv "$manifest.arm64" "$manifest"

  grep -Fxc "$replacement" "$manifest" | grep -qx 1
  ! grep -Fxq "$original" "$manifest"

  jq -n \
    --arg source gooroom-browser \
    --arg target_architecture arm64 \
    --arg manifest "$manifest" \
    --arg original_install_source "$original" \
    --arg replacement_install_source "$replacement" \
    --arg original_payload_sha256 "$(sha256sum "$original_payload" | awk '{print $1}')" \
    '{
      schema: 1,
      source: $source,
      target_architecture: $target_architecture,
      policy: "replace-packaged-prebuilt-crashpad-with-same-build-native-output",
      manifest: $manifest,
      original_install_source: $original_install_source,
      replacement_install_source: $replacement_install_source,
      original_payload_sha256: $original_payload_sha256,
      source_or_version_changed: false,
      byte_identity_claimed: false,
      native_build_output_required: true
    }' > /build/output/gooroom-browser-arm64-packaging-compatibility.json
fi

export SOURCE_DATE_EPOCH="$(dpkg-parsechangelog -S Date | date -f - +%s)"
'''


def digest(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wrapper", type=Path)
    args = parser.parse_args()

    source = args.wrapper.read_text(encoding="utf-8")
    if "gooroom-browser-arm64-packaging-compatibility.json" in source:
        raise SystemExit("wrapper already contains the browser ARM64 compatibility edit")
    count = source.count(OLD)
    if count != 1:
        raise SystemExit(f"expected exactly one locked build-root marker, found {count}")

    patched = source.replace(OLD, NEW)
    if patched.count(NEW) != 1 or OLD in patched:
        raise SystemExit("asserted browser ARM64 wrapper transformation failed")
    args.wrapper.write_text(patched, encoding="utf-8")
    print(f"wrapper_sha256_before={digest(source)}")
    print(f"wrapper_sha256_after={digest(patched)}")
    print("gooroom_browser_arm64_packaging_edit=applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
