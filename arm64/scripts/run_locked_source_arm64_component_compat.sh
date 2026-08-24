#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_WRAPPER="$SCRIPT_DIR/run_locked_source_arm64.sh"
BUILD_JOBS="${HANCOM_GOOROOM_BUILD_JOBS:-2}"

[ -f "$BASE_WRAPPER" ] || {
  echo "base compatibility wrapper not found: $BASE_WRAPPER" >&2
  exit 69
}
command -v python3 >/dev/null || {
  echo "python3 is required" >&2
  exit 69
}
case "$BUILD_JOBS" in
  1|2|3) ;;
  *)
    echo "HANCOM_GOOROOM_BUILD_JOBS must be 1, 2, or 3, got: $BUILD_JOBS" >&2
    exit 64
    ;;
esac

# Keep the patched wrapper beside the checked-in scripts so its BASH_SOURCE
# directory still resolves the exact generic builder and helper paths. The
# immutable component lock itself is never rewritten; its recorded SHA-256
# therefore remains the SHA-256 of the checked-in canonical lock.
PATCHED_WRAPPER="$(mktemp "$SCRIPT_DIR/.run-locked-component-compat.XXXXXX")"
cleanup() {
  rm -f "$PATCHED_WRAPPER"
}
trap cleanup EXIT

python3 - "$BASE_WRAPPER" "$PATCHED_WRAPPER" "$BUILD_JOBS" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
build_jobs = int(sys.argv[3])

old = '''      and .upstream.snapshot == $snapshot
      and .composition.extract == "upstream.files.orig only"
'''
new = '''      and .upstream.snapshot == $snapshot
      and (
        .composition.extract == "upstream.files.orig only"
        or (
          .composition.extract == "orig-only-strip-one-component"
          and .composition.overlay == "replace debian/ with exact packaging Git tree"
          and .composition.do_not_apply == "Debian debian.tar.xz"
        )
      )
'''
count = source.count(old)
if count != 1:
    raise SystemExit(
        f"expected exactly one legacy source-composition assertion, found {count}"
    )
source = source.replace(old, new)

# The generic wrapper patches the immutable base builder at runtime. Inject an
# asserted second-stage patch into that Python transformation so heavyweight
# composite sources can use a bounded one-to-three native compile jobs without
# changing the immutable source lock, package version, or default two-job path.
marker = "source = source.replace(old_options, new_options)\n\nold_docker_env ="
if source.count(marker) != 1:
    raise SystemExit(
        "expected exactly one build-options-to-docker transition in base wrapper"
    )

resource_patch = (
    "source = source.replace(old_options, new_options)\n\n"
    f"build_jobs = {build_jobs}\n"
    "if build_jobs != 2:\n"
    "    parallel_marker = \"parallel=2\"\n"
    "    parallel_count = source.count(parallel_marker)\n"
    "    if parallel_count < 1:\n"
    "        raise SystemExit(\"parallel build marker missing from patched builder\")\n"
    f"    source = source.replace(parallel_marker, \"parallel={build_jobs}\")\n"
    "    command_marker = \"dpkg-buildpackage -us -uc -B -j2\"\n"
    "    if source.count(command_marker) != 1:\n"
    "        raise SystemExit(\"expected exactly one dpkg-buildpackage -j2 command\")\n"
    f"    source = source.replace(command_marker, \"dpkg-buildpackage -us -uc -B -j{build_jobs}\")\n\n"
    "old_docker_env ="
)
source = source.replace(marker, resource_patch)

Path(sys.argv[2]).write_text(source, encoding="utf-8")
PY
chmod +x "$PATCHED_WRAPPER"

set +e
"$PATCHED_WRAPPER" "$@"
rc=$?
set -e
exit "$rc"
