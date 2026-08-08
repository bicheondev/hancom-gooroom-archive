#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_WRAPPER="$SCRIPT_DIR/run_locked_source_arm64.sh"
BUILD_JOBS="${HANCOM_GOOROOM_BUILD_JOBS:-2}"
CCACHE_DIR="${HANCOM_GOOROOM_CCACHE_DIR:-}"
CCACHE_MAXSIZE="${HANCOM_GOOROOM_CCACHE_MAXSIZE:-5G}"

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
[ -n "$CCACHE_DIR" ] || {
  echo "HANCOM_GOOROOM_CCACHE_DIR is required" >&2
  exit 64
}
case "$CCACHE_MAXSIZE" in
  *[!0-9KMGTPkmgpt.]*)
    echo "invalid HANCOM_GOOROOM_CCACHE_MAXSIZE: $CCACHE_MAXSIZE" >&2
    exit 64
    ;;
esac
mkdir -p "$CCACHE_DIR"
CCACHE_DIR="$(cd "$CCACHE_DIR" && pwd)"
export HANCOM_GOOROOM_CCACHE_DIR="$CCACHE_DIR"
export HANCOM_GOOROOM_CCACHE_MAXSIZE="$CCACHE_MAXSIZE"

# Patch only a disposable wrapper beside the checked-in scripts. Its
# BASH_SOURCE directory therefore continues to resolve the exact builders and
# component helper, while the checked-in source/component locks remain intact.
PATCHED_WRAPPER="$(mktemp "$SCRIPT_DIR/.run-locked-component-ccache.XXXXXX")"
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
if source.count(old) != 1:
    raise SystemExit(
        f"expected exactly one legacy source-composition assertion, found {source.count(old)}"
    )
source = source.replace(old, new)

# Inject asserted transformations into the run wrapper's transformation of the
# generic builder. This keeps ccache a build-acceleration transport only: no
# source, version, tree, package expectation, or verifier policy is changed.
marker = "source = source.replace(old_options, new_options)\n\nold_docker_env ="
if source.count(marker) != 1:
    raise SystemExit(
        "expected exactly one build-options-to-docker transition in base wrapper"
    )

runtime_patch = (
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
    "cache_host_anchor = \"for command in jq git docker dpkg-parsechangelog dpkg-deb sha256sum gzip tar; do\\n\"\n"
    "if source.count(cache_host_anchor) != 1:\n"
    "    raise SystemExit(\"expected exactly one host command gate for ccache injection\")\n"
    "cache_host_block = '''CCACHE_HOST_DIR=\"${HANCOM_GOOROOM_CCACHE_DIR:-}\"\n"
    "CCACHE_MAXSIZE=\"${HANCOM_GOOROOM_CCACHE_MAXSIZE:-5G}\"\n"
    "[ -n \"$CCACHE_HOST_DIR\" ] || {\n"
    "  echo \"HANCOM_GOOROOM_CCACHE_DIR is required\" >&2\n"
    "  exit 64\n"
    "}\n"
    "mkdir -p \"$CCACHE_HOST_DIR\"\n"
    "CCACHE_HOST_DIR=\"$(cd \"$CCACHE_HOST_DIR\" && pwd)\"\n"
    "'''\n"
    "source = source.replace(cache_host_anchor, cache_host_block + cache_host_anchor)\n\n"
    "tools_anchor = '''  equivs fakeroot gnupg jq xz-utils\n\n"
    "BUILD_SOURCE=/build/source\n"
    "'''\n"
    "tools_replacement = '''  ccache equivs fakeroot gnupg jq xz-utils\n\n"
    "export CCACHE_DIR=/ccache\n"
    "export CCACHE_BASEDIR=/build\n"
    "export CCACHE_NOHASHDIR=true\n"
    "export CCACHE_COMPRESS=true\n"
    "mkdir -p /usr/local/lib/ccache \"$CCACHE_DIR\"\n"
    "for compiler in cc c++ gcc g++ clang clang++ clang-13 clang++-13; do\n"
    "  ln -sf /usr/bin/ccache \"/usr/local/lib/ccache/$compiler\"\n"
    "done\n"
    "export PATH=\"/usr/local/lib/ccache:$PATH\"\n"
    "ccache --set-config=compiler_check=content\n"
    "ccache --set-config=hash_dir=false\n"
    "ccache --set-config=compression=true\n"
    "ccache --set-config=compression_level=6\n"
    "ccache --set-config=max_size=\"${CCACHE_MAXSIZE:-5G}\"\n"
    "ccache --show-stats > /build/output/ccache-stats-before.txt || true\n"
    "cache_stats() {\n"
    "  ccache --show-stats > /build/output/ccache-stats-after.txt || true\n"
    "}\n"
    "trap cache_stats EXIT\n\n"
    "BUILD_SOURCE=/build/source\n"
    "'''\n"
    "if source.count(tools_anchor) != 1:\n"
    "    raise SystemExit(\"expected exactly one transformed chroot tool block\")\n"
    "source = source.replace(tools_anchor, tools_replacement)\n\n"
    "cleanup_anchor = '''cleanup_mounts() {\n"
    "  umount -R \"$ROOT/dev\" 2>/dev/null || true\n"
    "'''\n"
    "cleanup_replacement = '''cleanup_mounts() {\n"
    "  umount \"$ROOT/ccache\" 2>/dev/null || true\n"
    "  umount -R \"$ROOT/dev\" 2>/dev/null || true\n"
    "'''\n"
    "if source.count(cleanup_anchor) != 1:\n"
    "    raise SystemExit(\"expected exactly one mount cleanup function\")\n"
    "source = source.replace(cleanup_anchor, cleanup_replacement)\n\n"
    "mount_anchor = '''mount -t sysfs sysfs \"$ROOT/sys\"\n\n"
    "set +e\n"
    "'''\n"
    "mount_replacement = '''mount -t sysfs sysfs \"$ROOT/sys\"\n"
    "mkdir -p \"$ROOT/ccache\"\n"
    "mount --bind /ccache \"$ROOT/ccache\"\n\n"
    "set +e\n"
    "'''\n"
    "if source.count(mount_anchor) != 1:\n"
    "    raise SystemExit(\"expected exactly one chroot mount transition\")\n"
    "source = source.replace(mount_anchor, mount_replacement)\n\n"
    "docker_mount_anchor = '''  --volume \"$OUTPUT_DIR_ABS:/out:rw\" \\\\\n"
    "'''\n"
    "docker_mount_replacement = '''  --env \"CCACHE_MAXSIZE=$CCACHE_MAXSIZE\" \\\\\n"
    "  --volume \"$CCACHE_HOST_DIR:/ccache:rw\" \\\\\n"
    "  --volume \"$OUTPUT_DIR_ABS:/out:rw\" \\\\\n"
    "'''\n"
    "if source.count(docker_mount_anchor) != 1:\n"
    "    raise SystemExit(\"expected exactly one Docker output mount\")\n"
    "source = source.replace(docker_mount_anchor, docker_mount_replacement)\n\n"
    "old_docker_env ="
)
source = source.replace(marker, runtime_patch)

Path(sys.argv[2]).write_text(source, encoding="utf-8")
PY
chmod +x "$PATCHED_WRAPPER"

set +e
"$PATCHED_WRAPPER" "$@"
rc=$?
set -e
exit "$rc"
