#!/usr/bin/env bash
set -Eeuo pipefail

# Compatibility guard for dpkg-source implementations that require the explicit
# extraction directory not to exist. The v1 builder creates an empty temporary
# directory before invoking `dpkg-source -x`; this shim removes only that empty
# destination and delegates every other invocation unchanged.
REAL_DPKG_SOURCE="$(command -v dpkg-source)"
[ -x "$REAL_DPKG_SOURCE" ]
SHIM_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$SHIM_DIR"
}
trap cleanup EXIT
cat > "$SHIM_DIR/dpkg-source" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
if [ "\${1:-}" = -x ] && [ "\$#" -ge 3 ]; then
  destination="\${@: -1}"
  if [ -d "\$destination" ]; then
    rmdir "\$destination" 2>/dev/null || true
  fi
fi
exec "$REAL_DPKG_SOURCE" "\$@"
EOF
chmod 0755 "$SHIM_DIR/dpkg-source"
export PATH="$SHIM_DIR:$PATH"
exec bash arm64/scripts/build_locked_dsc_source_arm64.sh "$@"
