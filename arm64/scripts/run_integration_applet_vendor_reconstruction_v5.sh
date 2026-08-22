#!/usr/bin/env bash
set -Eeuo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Run as sourced fragments so state, traps, and fail-closed shell options are shared.
source "$script_dir/run_integration_applet_vendor_reconstruction_v5.part1.sh"
source "$script_dir/run_integration_applet_vendor_reconstruction_v5.part2.sh"
