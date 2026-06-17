#!/usr/bin/env bash
# Thin wrapper around package_common.sh for RPM packaging (kept for backward compatibility)
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
"$SCRIPT_DIR/package_common.sh" --format rpm "$@"
