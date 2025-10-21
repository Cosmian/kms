#!/usr/bin/env bash
# Minimal entrypoint to build inside nix-shell and validate OpenSSL/static linkage
set -euo pipefail

HERE_DIR=$(cd "$(dirname "$0")" && pwd)
if command -v git >/dev/null 2>&1; then
  REPO_ROOT=$(git -C "$HERE_DIR" rev-parse --show-toplevel)
else
  REPO_ROOT=$(cd "$HERE_DIR/../.." && pwd)
fi
cd "$REPO_ROOT"

[ -f "$REPO_ROOT/nix/inner_build.sh" ] || {
  echo "Missing $REPO_ROOT/nix/inner_build.sh" >&2
  exit 1
}

if [ -f "$REPO_ROOT/shell.nix" ]; then
  nix-shell "$REPO_ROOT/shell.nix" --pure \
    --keep DEBUG_OR_RELEASE --keep TARGET --keep FEATURES \
    --run "bash '$REPO_ROOT/nix/inner_build.sh'"
elif [ -f "$REPO_ROOT/default.nix" ]; then
  nix-shell "$REPO_ROOT/default.nix" --pure \
    --keep DEBUG_OR_RELEASE --keep TARGET --keep FEATURES \
    --run "bash '$REPO_ROOT/nix/inner_build.sh'"
else
  echo "Error: No shell.nix or default.nix found at $REPO_ROOT" >&2
  exit 1
fi
