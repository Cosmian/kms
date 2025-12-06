#!/usr/bin/env bash
set -euo pipefail

# Run wasm tests for cosmian_kms_client_wasm
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

# Parse optional flags
PROFILE="${PROFILE:-debug}"
VARIANT="fips"
while [ $# -gt 0 ]; do
  case "$1" in
  --profile)
    PROFILE="${2:-$PROFILE}"
    shift 2 || true
    ;;
  --variant)
    VARIANT="${2:-$VARIANT}"
    shift 2 || true
    ;;
  --)
    shift
    break
    ;;
  *)
    break
    ;;
  esac
done

FEATURES_ARGS=""
if [ "$VARIANT" = "non-fips" ]; then
  FEATURES_ARGS="--features non-fips"
fi

# Prefer Node runner for speed/stability. If within Nix, use nix-shell to provide wasm-pack.
if command -v nix-shell >/dev/null 2>&1; then
  nix-shell -p wasm-pack nodejs --run "PATH=\"$HOME/.cargo/bin:$PATH\" cd crate/wasm && wasm-pack test --node $FEATURES_ARGS"
else
  if command -v wasm-pack >/dev/null 2>&1; then
    if command -v node >/dev/null 2>&1; then
      (cd crate/wasm && wasm-pack test --node "$FEATURES_ARGS")
    else
      echo "Node.js not found; falling back to Chrome headless"
      (cd crate/wasm && RUSTFLAGS="--cfg wasm_test_browser" wasm-pack test --headless --chrome "$FEATURES_ARGS")
    fi
  else
    echo "Installing wasm-pack via cargo (no nix-shell available)"
    cargo install wasm-pack --locked || true
    export PATH="$HOME/.cargo/bin:$PATH"
    if command -v wasm-pack >/dev/null 2>&1; then
      if command -v node >/dev/null 2>&1; then
        (cd crate/wasm && wasm-pack test --node "$FEATURES_ARGS")
      else
        echo "Node.js not found; falling back to Chrome headless"
        (cd crate/wasm && RUSTFLAGS="--cfg wasm_test_browser" wasm-pack test --headless --chrome "$FEATURES_ARGS")
      fi
    else
      echo "Error: wasm-pack not available. Please install nix or ensure cargo-installed bin is in PATH (e.g., add $HOME/.cargo/bin)." >&2
      exit 1
    fi
  fi
fi
