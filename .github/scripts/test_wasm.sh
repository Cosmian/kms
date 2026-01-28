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

FEATURES_ARGS=()
if [ "$VARIANT" = "non-fips" ]; then
  FEATURES_ARGS=(--features non-fips)
fi

WASM_PACK_VERSION="0.13.1"

# In the Nix CI/test environment we don't necessarily have rustup, extra Rust std
# components, Node.js, or a browser available. Since WASM tests are an optional
# tier, skip them there when prerequisites are missing.
if [ -n "${IN_NIX_SHELL:-}" ]; then
  # Prefer the Node runner; without it, the script would fall back to a browser
  # runner which is typically unavailable in minimal Nix shells.
  if ! command -v node >/dev/null 2>&1; then
    echo "Skipping WASM tests in Nix shell: Node.js is not available"
    exit 0
  fi

  sysroot="$(rustc --print sysroot 2>/dev/null || true)"
  if [ -z "$sysroot" ] || [ ! -d "$sysroot/lib/rustlib/wasm32-unknown-unknown/lib" ]; then
    echo "Skipping WASM tests in Nix shell: wasm32-unknown-unknown target is not installed"
    exit 0
  fi
fi

ensure_wasm_pack() {
  if command -v wasm-pack >/dev/null 2>&1 && wasm-pack --version 2>/dev/null | grep -q "${WASM_PACK_VERSION}"; then
    return 0
  fi

  echo "Installing wasm-pack ${WASM_PACK_VERSION} via cargo"
  cargo install --version "${WASM_PACK_VERSION}" wasm-pack --locked --force || true
  export PATH="$HOME/.cargo/bin:$PATH"
  command -v wasm-pack >/dev/null 2>&1
}

# Prefer Node runner for speed/stability.
# If Node is already available on the host, avoid nix-shell to keep output small and stable.
if ensure_wasm_pack && command -v node >/dev/null 2>&1; then
  (cd crate/wasm && wasm-pack test --node "${FEATURES_ARGS[@]}")
else
  if command -v nix-shell >/dev/null 2>&1; then
    ensure_wasm_pack
    nix-shell -p nodejs --run "export PATH=\"$HOME/.cargo/bin:$PATH\"; cd crate/wasm && wasm-pack test --node ${FEATURES_ARGS[*]}"
  else
    if command -v node >/dev/null 2>&1; then
      echo "Error: ensure_wasm_pack failed unexpectedly" >&2
      exit 1
    fi
    echo "Node.js not found; falling back to Chrome headless"
    (cd crate/wasm && RUSTFLAGS="--cfg wasm_test_browser" wasm-pack test --headless --chrome "${FEATURES_ARGS[@]}")
  fi
fi
