#!/usr/bin/env bash
set -euo pipefail

# Run wasm tests for cosmian_kms_client_wasm
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

# Parse optional flags
PROFILE="${PROFILE:-${BUILD_PROFILE:-debug}}"
VARIANT="${VARIANT:-fips}"
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

node_major_version() {
  if ! command -v node >/dev/null 2>&1; then
    echo 0
    return 0
  fi

  local v
  v="$(node --version 2>/dev/null || true)"
  v="${v#v}"
  echo "${v%%.*}"
}

# wasm-bindgen-test-runner and the UI toolchain require a reasonably modern Node.
# If an old Node is active (e.g. via nvm), prefer running inside nix-shell.
if [ "${IN_NIX_NODE_SHELL:-0}" != "1" ]; then
  node_major="$(node_major_version)"
  if [ "$node_major" -gt 0 ] && [ "$node_major" -lt 18 ] && command -v nix-shell >/dev/null 2>&1; then
    printf -v quoted_args '%q ' "$@"
    exec nix-shell -p nodejs wasm-pack --run "cd '$REPO_ROOT' && IN_NIX_NODE_SHELL=1 bash .github/scripts/test_wasm.sh ${quoted_args}"
  fi
fi

FEATURES_ARGS=()
if [ "$VARIANT" = "non-fips" ]; then
  FEATURES_ARGS+=(--features non-fips)
fi

PROFILE_ARGS=()
if [ "$PROFILE" = "release" ]; then
  PROFILE_ARGS+=(--release)
fi

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

ensure_pnpm() {
  if command -v pnpm >/dev/null 2>&1; then
    return 0
  fi

  if command -v corepack >/dev/null 2>&1; then
    corepack enable >/dev/null 2>&1 || true
    corepack prepare pnpm@9 --activate >/dev/null 2>&1 || true
  fi

  if command -v pnpm >/dev/null 2>&1; then
    return 0
  fi

  if ! command -v npm >/dev/null 2>&1; then
    echo "Error: npm not found; cannot install pnpm" >&2
    return 1
  fi

  # Avoid installing into read-only prefixes (e.g. /nix/store). Prefer a
  # user-writable prefix and update PATH.
  if npm install -g pnpm@9 >/dev/null 2>&1; then
    return 0
  fi

  local prefix_dir
  prefix_dir="${PNPM_PREFIX_DIR:-$HOME/.local}"
  npm install -g pnpm@9 --prefix "$prefix_dir" >/dev/null
  export PATH="$prefix_dir/bin:$PATH"
}

# nix.sh runs this script *inside* a nix-shell for wasm tests (nodejs + wasm-pack).
# Keep this script runnable standalone too.
if ! command -v wasm-pack >/dev/null 2>&1; then
  if command -v nix-shell >/dev/null 2>&1; then
    nix-shell -p nodejs wasm-pack --run "cd '$REPO_ROOT/crate/wasm' && wasm-pack test --node ${PROFILE_ARGS[*]} ${FEATURES_ARGS[*]}"
    exit 0
  fi
  echo "Error: wasm-pack not available (expected nix-shell or cargo-installed wasm-pack)." >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found (wasm-pack requires Rust toolchain)." >&2
  exit 1
fi

if command -v node >/dev/null 2>&1; then
  (cd crate/wasm && wasm-pack test --node "${PROFILE_ARGS[@]}" "${FEATURES_ARGS[@]}")
else
  echo "Node.js not found; falling back to Chrome headless" >&2
  (cd crate/wasm && RUSTFLAGS="--cfg wasm_test_browser" wasm-pack test --headless --chrome "${PROFILE_ARGS[@]}" "${FEATURES_ARGS[@]}")
fi

# Build the web-target WASM package and run React unit tests using the real artifacts.
(cd crate/wasm && wasm-pack build --target web "${PROFILE_ARGS[@]}" "${FEATURES_ARGS[@]}")

WASM_DIR="ui/src/wasm"
rm -rf "$WASM_DIR"
mkdir -p "$WASM_DIR"
cp -R crate/wasm/pkg "$WASM_DIR/"

# Some tools (notably Vite/Vitest) may require a "main" field to resolve directory imports
# like `import init from "./wasm/pkg"`. wasm-pack emits "module" but not always "main".
if [ -f "ui/src/wasm/pkg/package.json" ] && command -v node >/dev/null 2>&1; then
  node <<'NODE'
const fs = require('node:fs');
const path = 'ui/src/wasm/pkg/package.json';
const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));
if (!pkg.main) {
  pkg.main = pkg.module || 'cosmian_kms_client_wasm.js';
  fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\n');
}
NODE
fi

if [ -f ui/pnpm-lock.yaml ]; then
  ensure_pnpm
  (cd ui && pnpm install --frozen-lockfile && pnpm run lint && pnpm run test:unit)
elif [ -f ui/package-lock.json ]; then
  (cd ui && npm ci && npm run lint && npm run test:unit)
else
  (cd ui && npm install && npm run lint && npm run test:unit)
fi

# Run UI integration tests against a local dockerized KMS (when Docker is available).
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  if [ -f ui/docker-compose.yml ]; then
    echo "Starting KMS server for UI integration tests (docker compose)…" >&2
    docker compose -f ui/docker-compose.yml up -d
    cleanup() {
      docker compose -f ui/docker-compose.yml down >/dev/null 2>&1 || true
    }
    trap cleanup EXIT

    if [ -f ui/pnpm-lock.yaml ]; then
      ensure_pnpm
      (cd ui && KMS_URL="http://localhost:9998" pnpm run test:integration)
    elif [ -f ui/package-lock.json ]; then
      (cd ui && KMS_URL="http://localhost:9998" npm run test:integration)
    else
      (cd ui && KMS_URL="http://localhost:9998" npm run test:integration)
    fi
  else
    echo "Warning: ui/docker-compose.yml not found; skipping UI integration tests" >&2
  fi
else
  echo "Warning: docker/docker compose not available; skipping UI integration tests" >&2
fi
