#!/usr/bin/env bash

# Build the KMS UI
# This script:
# 1. Builds the WASM component
# 2. Builds the UI
# 3. Copies the built UI to the final location

# Exit on error, undefined vars, and fail pipelines; print commands
set -euo pipefail
set -x

CARGO_FEATURES=""
if [ -n "${FEATURES:-}" ]; then
  CARGO_FEATURES="--features ${FEATURES}"
fi

WASM_PACK_VERSION="0.13.1"

# Install nodejs from nodesource if npm is not installed
if ! command -v npm >/dev/null 2>&1; then
  SUDO="sudo"
  if [ "$(id -u)" = "0" ]; then SUDO=""; fi
  if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    curl -fsSL https://deb.nodesource.com/setup_23.x | "$SUDO" bash -
    "$SUDO" apt-get install -y nodejs
  elif [ -f /etc/redhat-release ]; then
    # RHEL/CentOS/Fedora
    curl -fsSL https://rpm.nodesource.com/setup_23.x | "$SUDO" bash -
    "$SUDO" yum install -y nodejs
  else
    echo "Unsupported distribution"
    exit 1
  fi
fi

# Install wasm-pack tool (pinned for compatibility with the WASM crate)
if ! command -v wasm-pack >/dev/null 2>&1 || ! wasm-pack --version 2>/dev/null | grep -q "${WASM_PACK_VERSION}"; then
  cargo install --version "${WASM_PACK_VERSION}" wasm-pack --locked --force
  export PATH="$HOME/.cargo/bin:$PATH"
fi

# Build WASM component
cd crate/wasm
# shellcheck disable=SC2086
wasm-pack build --target web --release $CARGO_FEATURES

# Copy WASM artifacts to UI directory
WASM_DIR="../../ui/src/wasm/"
rm -rf "$WASM_DIR"
mkdir -p "$WASM_DIR"
cp -R pkg "$WASM_DIR"

# Build UI
cd ../../ui # current path: ./ui
rm -rf node_modules

if [ -f pnpm-lock.yaml ]; then
  if ! command -v pnpm >/dev/null 2>&1; then
    if command -v corepack >/dev/null 2>&1; then
      corepack enable || true
      corepack prepare pnpm@9 --activate || true
    fi
  fi
  if ! command -v pnpm >/dev/null 2>&1; then
    if ! npm install -g pnpm@9; then
      PREFIX_DIR="${PNPM_PREFIX_DIR:-$HOME/.local}"
      npm install -g pnpm@9 --prefix "$PREFIX_DIR"
      export PATH="$PREFIX_DIR/bin:$PATH"
    fi
  fi

  pnpm install --frozen-lockfile
  pnpm run build
  pnpm run test
  pnpm run lint
  pnpm audit
elif [ -f package-lock.json ]; then
  npm ci
  npm run build
  pnpm run test
  npm run lint
  npm audit
else
  npm install
  npm run build
  npm run test
  npm run lint
  npm audit
fi

# Deploy built UI to root
cd .. # current path: ./

DEST_DIR="crate/server/ui${CARGO_FEATURES:+_non_fips}"
rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
cp -R ui/dist "$DEST_DIR"
