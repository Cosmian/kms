#!/bin/bash

# Build the KMS UI
# This script:
# 1. Builds the WASM component
# 2. Builds the UI
# 3. Copies the built UI to the final location

# Exit on error, print commands
set -ex

if [ -n "$FEATURES" ]; then
  FEATURES="--features $FEATURES"
fi

# Install nodejs from nodesource if npm is not installed
if ! command -v npm &>/dev/null; then
  SUDO="sudo"
  [ "$(id -u)" = "0" ] && SUDO=""
  if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    curl -fsSL https://deb.nodesource.com/setup_23.x | $SUDO bash -
    $SUDO apt-get install -y nodejs
  elif [ -f /etc/redhat-release ]; then
    # RHEL/CentOS/Fedora
    curl -fsSL https://rpm.nodesource.com/setup_23.x | $SUDO bash -
    $SUDO yum install -y nodejs
  else
    echo "Unsupported distribution"
    exit 1
  fi
fi

# Install wasm-pack tool
cargo install --version 0.13.1 wasm-pack --force

# Build WASM component
cd cli/crate/wasm
# shellcheck disable=SC2086
RUSTUP_TOOLCHAIN="nightly-2025-01-01" wasm-pack build --target web --release $FEATURES

# Copy WASM artifacts to UI directory
rm -rf ../../ui/src/wasm/
mkdir -p ../../ui/src/wasm/
cp -R pkg ../../ui/src/wasm/

# Build UI
cd ../../ui # current path: ./cli/ui
rm -rf node_modules
npm install
npm run build

# Deploy built UI to root
cd ../.. # current path: ./
rm -rf crate/server/ui/
mkdir -p crate/server/ui/
cp -R cli/ui/dist crate/server/ui/
