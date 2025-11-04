#!/bin/bash

# Build the KMS UI
# This script:
# 1. Builds the WASM component
# 2. Builds the UI
# 3. Copies the built UI to the final location

# Exit on error, print commands
set -ex

# Args: --variant fips|non-fips (default: fips)
VARIANT="fips"
while [ $# -gt 0 ]; do
  case "$1" in
  -v | --variant)
    VARIANT="${2:-}"
    shift 2 || true
    ;;
  *) shift ;; # ignore
  esac
done

case "$VARIANT" in
fips | non-fips) : ;;
*)
  echo "Error: --variant must be 'fips' or 'non-fips'" >&2
  exit 1
  ;;
esac

if [ "$VARIANT" = "non-fips" ]; then
  CARGO_FEATURES=(--features non-fips)
else
  CARGO_FEATURES=()
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
cargo install wasm-pack

# Build WASM component
cd crate/wasm
# shellcheck disable=SC2086
wasm-pack build --target web --release "${CARGO_FEATURES[@]}"

# Copy WASM artifacts to UI directory
WASM_DIR="../../ui/src/wasm/"
rm -rf "$WASM_DIR"
mkdir -p "$WASM_DIR"
cp -R pkg "$WASM_DIR"

# Build UI
cd ../../ui # current path: ./ui
rm -rf node_modules
npm install
npm run build
npm run lint
npm audit

# Deploy built UI to root
cd .. # current path: ./

DEST_DIR="crate/server/ui"
if [ "$VARIANT" = "non-fips" ]; then
  DEST_DIR="crate/server/ui_non_fips"
fi
rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
cp -R ui/dist "$DEST_DIR"
