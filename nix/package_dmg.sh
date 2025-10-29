#!/usr/bin/env bash
set -euo pipefail
set -x

# Build DMG package for macOS (FIPS or non-FIPS based on FEATURES env variable)
# This script is called from nix.sh inside a nix-shell environment

# Discover repo root (works inside nix-shell)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# Determine variant based on FEATURES environment variable
: "${DEBUG_OR_RELEASE:=debug}"
: "${FEATURES:=}"

RELEASE_FLAG=""
if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE_FLAG="--release"
fi

if [ -n "$FEATURES" ]; then
  VARIANT_NAME="non-FIPS"
else
  VARIANT_NAME="FIPS"
fi

# Detect OS
UNAME=$(uname)

if [ "$UNAME" != "Darwin" ]; then
  echo "Error: DMG packages can only be built on macOS" >&2
  exit 1
fi

echo "Building ${VARIANT_NAME} DMG package for macOS..."

# Install cargo-packager
cargo install --version 0.11.7 cargo-packager --force

# Build the server with appropriate features
cd crate/server
if [ -n "$FEATURES" ]; then
  cargo build --features "$FEATURES" $RELEASE_FLAG
else
  cargo build $RELEASE_FLAG
fi

# Build DMG package
cargo packager --verbose --formats dmg $RELEASE_FLAG

cd "$REPO_ROOT"

echo "${VARIANT_NAME} DMG package built successfully."

# Display package location (cargo-packager typically outputs to target/release/bundle)
find target/release -name "*.dmg" -type f 2>/dev/null || echo "DMG file should be in target/release/bundle/"

echo "${VARIANT_NAME} DMG package build completed successfully."
