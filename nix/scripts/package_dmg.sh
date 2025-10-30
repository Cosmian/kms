#!/usr/bin/env bash
set -euo pipefail
set -x

# Build DMG package for macOS (FIPS or non-FIPS based on FEATURES env variable)
# This script is called from nix.sh inside a nix-shell environment

# Discover repo root
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

# Detect OS
UNAME=$(uname)
if [ "$UNAME" != "Darwin" ]; then
  echo "Error: DMG packages can only be built on macOS" >&2
  exit 1
fi

# Set defaults
: "${DEBUG_OR_RELEASE:=release}"
: "${FEATURES:=}"

# Determine variant name for logging
VARIANT_NAME="FIPS"
if [ -n "$FEATURES" ]; then
  VARIANT_NAME="non-FIPS"
fi

echo "Building ${VARIANT_NAME} DMG package for macOS..."

# Install cargo-packager
cargo install --version 0.11.7 cargo-packager --force

# Run the standard build script
bash "$SCRIPT_DIR/build.sh"

# Build DMG package
cd "$REPO_ROOT/crate/server"
cargo packager --verbose --formats dmg

cd "$REPO_ROOT"

echo "${VARIANT_NAME} DMG package built successfully."

# Display package location
find target/release -name "*.dmg" -type f 2>/dev/null || echo "DMG file should be in target/release/bundle/"

echo "${VARIANT_NAME} DMG package build completed successfully."
