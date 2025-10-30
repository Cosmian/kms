#!/usr/bin/env bash
set -euo pipefail
set -x

# Build DEB package (FIPS or non-FIPS based on FEATURES env variable)
# This script is called from nix.sh inside a nix-shell environment

# Discover repo root
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

# Source common functions
# shellcheck source=nix/scripts/common.sh
source "$SCRIPT_DIR/common.sh"

# Set defaults
: "${DEBUG_OR_RELEASE:=release}"
: "${FEATURES:=}"

# Determine variant name for logging
VARIANT_NAME="FIPS"
if [ -n "$FEATURES" ]; then
  VARIANT_NAME="non-FIPS"
fi

echo "Building ${VARIANT_NAME} DEB package..."

# Prepare OpenSSL artifacts
prepare_openssl_staging "$REPO_ROOT"

# Clean previous packaging artifacts
rm -rf target/debian

# Install packaging tool
if cargo deb --version 2>/dev/null | grep -qv "2.4.0"; then
  cargo install --version 2.4.0 cargo-deb --force
fi

# Run the standard build script
bash "$SCRIPT_DIR/build.sh"

# Build DEB package
cd "$REPO_ROOT/crate/server"

# Determine variant flag for cargo-deb
BUILD_VARIANT=""
if [ -z "$FEATURES" ]; then
  BUILD_VARIANT="--variant fips"
fi

# shellcheck disable=SC2086
cargo deb $BUILD_VARIANT

cd "$REPO_ROOT"

echo "${VARIANT_NAME} DEB package built successfully."

# Display package location
DEB_FILES=$(find "$REPO_ROOT/target/debian" -name "*.deb" -type f)
if [ -z "$DEB_FILES" ]; then
  echo "Error: No .deb package found in $REPO_ROOT/target/debian" >&2
  exit 1
fi
echo "$DEB_FILES"

echo "${VARIANT_NAME} DEB package build completed successfully."
