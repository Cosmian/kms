#!/usr/bin/env bash
set -euo pipefail
set -x

# Build RPM package (FIPS or non-FIPS based on FEATURES env variable)
# This script is called from nix.sh inside a nix-shell environment

# Discover repo root
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

# Source common functions
# shellcheck source=nix/scripts/common.sh
source "$SCRIPT_DIR/common.sh"

# Set defaults (RPM always builds release)
: "${FEATURES:=}"

# Determine variant name for logging
VARIANT_NAME="FIPS"
if [ -n "$FEATURES" ]; then
  VARIANT_NAME="non-FIPS"
fi

echo "Building ${VARIANT_NAME} RPM package..."

# Prepare OpenSSL artifacts
prepare_openssl_staging "$REPO_ROOT"

# Clean previous packaging artifacts
rm -rf target/generate-rpm

# Install packaging tool
if ! cargo generate-rpm --version 0.16.0 2>/dev/null | grep -q "0.16.0"; then
  cargo install --version 0.16.0 cargo-generate-rpm --force
fi

# Run the standard build script
DEBUG_OR_RELEASE=release bash "$SCRIPT_DIR/build.sh"

# Build RPM package
cd "$REPO_ROOT"
cargo generate-rpm -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml

echo "${VARIANT_NAME} RPM package built successfully."

# Display package location
RPM_FILES=$(find "$REPO_ROOT/target/generate-rpm" -name "*.rpm" -type f)
if [ -z "$RPM_FILES" ]; then
  echo "Error: No .rpm package found in target/generate-rpm" >&2
  exit 1
fi
echo "$RPM_FILES"

echo "${VARIANT_NAME} RPM package build completed successfully."
