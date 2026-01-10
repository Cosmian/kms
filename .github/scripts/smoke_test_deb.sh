#!/usr/bin/env bash
#
# Smoke test for Debian packages built with Nix
# This script extracts a .deb package and verifies the cosmian_kms binary can be loaded
# with proper configuration.
#
# Usage:
#   ./smoke_test_deb.sh <path-to-deb-file>
#
# Example:
#   ./smoke_test_deb.sh result-deb-fips-static/cosmian-kms-server-fips-static-openssl_X.Y.Z-1_amd64.deb

set -euo pipefail

# Source common smoke test functions
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./smoke_test_linux.sh
source "$SCRIPT_DIR/smoke_test_linux.sh"

# Check arguments
if [ $# -ne 1 ]; then
  error "Usage: $0 <path-to-deb-file>"
fi
DEB_FILE="$1"

# Detect FIPS variant
detect_fips_variant "$DEB_FILE"

if [ ! -f "$DEB_FILE" ]; then
  error "Debian package not found: $DEB_FILE"
fi

info "Starting smoke test for: $DEB_FILE"

# Create a clean temporary directory for extraction
TEMP_DIR=$(mktemp -d -t cosmian-kms-smoke-test-XXXXXX)
trap 'rm -rf "$TEMP_DIR"' EXIT

info "Extracting .deb package to: $TEMP_DIR"

# Extract the .deb package
cd "$TEMP_DIR"
ar x "$DEB_FILE" || error "Failed to extract .deb archive"

# Extract the data tarball (handles .xz/.gz/.zst)
if [ -f data.tar.xz ]; then
  tar xf data.tar.xz || error "Failed to extract data.tar.xz"
elif [ -f data.tar.gz ]; then
  tar xf data.tar.gz || error "Failed to extract data.tar.gz"
elif [ -f data.tar.zst ]; then
  tar xf data.tar.zst || error "Failed to extract data.tar.zst"
else
  error "No data.tar.* found in .deb package"
fi

info "Package extracted successfully"

# Verify expected directory structure
if [ ! -d "usr/local/cosmian" ]; then
  error "Expected directory 'usr/local/cosmian' not found in package"
fi

# Use common functions to perform smoke tests
find_binary "$TEMP_DIR"
verify_crypto_modules "$TEMP_DIR" "$IS_FIPS"
check_binary_rpath "$BINARY_PATH"
detect_linkage_type "$BINARY_PATH"
verify_package_assets "$TEMP_DIR" "$IS_FIPS" "$IS_DYNAMIC"
verify_openssldir "$TEMP_DIR" "$BINARY_PATH" "$IS_FIPS" "$IS_DYNAMIC"
test_binary_execution "$TEMP_DIR" "$BINARY_PATH" "$IS_FIPS" "$IS_DYNAMIC"
verify_openssl_runtime_version "$TEMP_DIR" "$BINARY_PATH" "$IS_FIPS" "$IS_DYNAMIC"
print_success_message "$IS_FIPS" "deb"
