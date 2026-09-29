#!/usr/bin/env bash
#
# Smoke test for RPM packages built with Nix
# This script extracts an RPM package and verifies the cosmian_kms binary can be loaded
# with proper configuration.
#
# Usage:
#   ./smoke_test_rpm.sh <path-to-rpm-file>
#
# Example:
#   ./smoke_test_rpm.sh result-rpm-fips-static/cosmian_kms_server_fips_static-X.Y.Z-1.x86_64.rpm

set -euo pipefail

# Source common smoke test functions
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./smoke_test_linux.sh
source "$SCRIPT_DIR/smoke_test_linux.sh"

# Check arguments
if [ $# -ne 1 ]; then
  error "Usage: $0 <path-to-rpm-file>"
fi

RPM_FILE="$1"

# Detect FIPS variant
detect_fips_variant "$RPM_FILE"

if [ ! -f "$RPM_FILE" ]; then
  error "RPM package not found: $RPM_FILE"
fi

info "Starting smoke test for: $RPM_FILE"

# Create a clean temporary directory for extraction
TEMP_DIR=$(mktemp -d -t cosmian-kms-smoke-test-XXXXXX)
trap 'rm -rf "$TEMP_DIR"' EXIT

info "Extracting RPM package to: $TEMP_DIR"

# Extract the RPM package using rpm2cpio and cpio
cd "$TEMP_DIR"
# Note: We run this in a subshell without pipefail because cpio may return non-zero
# even on successful extraction (e.g., when encountering special files)
if ! (
  set +e
  rpm2cpio "$RPM_FILE" | cpio -idm >/dev/null 2>&1
); then
  # Double-check if extraction actually succeeded by checking for expected files
  if [ ! -d "usr" ]; then
    error "Failed to extract RPM package"
  fi
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
print_success_message "$IS_FIPS" "rpm"
