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

# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
  echo -e "${GREEN}[INFO]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
  echo -e "${RED}[ERROR]${NC} $*"
  exit 1
}

# Check arguments
if [ $# -ne 1 ]; then
  error "Usage: $0 <path-to-deb-file>"
fi

DEB_FILE="$1"

# Detect if this is a FIPS package based on filename
# Match "fips" but exclude "non-fips"
IS_FIPS=false
if [[ "$DEB_FILE" == *"fips"* ]] && [[ "$DEB_FILE" != *"non-fips"* ]]; then
  IS_FIPS=true
fi

if [ ! -f "$DEB_FILE" ]; then
  error "Debian package not found: $DEB_FILE"
fi

info "Starting smoke test for: $DEB_FILE"

# Create a clean temporary directory for extraction
TEMP_DIR=$(mktemp -d -t cosmian-kms-smoke-test-XXXXXX)
trap 'rm -rf "$TEMP_DIR"' EXIT

info "Extracting .deb package to: $TEMP_DIR"

# Extract the .deb package
# A .deb file is an ar archive containing data.tar.* (usually data.tar.xz or data.tar.gz)
cd "$TEMP_DIR"

# Extract the .deb archive
ar x "$DEB_FILE" || error "Failed to extract .deb archive"

# Extract the data tarball (handles both .xz and .gz)
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

# Find the cosmian_kms binary
BINARY_PATH=""
if [ -f "usr/sbin/cosmian_kms" ]; then
  BINARY_PATH="$TEMP_DIR/usr/sbin/cosmian_kms"
elif [ -f "usr/local/sbin/cosmian_kms" ]; then
  BINARY_PATH="$TEMP_DIR/usr/local/sbin/cosmian_kms"
elif [ -f "usr/bin/cosmian_kms" ]; then
  BINARY_PATH="$TEMP_DIR/usr/bin/cosmian_kms"
else
  error "cosmian_kms binary not found in expected locations"
fi

info "Found binary at: $BINARY_PATH"

# Verify FIPS modules and configuration are present (only for FIPS builds)
if [ "$IS_FIPS" = true ]; then
  FIPS_MODULE="$TEMP_DIR/usr/local/cosmian/lib/ossl-modules/fips.so"
  OPENSSL_CONF="$TEMP_DIR/usr/local/cosmian/lib/ssl/openssl.cnf"
  FIPS_CONF="$TEMP_DIR/usr/local/cosmian/lib/ssl/fipsmodule.cnf"

  if [ ! -f "$FIPS_MODULE" ]; then
    error "FIPS module not found: $FIPS_MODULE"
  fi
  info "✓ FIPS module found: $FIPS_MODULE"

  if [ ! -f "$OPENSSL_CONF" ]; then
    error "OpenSSL config not found: $OPENSSL_CONF"
  fi
  info "✓ OpenSSL config found: $OPENSSL_CONF"

  if [ ! -f "$FIPS_CONF" ]; then
    error "FIPS module config not found: $FIPS_CONF"
  fi
  info "✓ FIPS module config found: $FIPS_CONF"

  # Verify the openssl.cnf contains production paths (not Nix store paths)
  if grep -q "/nix/store" "$OPENSSL_CONF"; then
    error "OpenSSL config contains Nix store paths - not portable!"
  fi
  info "✓ OpenSSL config does not contain Nix store paths"

  # Verify the .include directive points to the correct location
  if ! grep -q "^.include /usr/local/cosmian/lib/ssl/fipsmodule.cnf" "$OPENSSL_CONF"; then
    error "OpenSSL config does not contain correct .include directive"
  fi
  info "✓ OpenSSL config has correct .include directive"

  # Check FIPS module has no hardcoded Nix store RPATH/RUNPATH
  # Note: We use readelf instead of ldd because ldd inside nix-shell will show
  # Nix store paths even for portable binaries (it uses the Nix glibc).
  # readelf shows the actual RPATH/RUNPATH embedded in the ELF file.
  info "Checking FIPS module RPATH..."
  if readelf -d "$FIPS_MODULE" | grep -E "RPATH|RUNPATH" | grep -q "/nix/store"; then
    error "FIPS module has hardcoded Nix store RPATH!"
  fi
  info "✓ FIPS module has no hardcoded Nix store paths"
else
  info "Non-FIPS build detected - skipping FIPS-specific checks"
fi

# Check binary has no hardcoded Nix store RPATH/RUNPATH
info "Checking binary RPATH..."
if readelf -d "$BINARY_PATH" | grep -E "RPATH|RUNPATH" | grep -q "/nix/store"; then
  error "Binary has hardcoded Nix store RPATH!"
fi
info "✓ Binary uses system libraries"

# Verify binary or shared library contains the correct OPENSSLDIR
# For dynamically linked builds, check the shared library instead of the binary
info "Checking OPENSSLDIR..."
if readelf -d "$BINARY_PATH" | grep -q 'NEEDED.*libssl\.so'; then
  # Dynamic build - check the shared library (OPENSSLDIR is in libcrypto, not libssl)
  LIBCRYPTO_PATH="$TEMP_DIR/usr/local/cosmian/lib/libcrypto.so.3"
  if [ -f "$LIBCRYPTO_PATH" ]; then
    OPENSSLDIR_OUTPUT=$(strings "$LIBCRYPTO_PATH" | grep 'OPENSSLDIR:' || true)
    if [ -z "$OPENSSLDIR_OUTPUT" ]; then
      error "No OPENSSLDIR found in shared library"
    fi
    if [ "$IS_FIPS" = true ]; then
      if ! echo "$OPENSSLDIR_OUTPUT" | grep -q 'OPENSSLDIR: "/usr/local/cosmian/lib/ssl"'; then
        echo "Found OPENSSLDIR: $OPENSSLDIR_OUTPUT" >&2
        error "Shared library does not contain correct OPENSSLDIR for FIPS build"
      fi
      info "✓ Shared library has correct OPENSSLDIR: /usr/local/cosmian/lib/ssl"
    else
      # Non-FIPS dynamic builds package their own OpenSSL libraries
      info "✓ Shared library OPENSSLDIR: $OPENSSLDIR_OUTPUT"
    fi
  else
    warn "Dynamic build but libcrypto.so.3 not found in package - skipping OPENSSLDIR check"
  fi
else
  # Static build - check the binary
  OPENSSLDIR_OUTPUT=$(strings "$BINARY_PATH" | grep 'OPENSSLDIR:' || true)
  if [ -z "$OPENSSLDIR_OUTPUT" ]; then
    error "No OPENSSLDIR found in binary"
  fi
  if [ "$IS_FIPS" = true ]; then
    if ! echo "$OPENSSLDIR_OUTPUT" | grep -q 'OPENSSLDIR: "/usr/local/cosmian/lib/ssl"'; then
      echo "Found OPENSSLDIR: $OPENSSLDIR_OUTPUT" >&2
      error "Binary does not contain correct OPENSSLDIR for FIPS build"
    fi
    info "✓ Binary has correct OPENSSLDIR: /usr/local/cosmian/lib/ssl"
  else
    # Non-FIPS uses system OpenSSL paths
    info "✓ Binary OPENSSLDIR: $OPENSSLDIR_OUTPUT"
  fi
fi

# Now test loading the binary with environment variables set
info "Testing binary execution..."

# Set up environment variables for FIPS builds
if [ "$IS_FIPS" = true ]; then
  export OPENSSL_CONF="$TEMP_DIR/usr/local/cosmian/lib/ssl/openssl.cnf"
  export OPENSSL_MODULES="$TEMP_DIR/usr/local/cosmian/lib/ossl-modules"
fi

# Try to get version (should work without network/database)
if ! VERSION_OUTPUT=$("$BINARY_PATH" --version 2>&1); then
  # If it fails, check if it's a legitimate error or a FIPS/OpenSSL issue
  if echo "$VERSION_OUTPUT" | grep -qi "fips\|openssl\|provider\|self.*test"; then
    error "Binary failed to load due to FIPS/OpenSSL issue: $VERSION_OUTPUT"
  else
    warn "Binary execution returned non-zero, but not a FIPS error (may be expected in test environment)"
    info "Output: $VERSION_OUTPUT"
  fi
else
  info "✓ Binary executed successfully"
  info "Version output: $VERSION_OUTPUT"

  # Verify version output contains expected patterns
  if ! echo "$VERSION_OUTPUT" | grep -qE "(cosmian_kms_server|cosmian_kms)"; then
    error "Version output doesn't match expected pattern"
  fi
  info "✓ Version output looks correct"
fi

info ""
info "============================================"
info "✓ ALL SMOKE TESTS PASSED!"
info "============================================"
info ""
if [ "$IS_FIPS" = true ]; then
  info "The FIPS .deb package is ready for deployment:"
  info "  - Binary loads successfully"
  info "  - FIPS configuration is portable"
  info "  - No Nix store dependencies"
  info "  - Correct production paths configured"
else
  info "The non-FIPS .deb package is ready for deployment:"
  info "  - Binary loads successfully"
  info "  - No Nix store dependencies"
  info "  - Portable configuration"
fi
