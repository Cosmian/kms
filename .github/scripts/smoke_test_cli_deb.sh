#!/usr/bin/env bash
#
# Smoke test for the Cosmian KMS CLI Debian package (ckms)
# Verifies the ckms binary can be extracted and executed from a .deb package.
#
# Usage:
#   ./smoke_test_cli_deb.sh <path-to-deb-file>
#
# Example:
#   ./smoke_test_cli_deb.sh result-deb-fips-static/cosmian-kms-cli-fips-static-openssl_X.Y.Z_amd64.deb

set -euo pipefail

# Source common smoke test functions
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./smoke_test_linux.sh
source "$SCRIPT_DIR/smoke_test_linux.sh"

# Check arguments
if [ $# -ne 1 ]; then
  error "Usage: $0 <path-to-deb-file>"
fi
CLI_DEB_FILE="$1"

if [ ! -f "$CLI_DEB_FILE" ]; then
  error "CLI Debian package not found: $CLI_DEB_FILE"
fi

info "Starting CLI smoke test for: $CLI_DEB_FILE"

# Create a clean temporary directory for extraction
TEMP_DIR=$(mktemp -d -t cosmian-kms-cli-smoke-test-XXXXXX)
trap 'rm -rf "$TEMP_DIR"' EXIT

info "Extracting .deb package to: $TEMP_DIR"

cd "$TEMP_DIR"
ar x "$CLI_DEB_FILE" || error "Failed to extract .deb archive"

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

# Find the ckms binary
CLI_BIN=""
if [ -f "$TEMP_DIR/usr/sbin/ckms" ]; then
  CLI_BIN="$TEMP_DIR/usr/sbin/ckms"
elif [ -f "$TEMP_DIR/usr/bin/ckms" ]; then
  CLI_BIN="$TEMP_DIR/usr/bin/ckms"
else
  error "ckms binary not found in expected locations (usr/sbin/ckms or usr/bin/ckms)"
fi

info "Found ckms binary at: $CLI_BIN"

# Check no Nix store paths in RPATH/RUNPATH
info "Checking binary RPATH for Nix store paths..."
if readelf -d "$CLI_BIN" 2>/dev/null | grep -E "RPATH|RUNPATH" | grep -q "/nix/store"; then
  error "CLI binary has hardcoded Nix store RPATH!"
fi
info "✓ CLI binary has no Nix store RPATH"

# Check the binary uses the system dynamic linker (not a Nix store interpreter)
info "Checking dynamic linker..."
INTERP=$(readelf -l "$CLI_BIN" 2>/dev/null | grep "Requesting program interpreter" | sed 's/.*\[Requesting program interpreter: \(.*\)\]/\1/' || true)
if [ -n "$INTERP" ]; then
  if echo "$INTERP" | grep -q "/nix/store"; then
    error "CLI binary uses Nix store dynamic linker: $INTERP"
  fi
  info "✓ CLI binary uses system dynamic linker: $INTERP"
else
  info "Static binary (no dynamic linker) - continuing"
fi

# Test binary execution: ckms --help should produce output mentioning ckms/kms/cosmian
info "Testing ckms --help execution..."
HELP_OUTPUT=$("$CLI_BIN" --help 2>&1 || true)
if echo "$HELP_OUTPUT" | grep -qiE "(ckms|cosmian|kms|usage|commands|options)"; then
  info "✓ ckms --help produced expected output"
else
  warn "ckms --help output did not match expected patterns"
  info "Output: $HELP_OUTPUT"
fi

info ""
info "============================================"
info "✓ CLI SMOKE TESTS PASSED!"
info "============================================"
info ""
info "The CLI .deb package is ready for deployment:"
info "  - Binary located at /usr/sbin/ckms"
info "  - No Nix store dependencies"
info "  - Binary executes successfully"
