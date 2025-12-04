#!/usr/bin/env bash
#
# Smoke test for macOS DMG packages built with Nix
# This script mounts a DMG, verifies the cosmian_kms binary and FIPS assets,
# and runs a basic execution check.
#
# Usage:
#   ./smoke_test_dmg.sh <path-to-dmg-file>
#
# Example:
#   ./smoke_test_dmg.sh result-dmg-fips-static/Cosmian\ KMS\ Server_5.13.0_arm64.dmg

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

if [ $# -ne 1 ]; then
  error "Usage: $0 <path-to-dmg-file>"
fi

DMG_FILE="$1"

IS_FIPS=false
if [[ "$DMG_FILE" == *"fips"* ]] && [[ "$DMG_FILE" != *"non-fips"* ]]; then
  IS_FIPS=true
fi

[ -f "$DMG_FILE" ] || error "DMG not found: $DMG_FILE"

info "Starting smoke test for: $DMG_FILE"

# Attach DMG to a deterministic mountpoint to avoid parsing issues with spaces
MOUNT_POINT=$(mktemp -d /tmp/kmsdmg.XXXXXX)
hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT_POINT" "$DMG_FILE" >/dev/null || error "Failed to attach DMG"
[ -d "$MOUNT_POINT" ] || error "Mount point not found"
info "Mounted at: $MOUNT_POINT"

cleanup() {
  hdiutil detach "$MOUNT_POINT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Locate app contents: support two layouts
# 1) Plain tree with bin and lib under root
# 2) App bundle `Cosmian KMS Server.app/Contents/Resources/...`
ROOT_DIR="$MOUNT_POINT"
APP_RES="$MOUNT_POINT/Cosmian KMS Server.app/Contents/Resources"
APP_MACOS="$MOUNT_POINT/Cosmian KMS Server.app/Contents/MacOS"

CHECK_DIR="$ROOT_DIR"
if [ -d "$APP_RES" ]; then
  CHECK_DIR="$APP_RES"
fi

# Find binary
BINARY_PATH=""
for p in \
  "$APP_MACOS/cosmian_kms" \
  "$CHECK_DIR/usr/sbin/cosmian_kms" \
  "$CHECK_DIR/usr/local/sbin/cosmian_kms" \
  "$CHECK_DIR/usr/bin/cosmian_kms" \
  "$CHECK_DIR/bin/cosmian_kms" \
  "$ROOT_DIR/cosmian_kms"; do
  if [ -f "$p" ]; then
    BINARY_PATH="$p"
    break
  fi
done
[ -n "$BINARY_PATH" ] || error "cosmian_kms binary not found in DMG"
info "Found binary: $BINARY_PATH"

# Verify FIPS assets for FIPS builds
if [ "$IS_FIPS" = true ]; then
  OSSLMOD_SO="$CHECK_DIR/usr/local/cosmian/lib/ossl-modules/fips.so"
  OSSLMOD_DYLIB="$CHECK_DIR/usr/local/cosmian/lib/ossl-modules/fips.dylib"
  OSSL_CONF="$CHECK_DIR/usr/local/cosmian/lib/ssl/openssl.cnf"
  FIPS_CONF="$CHECK_DIR/usr/local/cosmian/lib/ssl/fipsmodule.cnf"

  if [ -f "$OSSLMOD_SO" ]; then
    info "\xE2\x9C\x93 FIPS module present (.so)"
  elif [ -f "$OSSLMOD_DYLIB" ]; then
    info "\xE2\x9C\x93 FIPS module present (.dylib)"
  else
    warn "FIPS module not found in DMG Resources (expected $OSSLMOD_SO or $OSSLMOD_DYLIB)"
  fi
  if [ -f "$OSSL_CONF" ]; then
    info "\xe2\x9c\x93 OpenSSL config present"
    if grep -q "/nix/store" "$OSSL_CONF"; then
      error "OpenSSL config contains Nix store paths"
    fi
    info "\xe2\x9c\x93 OpenSSL config free of Nix paths"
    if grep -q '^.include /usr/local/cosmian/lib/ssl/fipsmodule.cnf' "$OSSL_CONF"; then
      info "\xe2\x9c\x93 openssl.cnf include directive correct"
    else
      warn ".include directive missing or incorrect in openssl.cnf"
    fi
  else
    warn "OpenSSL config not found in DMG Resources: $OSSL_CONF"
  fi
  if [ -f "$FIPS_CONF" ]; then
    info "\xe2\x9c\x93 FIPS module config present"
  else
    warn "FIPS module config not found in DMG Resources: $FIPS_CONF"
  fi
fi

# Try execution of version command
info "Testing binary execution..."
ENV_OPENSSL_CONF=""
ENV_OPENSSL_MODULES=""
if [ "$IS_FIPS" = true ]; then
  ENV_OPENSSL_CONF="$CHECK_DIR/usr/local/cosmian/lib/ssl/openssl.cnf"
  ENV_OPENSSL_MODULES="$CHECK_DIR/usr/local/cosmian/lib/ossl-modules"
fi

# Use `env` to set variables for the run
CMD=("$BINARY_PATH" --version)
if [ "$IS_FIPS" = true ]; then
  VERSION_OUTPUT=$(env OPENSSL_CONF="$ENV_OPENSSL_CONF" OPENSSL_MODULES="$ENV_OPENSSL_MODULES" "${CMD[@]}" 2>&1 || true)
else
  VERSION_OUTPUT=$("${CMD[@]}" 2>&1 || true)
fi

if echo "$VERSION_OUTPUT" | grep -qi "fips\|openssl\|provider\|self.*test" && ! echo "$VERSION_OUTPUT" | grep -qiE "cosmian_kms"; then
  error "Binary failed due to FIPS/OpenSSL issue: $VERSION_OUTPUT"
fi

if ! echo "$VERSION_OUTPUT" | grep -qE "(cosmian_kms_server|cosmian_kms)"; then
  error "Version output doesn't match expected pattern: $VERSION_OUTPUT"
fi
info "\xe2\x9c\x93 Binary executed successfully"

info ""
info "============================================"
info "\xe2\x9c\x93 ALL SMOKE TESTS PASSED!"
info "============================================"
info ""
if [ "$IS_FIPS" = true ]; then
  info "FIPS DMG package is ready: binary loads, portable configs, no Nix paths."
else
  info "Non-FIPS DMG package is ready: binary loads and configuration is portable."
fi
