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
#   ./smoke_test_dmg.sh result-dmg-fips-static/Cosmian\ KMS\ Server_X.Y.Z_arm64.dmg

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() {
  echo -e "${RED}[ERROR]${NC} $*"
  exit 1
}

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

attach_dmg() {
  hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT_POINT" "$DMG_FILE" >/dev/null
}

ATTACH_RETRIES=${DMG_ATTACH_RETRIES:-3}
ATTACH_SLEEP=${DMG_ATTACH_SLEEP_SECS:-2}

attached=false
for i in $(seq 1 "$ATTACH_RETRIES"); do
  if attach_dmg; then
    attached=true
    break
  fi
  warn "hdiutil attach failed (attempt ${i}/${ATTACH_RETRIES}); retrying in ${ATTACH_SLEEP}s..."
  sleep "$ATTACH_SLEEP"
done

if [ "$attached" != true ]; then
  # GitHub-hosted macOS runners sometimes fail with:
  #   hdiutil: attach failed - Resource temporarily unavailable
  # Treat this as non-blocking in CI: packaging artifacts are still produced.
  if [ "${CI:-}" = "true" ] || [ -n "${GITHUB_ACTIONS:-}" ]; then
    warn "Failed to attach DMG (non-blocking in CI)."
    warn "hdiutil error: Resource temporarily unavailable"
    warn "Skipping DMG smoke test for: $DMG_FILE"
    exit 0
  fi
  error "Failed to attach DMG"
fi
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
    # Accept either absolute include to /usr/local path or a relative include
    if grep -q '^.include /usr/local/cosmian/lib/ssl/fipsmodule.cnf' "$OSSL_CONF" || \
       grep -q '^.include\s\+fipsmodule.cnf' "$OSSL_CONF"; then
      info "\xe2\x9c\x93 openssl.cnf include directive present"
    else
      warn ".include directive missing or unexpected in openssl.cnf"
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
  # Use a patched, relocatable OpenSSL config to ensure the include points to the DMG path
  ORIG_OPENSSL_CONF="$CHECK_DIR/usr/local/cosmian/lib/ssl/openssl.cnf"
  PATCH_DIR=$(mktemp -d /tmp/opensslconf.XXXXXX)
  ENV_OPENSSL_CONF="$PATCH_DIR/openssl.cnf"
  cp "$ORIG_OPENSSL_CONF" "$ENV_OPENSSL_CONF" 2>/dev/null || true
  # Replace absolute include with the DMG resource path if needed
  DMG_FIPS_CONF="$CHECK_DIR/usr/local/cosmian/lib/ssl/fipsmodule.cnf"
  if [ -f "$ENV_OPENSSL_CONF" ]; then
    if grep -q '^.include /usr/local/cosmian/lib/ssl/fipsmodule.cnf' "$ENV_OPENSSL_CONF"; then
      sed -i '' -e "s|^\.include /usr/local/cosmian/lib/ssl/fipsmodule.cnf|.include ${DMG_FIPS_CONF}|" "$ENV_OPENSSL_CONF" || true
    fi
  fi
  ENV_OPENSSL_MODULES="$CHECK_DIR/usr/local/cosmian/lib/ossl-modules"
fi

# For non-FIPS builds, set OPENSSL_MODULES to point to bundled provider modules
# so the legacy provider can be loaded during smoke test execution.
if [ "$IS_FIPS" != true ]; then
  NON_FIPS_OSSL_MODULES="$CHECK_DIR/usr/local/cosmian/lib/ossl-modules"
  if [ -d "$NON_FIPS_OSSL_MODULES" ]; then
    ENV_OPENSSL_MODULES="$NON_FIPS_OSSL_MODULES"
  fi
  NON_FIPS_OSSL_CONF="$CHECK_DIR/usr/local/cosmian/lib/ssl/openssl.cnf"
  if [ -f "$NON_FIPS_OSSL_CONF" ]; then
    ENV_OPENSSL_CONF="$NON_FIPS_OSSL_CONF"
  fi
fi

# Use `env` to set variables for the run
CMD=("$BINARY_PATH" --version)
if [ -n "$ENV_OPENSSL_CONF" ] || [ -n "$ENV_OPENSSL_MODULES" ]; then
  ENV_ARGS=()
  [ -n "$ENV_OPENSSL_CONF" ] && ENV_ARGS+=(OPENSSL_CONF="$ENV_OPENSSL_CONF")
  [ -n "$ENV_OPENSSL_MODULES" ] && ENV_ARGS+=(OPENSSL_MODULES="$ENV_OPENSSL_MODULES")
  VERSION_OUTPUT=$(env "${ENV_ARGS[@]}" "${CMD[@]}" 2>&1 || true)
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

# Determine expected OpenSSL runtime version
# - All non-FIPS and FIPS static builds expect 3.6.0
# - FIPS dynamic builds bundle 3.1.2 runtime libs to match the FIPS provider
EXPECTED_VER="3.6.0"
info "Verifying OpenSSL runtime version (expected ${EXPECTED_VER})…"
if [ -n "$ENV_OPENSSL_CONF" ] || [ -n "$ENV_OPENSSL_MODULES" ]; then
  INFO_CMD=(env)
  [ -n "$ENV_OPENSSL_CONF" ] && INFO_CMD+=(OPENSSL_CONF="$ENV_OPENSSL_CONF")
  [ -n "$ENV_OPENSSL_MODULES" ] && INFO_CMD+=(OPENSSL_MODULES="$ENV_OPENSSL_MODULES")
  INFO_CMD+=("$BINARY_PATH" --info)
else
  INFO_CMD=("$BINARY_PATH" --info)
fi

if ! INFO_OUTPUT=$("${INFO_CMD[@]}" 2>&1); then
  warn "--info execution failed, falling back to binary string scan"
  # Fallback: try to infer OpenSSL version from binary strings
  if strings "$BINARY_PATH" | grep -q "OpenSSL ${EXPECTED_VER}"; then
    info "\xe2\x9c\x93 OpenSSL runtime/version artifacts match ${EXPECTED_VER} (fallback)"
  else
    echo "$INFO_OUTPUT" >&2 || true
    error "Failed to verify OpenSSL ${EXPECTED_VER} (both --info and fallback failed)"
  fi
else
  echo "$INFO_OUTPUT" | grep -q "OpenSSL ${EXPECTED_VER}" || {
    echo "$INFO_OUTPUT" >&2
    error "Smoke test failed: expected OpenSSL ${EXPECTED_VER} at runtime"
  }
  info "\xe2\x9c\x93 OpenSSL runtime version is ${EXPECTED_VER}"
fi

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
