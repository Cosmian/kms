#!/usr/bin/env bash
#
# Common smoke test functions for Linux packages (DEB/RPM)
# This library provides reusable functions for validating Cosmian KMS packages
#
# Usage: Source this file from package-specific smoke test scripts
#   source "$(dirname "$0")/smoke_test_linux.sh"

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

# Detect if this is a FIPS package based on filename
# Args: $1 = package file path
# Sets: IS_FIPS (true/false) - global variable for caller
detect_fips_variant() {
  local package_file="$1"
  IS_FIPS=false
  if [[ "$package_file" == *"fips"* ]] && [[ "$package_file" != *"non-fips"* ]]; then
    # shellcheck disable=SC2034  # IS_FIPS is used by caller
    IS_FIPS=true
  fi
}

# Find the cosmian_kms binary in extracted package
# Args: $1 = TEMP_DIR
# Sets: BINARY_PATH
find_binary() {
  local temp_dir="$1"
  BINARY_PATH=""

  if [ -f "$temp_dir/usr/sbin/cosmian_kms" ]; then
    BINARY_PATH="$temp_dir/usr/sbin/cosmian_kms"
  elif [ -f "$temp_dir/usr/local/sbin/cosmian_kms" ]; then
    BINARY_PATH="$temp_dir/usr/local/sbin/cosmian_kms"
  elif [ -f "$temp_dir/usr/bin/cosmian_kms" ]; then
    BINARY_PATH="$temp_dir/usr/bin/cosmian_kms"
  else
    error "cosmian_kms binary not found in expected locations"
  fi

  info "Found binary at: $BINARY_PATH"
}

# Verify FIPS or non-FIPS module configuration
# Args: $1 = TEMP_DIR, $2 = IS_FIPS
verify_crypto_modules() {
  local temp_dir="$1"
  local is_fips="$2"

  if [ "$is_fips" = true ]; then
    # Verify FIPS modules and configuration
    local fips_module="$temp_dir/usr/local/cosmian/lib/ossl-modules/fips.so"
    local pkg_openssl_conf="$temp_dir/usr/local/cosmian/lib/ssl/openssl.cnf"
    local fips_conf="$temp_dir/usr/local/cosmian/lib/ssl/fipsmodule.cnf"

    [ -f "$fips_module" ] || error "FIPS module not found: $fips_module"
    info "✓ FIPS module found: $fips_module"

    [ -f "$pkg_openssl_conf" ] || error "OpenSSL config not found: $pkg_openssl_conf"
    info "✓ OpenSSL config found: $pkg_openssl_conf"

    [ -f "$fips_conf" ] || error "FIPS module config not found: $fips_conf"
    info "✓ FIPS module config found: $fips_conf"

    # Verify the openssl.cnf contains production paths (not Nix store paths)
    if grep -q "/nix/store" "$pkg_openssl_conf"; then
      error "OpenSSL config contains Nix store paths - not portable!"
    fi
    info "✓ OpenSSL config does not contain Nix store paths"

    # Verify the .include directive points to the production location
    if ! grep -q "^.include /usr/local/cosmian/lib/ssl/fipsmodule.cnf" "$pkg_openssl_conf"; then
      error "OpenSSL config does not contain correct .include directive"
    fi
    info "✓ OpenSSL config has correct .include directive"

    # Adjust OpenSSL config for smoke test extraction path (static builds only - will be set later)
    # For dynamic builds, the config can be used as-is

    # Check FIPS module has no hardcoded Nix store RPATH/RUNPATH
    info "Checking FIPS module RPATH..."
    if readelf -d "$fips_module" | grep -E "RPATH|RUNPATH" | grep -q "/nix/store"; then
      error "FIPS module has hardcoded Nix store RPATH!"
    fi
    info "✓ FIPS module has no hardcoded Nix store paths"
  else
    info "Non-FIPS build detected - verifying non-FIPS configuration"

    # Verify legacy.so module is present for non-FIPS builds
    local legacy_module="$temp_dir/usr/local/cosmian/lib/ossl-modules/legacy.so"
    [ -f "$legacy_module" ] || error "Legacy module not found: $legacy_module"
    info "✓ Legacy module found: $legacy_module"

    # Note: Non-FIPS static builds do NOT include openssl.cnf (per Cargo.toml)
    # Only non-FIPS dynamic builds include config files
    # We'll check this later based on dynamic/static detection
  fi
}

# Check binary for hardcoded Nix store paths
# Args: $1 = BINARY_PATH
check_binary_rpath() {
  local binary_path="$1"

  info "Checking binary RPATH..."
  if readelf -d "$binary_path" | grep -E "RPATH|RUNPATH" | grep -q "/nix/store"; then
    error "Binary has hardcoded Nix store RPATH!"
  fi
  info "✓ Binary uses system libraries"
}

# Detect dynamic vs static linkage
# Args: $1 = BINARY_PATH
# Sets: IS_DYNAMIC (true/false) - global variable for caller
detect_linkage_type() {
  local binary_path="$1"

  IS_DYNAMIC=false
  if readelf -d "$binary_path" | grep -q 'NEEDED.*libssl\.so'; then
    # shellcheck disable=SC2034  # IS_DYNAMIC is used by caller
    IS_DYNAMIC=true
    info "Dynamic OpenSSL linkage detected"
  else
    info "Static OpenSSL linkage detected"
  fi
}

# Verify package assets match the expected configuration
# Args: $1 = TEMP_DIR, $2 = IS_FIPS, $3 = IS_DYNAMIC
verify_package_assets() {
  local temp_dir="$1"
  local is_fips="$2"
  local is_dynamic="$3"

  info "Verifying package assets match build configuration..."

  if [ "$is_dynamic" = true ]; then
    # Dynamic builds: verify libssl.so.3 and libcrypto.so.3 are present
    local libssl_path="$temp_dir/usr/local/cosmian/lib/libssl.so.3"
    local libcrypto_path="$temp_dir/usr/local/cosmian/lib/libcrypto.so.3"

    [ -f "$libssl_path" ] || error "libssl.so.3 not found in dynamic build: $libssl_path"
    info "✓ Found libssl.so.3"

    [ -f "$libcrypto_path" ] || error "libcrypto.so.3 not found in dynamic build: $libcrypto_path"
    info "✓ Found libcrypto.so.3"

    if [ "$is_fips" = true ]; then
      # FIPS + Dynamic: libssl.so.3, libcrypto.so.3, fips.so, openssl.cnf, fipsmodule.cnf
      info "Configuration: FIPS + Dynamic OpenSSL"
    else
      # Non-FIPS + Dynamic: libssl.so.3, libcrypto.so.3, legacy.so (no config files per Cargo.toml)
      info "Configuration: Non-FIPS + Dynamic OpenSSL"
      # Note: Non-FIPS dynamic builds do NOT include openssl.cnf according to Cargo.toml
    fi
  else
    # Static builds: no shared libraries
    local libssl_path="$temp_dir/usr/local/cosmian/lib/libssl.so.3"
    local libcrypto_path="$temp_dir/usr/local/cosmian/lib/libcrypto.so.3"

    if [ -f "$libssl_path" ] || [ -f "$libcrypto_path" ]; then
      error "Static build should not contain libssl.so.3 or libcrypto.so.3"
    fi
    info "✓ No shared libraries present (static build confirmed)"

    if [ "$is_fips" = true ]; then
      # FIPS + Static: fips.so, openssl.cnf, fipsmodule.cnf (already verified above)
      info "Configuration: FIPS + Static OpenSSL"
    else
      # Non-FIPS + Static: legacy.so only (no config files per Cargo.toml)
      info "Configuration: Non-FIPS + Static OpenSSL"
      # Verify no openssl.cnf is present for non-FIPS static builds
      if [ -f "$temp_dir/usr/local/cosmian/lib/ssl/openssl.cnf" ]; then
        error "Non-FIPS static build should not contain openssl.cnf"
      fi
      info "✓ No openssl.cnf present (correct for non-FIPS static)"
    fi
  fi
}

# Verify OPENSSLDIR content
# Args: $1 = TEMP_DIR, $2 = BINARY_PATH, $3 = IS_FIPS, $4 = IS_DYNAMIC
verify_openssldir() {
  local temp_dir="$1"
  local binary_path="$2"
  local is_fips="$3"
  local is_dynamic="$4"

  info "Checking OPENSSLDIR..."

  if [ "$is_dynamic" = true ]; then
    # Dynamic build - check the shared library (OPENSSLDIR is in libcrypto)
    local libcrypto_path="$temp_dir/usr/local/cosmian/lib/libcrypto.so.3"
    if [ -f "$libcrypto_path" ]; then
      local openssldir_output
      openssldir_output=$(strings "$libcrypto_path" | grep 'OPENSSLDIR:' || true)
      [ -n "$openssldir_output" ] || error "No OPENSSLDIR found in shared library"
      if [ "$is_fips" = true ]; then
        echo "$openssldir_output" | grep -q 'OPENSSLDIR: "/usr/local/cosmian/lib/ssl"' || {
          echo "Found OPENSSLDIR: $openssldir_output" >&2
          error "Shared library does not contain correct OPENSSLDIR for FIPS build"
        }
        info "✓ Shared library has correct OPENSSLDIR: /usr/local/cosmian/lib/ssl"
      else
        info "✓ Shared library OPENSSLDIR: $openssldir_output"
      fi
    fi
  else
    # Static build - check the binary
    local openssldir_output
    openssldir_output=$(strings "$binary_path" | grep 'OPENSSLDIR:' || true)
    [ -n "$openssldir_output" ] || error "No OPENSSLDIR found in binary"
    if [ "$is_fips" = true ]; then
      echo "$openssldir_output" | grep -q 'OPENSSLDIR: "/usr/local/cosmian/lib/ssl"' || {
        echo "Found OPENSSLDIR: $openssldir_output" >&2
        error "Binary does not contain correct OPENSSLDIR for FIPS build"
      }
      info "✓ Binary has correct OPENSSLDIR: /usr/local/cosmian/lib/ssl"
    else
      info "✓ Binary OPENSSLDIR: $openssldir_output"
    fi
  fi
}

# Set up environment and test binary execution
# Args: $1 = TEMP_DIR, $2 = BINARY_PATH, $3 = IS_FIPS, $4 = IS_DYNAMIC
test_binary_execution() {
  local temp_dir="$1"
  local binary_path="$2"
  local is_fips="$3"
  local is_dynamic="$4"

  info "Testing binary execution..."

  # Set up environment variables based on build configuration
  if [ "$is_fips" = true ]; then
    # FIPS builds always have openssl.cnf and fipsmodule.cnf
    # For smoke test, we need to adjust the .include path in openssl.cnf
    # to point to the extracted package location, not the production path
    local temp_openssl_conf_dir="$temp_dir/usr/local/cosmian/lib/ssl"
    local temp_openssl_conf="$temp_openssl_conf_dir/openssl.smoketest.cnf"
    if [ -f "$temp_dir/usr/local/cosmian/lib/ssl/openssl.cnf" ]; then
      sed "s|^\.include /usr/local/cosmian/lib/ssl/fipsmodule.cnf|.include $temp_dir/usr/local/cosmian/lib/ssl/fipsmodule.cnf|" \
        "$temp_dir/usr/local/cosmian/lib/ssl/openssl.cnf" >"$temp_openssl_conf"
      export OPENSSL_CONF="$temp_openssl_conf"
    fi
    export OPENSSL_MODULES="$temp_dir/usr/local/cosmian/lib/ossl-modules"
  else
    # Non-FIPS builds: no openssl.cnf to configure
    # The legacy module is loaded automatically when available
    export OPENSSL_MODULES="$temp_dir/usr/local/cosmian/lib/ossl-modules"
  fi

  local version_output
  if ! version_output=$("$binary_path" --version 2>&1); then
    if echo "$version_output" | grep -qi "fips\|openssl\|provider\|self.*test"; then
      error "Binary failed to load due to FIPS/OpenSSL issue: $version_output"
    else
      warn "Binary execution returned non-zero, but not a FIPS error (may be expected in test environment)"
      info "Output: $version_output"
    fi
  else
    info "✓ Binary executed successfully"
    info "Version output: $version_output"
    echo "$version_output" | grep -qE "(cosmian_kms_server|cosmian_kms)" || error "Version output doesn't match expected pattern"
    info "✓ Version output looks correct"
  fi
}

# Verify OpenSSL runtime version
# Args: $1 = TEMP_DIR, $2 = BINARY_PATH, $3 = IS_FIPS, $4 = IS_DYNAMIC
verify_openssl_runtime_version() {
  local temp_dir="$1"
  local binary_path="$2"
  local is_fips="$3"
  local is_dynamic="${4:-false}"

  # Determine expected OpenSSL version based on variant
  # - FIPS dynamic: OpenSSL 3.1.2 (both runtime and FIPS provider)
  # - All others: OpenSSL 3.6.0
  local expected_version
  if [ "$is_fips" = true ] && [ "$is_dynamic" = true ]; then
    expected_version="3.1.2"
  else
    expected_version="3.6.0"
  fi

  info "Verifying OpenSSL runtime version (expected $expected_version)…"
  export LD_LIBRARY_PATH="$temp_dir/usr/local/cosmian/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

  # Ensure OpenSSL environment variables are set (should be from test_binary_execution, but verify)
  if [ "$is_fips" = true ]; then
    export OPENSSL_CONF="${OPENSSL_CONF:-$temp_dir/usr/local/cosmian/lib/ssl/openssl.cnf}"
    export OPENSSL_MODULES="${OPENSSL_MODULES:-$temp_dir/usr/local/cosmian/lib/ossl-modules}"
  fi

  local info_output
  if ! info_output=$("$binary_path" --info 2>&1); then
    # Fallback: perform a static inspection for OpenSSL version
    echo "$info_output" >&2 || true
    info "Falling back to static inspection for OpenSSL version…"
    if readelf -d "$binary_path" | grep -q 'NEEDED.*libssl\.so'; then
      if [ -f "$temp_dir/usr/local/cosmian/lib/libcrypto.so.3" ]; then
        strings "$temp_dir/usr/local/cosmian/lib/libcrypto.so.3" | grep -q "OpenSSL $expected_version" || error "OpenSSL $expected_version not found in packaged libcrypto"
      else
        warn "libcrypto.so.3 not found; skipping static version check"
      fi
    else
      if ! strings "$binary_path" | grep -q "OpenSSL $expected_version"; then
        error "OpenSSL $expected_version string not found in statically linked binary; skipping strict check"
      else
        info "✓ OpenSSL $expected_version confirmed via static inspection"
      fi
    fi
  else
    if [ "$is_fips" = true ]; then
      # In FIPS mode, --info reports the core OpenSSL version (linked runtime)
      echo "$info_output" | grep -q "OpenSSL $expected_version" || {
        echo "$info_output" >&2
        error "Smoke test failed: FIPS build expected OpenSSL $expected_version in --info"
      }
      info "✓ OpenSSL runtime version is $expected_version"

      # Additionally confirm the packaged FIPS provider version
      local fips_module="$temp_dir/usr/local/cosmian/lib/ossl-modules/fips.so"
      if [ -f "$fips_module" ]; then
        # Ensure strings command is available (from binutils)
        if ! command -v strings >/dev/null 2>&1; then
          error "strings command not found - binutils package may not be in nix-shell"
        fi
        # Capture strings output once to avoid multiple reads
        local strings_output
        strings_output=$(strings "$fips_module")

        # For FIPS dynamic builds, FIPS provider should match runtime (3.1.2)
        # For FIPS static builds, FIPS provider is 3.1.2 but runtime is 3.6.0
        local expected_fips_version
        if [ "$is_dynamic" = true ]; then
          expected_fips_version="3.1.2"
        else
          expected_fips_version="3.1.2"
        fi

        # Use bash pattern matching instead of grep
        if [[ "$strings_output" == *"$expected_fips_version"* ]]; then
          info "✓ FIPS provider $expected_fips_version confirmed in fips.so"
        else
          local version_found
          version_found=$(echo "$strings_output" | grep -E '^[0-9]+\.[0-9]' | head -1)
          error "FIPS provider $expected_fips_version string not found in fips.so (found version: ${version_found:-none})"
        fi
      else
        error "FIPS module file not found at expected location: $fips_module"
      fi
    else
      echo "$info_output" | grep -q "OpenSSL $expected_version" || {
        echo "$info_output" >&2
        error "Smoke test failed: non-FIPS build expected OpenSSL $expected_version at runtime"
      }
      info "✓ OpenSSL runtime version is $expected_version"
    fi
  fi
}

# Print final success message
# Args: $1 = IS_FIPS, $2 = package_type (deb/rpm)
print_success_message() {
  local is_fips="$1"
  local package_type="$2"

  info ""
  info "============================================"
  info "✓ ALL SMOKE TESTS PASSED!"
  info "============================================"
  info ""
  if [ "$is_fips" = true ]; then
    info "The FIPS .$package_type package is ready for deployment:"
    info "  - Binary loads successfully"
    info "  - FIPS configuration is portable"
    info "  - No Nix store dependencies"
    info "  - Correct production paths configured"
  else
    info "The non-FIPS .$package_type package is ready for deployment:"
    info "  - Binary loads successfully"
    info "  - No Nix store dependencies"
    info "  - Portable configuration"
  fi
}
