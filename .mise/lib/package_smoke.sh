#!/usr/bin/env bash
# .mise/lib/package_smoke.sh — Shared smoke test functions for Linux packages (DEB/RPM).
#
# Source this from package smoke-test tasks:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/package_smoke.sh"
#
# Provides:
#   detect_fips_variant <package_file>
#   find_binary <temp_dir>
#   verify_crypto_modules <temp_dir> <is_fips>
#   check_binary_rpath <binary_path>
#   detect_linkage_type <binary_path>
#   verify_package_assets <temp_dir> <is_fips> <is_dynamic>
#   test_binary_execution <binary_path> <temp_dir> <is_fips> <is_dynamic>
#
# Globals set: IS_FIPS, IS_DYNAMIC, BINARY_PATH

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_PACKAGE_SMOKE_SH_LOADED:-}" ] && return 0
_MISE_PACKAGE_SMOKE_SH_LOADED=1

# ── Require common.sh ─────────────────────────────────────────────────────────
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  source "${MISE_CONFIG_ROOT:-.}/.mise/lib/common.sh"
fi

# ── State ─────────────────────────────────────────────────────────────────────
IS_FIPS=false
IS_DYNAMIC=false
BINARY_PATH=""

# Detect if this is a FIPS package based on filename.
# Args: $1 = package file path
# Sets: IS_FIPS (true/false)
detect_fips_variant() {
  local package_file="$1"
  # shellcheck disable=SC2034  # IS_FIPS is a global output variable consumed by callers
  IS_FIPS=false
  # shellcheck disable=SC2034
  if [[ "$package_file" == *"fips"* ]] && [[ "$package_file" != *"non-fips"* ]]; then
    IS_FIPS=true
  fi
}

# Find the cosmian_kms binary in extracted package.
# Args: $1 = temp_dir
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
    print_error "cosmian_kms binary not found in expected locations"
  fi
  print_status "Found binary at: $BINARY_PATH"
}

# Verify FIPS or non-FIPS module configuration.
# Args: $1 = temp_dir, $2 = is_fips (true/false)
verify_crypto_modules() {
  local temp_dir="$1" is_fips="$2"

  if [ "$is_fips" = true ]; then
    local fips_module="$temp_dir/usr/local/cosmian/lib/ossl-modules/fips.so"
    local pkg_openssl_conf="$temp_dir/usr/local/cosmian/lib/ssl/openssl.cnf"
    local fips_conf="$temp_dir/usr/local/cosmian/lib/ssl/fipsmodule.cnf"

    [ -f "$fips_module" ] || print_error "FIPS module not found: $fips_module"
    print_status "FIPS module found: $fips_module"

    [ -f "$pkg_openssl_conf" ] || print_error "OpenSSL config not found: $pkg_openssl_conf"
    print_status "OpenSSL config found: $pkg_openssl_conf"

    [ -f "$fips_conf" ] || print_error "FIPS module config not found: $fips_conf"
    print_status "FIPS module config found: $fips_conf"

    if grep -q "/nix/store" "$pkg_openssl_conf"; then
      print_error "OpenSSL config contains Nix store paths - not portable!"
    fi
    print_status "OpenSSL config does not contain Nix store paths"

    if ! grep -q "^.include /usr/local/cosmian/lib/ssl/fipsmodule.cnf" "$pkg_openssl_conf"; then
      print_error "OpenSSL config does not contain correct .include directive"
    fi
    print_status "OpenSSL config has correct .include directive"

    if readelf -d "$fips_module" | grep -E "RPATH|RUNPATH" | grep -q "/nix/store"; then
      print_error "FIPS module has hardcoded Nix store RPATH!"
    fi
    print_status "FIPS module has no hardcoded Nix store paths"
  else
    print_status "Non-FIPS build detected - verifying non-FIPS configuration"
    local legacy_module="$temp_dir/usr/local/cosmian/lib/ossl-modules/legacy.so"
    [ -f "$legacy_module" ] || print_error "Legacy module not found: $legacy_module"
    print_status "Legacy module found: $legacy_module"
  fi
}

# Check binary for hardcoded Nix store paths.
# Args: $1 = binary_path
check_binary_rpath() {
  local binary_path="$1"
  print_status "Checking binary RPATH..."
  if readelf -d "$binary_path" | grep -E "RPATH|RUNPATH" | grep -q "/nix/store"; then
    print_error "Binary has hardcoded Nix store RPATH!"
  fi
  print_status "Binary uses system libraries (no Nix store RPATH)"
}

# Detect dynamic vs static linkage.
# Args: $1 = binary_path
# Sets: IS_DYNAMIC (true/false)
detect_linkage_type() {
  local binary_path="$1"
  # shellcheck disable=SC2034  # IS_DYNAMIC is a global output variable consumed by callers
  IS_DYNAMIC=false
  # shellcheck disable=SC2034
  if readelf -d "$binary_path" | grep -q 'NEEDED.*libssl\.so'; then
    IS_DYNAMIC=true
    print_status "Dynamic OpenSSL linkage detected"
  else
    print_status "Static OpenSSL linkage detected"
  fi
}

# Verify package assets match the expected configuration.
# Args: $1 = temp_dir, $2 = is_fips, $3 = is_dynamic
verify_package_assets() {
  local temp_dir="$1" is_fips="$2" is_dynamic="$3"
  print_status "Verifying package assets match build configuration..."

  if [ "$is_dynamic" = true ]; then
    local libssl_path="$temp_dir/usr/local/cosmian/lib/libssl.so.3"
    local libcrypto_path="$temp_dir/usr/local/cosmian/lib/libcrypto.so.3"
    [ -f "$libssl_path" ] || print_error "libssl.so.3 not found in dynamic build"
    print_status "Found libssl.so.3"
    [ -f "$libcrypto_path" ] || print_error "libcrypto.so.3 not found in dynamic build"
    print_status "Found libcrypto.so.3"
  else
    local libssl_path="$temp_dir/usr/local/cosmian/lib/libssl.so.3"
    local libcrypto_path="$temp_dir/usr/local/cosmian/lib/libcrypto.so.3"
    if [ -f "$libssl_path" ] || [ -f "$libcrypto_path" ]; then
      print_error "Static build should not contain libssl.so.3 or libcrypto.so.3"
    fi
    print_status "No shared libraries present (static build confirmed)"
    if [ "$is_fips" != true ] && [ -f "$temp_dir/usr/local/cosmian/lib/ssl/openssl.cnf" ]; then
      print_error "Non-FIPS static build should not contain openssl.cnf"
    fi
  fi
}

# Run the binary with --version to validate execution.
# Args: $1 = binary_path, $2 = temp_dir, $3 = is_fips, $4 = is_dynamic
test_binary_execution() {
  local binary_path="$1" temp_dir="$2" is_fips="$3" is_dynamic="$4"
  print_status "Testing binary execution..."

  local env_vars=()
  if [ "$is_fips" = true ]; then
    env_vars+=(
      "OPENSSL_CONF=$temp_dir/usr/local/cosmian/lib/ssl/openssl.cnf"
      "OPENSSL_MODULES=$temp_dir/usr/local/cosmian/lib/ossl-modules"
    )
  fi
  if [ "$is_dynamic" = true ]; then
    env_vars+=("LD_LIBRARY_PATH=$temp_dir/usr/local/cosmian/lib")
  fi

  local version_output
  if [ ${#env_vars[@]} -gt 0 ]; then
    version_output=$(env "${env_vars[@]}" "$binary_path" --version 2>&1) || true
  else
    version_output=$("$binary_path" --version 2>&1) || true
  fi

  if [ -z "$version_output" ]; then
    print_error "Binary produced no version output"
  fi
  print_status "Binary version: $version_output"
  print_success "Binary execution test passed"
}
