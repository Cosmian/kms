#!/usr/bin/env bash
# Common build utilities for Cosmian KMS build and packaging scripts
# Source this file to use the functions

# Prepare OpenSSL staging directory for packaging
# Usage: prepare_openssl_staging
prepare_openssl_staging() {
  local repo_root="${1:-$(pwd)}"
  : "${FEATURES:=}"

  # Determine variant based on FEATURES
  local variant_name module_name
  if [ -n "$FEATURES" ]; then
    variant_name="non-FIPS"
    module_name="legacy"
  else
    variant_name="FIPS"
    module_name="fips"
  fi

  echo "Preparing OpenSSL artifacts for ${variant_name} packaging..."

  local openssl_staging="$repo_root/target/openssl-staging"

  # Clean staging directory first
  rm -rf "$openssl_staging"
  mkdir -p "$openssl_staging/lib64/ossl-modules"

  # Find OpenSSL in Nix store
  local openssl_path openssl_dir
  openssl_path=$(type -p openssl || command -v openssl)
  if [ -z "$openssl_path" ]; then
    echo "Error: openssl not found in PATH" >&2
    return 1
  fi

  openssl_dir=$(dirname "$(dirname "$openssl_path")")
  echo "Using OpenSSL from: $openssl_dir"
  echo "Staging OpenSSL artifacts to: $openssl_staging"

  # Copy the appropriate module
  if [ -f "$openssl_dir/lib64/ossl-modules/${module_name}.so" ]; then
    cp "$openssl_dir/lib64/ossl-modules/${module_name}.so" "$openssl_staging/lib64/ossl-modules/"
    echo "Copied ${module_name}.so from lib64"
  elif [ -f "$openssl_dir/lib/ossl-modules/${module_name}.so" ]; then
    cp "$openssl_dir/lib/ossl-modules/${module_name}.so" "$openssl_staging/lib64/ossl-modules/"
    echo "Copied ${module_name}.so from lib"
  else
    echo "Error: ${module_name}.so not found" >&2
    return 1
  fi

  # Copy SSL configuration files for FIPS variant
  if [ -z "$FEATURES" ]; then
    mkdir -p "$openssl_staging/ssl"

    if [ -f "$openssl_dir/ssl/openssl.cnf" ]; then
      cp "$openssl_dir/ssl/openssl.cnf" "$openssl_staging/ssl/"
      # Replace nix store path with /usr/local/lib/openssl
      sed -i "s|$openssl_dir/ssl|/usr/local/lib/openssl|g" "$openssl_staging/ssl/openssl.cnf"
      echo "Copied and updated openssl.cnf"
    fi

    if [ -f "$openssl_dir/ssl/fipsmodule.cnf" ]; then
      # Regenerate fipsmodule.cnf with correct module path for packaging
      "$openssl_path" fipsinstall \
        -module "$openssl_staging/lib64/ossl-modules/fips.so" \
        -out "$openssl_staging/ssl/fipsmodule.cnf"

      # Add explicit module path pointing to install location
      sed -i '/^\[fips_sect\]/a module-filename = /usr/local/lib/openssl/lib64/ossl-modules/fips.so' \
        "$openssl_staging/ssl/fipsmodule.cnf"

      echo "Regenerated fipsmodule.cnf with correct MAC and paths"
    fi
  fi

  echo "OpenSSL ${variant_name} artifacts prepared at: $openssl_staging"
  ls -la "$openssl_staging/lib64/ossl-modules/"
  if [ -z "$FEATURES" ]; then
    ls -la "$openssl_staging/ssl/"
  fi
}
