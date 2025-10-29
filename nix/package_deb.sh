#!/usr/bin/env bash
set -euo pipefail
set -x

# Build DEB package (FIPS or non-FIPS based on FEATURES env variable)
# This script is called from nix.sh inside a nix-shell environment

# Discover repo root (works inside nix-shell)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# Determine variant based on FEATURES environment variable
: "${FEATURES:=}"

if [ -n "$FEATURES" ]; then
  VARIANT_NAME="non-FIPS"
  MODULE_NAME="legacy"
  BUILD_VARIANT=""
else
  VARIANT_NAME="FIPS"
  MODULE_NAME="fips"
  BUILD_VARIANT="--variant fips"
fi

echo "Building ${VARIANT_NAME} DEB package for Debian-based system..."

# Clean previous packaging artifacts
rm -rf target/debian

# Install packaging tool
cargo install --version 2.4.0 cargo-deb --force

# Prepare OpenSSL artifacts from Nix store
echo "Preparing OpenSSL artifacts for ${VARIANT_NAME} packaging..."

OPENSSL_STAGING="$REPO_ROOT/target/openssl-staging"

# Clean staging directory first to avoid permission issues with read-only files from Nix store
rm -rf "$OPENSSL_STAGING"

mkdir -p "$OPENSSL_STAGING/lib64/ossl-modules"

# Find OpenSSL in Nix store - it should be in PATH from nix-shell
OPENSSL_PATH=$(type -p openssl || command -v openssl)
if [ -z "$OPENSSL_PATH" ]; then
  echo "Error: openssl not found in PATH" >&2
  exit 1
fi

OPENSSL_DIR=$(dirname "$(dirname "$OPENSSL_PATH")")

echo "Using OpenSSL from: $OPENSSL_DIR"
echo "Staging OpenSSL artifacts to: $OPENSSL_STAGING"

# Copy the appropriate module based on variant
if [ -f "$OPENSSL_DIR/lib64/ossl-modules/${MODULE_NAME}.so" ]; then
  cp "$OPENSSL_DIR/lib64/ossl-modules/${MODULE_NAME}.so" "$OPENSSL_STAGING/lib64/ossl-modules/"
  echo "Copied ${MODULE_NAME}.so from lib64"
elif [ -f "$OPENSSL_DIR/lib/ossl-modules/${MODULE_NAME}.so" ]; then
  cp "$OPENSSL_DIR/lib/ossl-modules/${MODULE_NAME}.so" "$OPENSSL_STAGING/lib64/ossl-modules/"
  echo "Copied ${MODULE_NAME}.so from lib"
else
  echo "Error: ${MODULE_NAME}.so not found"
  exit 1
fi

# Copy SSL configuration files for FIPS variant
if [ -z "$FEATURES" ]; then
  mkdir -p "$OPENSSL_STAGING/ssl"
  if [ -f "$OPENSSL_DIR/ssl/openssl.cnf" ]; then
    cp "$OPENSSL_DIR/ssl/openssl.cnf" "$OPENSSL_STAGING/ssl/"
    echo "Copied openssl.cnf"
  fi
  if [ -f "$OPENSSL_DIR/ssl/fipsmodule.cnf" ]; then
    cp "$OPENSSL_DIR/ssl/fipsmodule.cnf" "$OPENSSL_STAGING/ssl/"
    echo "Copied fipsmodule.cnf"
  fi
fi

echo "OpenSSL ${VARIANT_NAME} artifacts prepared at: $OPENSSL_STAGING"
ls -la "$OPENSSL_STAGING/lib64/ossl-modules/"
if [ -z "$FEATURES" ]; then
  ls -la "$OPENSSL_STAGING/ssl/" || true
fi

# Build the server with appropriate features
cd crate/server
if [ -n "$FEATURES" ]; then
  cargo build --features "$FEATURES" --release
else
  cargo build --release
fi
cd "$REPO_ROOT"

# Build DEB package with appropriate variant
# shellcheck disable=SC2086
cargo deb -p cosmian_kms_server $BUILD_VARIANT

echo "${VARIANT_NAME} DEB package built successfully."

# Display package location
find target/debian -name "*.deb" -type f

echo "${VARIANT_NAME} DEB package build completed successfully."
