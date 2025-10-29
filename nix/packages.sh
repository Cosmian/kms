#!/usr/bin/env bash
set -euo pipefail
set -x

# Discover repo root (works inside nix-shell)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# Resolve inputs with defaults inside the nix environment
: "${DEBUG_OR_RELEASE:=release}"
: "${FEATURES:=}"

# Using nix-shell OpenSSL toolchain provided by the environment (no external import)

FEATURES_FLAG=()
if [ -n "$FEATURES" ]; then
  FEATURES_FLAG=(--features "$FEATURES")
fi

# Detect OS
UNAME=$(uname)

# Clean previous packaging artifacts
rm -rf target/debian
rm -rf target/generate-rpm

# macOS: Build DMG package using cargo-packager
if [ "$UNAME" = "Darwin" ]; then
  echo "Building DMG package for macOS..."

  cargo install --version 0.11.7 cargo-packager --force

  cd crate/server
  cargo build --features non-fips --release
  cargo packager --verbose --formats dmg --release
  cd "$REPO_ROOT"

  echo "DMG package build completed successfully."
  exit 0
fi

# Linux: Build DEB and RPM packages
echo "Building packages for Linux..."

# Install packaging tools
cargo install --version 2.4.0 cargo-deb --force
cargo install --version 0.16.0 cargo-generate-rpm --force

# Copy OpenSSL artifacts from Nix store to a staging directory for packaging
echo "Preparing OpenSSL artifacts for packaging..."

# Use a staging directory in the project that doesn't require special permissions
OPENSSL_STAGING="$REPO_ROOT/target/openssl-staging"
mkdir -p "$OPENSSL_STAGING/lib64/ossl-modules"
mkdir -p "$OPENSSL_STAGING/ssl"

# Find OpenSSL in Nix store - it should be in PATH from nix-shell
# Use type -p instead of which for better portability
OPENSSL_PATH=$(type -p openssl || command -v openssl)
if [ -z "$OPENSSL_PATH" ]; then
  echo "Error: openssl not found in PATH" >&2
  exit 1
fi

OPENSSL_DIR=$(dirname "$(dirname "$OPENSSL_PATH")")

echo "Using OpenSSL from: $OPENSSL_DIR"
echo "Staging OpenSSL artifacts to: $OPENSSL_STAGING"

# Copy FIPS and legacy modules
if [ -f "$OPENSSL_DIR/lib64/ossl-modules/fips.so" ]; then
  cp "$OPENSSL_DIR/lib64/ossl-modules/fips.so" "$OPENSSL_STAGING/lib64/ossl-modules/"
  echo "Copied fips.so from lib64"
elif [ -f "$OPENSSL_DIR/lib/ossl-modules/fips.so" ]; then
  cp "$OPENSSL_DIR/lib/ossl-modules/fips.so" "$OPENSSL_STAGING/lib64/ossl-modules/"
  echo "Copied fips.so from lib"
else
  echo "Error: fips.so not found"
  exit 1
fi

if [ -f "$OPENSSL_DIR/lib64/ossl-modules/legacy.so" ]; then
  cp "$OPENSSL_DIR/lib64/ossl-modules/legacy.so" "$OPENSSL_STAGING/lib64/ossl-modules/"
  echo "Copied legacy.so from lib64"
elif [ -f "$OPENSSL_DIR/lib/ossl-modules/legacy.so" ]; then
  cp "$OPENSSL_DIR/lib/ossl-modules/legacy.so" "$OPENSSL_STAGING/lib64/ossl-modules/"
  echo "Copied legacy.so from lib"
else
  echo "Error: legacy.so not found"
  exit 1
fi

# Copy SSL configuration files
if [ -f "$OPENSSL_DIR/ssl/openssl.cnf" ]; then
  cp "$OPENSSL_DIR/ssl/openssl.cnf" "$OPENSSL_STAGING/ssl/"
  echo "Copied openssl.cnf"
fi
if [ -f "$OPENSSL_DIR/ssl/fipsmodule.cnf" ]; then
  cp "$OPENSSL_DIR/ssl/fipsmodule.cnf" "$OPENSSL_STAGING/ssl/"
  echo "Copied fipsmodule.cnf"
fi

echo "OpenSSL artifacts prepared at: $OPENSSL_STAGING"
ls -la "$OPENSSL_STAGING/lib64/ossl-modules/"
ls -la "$OPENSSL_STAGING/ssl/"

# Red Hat/Fedora/CentOS: Build RPM package
echo "Building RPM package for Red Hat-based system..."

# Build with non-fips features for RPM
cd crate/server
cargo build --features non-fips --release
cd "$REPO_ROOT"

cargo generate-rpm -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml

echo "RPM package built successfully."

# Debian/Ubuntu: Build DEB package
echo "Building DEB package for Debian-based system..."

if [ -n "$FEATURES" ]; then
  # Non-FIPS variant
  cargo deb -p cosmian_kms_server "${FEATURES_FLAG[@]}"
else
  # FIPS variant
  cargo deb -p cosmian_kms_server --variant fips
fi

echo "DEB package built successfully."

# Display package location
if [ -f /etc/redhat-release ]; then
  find target/generate-rpm -name "*.rpm" -type f
elif [ -f /etc/debian_version ]; then
  find target/debian -name "*.deb" -type f
fi

echo "Package build completed successfully."
