#!/usr/bin/env bash
# Setup OpenSSL runtime files in /usr/local/lib/openssl
# This script is only needed for FIPS builds
# Non-FIPS builds work out of the box without any runtime setup
set -euo pipefail

# Check if this is a non-FIPS build
if [ -n "${FEATURES:-}" ] && [[ "$FEATURES" == *"non-fips"* ]]; then
  echo "This is a non-FIPS build - no OpenSSL runtime setup needed"
  echo "You can run cosmian_kms directly without any configuration"
  exit 0
fi

# Find the OpenSSL nix store path
OPENSSL_STORE_PATH="${NIX_OPENSSL_OUT:-}"

if [ -z "$OPENSSL_STORE_PATH" ]; then
  echo "Error: NIX_OPENSSL_OUT environment variable is not set"
  echo "This script should be run from within the nix-shell environment"
  exit 1
fi

if [ ! -d "$OPENSSL_STORE_PATH" ]; then
  echo "Error: OpenSSL store path does not exist: $OPENSSL_STORE_PATH"
  exit 1
fi

echo "Setting up OpenSSL runtime files in /usr/local/lib/openssl"
echo "OpenSSL source: $OPENSSL_STORE_PATH"

# Create the target directory
sudo mkdir -p /usr/local/lib/openssl
sudo mkdir -p /usr/local/lib/openssl/ossl-modules

# Copy configuration files
if [ -f "$OPENSSL_STORE_PATH/ssl/openssl.cnf" ]; then
  echo "Copying openssl.cnf..."
  sudo cp "$OPENSSL_STORE_PATH/ssl/openssl.cnf" /usr/local/lib/openssl/
else
  echo "Warning: openssl.cnf not found at $OPENSSL_STORE_PATH/ssl/openssl.cnf"
fi

# Copy FIPS provider module - check both lib and lib64
FIPS_MODULE=""
if [ -f "$OPENSSL_STORE_PATH/lib64/ossl-modules/fips.so" ]; then
  FIPS_MODULE="$OPENSSL_STORE_PATH/lib64/ossl-modules/fips.so"
elif [ -f "$OPENSSL_STORE_PATH/lib/ossl-modules/fips.so" ]; then
  FIPS_MODULE="$OPENSSL_STORE_PATH/lib/ossl-modules/fips.so"
fi

if [ -n "$FIPS_MODULE" ]; then
  echo "Copying FIPS provider module..."
  sudo cp "$FIPS_MODULE" /usr/local/lib/openssl/ossl-modules/

  # Regenerate fipsmodule.cnf with the correct MAC for the copied module
  echo "Regenerating FIPS module configuration..."
  if [ -f "$OPENSSL_STORE_PATH/bin/openssl" ]; then
    sudo "$OPENSSL_STORE_PATH/bin/openssl" fipsinstall \
      -module /usr/local/lib/openssl/ossl-modules/fips.so \
      -out /usr/local/lib/openssl/fipsmodule.cnf

    # Add explicit module path to fipsmodule.cnf
    echo "Adding module path to fipsmodule.cnf..."
    sudo sed -i '/^\[fips_sect\]/a module-filename = /usr/local/lib/openssl/ossl-modules/fips.so' /usr/local/lib/openssl/fipsmodule.cnf
  fi
else
  echo "Warning: fips.so not found"
fi

# Copy legacy provider if it exists
LEGACY_MODULE=""
if [ -f "$OPENSSL_STORE_PATH/lib64/ossl-modules/legacy.so" ]; then
  LEGACY_MODULE="$OPENSSL_STORE_PATH/lib64/ossl-modules/legacy.so"
elif [ -f "$OPENSSL_STORE_PATH/lib/ossl-modules/legacy.so" ]; then
  LEGACY_MODULE="$OPENSSL_STORE_PATH/lib/ossl-modules/legacy.so"
fi

if [ -n "$LEGACY_MODULE" ]; then
  echo "Copying legacy provider module..."
  sudo cp "$LEGACY_MODULE" /usr/local/lib/openssl/ossl-modules/
fi

# Update the openssl.cnf to point to the correct paths
if [ -f "/usr/local/lib/openssl/openssl.cnf" ]; then
  echo "Updating paths in openssl.cnf..."
  sudo sed -i "s|$OPENSSL_STORE_PATH/ssl|/usr/local/lib/openssl|g" /usr/local/lib/openssl/openssl.cnf
fi

echo ""
echo "✓ OpenSSL runtime files installed successfully!"
echo ""
echo "Files installed:"
ls -la /usr/local/lib/openssl/
ls -la /usr/local/lib/openssl/ossl-modules/
echo ""
echo "You can now run: ./target/debug/cosmian_kms --info"
