#!/usr/bin/env bash
# Setup OpenSSL runtime files in /usr/local/lib/openssl (FIPS only)
set -euo pipefail

# Skip for non-FIPS builds
[ -n "${FEATURES:-}" ] && [[ "$FEATURES" == *"non-fips"* ]] && {
  echo "This is a non-FIPS build - no OpenSSL runtime setup needed"
  echo "You can run cosmian_kms directly without any configuration"
  exit 0
}

OPENSSL_STORE_PATH="${NIX_OPENSSL_OUT:-}"
[ -z "$OPENSSL_STORE_PATH" ] && {
  echo "Error: NIX_OPENSSL_OUT environment variable is not set" >&2
  echo "This script should be run from within the nix-shell environment" >&2
  exit 1
}

[ ! -d "$OPENSSL_STORE_PATH" ] && {
  echo "Error: OpenSSL store path does not exist: $OPENSSL_STORE_PATH" >&2
  exit 1
}

echo "Setting up OpenSSL runtime files in /usr/local/lib/openssl"
echo "OpenSSL source: $OPENSSL_STORE_PATH"

sudo mkdir -p /usr/local/lib/openssl/ossl-modules

# Copy configuration files
[ -f "$OPENSSL_STORE_PATH/ssl/openssl.cnf" ] && {
  echo "Copying openssl.cnf..."
  sudo cp "$OPENSSL_STORE_PATH/ssl/openssl.cnf" /usr/local/lib/openssl/
} || echo "Warning: openssl.cnf not found at $OPENSSL_STORE_PATH/ssl/openssl.cnf"

# Find and copy FIPS provider module
FIPS_MODULE=""
for libdir in lib64 lib; do
  [ -f "$OPENSSL_STORE_PATH/$libdir/ossl-modules/fips.so" ] && {
    FIPS_MODULE="$OPENSSL_STORE_PATH/$libdir/ossl-modules/fips.so"
    break
  }
done

[ -n "$FIPS_MODULE" ] && {
  echo "Copying FIPS provider module..."
  sudo cp "$FIPS_MODULE" /usr/local/lib/openssl/ossl-modules/

  [ -f "$OPENSSL_STORE_PATH/bin/openssl" ] && {
    echo "Regenerating FIPS module configuration..."
    sudo "$OPENSSL_STORE_PATH/bin/openssl" fipsinstall \
      -module /usr/local/lib/openssl/ossl-modules/fips.so \
      -out /usr/local/lib/openssl/fipsmodule.cnf
    echo "Adding module path to fipsmodule.cnf..."
    sudo sed -i '/^\[fips_sect\]/a module-filename = /usr/local/lib/openssl/ossl-modules/fips.so' \
      /usr/local/lib/openssl/fipsmodule.cnf
  }
} || echo "Warning: fips.so not found"

# Copy legacy provider if it exists
for libdir in lib64 lib; do
  [ -f "$OPENSSL_STORE_PATH/$libdir/ossl-modules/legacy.so" ] && {
    echo "Copying legacy provider module..."
    sudo cp "$OPENSSL_STORE_PATH/$libdir/ossl-modules/legacy.so" /usr/local/lib/openssl/ossl-modules/
    break
  }
done

# Update paths in openssl.cnf
[ -f "/usr/local/lib/openssl/openssl.cnf" ] && {
  echo "Updating paths in openssl.cnf..."
  sudo sed -i "s|$OPENSSL_STORE_PATH/ssl|/usr/local/lib/openssl|g" /usr/local/lib/openssl/openssl.cnf
}

echo ""
echo "✓ OpenSSL runtime files installed successfully!"
echo ""
echo "Files installed:"
ls -la /usr/local/lib/openssl/
ls -la /usr/local/lib/openssl/ossl-modules/
echo ""
echo "You can now run: ./target/debug/cosmian_kms --info"
