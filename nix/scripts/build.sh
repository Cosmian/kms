#!/usr/bin/env bash
set -eo pipefail
set -x

# Resolve inputs with defaults inside the nix environment
: "${DEBUG_OR_RELEASE:=debug}"
: "${FEATURES:=}"

RELEASE_FLAG=""
if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE_FLAG="--release"
fi

# Construct features flag
FEATURES_FLAG=()
if [ -n "$FEATURES" ]; then
  FEATURES_FLAG=(--features "$FEATURES")
fi

cargo build -p cosmian_kms_server $RELEASE_FLAG "${FEATURES_FLAG[@]}"

COSMIAN_KMS_EXE="target/$DEBUG_OR_RELEASE/cosmian_kms"

# For verification during build, we temporarily use the nix store OpenSSL config
# At runtime, the binary will use /usr/local/lib/openssl (its compiled-in OPENSSLDIR)
# after running the setup_openssl_runtime.sh script
export OPENSSL_CONF="${NIX_OPENSSL_OUT:-}/ssl/openssl.cnf"
INFO_OUTPUT=$("$COSMIAN_KMS_EXE" --version 2>&1 || true)
echo "$INFO_OUTPUT"
echo "$INFO_OUTPUT" | grep -q "cosmian_kms_server" || {
  echo "Error: Binary does not appear to be working" >&2
  exit 1
}

# Unset OPENSSL_CONF so runtime will use the compiled-in OPENSSLDIR
unset OPENSSL_CONF

echo "Note: Binary built with OPENSSLDIR=/usr/local/lib/openssl"
echo "Run 'nix-shell --keep NIX_OPENSSL_OUT shell.nix --run \"bash nix/scripts/setup_openssl_runtime.sh\"' to install runtime files"

UNAME=$(uname)
if [ "$UNAME" = "Linux" ]; then
  LDD_OUTPUT=$(ldd "$COSMIAN_KMS_EXE")
  echo "$LDD_OUTPUT"
  echo "$LDD_OUTPUT" | grep -qi ssl && {
    echo "Error: Dynamic OpenSSL linkage detected on Linux (ldd | grep ssl)." >&2
    exit 1
  }

  # Verify GLIBC symbol versions are <= 2.28 (Linux only)
  GLIBC_SYMS=$(readelf -sW "$COSMIAN_KMS_EXE" | grep -o 'GLIBC_[0-9][0-9.]*' | sort -Vu)
  echo "$GLIBC_SYMS"
  MAX_GLIBC_VER=""
  if [ -n "$GLIBC_SYMS" ]; then
    MAX_GLIBC_VER=$(echo "$GLIBC_SYMS" | sed 's/^GLIBC_//' | sort -V | tail -n1)
  fi
  if [ -n "$MAX_GLIBC_VER" ] && [ "$(printf '%s\n' "$MAX_GLIBC_VER" "2.28" | sort -V | tail -n1)" != "2.28" ]; then
    echo "Error: GLIBC symbols exceed 2.28 (max found: $MAX_GLIBC_VER)." >&2
    exit 1
  fi
else
  # macOS: check with otool
  if command -v otool >/dev/null 2>&1; then
    OTOOL_OUTPUT=$(otool -L "$COSMIAN_KMS_EXE")
    echo "$OTOOL_OUTPUT"
    echo "$OTOOL_OUTPUT" | grep -qi ssl && {
      echo "Error: Dynamic OpenSSL linkage detected on macOS (otool -L | grep openssl)." >&2
      exit 1
    }
  fi
fi

echo "Build and OpenSSL checks succeeded."
