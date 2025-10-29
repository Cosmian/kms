#!/usr/bin/env bash
set -euo pipefail
set -x

# Resolve inputs with defaults inside the nix environment
: "${DEBUG_OR_RELEASE:=debug}"
: "${FEATURES:=}"

# Using nix-shell OpenSSL toolchain provided by the environment (no external import)

RELEASE_FLAG=""
if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE_FLAG="--release"
fi

FEATURES_FLAG=()
if [ -n "$FEATURES" ]; then
  FEATURES_FLAG=(--features "$FEATURES")
fi

cargo build -p cosmian_kms_server $RELEASE_FLAG "${FEATURES_FLAG[@]}"

COSMIAN_KMS_EXE="target/$DEBUG_OR_RELEASE/cosmian_kms"

# Run --info with the composed OpenSSL config so the FIPS provider can load using the
# fipsmodule.cnf provided by the OpenSSL build
INFO_OUTPUT=$("$COSMIAN_KMS_EXE" --info)
echo "$INFO_OUTPUT"
echo "$INFO_OUTPUT" | grep -q "OpenSSL 3.1.2" || {
  echo "Error: The correct OpenSSL version 3.1.2 is not found in --info output." >&2
  exit 1
}

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
