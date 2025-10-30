#!/usr/bin/env bash
set -eo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env

# shellcheck disable=SC2086
cargo build -p cosmian_kms_server $RELEASE_FLAG "${FEATURES_FLAG[@]}"

COSMIAN_KMS_EXE="target/$DEBUG_OR_RELEASE/cosmian_kms"

# Verify binary works (temporarily use nix store OpenSSL config)
export OPENSSL_CONF="${NIX_OPENSSL_OUT:-}/ssl/openssl.cnf"
INFO_OUTPUT=$("$COSMIAN_KMS_EXE" --version 2>&1 || true)
echo "$INFO_OUTPUT"
echo "$INFO_OUTPUT" | grep -q "cosmian_kms_server" || {
  echo "Error: Binary does not appear to be working" >&2
  exit 1
}
unset OPENSSL_CONF

echo "Note: Binary built with OPENSSLDIR=/usr/local/lib/openssl"
echo "Run 'nix-shell --keep NIX_OPENSSL_OUT shell.nix --run \"bash nix/scripts/setup_openssl_runtime.sh\"' to install runtime files"

# Platform-specific checks
UNAME=$(uname)
if [ "$UNAME" = "Linux" ]; then
  LDD_OUTPUT=$(ldd "$COSMIAN_KMS_EXE")
  echo "$LDD_OUTPUT"
  echo "$LDD_OUTPUT" | grep -qi ssl && {
    echo "Error: Dynamic OpenSSL linkage detected on Linux (ldd | grep ssl)." >&2
    exit 1
  }

  # Verify GLIBC symbol versions are <= 2.28
  GLIBC_SYMS=$(readelf -sW "$COSMIAN_KMS_EXE" | grep -o 'GLIBC_[0-9][0-9.]*' | sort -Vu)
  echo "$GLIBC_SYMS"
  MAX_GLIBC_VER=""
  [ -n "$GLIBC_SYMS" ] && MAX_GLIBC_VER=$(echo "$GLIBC_SYMS" | sed 's/^GLIBC_//' | sort -V | tail -n1)
  [ -n "$MAX_GLIBC_VER" ] && [ "$(printf '%s\n' "$MAX_GLIBC_VER" "2.28" | sort -V | tail -n1)" != "2.28" ] && {
    echo "Error: GLIBC symbols exceed 2.28 (max found: $MAX_GLIBC_VER)." >&2
    exit 1
  }
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
