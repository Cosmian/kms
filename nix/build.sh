#!/usr/bin/env bash
set -euo pipefail
set -x

# Discover repo root (works inside nix-shell)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# Resolve inputs with defaults inside the nix environment
: "${DEBUG_OR_RELEASE:=debug}"
: "${TARGET:=x86_64-unknown-linux-gnu}"
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

if command -v rustup >/dev/null 2>&1; then
  rustup target add "$TARGET"
fi

cargo build -p cosmian_kms_server --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}"

COSMIAN_KMS_EXE="target/$TARGET/$DEBUG_OR_RELEASE/cosmian_kms"

# Prepare OpenSSL runtime config from templates in nix/ and use it for --info
# Discover the nix OpenSSL install dir used during link/runtime
NIX_OPENSSLDIR=$(openssl version -d | awk -F '"' '{print $2}')
NIX_OPENSSL_BASE=$(dirname "$NIX_OPENSSLDIR")
NIX_OPENSSL_MODULES="$NIX_OPENSSL_BASE/lib/ossl-modules"

if [[ "${FEATURES}" != *"non-fips"* ]]; then
  # FIPS build: Use the installed openssl.cnf which already includes fipsmodule.cnf
  OPENSSL_CONF_PATH="$NIX_OPENSSLDIR/openssl.cnf"
  if [ ! -f "$OPENSSL_CONF_PATH" ]; then
    echo "Error: openssl.cnf not found at $OPENSSL_CONF_PATH" >&2
    exit 1
  fi
  FIPS_CNF_SRC="$NIX_OPENSSLDIR/fipsmodule.cnf"
  if [ ! -f "$FIPS_CNF_SRC" ]; then
    echo "Error: fipsmodule.cnf not found at $FIPS_CNF_SRC. The OpenSSL 3.1.2 build must provide it."
    echo "Ensure you're using the Nix-provided OpenSSL FIPS build, or adjust the nix derivation to install fipsmodule.cnf." >&2
    exit 1
  fi
else
  # Non-FIPS: use the repo-provided default config directly, do not generate or copy
  OPENSSL_CONF_PATH="$REPO_ROOT/nix/openssl-default.cnf.in"
fi
:

# Run --info with the composed OpenSSL config so the FIPS provider can load using the
# fipsmodule.cnf provided by the OpenSSL build
INFO_OUTPUT=$(OPENSSL_CONF="$OPENSSL_CONF_PATH" OPENSSL_MODULES="$NIX_OPENSSL_MODULES" "$COSMIAN_KMS_EXE" --info)
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
