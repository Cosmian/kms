#!/bin/bash

set -exo pipefail

# export FEATURES="non-fips"

if [ -z "$TARGET" ]; then
  echo "Error: TARGET is not set. Examples of TARGET are x86_64-unknown-linux-gnu, x86_64-apple-darwin, aarch64-apple-darwin."
  exit 1
fi

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE="--release"
fi

if [ -n "$FEATURES" ]; then
  FEATURES="--features $FEATURES"
fi

if [ -z "$FEATURES" ]; then
  echo "Info: FEATURES is not set."
  unset FEATURES
fi

if [ -z "$OPENSSL_DIR" ]; then
  echo "Error: OPENSSL_DIR is not set. Example OPENSSL_DIR=/usr/local/openssl"
  exit 1
fi

# Force on Rust-openssl no vendoring to ensure linkage against the system OpenSSL
export OPENSSL_NO_VENDOR=1

rustup target add "$TARGET"

# shellcheck disable=SC2086
cargo build -p cosmian_kms_server --target $TARGET $RELEASE $FEATURES

COSMIAN_KMS_EXE="target/$TARGET/$DEBUG_OR_RELEASE/cosmian_kms"

# Must use OpenSSL with this specific version 3.2.0
OPENSSL_VERSION_REQUIRED="3.2.0"
correct_openssl_version_found=$(./"$COSMIAN_KMS_EXE" --info | grep "$OPENSSL_VERSION_REQUIRED")
if [ -z "$correct_openssl_version_found" ]; then
  echo "Error: The correct OpenSSL version $OPENSSL_VERSION_REQUIRED is not found."
  exit 1
fi

if [ "$(uname)" = "Linux" ]; then
  LDD_OUTPUT=$(ldd "$COSMIAN_KMS_EXE")
  echo "$LDD_OUTPUT"
  if echo "$LDD_OUTPUT" | grep -qi ssl; then
    echo "Error: Dynamic OpenSSL linkage detected on Linux (ldd | grep ssl)."
    exit 1
  fi
else
  OTOOL_OUTPUT=$(otool -L "$COSMIAN_KMS_EXE")
  echo "$OTOOL_OUTPUT"
  if echo "$OTOOL_OUTPUT" | grep -qi ssl; then
    echo "Error: Dynamic OpenSSL linkage detected on macOS (otool -L | grep openssl)."
    exit 1
  fi
fi
