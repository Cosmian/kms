#!/bin/bash

set -exo pipefail

# --- Declare the following variables for tests
# export TARGET=x86_64-unknown-linux-gnu
# export TARGET=x86_64-apple-darwin
# export TARGET=aarch64-apple-darwin
# export DEBUG_OR_RELEASE=debug
# export OPENSSL_DIR=/usr/local/openssl
# export FEATURES="non-fips"

if [ -z "$TARGET" ]; then
  echo "Error: TARGET is not set."
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

rustup target add "$TARGET"

if [ -z "$OPENSSL_DIR" ]; then
  echo "Error: OPENSSL_DIR is not set."
  exit 1
fi

# shellcheck disable=SC2086
cargo build --target $TARGET $RELEASE $FEATURES

COSMIAN_KMS_EXE="target/$TARGET/$DEBUG_OR_RELEASE/cosmian_kms"

# Must use OpenSSL with this specific version 3.2.0
OPENSSL_VERSION_REQUIRED="3.2.0"
correct_openssl_version_found=$(./"$COSMIAN_KMS_EXE" --info | grep "$OPENSSL_VERSION_REQUIRED")
if [ -z "$correct_openssl_version_found" ]; then
  echo "Error: The correct OpenSSL version $OPENSSL_VERSION_REQUIRED is not found."
  exit 1
fi

if [ "$(uname)" = "Linux" ]; then
  ldd "$COSMIAN_KMS_EXE" | grep ssl && exit 1
else
  otool -L "$COSMIAN_KMS_EXE" | grep openssl && exit 1
fi
