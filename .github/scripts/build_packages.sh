#!/bin/bash

set -exo pipefail

# --- Declare the following variables for tests
# export TARGET=x86_64-unknown-linux-gnu
# export TARGET=x86_64-apple-darwin
# export TARGET=aarch64-apple-darwin
# export DEBUG_OR_RELEASE=debug
# export OPENSSL_DIR=/usr/local/openssl
# export FEATURES="non-fips"

ROOT_FOLDER=$(pwd)

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  # First build the Debian and RPM packages. It must come at first since
  # after this step `cosmian` and `cosmian_kms` are built with custom features flags (non-fips for example).
  rm -rf target/"$TARGET"/debian
  rm -rf target/"$TARGET"/generate-rpm
  if [ -f /etc/redhat-release ]; then
    cd crate/server && cargo build --features non-fips --release --target "$TARGET" && cd -
    cargo install --version 0.16.0 cargo-generate-rpm --force
    cd "$ROOT_FOLDER"
    cargo generate-rpm --target "$TARGET" -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml
  elif [ -f /etc/debian_version ]; then
    cargo install --version 2.4.0 cargo-deb --force
    if [ -n "$FEATURES" ]; then
      cargo deb --target "$TARGET" -p cosmian_kms_server
    else
      cargo deb --target "$TARGET" -p cosmian_kms_server --variant fips
    fi
  fi
fi
