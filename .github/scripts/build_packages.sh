#!/bin/bash

set -exo pipefail

# export FEATURES="non-fips"

if [ -z "$TARGET" ]; then
  echo "Error: TARGET is not set. Examples of TARGET are x86_64-unknown-linux-gnu, x86_64-apple-darwin, aarch64-apple-darwin."
  exit 1
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
  elif [[ "$TARGET" == *"apple-darwin"* ]]; then
    cargo install --version 0.11.7 cargo-packager --force
    cd crate/server
    cargo packager --verbose --formats dmg --release
    cd "$ROOT_FOLDER"
  fi

fi
