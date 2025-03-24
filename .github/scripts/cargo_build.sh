#!/bin/bash

set -ex

# --- Declare the following variables for tests
# export TARGET=x86_64-unknown-linux-gnu
# export TARGET=aarch64-apple-darwin
# export DEBUG_OR_RELEASE=debug
# export OPENSSL_DIR=/usr/local/openssl
# export SKIP_SERVICES_TESTS="--skip hsm"

ROOT_FOLDER=$(pwd)

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  # First build the Debian and RPM packages. It must come at first since
  # after this step `cosmian` and `cosmian_gui` are built with custom features flags (fips for example).
  rm -rf target/"$TARGET"/debian
  rm -rf target/"$TARGET"/generate-rpm
  if [ -f /etc/redhat-release ]; then
    cargo build --target "$TARGET" --release
    cargo install --version 0.14.1 cargo-generate-rpm --force
    cargo generate-rpm --target "$TARGET" -p crate/cli
  elif [ -f /etc/lsb-release ]; then
    cargo build --target "$TARGET" --release
    cargo install --version 2.4.0 cargo-deb --force
    cargo deb --target "$TARGET" -p cosmian_cli
  fi
fi

if [ -z "$TARGET" ]; then
  echo "Error: TARGET is not set."
  exit 1
fi

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE="--release"
fi

if [ -z "$SKIP_SERVICES_TESTS" ]; then
  echo "Info: SKIP_SERVICES_TESTS is not set."
  unset SKIP_SERVICES_TESTS
fi

rustup target add "$TARGET"

cd "$ROOT_FOLDER"

if [ -z "$OPENSSL_DIR" ]; then
  echo "Error: OPENSSL_DIR is not set."
  exit 1
fi

crates=("crate/gui" "crate/cli" "crate/pkcs11/provider")
for crate in "${crates[@]}"; do
  echo "Building $crate"
  cd "$crate"
  # shellcheck disable=SC2086
  cargo build --target $TARGET $RELEASE
  cd "$ROOT_FOLDER"
done

# Debug
# find .

TARGET_FOLDER=./target/"$TARGET/$DEBUG_OR_RELEASE"
"${TARGET_FOLDER}"/cosmian -h
"${TARGET_FOLDER}"/cosmian_gui -h

if [ "$(uname)" = "Linux" ]; then
  ldd "${TARGET_FOLDER}"/cosmian | grep ssl && exit 1
  ldd "${TARGET_FOLDER}"/cosmian_gui | grep ssl && exit 1
else
  otool -L "${TARGET_FOLDER}"/cosmian | grep openssl && exit 1
  otool -L "${TARGET_FOLDER}"/cosmian_gui | grep openssl && exit 1
fi

find . -type d -name cosmian-findex-server -exec rm -rf \{\} \; -print || true
rm -f /tmp/*.json /tmp/*.toml

# shellcheck disable=SC2086
cargo build --target $TARGET $RELEASE $FEATURES

export RUST_LOG="cosmian_cli=error,cosmian_findex_client=error,cosmian_kmip=error,cosmian_kms_client=error,test_findex_server=error"

# shellcheck disable=SC2086
cargo test -v --workspace --lib --target $TARGET $RELEASE $FEATURES -- $SKIP_SERVICES_TESTS

# shellcheck disable=SC2086
cargo test --workspace --bins --target $TARGET $RELEASE $FEATURES

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  # shellcheck disable=SC2086
  cargo bench --target $TARGET $FEATURES --no-run
fi

# while true; do
#   sleep 1 && reset
#   # shellcheck disable=SC2086
#   cargo test -v --target $TARGET $RELEASE $FEATURES --workspace -- --nocapture $SKIP_SERVICES_TESTS
# done
