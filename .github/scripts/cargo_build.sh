#!/bin/bash

set -ex

# --- Declare the following variables for tests
# export TARGET=x86_64-unknown-linux-gnu
# export DEBUG_OR_RELEASE=debug
# export OPENSSL_DIR=/usr/local/openssl
# export SKIP_SERVICES_TESTS="--skip test_mysql --skip test_pgsql --skip test_redis --skip google_cse --skip test_all_authentications"

ROOT_FOLDER=$(pwd)

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

if [ -z "$SKIP_SERVICES_TESTS" ]; then
  echo "Info: SKIP_SERVICES_TESTS is not set."
  unset SKIP_SERVICES_TESTS
fi

rustup target add "$TARGET"

echo "Building crate/pkcs11/provider"
cd crate/pkcs11/provider
# shellcheck disable=SC2086
cargo build --target $TARGET $RELEASE
cd "$ROOT_FOLDER"

if [ -z "$OPENSSL_DIR" ]; then
  echo "Error: OPENSSL_DIR is not set."
  exit 1
fi

crates=("crate/server" "crate/cli")
for crate in "${crates[@]}"; do
  echo "Building $crate"
  cd "$crate"
  # shellcheck disable=SC2086
  cargo build --target $TARGET $RELEASE $FEATURES
  cd "$ROOT_FOLDER"
done

# Debug
# find .

./target/"$TARGET/$DEBUG_OR_RELEASE"/ckms -h
./target/"$TARGET/$DEBUG_OR_RELEASE"/cosmian_kms_server -h

if [ "$(uname)" = "Linux" ]; then
  ldd target/"$TARGET/$DEBUG_OR_RELEASE"/ckms | grep ssl && exit 1
  ldd target/"$TARGET/$DEBUG_OR_RELEASE"/cosmian_kms_server | grep ssl && exit 1
else
  otool -L target/"$TARGET/$DEBUG_OR_RELEASE"/ckms | grep openssl && exit 1
  otool -L target/"$TARGET/$DEBUG_OR_RELEASE"/cosmian_kms_server | grep openssl && exit 1
fi

find . -type d -name cosmian-kms -exec rm -rf \{\} \; -print || true
rm -f /tmp/*.json
export RUST_LOG="cosmian_kms_cli=debug,cosmian_kms_server=debug"
# shellcheck disable=SC2086
cargo test --target $TARGET $RELEASE $FEATURES --workspace -- --nocapture $SKIP_SERVICES_TESTS

# Uncomment this code to run tests indefinitely
# counter=1
# while true; do
#   # shellcheck disable=SC2086
#   cargo test --target $TARGET $RELEASE $FEATURES --workspace -- --nocapture $SKIP_SERVICES_TESTS
#   counter=$((counter + 1))
#   echo "Round: $counter"
#   sleep 3
# done

rm -rf target/"$TARGET"/debian
rm -rf target/"$TARGET"/generate-rpm

if [ -f /etc/redhat-release ]; then
  cd crate/cli && cargo build --target "$TARGET" --release && cd -
  cd crate/server && cargo build --target "$TARGET" --release && cd -
  cargo install --version 0.14.1 cargo-generate-rpm --force
  cd "$ROOT_FOLDER"
  cargo generate-rpm --target "$TARGET" -p crate/cli
  cargo generate-rpm --target "$TARGET" -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml
elif [ -f /etc/lsb-release ]; then
  cargo install --version 2.4.0 cargo-deb --force
  cargo deb --target "$TARGET" -p cosmian_kms_cli --variant fips
  cargo deb --target "$TARGET" -p cosmian_kms_cli
  cargo deb --target "$TARGET" -p cosmian_kms_server --variant fips
  cargo deb --target "$TARGET" -p cosmian_kms_server
fi
