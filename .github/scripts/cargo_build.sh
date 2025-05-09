#!/bin/bash

set -ex

# --- Declare the following variables for tests
# export TARGET=x86_64-unknown-linux-gnu
# export TARGET=x86_64-apple-darwin
# export TARGET=aarch64-apple-darwin
# export DEBUG_OR_RELEASE=debug
# export OPENSSL_DIR=/usr/local/openssl
# export SKIP_SERVICES_TESTS="--skip test_mysql --skip test_pgsql --skip test_redis --skip google_cse --skip hsm --skip pykmip"
# export FEATURES="fips"

ROOT_FOLDER=$(pwd)

# Build the UI in release mode
if [ -f /etc/lsb-release ]; then
  bash .github/scripts/build_ui.sh
fi

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  # First build the Debian and RPM packages. It must come at first since
  # after this step `cosmian` and `cosmian_kms` are built with custom features flags (fips for example).
  rm -rf target/"$TARGET"/debian
  rm -rf target/"$TARGET"/generate-rpm
  if [ -f /etc/redhat-release ]; then
    cd crate/server && cargo build --target "$TARGET" --release && cd -
    cargo install --version 0.16.0 cargo-generate-rpm --force
    cd "$ROOT_FOLDER"
    cargo generate-rpm --target "$TARGET" -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml
  elif [ -f /etc/lsb-release ]; then
    cargo install --version 2.4.0 cargo-deb --force
    if [ -n "$FEATURES" ]; then
      cargo deb --target "$TARGET" -p cosmian_kms_server --variant fips
    else
      cargo deb --target "$TARGET" -p cosmian_kms_server
    fi
  fi
fi

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

if [ -f /etc/lsb-release ]; then
  bash .github/scripts/test_utimaco.sh
fi

if [ -z "$OPENSSL_DIR" ]; then
  echo "Error: OPENSSL_DIR is not set."
  exit 1
fi

# shellcheck disable=SC2086
cargo build --target $TARGET $RELEASE $FEATURES

COSMIAN_EXE="target/$TARGET/$DEBUG_OR_RELEASE/cosmian"
COSMIAN_KMS_EXE="target/$TARGET/$DEBUG_OR_RELEASE/cosmian_kms"

./"$COSMIAN_EXE" -h

# Must use OpenSSL with this specific version 3.2.0
OPENSSL_VERSION_REQUIRED="3.2.0"
correct_openssl_version_found=$(./"$COSMIAN_KMS_EXE" --info | grep "$OPENSSL_VERSION_REQUIRED")
if [ -z "$correct_openssl_version_found" ]; then
  echo "Error: The correct OpenSSL version $OPENSSL_VERSION_REQUIRED is not found."
  exit 1
fi

if [ "$(uname)" = "Linux" ]; then
  ldd "$COSMIAN_EXE" | grep ssl && exit 1
  ldd "$COSMIAN_KMS_EXE" | grep ssl && exit 1
else
  otool -L "$COSMIAN_EXE" | grep openssl && exit 1
  otool -L "$COSMIAN_KMS_EXE" | grep openssl && exit 1
fi

find . -type d -name cosmian-kms -exec rm -rf \{\} \; -print || true
rm -f /tmp/*.toml

export RUST_LOG="cosmian_cli=info,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=trace"

# shellcheck disable=SC2086
cargo build --target $TARGET $RELEASE $FEATURES

declare -a DATABASES=('redis-findex' 'sqlite' 'postgresql' 'mysql')
for KMS_TEST_DB in "${DATABASES[@]}"; do
  echo "Database KMS: $KMS_TEST_DB"

  # for now, discard tests on postgresql and mysql
  if [ "$KMS_TEST_DB" = "postgresql" ] || [ "$KMS_TEST_DB" = "mysql" ]; then
    continue
  fi

  # no docker containers on macOS Github runner
  if [ "$(uname)" = "Darwin" ] && [ "$KMS_TEST_DB" != "sqlite" ]; then
    continue
  fi

  # only tests all databases on release mode - keep sqlite for debug
  if [ "$DEBUG_OR_RELEASE" = "debug" ] && [ "$KMS_TEST_DB" != "sqlite" ]; then
    continue
  fi

  export KMS_TEST_DB="$KMS_TEST_DB"
  # shellcheck disable=SC2086
  cargo test --workspace --lib --target $TARGET $RELEASE $FEATURES \
    --exclude cosmian_kms_client_utils \
    --exclude cosmian_findex_client \
    --exclude cosmian_gui \
    --exclude cosmian_kms_client \
    --exclude cosmian_pkcs11_module \
    --exclude cosmian_pkcs11 \
    --exclude test_findex_server \
    --exclude test_kms_server \
    --exclude cosmian_kms_client_wasm \
    -- --nocapture $SKIP_SERVICES_TESTS
done

# shellcheck disable=SC2086
cargo test --workspace --bins --target $TARGET $RELEASE $FEATURES

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  # shellcheck disable=SC2086
  cargo bench --target $TARGET $FEATURES --no-run
fi
