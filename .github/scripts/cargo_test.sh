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

if [ -z "$OPENSSL_DIR" ]; then
  echo "Error: OPENSSL_DIR is not set."
  exit 1
fi

export RUST_LOG="cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"

# shellcheck disable=SC2086
cargo build --target $TARGET $RELEASE $FEATURES

declare -a DATABASES=('redis-findex' 'sqlite' 'postgresql' 'mysql')
for KMS_TEST_DB in "${DATABASES[@]}"; do
  echo "Database KMS: $KMS_TEST_DB"

  # Skip redis-findex in FIPS mode since it is not supported in FIPS mode
  if [ "$KMS_TEST_DB" = "redis-findex" ] && [ -z "$FEATURES" ]; then
    echo "Skipping redis-findex in FIPS mode."
    continue
  fi

  # for now, discard tests on mysql
  if [ "$KMS_TEST_DB" = "mysql" ]; then
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
  cargo test --workspace --lib --target $TARGET $RELEASE $FEATURES -- --nocapture
  # shellcheck disable=SC2086
  cargo test --workspace --lib --target $TARGET $RELEASE $FEATURES -- --nocapture test_db --ignored
done

# Google CSE tests
if [ -n "$TEST_GOOGLE_OAUTH_CLIENT_ID" ] && [ -n "$TEST_GOOGLE_OAUTH_CLIENT_SECRET" ] && [ -n "$TEST_GOOGLE_OAUTH_REFRESH_TOKEN" ] && [ -n "$GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY" ]; then
  echo "Running Google CSE tests..."
  # shellcheck disable=SC2086
  cargo test --workspace --target $TARGET $RELEASE $FEATURES -- --nocapture test_google_cse --ignored
fi

if [ -f /etc/lsb-release ]; then
  export HSM_USER_PASSWORD="12345678"

  # Install Utimaco simulator and run tests
  bash .github/reusable_scripts/test_utimaco.sh

  # Install SoftHSM2 and run tests
  sudo apt-get install -y libsofthsm2
  sudo softhsm2-util --init-token --slot 0 --label "my_token_1" --so-pin "$HSM_USER_PASSWORD" --pin "$HSM_USER_PASSWORD"

  UTIMACO_HSM_SLOT_ID=0
  SOFTHSM2_HSM_SLOT_ID=$(sudo softhsm2-util --show-slots | grep -o "Slot [0-9]*" | head -n1 | awk '{print $2}')

  # HSM tests with uniformized loop
  declare -a HSM_MODELS=('utimaco' 'softhsm2')
  for HSM_MODEL in "${HSM_MODELS[@]}"; do
    if [ "$HSM_MODEL" = "utimaco" ]; then
      HSM_SLOT_ID="$UTIMACO_HSM_SLOT_ID"
      HSM_PACKAGE="utimaco_pkcs11_loader"
      HSM_FEATURE="utimaco"
    else
      HSM_SLOT_ID="$SOFTHSM2_HSM_SLOT_ID"
      HSM_PACKAGE="softhsm2_pkcs11_loader"
      HSM_FEATURE="softhsm2"
    fi

    # Test HSM package directly
    # shellcheck disable=SC2086
    sudo -E env "PATH=$PATH" HSM_MODEL="$HSM_MODEL" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" \
      cargo test -p "$HSM_PACKAGE" --target "$TARGET" $RELEASE --features "$HSM_FEATURE" -- tests::test_hsm_${HSM_MODEL}_all --ignored

    # Test HSM integration with KMS server
    # shellcheck disable=SC2086
    sudo -E env "PATH=$PATH" HSM_MODEL="$HSM_MODEL" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" \
      cargo test --target "$TARGET" $FEATURES $RELEASE -- tests::hsm::test_hsm_all --ignored
  done
fi

# shellcheck disable=SC2086
cargo test --workspace --bins --target $TARGET $RELEASE $FEATURES

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  # shellcheck disable=SC2086
  cargo bench --target $TARGET $FEATURES --no-run
fi
