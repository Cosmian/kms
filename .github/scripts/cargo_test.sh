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

export RUST_LOG="cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"

echo "SQLite is running on filesystem"
# shellcheck disable=SC2086
KMS_TEST_DB="sqlite" cargo test --workspace --lib --target $TARGET $RELEASE $FEATURES -- --nocapture
# shellcheck disable=SC2086
KMS_TEST_DB="sqlite" cargo test -p cosmian_kms_server_database --lib --target $TARGET $RELEASE $FEATURES -- --nocapture test_db_sqlite --ignored

if nc -z "$REDIS_HOST" "$REDIS_PORT"; then
  echo "Redis is running at $REDIS_HOST:$REDIS_PORT"
  # shellcheck disable=SC2086
  KMS_TEST_DB="redis-findex" cargo test --workspace --lib --target $TARGET $RELEASE $FEATURES -- --nocapture
  # shellcheck disable=SC2086
  KMS_TEST_DB="redis-findex" cargo test -p cosmian_kms_server_database --lib --target $TARGET $RELEASE $FEATURES -- --nocapture test_db_redis_with_findex --ignored
else
  echo "Redis is not running at $REDIS_HOST:$REDIS_PORT"
fi

if nc -z "$MYSQL_HOST" "$MYSQL_PORT"; then
  echo "MySQL is running at $MYSQL_HOST:$MYSQL_PORT"
  # shellcheck disable=SC2086
  KMS_TEST_DB="mysql" cargo test --workspace --lib --target $TARGET $RELEASE $FEATURES -- --nocapture
  # shellcheck disable=SC2086
  KMS_TEST_DB="mysql" cargo test -p cosmian_kms_server_database --lib --target $TARGET $RELEASE $FEATURES -- --nocapture test_db_mysql --ignored
else
  echo "MySQL is not running at $MYSQL_HOST:$MYSQL_PORT"
fi

if nc -z "$POSTGRES_HOST" "$POSTGRES_PORT"; then
  echo "PostgreSQL is running at $POSTGRES_HOST:$POSTGRES_PORT"
  # shellcheck disable=SC2086
  KMS_TEST_DB="postgresql" cargo test --workspace --lib --target $TARGET $RELEASE $FEATURES -- --nocapture
  # shellcheck disable=SC2086
  KMS_TEST_DB="postgresql" cargo test --workspace --lib --target $TARGET $RELEASE $FEATURES -- --nocapture test_db_postgresql --ignored
else
  echo "PostgreSQL is not running at $POSTGRES_HOST:$POSTGRES_PORT"
fi

# Google CSE tests
if [ -n "$TEST_GOOGLE_OAUTH_CLIENT_ID" ] && [ -n "$TEST_GOOGLE_OAUTH_CLIENT_SECRET" ] && [ -n "$TEST_GOOGLE_OAUTH_REFRESH_TOKEN" ] && [ -n "$GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY" ]; then
  echo "Running Google CSE tests..."
  # shellcheck disable=SC2086
  cargo test -p cosmian_kms_server_database --target $TARGET $RELEASE $FEATURES -- --nocapture test_google_cse --ignored
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
