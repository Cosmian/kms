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

export RUST_LOG="cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"

# Portable function to check if a TCP port is open (works on all Linux distros and macOS)
# Uses bash's built-in /dev/tcp feature with a timeout mechanism
check_port() {
  local host="$1"
  local port="$2"

  # Try to connect using bash's built-in /dev/tcp with timeout
  # Use a subshell to avoid hanging indefinitely
  (exec 3<>/dev/tcp/"$host"/"$port") 2>/dev/null &
  local pid=$!

  # Wait for up to 2 seconds
  local count=0
  while [ $count -lt 20 ]; do
    if ! kill -0 $pid 2>/dev/null; then
      # Process finished
      wait $pid 2>/dev/null
      return $?
    fi
    sleep 0.1
    count=$((count + 1))
  done

  # Timeout reached, kill the process
  kill -9 $pid 2>/dev/null
  wait $pid 2>/dev/null
  return 1
}

# Test workspace binaries
cargo test --workspace --bins --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}"

# Run benchmarks (no-run mode)
cargo bench --target "$TARGET" "${FEATURES_FLAG[@]}" --no-run

# SQLite tests (always available)
echo "SQLite is running on filesystem"
KMS_TEST_DB="sqlite" cargo test --workspace --lib --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture
KMS_TEST_DB="sqlite" cargo test -p cosmian_kms_server_database --lib --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture test_db_sqlite --ignored

# Redis tests (if available)
: "${REDIS_HOST:=127.0.0.1}"
: "${REDIS_PORT:=6379}"
if check_port "$REDIS_HOST" "$REDIS_PORT"; then
  echo "Redis is running at $REDIS_HOST:$REDIS_PORT"
  # Skip redis-findex in FIPS mode (not supported)
  if [[ "${FEATURES}" != *"non-fips"* ]]; then
    echo "Skipping Redis-findex tests in FIPS mode"
  else
    KMS_TEST_DB="redis-findex" cargo test --workspace --lib --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture
    KMS_TEST_DB="redis-findex" cargo test -p cosmian_kms_server_database --lib --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture test_db_redis_with_findex --ignored
  fi
else
  echo "Redis is not running at $REDIS_HOST:$REDIS_PORT"
fi

# MySQL tests (if available)
: "${MYSQL_HOST:=127.0.0.1}"
: "${MYSQL_PORT:=3306}"
if check_port "$MYSQL_HOST" "$MYSQL_PORT"; then
  echo "MySQL is running at $MYSQL_HOST:$MYSQL_PORT"
  KMS_TEST_DB="mysql" cargo test --workspace --lib --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture
  KMS_TEST_DB="mysql" cargo test -p cosmian_kms_server_database --lib --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture test_db_mysql --ignored
else
  echo "MySQL is not running at $MYSQL_HOST:$MYSQL_PORT"
fi

# PostgreSQL tests (if available)
: "${POSTGRES_HOST:=127.0.0.1}"
: "${POSTGRES_PORT:=5432}"
if check_port "$POSTGRES_HOST" "$POSTGRES_PORT"; then
  echo "PostgreSQL is running at $POSTGRES_HOST:$POSTGRES_PORT"
  KMS_TEST_DB="postgresql" cargo test --workspace --lib --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture
  KMS_TEST_DB="postgresql" cargo test --workspace --lib --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture test_db_postgresql --ignored
else
  echo "PostgreSQL is not running at $POSTGRES_HOST:$POSTGRES_PORT"
fi

# Google CSE tests (if credentials are available)
if [ -n "${TEST_GOOGLE_OAUTH_CLIENT_ID:-}" ] &&
  [ -n "${TEST_GOOGLE_OAUTH_CLIENT_SECRET:-}" ] &&
  [ -n "${TEST_GOOGLE_OAUTH_REFRESH_TOKEN:-}" ] &&
  [ -n "${GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY:-}" ]; then
  echo "Running Google CSE tests..."
  cargo test --workspace --lib --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture test_google_cse --ignored
else
  echo "Skipping Google CSE tests (credentials not provided)"
fi

# HSM tests (Linux only)
if [ -f /etc/lsb-release ]; then
  export HSM_USER_PASSWORD="12345678"

  # Install Utimaco simulator and run tests
  bash "$REPO_ROOT/.github/reusable_scripts/test_utimaco.sh"

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
    sudo -E env "PATH=$PATH" HSM_MODEL="$HSM_MODEL" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" \
      cargo test -p "$HSM_PACKAGE" --target "$TARGET" $RELEASE_FLAG --features "$HSM_FEATURE" -- tests::test_hsm_"${HSM_MODEL}"_all --ignored

    # Test HSM integration with KMS server
    sudo -E env "PATH=$PATH" HSM_MODEL="$HSM_MODEL" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" \
      cargo test --target "$TARGET" "${FEATURES_FLAG[@]}" $RELEASE_FLAG -- tests::hsm::test_hsm_all --ignored
  done
else
  echo "Skipping HSM tests (not on Linux)"
fi

echo "All tests completed successfully."
