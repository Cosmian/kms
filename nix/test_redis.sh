#!/usr/bin/env bash
set -euo pipefail
set -x

# Redis-findex tests - requires Redis server running
# This script is called from nix.sh inside a nix-shell environment

# Resolve inputs with defaults inside the nix environment
: "${DEBUG_OR_RELEASE:=debug}"
: "${FEATURES:=}"

RELEASE_FLAG=""
if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE_FLAG="--release"
fi

FEATURES_FLAG=()
if [ -n "$FEATURES" ]; then
  FEATURES_FLAG=(--features "$FEATURES")
fi

export RUST_LOG="cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"

# Portable function to check if a TCP port is open
check_port() {
  local host="$1"
  local port="$2"

  # Try to connect using bash's built-in /dev/tcp with timeout
  (exec 3<>/dev/tcp/"$host"/"$port") 2>/dev/null &
  local pid=$!

  # Wait for up to 2 seconds
  local count=0
  while [ $count -lt 20 ]; do
    if ! kill -0 $pid 2>/dev/null; then
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

echo "========================================="
echo "Running Redis-findex tests"
echo "========================================="

# Skip redis-findex in FIPS mode (not supported)
if [[ "${FEATURES}" != *"non-fips"* ]]; then
  echo "Error: Redis-findex tests are not supported in FIPS mode" >&2
  echo "Please run with FEATURES=non-fips" >&2
  exit 1
fi

# Redis tests (if available)
: "${REDIS_HOST:=127.0.0.1}"
: "${REDIS_PORT:=6379}"

if check_port "$REDIS_HOST" "$REDIS_PORT"; then
  echo "Redis is running at $REDIS_HOST:$REDIS_PORT"

  echo "Running Redis-findex library tests..."
  KMS_TEST_DB="redis-findex" cargo test --workspace --lib $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture

  echo "Running Redis-findex database-specific tests..."
  KMS_TEST_DB="redis-findex" cargo test -p cosmian_kms_server_database --lib $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture test_db_redis_with_findex --ignored

  echo "Redis-findex tests completed successfully."
else
  echo "Error: Redis is not running at $REDIS_HOST:$REDIS_PORT" >&2
  exit 1
fi
