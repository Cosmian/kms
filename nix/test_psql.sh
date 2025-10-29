#!/usr/bin/env bash
set -euo pipefail
set -x

# PostgreSQL tests - requires PostgreSQL server running
# This script is called from nix.sh inside a nix-shell environment

# Discover repo root (works inside nix-shell)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

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
echo "Running PostgreSQL tests"
echo "========================================="

# PostgreSQL tests (if available)
: "${POSTGRES_HOST:=127.0.0.1}"
: "${POSTGRES_PORT:=5432}"

if check_port "$POSTGRES_HOST" "$POSTGRES_PORT"; then
  echo "PostgreSQL is running at $POSTGRES_HOST:$POSTGRES_PORT"

  echo "Running PostgreSQL library tests..."
  KMS_TEST_DB="postgresql" cargo test --workspace --lib $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture

  echo "Running PostgreSQL database-specific tests..."
  KMS_TEST_DB="postgresql" cargo test --workspace --lib $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture test_db_postgresql --ignored

  echo "PostgreSQL tests completed successfully."
else
  echo "Error: PostgreSQL is not running at $POSTGRES_HOST:$POSTGRES_PORT" >&2
  exit 1
fi
