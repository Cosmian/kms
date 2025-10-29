#!/usr/bin/env bash
set -euo pipefail
set -x

# SQLite tests - always available, runs on filesystem
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

echo "========================================="
echo "Running SQLite tests"
echo "========================================="

# Test workspace binaries
echo "Testing workspace binaries..."
cargo test --workspace --bins $RELEASE_FLAG "${FEATURES_FLAG[@]}"

# Run benchmarks (no-run mode)
echo "Building benchmarks..."
cargo bench "${FEATURES_FLAG[@]}" --no-run

# SQLite tests
echo "Running SQLite library tests..."
KMS_TEST_DB="sqlite" cargo test --workspace --lib $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture

echo "Running SQLite database-specific tests..."
KMS_TEST_DB="sqlite" cargo test -p cosmian_kms_server_database --lib $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture test_db_sqlite --ignored

echo "SQLite tests completed successfully."
