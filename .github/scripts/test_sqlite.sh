#!/usr/bin/env bash
set -euo pipefail
set -x

# SQLite tests - always available, runs on filesystem
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging
setup_fips_openssl_env

# Ensure required tools are available when running outside Nix
require_cmd cargo "Cargo is required to build and run tests. Install Rust (rustup) and retry."

echo "========================================="
echo "Running SQLite tests"
echo "========================================="

echo "Testing workspace binaries..."
# shellcheck disable=SC2086
cargo test --workspace --bins $RELEASE_FLAG "${FEATURES_FLAG[@]}"

run_db_tests "sqlite"

echo "SQLite tests completed successfully."
