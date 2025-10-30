#!/usr/bin/env bash
set -euo pipefail
set -x

# SQLite tests - always available, runs on filesystem
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env
setup_test_logging

echo "========================================="
echo "Running SQLite tests"
echo "========================================="

echo "Testing workspace binaries..."
cargo test --workspace --bins "$RELEASE_FLAG" "${FEATURES_FLAG[@]}"

echo "Building benchmarks..."
cargo bench "${FEATURES_FLAG[@]}" --no-run

run_db_tests "sqlite"

echo "SQLite tests completed successfully."
