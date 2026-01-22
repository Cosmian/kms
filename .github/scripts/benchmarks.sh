#!/usr/bin/env bash
set -euo pipefail
set -x

# SQLite tests - always available, runs on filesystem
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

# Ensure required tools are available when running outside Nix
require_cmd cargo "Cargo is required to build and run tests. Install Rust (rustup) and retry."

echo "========================================="
echo "Benchmarks tests"
echo "========================================="

echo "Building benchmarks..."
cargo bench "${FEATURES_FLAG[@]}" --no-run

echo "Benchmarks completed successfully."
