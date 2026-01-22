#!/usr/bin/env bash
set -euo pipefail
set -x

# PostgreSQL tests - requires PostgreSQL server running
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running PostgreSQL tests"
echo "========================================="

: "${POSTGRES_HOST:=127.0.0.1}"
: "${POSTGRES_PORT:=5432}"

check_and_test_db "PostgreSQL" "postgresql" "POSTGRES_HOST" "POSTGRES_PORT"
