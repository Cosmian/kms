#!/usr/bin/env bash
set -euo pipefail
set -x

# MySQL tests - requires MySQL server running
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running MySQL tests"
echo "========================================="

: "${MYSQL_HOST:=127.0.0.1}"
: "${MYSQL_PORT:=3306}"

check_and_test_db "MySQL" "mysql" "MYSQL_HOST" "MYSQL_PORT"
