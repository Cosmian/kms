#!/usr/bin/env bash
set -euo pipefail
set -x

# MariaDB tests - requires MariaDB server running
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running MariaDB tests"
echo "========================================="

: "${MARIADB_HOST:=127.0.0.1}"
: "${MARIADB_PORT:=3308}"

export KMS_MYSQL_URL="${KMS_MARIADB_URL:-mysql://root:kms@${MARIADB_HOST}:${MARIADB_PORT}/kms}"

check_and_test_db "MariaDB" "mysql" "MARIADB_HOST" "MARIADB_PORT"
