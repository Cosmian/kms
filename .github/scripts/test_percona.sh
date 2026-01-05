#!/usr/bin/env bash
set -euo pipefail
set -x

# Percona XtraDB Cluster tests - requires Percona server running
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running Percona XtraDB Cluster tests"
echo "========================================="

: "${PERCONA_HOST:=127.0.0.1}"
: "${PERCONA_PORT:=3307}"

export KMS_MYSQL_URL="${KMS_PERCONA_URL:-mysql://root:kms@${PERCONA_HOST}:${PERCONA_PORT}/kms}"

check_and_test_db "Percona XtraDB Cluster" "mysql" "PERCONA_HOST" "PERCONA_PORT"
