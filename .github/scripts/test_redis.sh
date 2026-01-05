#!/usr/bin/env bash
set -euo pipefail
set -x

# Redis-findex tests - requires Redis server running
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running Redis-findex tests"
echo "========================================="

# Skip redis-findex in FIPS mode (not supported)
if [ "$VARIANT" != "non-fips" ]; then
  echo "Error: Redis-findex tests are not supported in FIPS mode" >&2
  echo "Please run with --variant non-fips" >&2
  exit 1
fi

: "${REDIS_HOST:=127.0.0.1}"
: "${REDIS_PORT:=6379}"

check_and_test_db "Redis" "redis-findex" "REDIS_HOST" "REDIS_PORT"
