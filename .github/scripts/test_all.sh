#!/usr/bin/env bash
set -euo pipefail
set -x

# Orchestrate running all available test categories sequentially
# Categories: sqlite, psql, mysql, redis (non-fips only), google_cse (if creds present), hsm (Linux)

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running ALL tests"
echo "Variant: ${VARIANT_NAME} | Mode: ${BUILD_PROFILE}"
echo "========================================="

# Helper to run a test script with a nice header and capture/continue on skip-eligible failures
run_step() {
  local name="$1"
  shift
  printf "\n===== %s =====\n" "$name"
  (
    set -euo pipefail
    bash "$@"
  )
}

# 1) SQLite (always)
run_step "SQLite" "$SCRIPT_DIR/test_sqlite.sh"

# 2) PostgreSQL (requires server)
run_step "PostgreSQL" "$SCRIPT_DIR/test_psql.sh"

# 3) MySQL (requires server)
run_step "MySQL" "$SCRIPT_DIR/test_mysql.sh"

# 4) Redis-findex (non-FIPS only)
if [ "$VARIANT_NAME" = "non-FIPS" ]; then
  run_step "Redis-findex" "$SCRIPT_DIR/test_redis.sh"
else
  echo "Skipping Redis-findex (FIPS mode)"
fi

# 5) Google CSE (only if all creds are present)
missing_creds=false
for var in TEST_GOOGLE_OAUTH_CLIENT_ID TEST_GOOGLE_OAUTH_CLIENT_SECRET \
  TEST_GOOGLE_OAUTH_REFRESH_TOKEN GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY; do
  if [ -z "${!var:-}" ]; then
    missing_creds=true
    break
  fi
done
if [ "$missing_creds" = false ]; then
  run_step "Google CSE" "$SCRIPT_DIR/test_google_cse.sh"
else
  echo "Skipping Google CSE (credentials not fully provided)"
fi

# 6) HSM (Linux only)
if [ -f /etc/lsb-release ]; then
  # Running both SoftHSM2 and Utimaco wrappers (the wrapper script already sequences them)
  # Note: hsm scripts adjust LD_LIBRARY_PATH and vendor env, and may require simulator setup
  run_step "HSM (SoftHSM2 + Utimaco)" "$SCRIPT_DIR/test_hsm.sh"
else
  echo "Skipping HSM tests (non-Linux environment)"
fi

echo "========================================="
echo "All test categories executed."
echo "========================================="
