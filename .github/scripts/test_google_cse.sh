#!/usr/bin/env bash
set -euo pipefail
set -x

# Google CSE tests - requires Google OAuth credentials
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running Google CSE tests"
echo "========================================="

# Verify all required credentials are available
for var in TEST_GOOGLE_OAUTH_CLIENT_ID TEST_GOOGLE_OAUTH_CLIENT_SECRET \
  TEST_GOOGLE_OAUTH_REFRESH_TOKEN GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY; do
  [ -z "${!var:-}" ] && {
    echo "Error: Required environment variable $var is not set" >&2
    exit 1
  }
done

echo "Running Google CSE tests..."
cargo test --workspace --lib "$RELEASE_FLAG" ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} -- --nocapture test_google_cse --ignored --exact

echo "Google CSE tests completed successfully."
