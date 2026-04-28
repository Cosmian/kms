#!/usr/bin/env bash
# Entry point for the REST Crypto API end-to-end test suite.
# Delegates to rest_crypto_test.sh after variant setup.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"

echo "Running REST Crypto API E2E tests (variant: ${VARIANT_NAME})..."
bash "$SCRIPT_DIR/rest_crypto_test.sh" "$@"
echo "All REST Crypto API E2E tests passed!"
