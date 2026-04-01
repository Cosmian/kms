#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"

if [[ "${VARIANT_NAME:-}" == *"FIPS"* ]] && [[ "${VARIANT_NAME:-}" != *"non-FIPS"* ]]; then
  echo "Skipping Azure EKM tests (FIPS mode is not supported for these tests)"
  exit 0
fi

echo "Running Azure EKM tests..."
bash "$SCRIPT_DIR/azure_ekm_test.sh" "$@"
bash "$SCRIPT_DIR/azure_ekm_mtls_test.sh" "$@"
echo "All Azure EKM tests passed!"
