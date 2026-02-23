#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

echo "Running Azure EKM tests..."
bash "$SCRIPT_DIR/azure_ekm_test.sh" "$@"
bash "$SCRIPT_DIR/azure_ekm_mtls_test.sh" "$@"
echo "All Azure EKM tests passed!"
