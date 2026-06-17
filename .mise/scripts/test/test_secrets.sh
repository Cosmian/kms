#!/usr/bin/env bash
set -euo pipefail
set -x

# Secret backend integration tests — runs all backends in sequence:
#   1. HashiCorp Vault KV-v2  (vault://)
#   2. AWS SSM Parameter Store (aws-ssm://)
#   3. Azure Key Vault         (azure-kv://)
#   4. Cosmian KMS             (cosmian-kms://)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Running Vault secret backend tests ==="
bash "$SCRIPT_DIR/test_secret_vault.sh"

echo "=== Running AWS SSM secret backend tests ==="
bash "$SCRIPT_DIR/test_secret_aws.sh"

echo "=== Running Azure Key Vault secret backend tests ==="
bash "$SCRIPT_DIR/test_secret_azure.sh"

echo "=== Running Cosmian KMS secret backend tests ==="
bash "$SCRIPT_DIR/test_secret_cosmian_kms.sh"

echo "=== All secret backend tests passed ==="
