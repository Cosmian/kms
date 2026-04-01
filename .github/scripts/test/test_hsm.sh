#!/usr/bin/env bash
set -euo pipefail
set -x

# Wrapper to run HSM tests
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

echo "========================================="
echo "Running all HSM tests (SoftHSM2 + Utimaco + Proteccio)"
echo "========================================="

bash "$SCRIPT_DIR/test_hsm_softhsm2.sh" "$@"
bash "$SCRIPT_DIR/test_hsm_utimaco.sh" "$@"
bash "$SCRIPT_DIR/test_hsm_proteccio.sh" "$@"

echo "All HSM tests completed successfully."
