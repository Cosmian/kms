#!/usr/bin/env bash
set -eo pipefail
set -x

# Crypt2pay-only tests (Linux only)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running Crypt2pay HSM tests"
echo "========================================="

[ ! -f /etc/lsb-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

export HSM_USER_PASSWORD="${CRYPT2PAY_PASSWORD:?CRYPT2PAY_PASSWORD not set}"

# Note: This script assumes Crypt2pay HSM setup is already configured
# Users need to set up the Crypt2pay HSM environment and related variables

# CRYPT2PAY integration test (KMS)
env \
  PATH="$PATH" \
  HSM_MODEL="crypt2pay" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="${CRYPT2PAY_SLOT_ID:-1}" \
  cargo test \
  -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  "$RELEASE_FLAG" \
  -- tests::hsm::test_hsm_all --ignored --exact

env \
  PATH="$PATH" \
  HSM_MODEL="crypt2pay" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="${CRYPT2PAY_SLOT_ID:-1}" \
  cargo test \
  -p crypt2pay_pkcs11_loader \
  "$RELEASE_FLAG" \
  --features crypt2pay \
  -- tests::test_hsm_crypt2pay_all --ignored --exact

echo "Crypt2pay HSM tests completed successfully."
