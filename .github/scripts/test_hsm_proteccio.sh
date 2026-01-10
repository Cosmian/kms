#!/usr/bin/env bash
set -eo pipefail
set -x

# Proteccio-only tests (Linux only)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging
setup_fips_openssl_env

echo "========================================="
echo "Running Proteccio HSM tests"
echo "========================================="

[ ! -f /etc/lsb-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

# If HSM env variables are missing or HSM is unreachable, skip tests gracefully.
if [ -z "${PROTECCIO_IP:-}" ]; then
  echo "Skipping Proteccio HSM tests: PROTECCIO_IP not set."
  exit 0
fi
if [ -z "${PROTECCIO_PASSWORD:-}" ]; then
  echo "Skipping Proteccio HSM tests: PROTECCIO_PASSWORD not set."
  exit 0
fi
if ! ping -c 1 -W 1 "$PROTECCIO_IP" &>/dev/null; then
  echo "Warning: PROTECCIO_IP=$PROTECCIO_IP unreachable. Skipping Proteccio tests."
  exit 0
fi

export HSM_USER_PASSWORD="${PROTECCIO_PASSWORD}"

# Setup Proteccio HSM client tools
source "$REPO_ROOT/.github/reusable_scripts/prepare_proteccio.sh"

# PROTECCIO integration test (KMS)
env \
  PATH="$PATH" \
  HSM_MODEL="proteccio" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="1" \
  cargo test \
  -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  "$RELEASE_FLAG" \
  -- tests::hsm::test_hsm_all --ignored --exact

env \
  PATH="$PATH" \
  HSM_MODEL="proteccio" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="1" \
  RUST_LOG="trace" \
  cargo test \
  -p proteccio_pkcs11_loader \
  "$RELEASE_FLAG" \
  --features proteccio \
  -- tests::test_hsm_proteccio_all --ignored --exact

echo "Proteccio HSM tests completed successfully."
