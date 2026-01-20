#!/usr/bin/env bash
set -eo pipefail
set -x

# Proteccio-only tests (Linux only)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running Proteccio HSM tests"
echo "========================================="

[ ! -f /etc/lsb-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

# Disable trace to avoid leaking password in logs
set +x
export HSM_USER_PASSWORD="${PROTECCIO_PASSWORD}"
HSM_SLOT_ID_VALUE="${PROTECCIO_SLOT}"
set -x

# Setup Proteccio HSM client tools
if ! source "$REPO_ROOT/.github/reusable_scripts/prepare_proteccio.sh"; then
  echo "Warning: Failed to source prepare_proteccio.sh, nethsmstatus may be failing. with return code $?."
  exit 0
fi

# PROTECCIO integration test (KMS)
# Unset Nix OpenSSL environment to use system libraries for Proteccio HSM
env -u LD_PRELOAD -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  PATH="$PATH" \
  HSM_MODEL="proteccio" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  RUST_LOG="cosmian_kms_server=trace" \
  HSM_SLOT_ID="$HSM_SLOT_ID_VALUE" \
  cargo test \
  -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  "$RELEASE_FLAG" \
  -- tests::hsm::test_hsm_all --ignored --exact

set +x
env -u LD_PRELOAD -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  PATH="$PATH" \
  HSM_MODEL="proteccio" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="$HSM_SLOT_ID_VALUE" \
  RUST_LOG="cosmian_kms_server=trace" \
  cargo test \
  -p proteccio_pkcs11_loader \
  "$RELEASE_FLAG" \
  --features proteccio \
  -- tests::test_hsm_proteccio_all --ignored --exact
set -x

echo "Proteccio HSM tests completed successfully."
