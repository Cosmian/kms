#!/usr/bin/env bash
set -euo pipefail
set -x

# SoftHSM2-only tests (Linux only)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running SoftHSM2 HSM tests"
echo "========================================="

[ ! -f /etc/lsb-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

export HSM_USER_PASSWORD="12345678"

# Prepare SoftHSM2 token
export SOFTHSM2_HOME="$REPO_ROOT/.softhsm2"
mkdir -p "$SOFTHSM2_HOME/tokens"
export SOFTHSM2_CONF="$SOFTHSM2_HOME/softhsm2.conf"
echo "directories.tokendir = $SOFTHSM2_HOME/tokens" >"$SOFTHSM2_CONF"

softhsm2-util --version
SOFTHSM2_BIN_PATH="$(command -v softhsm2-util || true)"
if [ -n "$SOFTHSM2_BIN_PATH" ]; then
  SOFTHSM2_PREFIX="$(dirname "$(dirname "$SOFTHSM2_BIN_PATH")")"
  if [ -d "$SOFTHSM2_PREFIX/lib/softhsm" ]; then
    SOFTHSM2_LIB_DIR="$SOFTHSM2_PREFIX/lib/softhsm"
  elif [ -d "$SOFTHSM2_PREFIX/lib" ]; then
    SOFTHSM2_LIB_DIR="$SOFTHSM2_PREFIX/lib"
  else
    SOFTHSM2_LIB_DIR=""
  fi
fi
SOFTHSM2_PKCS11_LIB_PATH="${SOFTHSM2_LIB_DIR:+$SOFTHSM2_LIB_DIR/libsofthsm2.so}"
INIT_OUT=$(softhsm2-util --init-token --free --label "my_token_1" --so-pin "$HSM_USER_PASSWORD" --pin "$HSM_USER_PASSWORD" 2>&1 | tee /dev/stderr)

SOFTHSM2_HSM_SLOT_ID=$(echo "$INIT_OUT" | grep -o 'reassigned to slot [0-9]*' | awk '{print $4}')
if [ -z "${SOFTHSM2_HSM_SLOT_ID:-}" ]; then
  SOFTHSM2_HSM_SLOT_ID=$(softhsm2-util --show-slots | awk 'BEGIN{sid=""} /^Slot/ {sid=$2} /Token label/ && $0 ~ /my_token_1/ {print sid; exit}')
fi
[ -n "${SOFTHSM2_HSM_SLOT_ID:-}" ] || {
  echo "Error: Could not determine SoftHSM2 slot id" >&2
  exit 1
}

env \
  PATH="$PATH" \
  LD_LIBRARY_PATH="${SOFTHSM2_LIB_DIR:+$SOFTHSM2_LIB_DIR:}${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
  SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH:-}" \
  HSM_MODEL="softhsm2" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="$SOFTHSM2_HSM_SLOT_ID" \
  cargo test \
  -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  "$RELEASE_FLAG" \
  -- tests::hsm::test_hsm_all --ignored --exact

echo "SoftHSM2 KMS server tests completed successfully."

env \
  PATH="$PATH" \
  LD_LIBRARY_PATH="${SOFTHSM2_LIB_DIR:+$SOFTHSM2_LIB_DIR:}${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
  SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH:-}" \
  HSM_MODEL="softhsm2" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="$SOFTHSM2_HSM_SLOT_ID" \
  cargo test \
  -p softhsm2_pkcs11_loader \
  ${RELEASE_FLAG:+$RELEASE_FLAG} \
  --features softhsm2 \
  -- tests::test_hsm_softhsm2_all --ignored

echo "SoftHSM2 Loader tests completed successfully."
