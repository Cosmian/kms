#!/usr/bin/env bash
set -euo pipefail
set -x

# HSM tests - Linux only, requires Utimaco simulator and SoftHSM2
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env
setup_test_logging

echo "========================================="
echo "Running HSM tests"
echo "========================================="

[ ! -f /etc/lsb-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

export HSM_USER_PASSWORD="12345678"

# Setup Utimaco HSM simulator
echo "Setting up Utimaco HSM simulator..."
bash "$REPO_ROOT/.github/reusable_scripts/test_utimaco.sh"
export UTIMACO_PKCS11_LIB="${UTIMACO_PKCS11_LIB:-$REPO_ROOT/.utimaco/libcs_pkcs11_R3.so}"
export CS_PKCS11_R3_CFG="${CS_PKCS11_R3_CFG:-$REPO_ROOT/.utimaco/cs_pkcs11_R3.cfg}"

# Setup LD_LIBRARY_PATH for Utimaco PKCS#11 module
CXX_LIB_PATH="$(gcc -print-file-name=libstdc++.so.6 || true)"
[ -n "$CXX_LIB_PATH" ] && [ -f "$CXX_LIB_PATH" ] && {
  CXX_LIB_DIR="$(dirname "$CXX_LIB_PATH")"
  export LD_LIBRARY_PATH="${CXX_LIB_DIR}:${LD_LIBRARY_PATH:-}"
}
UTIMACO_LIB_DIR="$(dirname "$UTIMACO_PKCS11_LIB")"
export LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${LD_LIBRARY_PATH:-}"
echo "Using UTIMACO_PKCS11_LIB=$UTIMACO_PKCS11_LIB"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"

# Setup SoftHSM2 (optional, disabled by default due to dynamic link issues)
: "${SKIP_SOFTHSM2:=1}"
UTIMACO_HSM_SLOT_ID=0
[ "$SKIP_SOFTHSM2" != "1" ] && {
  echo "Setting up SoftHSM2..."
  export SOFTHSM2_HOME="$REPO_ROOT/.softhsm2"
  mkdir -p "$SOFTHSM2_HOME/tokens"
  export SOFTHSM2_CONF="$SOFTHSM2_HOME/softhsm2.conf"
  echo "directories.tokendir = $SOFTHSM2_HOME/tokens" >"$SOFTHSM2_CONF"
  softhsm2-util --init-token --slot 0 --label "my_token_1" --so-pin "$HSM_USER_PASSWORD" --pin "$HSM_USER_PASSWORD"
  SOFTHSM2_HSM_SLOT_ID=$(softhsm2-util --show-slots | grep -o "Slot [0-9]*" | head -n1 | awk '{print $2}')
}

# Run HSM tests
declare -a HSM_MODELS=('utimaco')
for HSM_MODEL in "${HSM_MODELS[@]}"; do
  echo "Running tests for HSM model: $HSM_MODEL"

  if [ "$HSM_MODEL" = "utimaco" ]; then
    HSM_SLOT_ID="$UTIMACO_HSM_SLOT_ID"
    HSM_PACKAGE="utimaco_pkcs11_loader"
    HSM_FEATURE="utimaco"
    echo "Skipping direct utimaco crate tests (requires root to install PKCS#11 lib into /lib)."
  else
    HSM_SLOT_ID="$SOFTHSM2_HSM_SLOT_ID"
    HSM_PACKAGE="softhsm2_pkcs11_loader"
    HSM_FEATURE="softhsm2"
    echo "Testing $HSM_MODEL HSM package..."
    env "PATH=$PATH" HSM_MODEL="$HSM_MODEL" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" \
      UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
      cargo test -p "$HSM_PACKAGE" "$RELEASE_FLAG" --features "$HSM_FEATURE" -- tests::test_hsm_"${HSM_MODEL}"_all --ignored
  fi

  # Test HSM integration with KMS server
  echo "Testing $HSM_MODEL HSM integration with KMS server..."
  env "PATH=$PATH" HSM_MODEL="$HSM_MODEL" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" \
    UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    cargo test "${FEATURES_FLAG[@]}" "$RELEASE_FLAG" -- tests::hsm::test_hsm_all --ignored
done

echo "HSM tests completed successfully."
