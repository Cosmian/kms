#!/usr/bin/env bash
set -euo pipefail
set -x

# HSM tests - Linux only, requires Utimaco simulator and SoftHSM2
# This script is called from nix.sh inside a nix-shell environment

# Discover repo root (works inside nix-shell)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

# Resolve inputs with defaults inside the nix environment
: "${DEBUG_OR_RELEASE:=debug}"
: "${FEATURES:=}"

RELEASE_FLAG=""
if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE_FLAG="--release"
fi

FEATURES_FLAG=()
if [ -n "$FEATURES" ]; then
  FEATURES_FLAG=(--features "$FEATURES")
fi

export RUST_LOG="cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"

echo "========================================="
echo "Running HSM tests"
echo "========================================="

# HSM tests (Linux only)
if [ ! -f /etc/lsb-release ]; then
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
fi

export HSM_USER_PASSWORD="12345678"

# Install Utimaco simulator and run tests
echo "Setting up Utimaco HSM simulator..."
# In nix-shell we include psmisc and other tools via WITH_HSM=1; run the setup script.
bash "$REPO_ROOT/.github/reusable_scripts/test_utimaco.sh"
# Respect env exported by the setup script; if missing (since we exec in subshell), default to local copies
export UTIMACO_PKCS11_LIB="${UTIMACO_PKCS11_LIB:-$REPO_ROOT/.utimaco/libcs_pkcs11_R3.so}"
export CS_PKCS11_R3_CFG="${CS_PKCS11_R3_CFG:-$REPO_ROOT/.utimaco/cs_pkcs11_R3.cfg}"

# Ensure the C++ standard library is discoverable for the Utimaco PKCS#11 module
# Find libstdc++.so.6 from the active gcc in nix-shell and prepend to LD_LIBRARY_PATH
CXX_LIB_PATH="$(gcc -print-file-name=libstdc++.so.6 || true)"
if [ -n "$CXX_LIB_PATH" ] && [ -f "$CXX_LIB_PATH" ]; then
  CXX_LIB_DIR="$(dirname "$CXX_LIB_PATH")"
  export LD_LIBRARY_PATH="${CXX_LIB_DIR}:${LD_LIBRARY_PATH:-}"
fi
# Also include the directory that contains the Utimaco PKCS#11 library
UTIMACO_LIB_DIR="$(dirname "$UTIMACO_PKCS11_LIB")"
export LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${LD_LIBRARY_PATH:-}"
echo "Using UTIMACO_PKCS11_LIB=$UTIMACO_PKCS11_LIB"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"

# Optionally install SoftHSM2 and run tests (disabled by default in nix-shell due to dynamic link issues)
: "${SKIP_SOFTHSM2:=1}"
UTIMACO_HSM_SLOT_ID=0
if [ "$SKIP_SOFTHSM2" != "1" ]; then
  echo "Setting up SoftHSM2..."
  export SOFTHSM2_HOME="$REPO_ROOT/.softhsm2"
  mkdir -p "$SOFTHSM2_HOME/tokens"
  export SOFTHSM2_CONF="$SOFTHSM2_HOME/softhsm2.conf"
  echo "directories.tokendir = $SOFTHSM2_HOME/tokens" >"$SOFTHSM2_CONF"
  softhsm2-util --init-token --slot 0 --label "my_token_1" --so-pin "$HSM_USER_PASSWORD" --pin "$HSM_USER_PASSWORD"
  SOFTHSM2_HSM_SLOT_ID=$(softhsm2-util --show-slots | grep -o "Slot [0-9]*" | head -n1 | awk '{print $2}')
fi

# HSM tests with uniformized loop
declare -a HSM_MODELS=('utimaco')
for HSM_MODEL in "${HSM_MODELS[@]}"; do
  echo "Running tests for HSM model: $HSM_MODEL"

  if [ "$HSM_MODEL" = "utimaco" ]; then
    HSM_SLOT_ID="$UTIMACO_HSM_SLOT_ID"
    HSM_PACKAGE="utimaco_pkcs11_loader"
    HSM_FEATURE="utimaco"
  else
    HSM_SLOT_ID="$SOFTHSM2_HSM_SLOT_ID"
    HSM_PACKAGE="softhsm2_pkcs11_loader"
    HSM_FEATURE="softhsm2"
  fi

  # Test HSM package directly (skip Utimaco crate tests in non-root nix env due to hard-coded /lib path)
  if [ "$HSM_MODEL" = "utimaco" ]; then
    echo "Skipping direct utimaco crate tests (requires root to install PKCS#11 lib into /lib)."
  else
    echo "Testing $HSM_MODEL HSM package..."
    env "PATH=$PATH" HSM_MODEL="$HSM_MODEL" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" \
      UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
      cargo test -p "$HSM_PACKAGE" $RELEASE_FLAG --features "$HSM_FEATURE" -- tests::test_hsm_"${HSM_MODEL}"_all --ignored
  fi

  # Test HSM integration with KMS server
  echo "Testing $HSM_MODEL HSM integration with KMS server..."
  env "PATH=$PATH" HSM_MODEL="$HSM_MODEL" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" \
    UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    cargo test "${FEATURES_FLAG[@]}" $RELEASE_FLAG -- tests::hsm::test_hsm_all --ignored
done

echo "HSM tests completed successfully."
