#!/usr/bin/env bash
set -euo pipefail
set -x

# HSM tests - Linux only, requires Utimaco simulator and SoftHSM2
# This script is called from nix.sh inside a nix-shell environment

# Discover repo root (works inside nix-shell)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

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
bash "$REPO_ROOT/.github/reusable_scripts/test_utimaco.sh"

# Install SoftHSM2 and run tests
echo "Setting up SoftHSM2..."
sudo apt-get install -y libsofthsm2
sudo softhsm2-util --init-token --slot 0 --label "my_token_1" --so-pin "$HSM_USER_PASSWORD" --pin "$HSM_USER_PASSWORD"

UTIMACO_HSM_SLOT_ID=0
SOFTHSM2_HSM_SLOT_ID=$(sudo softhsm2-util --show-slots | grep -o "Slot [0-9]*" | head -n1 | awk '{print $2}')

# HSM tests with uniformized loop
declare -a HSM_MODELS=('utimaco' 'softhsm2')
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

  # Test HSM package directly
  echo "Testing $HSM_MODEL HSM package..."
  sudo -E env "PATH=$PATH" HSM_MODEL="$HSM_MODEL" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" \
    cargo test -p "$HSM_PACKAGE" $RELEASE_FLAG --features "$HSM_FEATURE" -- tests::test_hsm_"${HSM_MODEL}"_all --ignored

  # Test HSM integration with KMS server
  echo "Testing $HSM_MODEL HSM integration with KMS server..."
  sudo -E env "PATH=$PATH" HSM_MODEL="$HSM_MODEL" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" \
    cargo test "${FEATURES_FLAG[@]}" $RELEASE_FLAG -- tests::hsm::test_hsm_all --ignored
done

echo "HSM tests completed successfully."
