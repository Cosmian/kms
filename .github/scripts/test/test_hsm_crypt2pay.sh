#!/usr/bin/env bash
set -eo pipefail
set -x

#  OpenVPN setup
if ! command -v openvpn >/dev/null 2>&1; then
    echo "Installation d'OpenVPN..."
    sudo apt-get update
    sudo apt-get install -y openvpn
fi

export OVPN_CONF="${OVPN_CONF}"
echo "$OVPN_CONF" | sudo tee /tmp/openvpn.ovpn > /dev/null

sudo touch /tmp/vpn.log

sudo openvpn --config /tmp/openvpn.ovpn \
  --log /tmp/vpn.log \
  --daemon

echo "Attente de la connexion VPN..."

for _i in {1..30}; do
  if grep -q "Initialization Sequence Completed" /tmp/vpn.log; then
    echo "VPN connecté ✅"
    break
  fi
  sleep 1
done

if ! grep -q "Initialization Sequence Completed" /tmp/vpn.log; then
  echo "❌ VPN non connecté"
  cat /tmp/vpn.log
  exit 1
fi

echo "Logs VPN:"
tail -n 50 /tmp/vpn.log

# Crypt2pay-only tests (Linux only)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running Crypt2pay HSM tests"
echo "========================================="

[ ! -f /etc/lsb-release ] && [ ! -f /etc/os-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

export HSM_USER_PASSWORD="${CRYPT2PAY_PASSWORD:?CRYPT2PAY_PASSWORD not set}"

# Setup Crypt2pay HSM client tools
if ! source "$REPO_ROOT/.github/reusable_scripts/prepare_crypt2pay.sh"; then
  echo "Warning: Failed to source prepare_crypt2pay.sh, c2pstatus may be failing. with return code $?."
  exit 0
fi

# CRYPT2PAY integration test (KMS)
env \
  PATH="$PATH" \
  HSM_MODEL="crypt2pay" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="${CRYPT2PAY_SLOT_ID:-1}" \
  cargo test \
  -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  -- tests::hsm::test_hsm_all --ignored --exact

env \
  PATH="$PATH" \
  HSM_MODEL="crypt2pay" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="${CRYPT2PAY_SLOT_ID:-1}" \
  cargo test \
  -p crypt2pay_pkcs11_loader \
  --features crypt2pay \
  -- tests::test_hsm_crypt2pay_all --ignored --exact

echo "Crypt2pay HSM tests completed successfully."
