#!/usr/bin/env bash
set -eo pipefail
set -x

#  OpenVPN setup
if ! command -v openvpn >/dev/null 2>&1; then
    echo "Installing OpenVPN..."
    sudo apt-get update
    sudo apt-get install -y openvpn
fi

: "${OVPN_CONF:?OVPN_CONF not set}"

# Strip route-nopull so that server-pushed routes are accepted.
# Keep pull-filter ignore "redirect-gateway" to avoid full traffic redirect.
OVPN_CONF_FIXED=$(echo "$OVPN_CONF" | grep -v '^route-nopull$')
echo "$OVPN_CONF_FIXED" | sudo tee /tmp/openvpn.ovpn > /dev/null

# Kill any previous openvpn instances to avoid duplicate routes / stale tunnels
sudo killall openvpn 2>/dev/null || true
sleep 1

# Remove stale tun0 interface to avoid "File exists" route conflicts
sudo ip link del tun0 2>/dev/null || true
sleep 1

VPN_LOG=/tmp/vpn.log
sudo truncate -s 0 "$VPN_LOG" 2>/dev/null || sudo touch "$VPN_LOG"
sudo chmod 644 "$VPN_LOG"

sudo openvpn --config /tmp/openvpn.ovpn \
  --log "$VPN_LOG" \
  --daemon

echo "Waiting for VPN connection..."

for _i in {1..30}; do
  if grep -q "Initialization Sequence Completed" "$VPN_LOG"; then
    echo "VPN connected"
    break
  fi
  sleep 1
done

if ! grep -q "Initialization Sequence Completed" "$VPN_LOG"; then
  echo "Error: VPN not connected"
  cat "$VPN_LOG"
  exit 1
fi

echo "VPN logs:"
tail -n 50 "$VPN_LOG"

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
  echo "Warning: Failed to source prepare_crypt2pay.sh with return code $?."
  if [ -f /lib/libpkcs11c2p.so ] && [ -f /etc/c2p/c2p.xml ]; then
    echo "Continuing: Crypt2Pay client appears installed despite prepare script self-test failure."
  else
    echo "Error: Crypt2Pay client setup is incomplete."
    exit 1
  fi
fi

export C2P_CONF="${C2P_CONF:-/etc/c2p/c2p.xml}"

# Extract the C2P HSM host and port from the config
C2P_HOST=$(grep -ioP '(?<=<ip>)[^<]+' "$C2P_CONF" | head -1)
C2P_PORT=$(grep -ioP '(?<=<port>)[^<]+' "$C2P_CONF" | head -1)

if [ -n "$C2P_HOST" ] && [ -n "$C2P_PORT" ]; then
  echo "Checking HSM connectivity at $C2P_HOST:$C2P_PORT ..."
  HSM_REACHABLE=false
  for _i in {1..30}; do
    if timeout 3 bash -c "echo >/dev/tcp/$C2P_HOST/$C2P_PORT" 2>/dev/null; then
      echo "HSM service is reachable"
      HSM_REACHABLE=true
      break
    fi
    echo "  retry $_i/30 - waiting 2s..."
    sleep 2
  done
  if [ "$HSM_REACHABLE" = false ]; then
    echo "Error: HSM service $C2P_HOST:$C2P_PORT is not reachable over the VPN"
    exit 1
  fi
fi

# CRYPT2PAY integration test (KMS server)
env \
  PATH="$PATH" \
  HSM_MODEL="crypt2pay" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="${CRYPT2PAY_SLOT_ID:-1}" \
  cargo test \
  -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  -- tests::hsm::test_hsm_all --ignored --exact

# CRYPT2PAY PKCS#11 loader test
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
