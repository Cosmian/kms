#!/usr/bin/env bash
# Run Synology DSM KMIP simulation tests against a locally launched Cosmian KMS
# inside nix-shell.  This script mirrors .github/scripts/test_pykmip.sh but
# targets the Synology DSM operation sequence defined in
# scripts/synology_dsm_client.py.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"
setup_test_logging

# Synology DSM KMIP tests require non-FIPS (PKCS#12 TLS + AES-CBC wrapping)
if [ "${VARIANT}" != "non-fips" ]; then
  echo "Note: For Synology DSM tests, forcing non-FIPS features (overriding --variant ${VARIANT})." >&2
fi

VARIANT="non-fips"
FEATURES_FLAG=(--features non-fips)

: "${COSMIAN_KMS_CONF:=$REPO_ROOT/.github/scripts/pykmip/kms.toml}"
export COSMIAN_KMS_CONF

# Ensure Python is available (nix.sh sets WITH_PYTHON=1 which adds python311 + virtualenv)
require_cmd python3 "Python 3 is required. Re-run via 'bash .github/scripts/nix.sh test synology_dsm' so nix-shell can provide it."

PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
echo "Using Python interpreter: $PYTHON_BIN"

# Verify ssl module is available in chosen Python
if ! env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES "$PYTHON_BIN" - <<'PY'; then
import ssl, sys
print("SSL OK:", ssl.OPENSSL_VERSION)
PY
  echo "Error: Selected Python has no working ssl module." >&2
  exit 1
fi

# Prepare a throwaway virtualenv under .venv if none exists
VENV_DIR="$REPO_ROOT/.venv"
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating Python virtual environment at $VENV_DIR …"
  if command -v virtualenv >/dev/null 2>&1; then
    env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES virtualenv -p "$PYTHON_BIN" "$VENV_DIR"
  else
    echo "Error: virtualenv command not found. Ensure WITH_PYTHON=1 is set in nix-shell." >&2
    exit 1
  fi
fi
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"
echo "Upgrading pip in virtual environment…"
env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -m pip install --upgrade pip

# Install PyKMIP if not already present
if ! env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -c "import kmip" >/dev/null 2>&1; then
  echo "Installing PyKMIP into virtualenv …"
  if ! env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -m pip install --no-compile PyKMIP >/dev/null; then
    echo "Falling back to installing PyKMIP from GitHub…"
    env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -m pip install --no-compile git+https://github.com/OpenKMIP/PyKMIP.git
  fi
fi

# Build and launch the KMS server in the background
pushd "$REPO_ROOT" >/dev/null
cargo build --bin cosmian_kms ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}

KMS_PORT=9998
KMIP_PORT=15696

free_port() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    local pids
    pids=$(ss -ltnp 2>/dev/null | awk -v p=":$port" '$4 ~ p {gsub(/.*pid=([0-9]+).*/,"\\1",$NF); print $NF}')
    if [ -n "$pids" ]; then
      echo "Freeing port $port (PIDs: $pids) …"
      # shellcheck disable=SC2086
      kill $pids 2>/dev/null || true
    fi
  elif command -v lsof >/dev/null 2>&1; then
    local pids
    pids=$(lsof -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
    if [ -n "$pids" ]; then
      echo "Freeing port $port (PIDs: $pids) …"
      # shellcheck disable=SC2086
      kill $pids 2>/dev/null || true
    fi
  fi
}

free_port "$KMS_PORT"
free_port "$KMIP_PORT"

RUST_LOG=${RUST_LOG:-warn} COSMIAN_KMS_CONF="$COSMIAN_KMS_CONF" \
  cargo run --bin cosmian_kms ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} &
KMS_PID=$!

# shellcheck disable=SC2317,SC2329
cleanup() {
  set +e
  if ps -p "$KMS_PID" >/dev/null 2>&1; then
    kill "$KMS_PID" >/dev/null 2>&1 || true
    sleep 1
    if ps -p "$KMS_PID" >/dev/null 2>&1; then
      kill -9 "$KMS_PID" >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT INT TERM

if _wait_for_port 127.0.0.1 "$KMS_PORT" 20 && _wait_for_port 127.0.0.1 "$KMIP_PORT" 20; then
  echo "KMS is up on ports $KMS_PORT (HTTP) and $KMIP_PORT (KMIP). Running Synology DSM simulation…"
else
  echo "Error: KMS did not start on required ports in time." >&2
  exit 1
fi

# Run the Synology DSM simulation test runner (expects venv already active)
env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES bash "$REPO_ROOT/.github/scripts/pykmip/test_synology_dsm.sh" simulate
DSM_STATUS=$?

popd >/dev/null

exit $DSM_STATUS
