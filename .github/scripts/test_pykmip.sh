#!/usr/bin/env bash
# Run PyKMIP client tests against a locally launched Cosmian KMS inside nix-shell
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

# Enforce non-FIPS for PyKMIP as per existing CI workflow
if [ "${VARIANT}" != "non-fips" ]; then
  echo "Note: For PyKMIP tests, forcing non-FIPS features (overriding --variant ${VARIANT})." >&2
fi

VARIANT="non-fips"
FEATURES_FLAG=(--features non-fips)

# Default KMS config (can be overridden by env before invoking nix.sh)
: "${COSMIAN_KMS_CONF:=$REPO_ROOT/scripts/kms.toml}"
export COSMIAN_KMS_CONF

# Note: OPENSSL_CONF and OPENSSL_MODULES are intentionally kept set here so the KMS
# server process can find the OpenSSL providers (e.g. legacy.dylib) in the Nix store.
# The compiled-in MODULESDIR is /usr/local/cosmian/lib/ossl-modules (production path),
# which does not exist in the nix-shell dev environment.
# All Python invocations below already use `env -u OPENSSL_CONF -u OPENSSL_MODULES`
# to isolate Python's ssl module from the Rust/KMS OpenSSL configuration.

# Ensure Python is available (nix.sh sets WITH_PYTHON=1 which adds python311 + virtualenv)
require_cmd python3 "Python 3 is required. Re-run via 'bash .github/scripts/nix.sh test pykmip' so nix-shell can provide it."

# Prefer Nix-provided Python (3.11) which is compatible with PyKMIP
# The system Python may be too new (3.12+) which lacks ssl.wrap_socket
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
echo "Using Python interpreter: $PYTHON_BIN"

# Verify ssl module is available in chosen Python
if ! env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES "$PYTHON_BIN" - <<'PY'; then
import ssl, sys
print("SSL OK:", ssl.OPENSSL_VERSION)
PY
  echo "Error: Selected Python has no working ssl module. Please install system Python with OpenSSL (e.g., python3 + libssl)." >&2
  exit 1
fi

# Prepare a throwaway virtualenv under .venv if none exists
VENV_DIR="$REPO_ROOT/.venv"
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating Python virtual environment at $VENV_DIR …"
  # Use virtualenv from Nix which handles pip installation properly
  if command -v virtualenv >/dev/null 2>&1; then
    env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES virtualenv -p "$PYTHON_BIN" "$VENV_DIR"
  else
    echo "Error: virtualenv command not found. Ensure WITH_PYTHON=1 is set in nix-shell." >&2
    exit 1
  fi
fi
# Activate venv and ensure pip works
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"
echo "Upgrading pip in virtual environment…"
env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -m pip install --upgrade pip

# Install PyKMIP if not already present
if ! env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -c "import kmip" >/dev/null 2>&1; then
  echo "Installing PyKMIP into virtualenv …"
  # Prefer a straightforward install; fall back to dev head if needed
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

# Clean up any previous server on the same ports (HTTP and KMIP)
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

# Start server
RUST_LOG=${RUST_LOG:-warn} COSMIAN_KMS_CONF="$COSMIAN_KMS_CONF" \
  cargo run --bin cosmian_kms ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} &
KMS_PID=$!

# Ensure we stop the server on exit
# shellcheck disable=SC2329
cleanup() {
  set +e
  if ps -p "$KMS_PID" >/dev/null 2>&1; then
    kill "$KMS_PID" >/dev/null 2>&1 || true
    # Give it a moment to stop
    sleep 1
    if ps -p "$KMS_PID" >/dev/null 2>&1; then
      kill -9 "$KMS_PID" >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT INT TERM

# Wait for the port to be ready
if _wait_for_port 127.0.0.1 "$KMS_PORT" 20 && _wait_for_port 127.0.0.1 "$KMIP_PORT" 20; then
  echo "KMS is up on ports $KMS_PORT (HTTP) and $KMIP_PORT (KMIP). Running PyKMIP tests…"
else
  echo "Error: KMS did not start on required ports in time." >&2
  exit 1
fi

# Run the PyKMIP test runner (expects venv already active)
# Use 'all' to exercise a suite of operations
env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES bash "$REPO_ROOT/scripts/test_pykmip.sh" all
PYKMIP_STATUS=$?

popd >/dev/null

exit $PYKMIP_STATUS
