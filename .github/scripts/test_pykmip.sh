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

# Call setup_fips_openssl_env AFTER setting VARIANT to ensure correct OpenSSL config
setup_fips_openssl_env

# Default KMS config (can be overridden by env before invoking nix.sh)
: "${COSMIAN_KMS_CONF:=$REPO_ROOT/scripts/kms.toml}"
export COSMIAN_KMS_CONF

# Ensure Python is available (nix.sh sets WITH_PYTHON=1 which adds python311 + virtualenv)
require_cmd python3 "Python 3 is required. Re-run via 'bash .github/scripts/nix.sh test pykmip' so nix-shell can provide it."

# Prepare a throwaway virtualenv under target/tmp if none exists
VENV_DIR="$REPO_ROOT/.venv"
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating Python virtual environment at $VENV_DIR …"
  if command -v virtualenv >/dev/null 2>&1; then
    virtualenv -p python3 "$VENV_DIR"
  else
    python3 -m venv "$VENV_DIR"
  fi
fi
# Activate venv and ensure pip works
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip >/dev/null

# Install PyKMIP if not already present
if ! python -c "import kmip" >/dev/null 2>&1; then
  echo "Installing PyKMIP into virtualenv …"
  # Prefer a straightforward install; fall back to dev head if needed
  if ! python -m pip install --no-compile PyKMIP >/dev/null; then
    echo "Falling back to installing PyKMIP from GitHub…"
    python -m pip install --no-compile git+https://github.com/OpenKMIP/PyKMIP.git
  fi
fi

# Build and launch the KMS server in the background
pushd "$REPO_ROOT" >/dev/null
cargo build --bin cosmian_kms ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}

# Clean up any previous server on the same port
KMS_PORT=9998

# Start server
set +e
RUST_LOG=${RUST_LOG:-warn} COSMIAN_KMS_CONF="$COSMIAN_KMS_CONF" \
  cargo run --bin cosmian_kms ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} &
KMS_PID=$!
set -e

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
if _wait_for_port 127.0.0.1 "$KMS_PORT" 20; then
  echo "KMS is up on port $KMS_PORT. Running PyKMIP tests…"
else
  echo "Error: KMS did not start on port $KMS_PORT in time." >&2
  exit 1
fi

# Run the PyKMIP test runner (expects venv already active)
# Use 'all' to exercise a suite of operations
bash "$REPO_ROOT/scripts/test_pykmip.sh" all
PYKMIP_STATUS=$?

popd >/dev/null

exit $PYKMIP_STATUS
