#!/bin/bash
# Setup script for EDB TDE KMIP integration tests
# Prepares the Python virtual environment with required dependencies
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
VENV_DIR="$REPO_ROOT/.venv"

echo "Setting up EDB TDE KMIP test environment..."

# Prefer Python 3.11 (PyKMIP requires ssl.wrap_socket, removed in 3.12+)
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3.11 || command -v python3)}"
python_minor=$($PYTHON_BIN -c "import sys; print(sys.version_info.minor)")
if [ "$python_minor" -ge 12 ]; then
  echo "Error: Python 3.12+ detected. PyKMIP requires Python 3.11 or earlier." >&2
  echo "Install Python 3.11: brew install python@3.11  (macOS)" >&2
  exit 1
fi
echo "Using Python: $PYTHON_BIN ($($PYTHON_BIN --version))"

# Create virtualenv if it does not exist
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment at $VENV_DIR ..."
  if command -v virtualenv >/dev/null 2>&1; then
    env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
      virtualenv -p "$PYTHON_BIN" "$VENV_DIR"
  else
    "$PYTHON_BIN" -m venv "$VENV_DIR"
  fi
fi

# Activate and install dependencies
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

echo "Installing dependencies..."
env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  python -m pip install --upgrade pip --quiet

# Install PyKMIP (core dependency)
if ! env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  python -c "from kmip.services import kmip_client" >/dev/null 2>&1; then
  echo "Installing PyKMIP..."
  env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    python -m pip install --no-compile PyKMIP --quiet
fi

# Install cryptography package (for Thales variant local AES-GCM)
if ! env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  python -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM" >/dev/null 2>&1; then
  echo "Installing cryptography package..."
  env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    python -m pip install --no-compile cryptography --quiet
fi

# Optionally try to install the real edb-tde-kmip-client (may fail without EDB repos)
echo "Attempting to install edb-tde-kmip-client (optional)..."
if env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  python -m pip install --no-compile edb-tde-kmip-client --quiet 2>/dev/null; then
  echo "  ✓ Real edb-tde-kmip-client installed"
else
  echo "  ⓘ edb-tde-kmip-client not available (EDB repos required) — using simulation"
fi

echo ""
echo "Setup complete. Run tests with:"
echo "  bash .mise/scripts/edb_tde/test_edb_tde.sh"
