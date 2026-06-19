#!/usr/bin/env bash
# Run EDB TDE KMIP compliance tests against a locally launched Cosmian KMS inside nix-shell.
#
# Requires EDB_SUBSCRIPTION_TOKEN to be set (fails immediately otherwise).
#
# Runs:
#   - PyKMIP variant (KMIP Encrypt/Decrypt server-side wrap)
#   - Thales variant (KMIP Get + local AES-256-GCM client-side wrap)
#   - Key rotation scenario
#   - Multiple DEK sizes
#   - Real EDB Postgres Advanced Server 17 container (edb-tde service in docker-compose.yml)
#     - initdb --data-encryption calls the KMS to seal the cluster DEK
#     - Verifies data_encryption_version = 1
#     - Writes and reads back an encrypted row
#
# Usage:
#   EDB_SUBSCRIPTION_TOKEN=<token> bash .mise/scripts/nix.sh --variant non-fips test edb_tde
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${MISE_CONFIG_ROOT:-.}/.mise/scripts/common.sh"
REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")

init_build_env "$@"
setup_test_logging

# Enforce non-FIPS for EDB TDE tests (PyKMIP requires ssl.wrap_socket → Python 3.11)
if [ "${VARIANT}" != "non-fips" ]; then
  echo "Note: For EDB TDE tests, forcing non-FIPS features (overriding --variant ${VARIANT})." >&2
fi

VARIANT="non-fips"
FEATURES_FLAG=(--features non-fips)

# Default KMS config (same mTLS config as PyKMIP tests)
: "${COSMIAN_KMS_CONF:=$REPO_ROOT/.mise/scripts/pykmip/kms.toml}"
export COSMIAN_KMS_CONF

# Ensure Python is available
require_cmd python3 "Python 3 is required. Re-run via 'bash .mise/scripts/nix.sh test edb_tde' so nix-shell can provide it."

# Prefer Nix-provided Python (3.11)
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
echo "Using Python interpreter: $PYTHON_BIN"

# Verify ssl module is available
if ! env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES "$PYTHON_BIN" - <<'PY'; then
import ssl, sys
print("SSL OK:", ssl.OPENSSL_VERSION)
PY
  echo "Error: Selected Python has no working ssl module." >&2
  exit 1
fi

# Prepare virtualenv
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
env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -m pip install --upgrade pip --quiet

# Install PyKMIP + cryptography (for thales variant)
if ! env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -c "from kmip.services import kmip_client" >/dev/null 2>&1; then
  echo "Installing PyKMIP into virtualenv …"
  env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -m pip install --no-compile PyKMIP --quiet
fi
if ! env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM" >/dev/null 2>&1; then
  echo "Installing cryptography package …"
  env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES python -m pip install --no-compile cryptography --quiet
fi

# Build and launch the KMS server
pushd "$REPO_ROOT" >/dev/null
cargo build --bin cosmian_kms ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}

KMS_PORT=9998
KMIP_PORT=15696

# Clean up ports
free_port() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids=$(lsof -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
    if [ -n "$pids" ]; then
      echo "Freeing port $port (PIDs: $pids) …"
      # shellcheck disable=SC2086
      kill $pids 2>/dev/null || true
    fi
  elif command -v ss >/dev/null 2>&1; then
    local pids
    pids=$(ss -ltnp 2>/dev/null | awk -v p=":$port" '$4 ~ p {gsub(/.*pid=([0-9]+).*/,"\\1",$NF); print $NF}')
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

# Ensure cleanup on exit
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
  # Stop EDB container — no-op if not started yet.
  docker compose --project-directory "$REPO_ROOT" stop edb-tde 2>/dev/null || true
  docker compose --project-directory "$REPO_ROOT" rm -f edb-tde 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for ports
if _wait_for_port 127.0.0.1 "$KMS_PORT" 20 && _wait_for_port 127.0.0.1 "$KMIP_PORT" 20; then
  echo "KMS is up on ports $KMS_PORT (HTTP) and $KMIP_PORT (KMIP)."
else
  echo "Error: KMS did not start on required ports in time." >&2
  exit 1
fi

# ── EDB container lifecycle ────────────────────────────────────────────────────
# Login to the EDB registry.  In CI, test_all.yml does this before the Test step;
# here we repeat it so the test also works when run locally.
if [ -z "${EDB_SUBSCRIPTION_TOKEN:-}" ]; then
  echo "Error: EDB_SUBSCRIPTION_TOKEN is not set." >&2
  echo "Set it to your EDB registry token to run this test suite." >&2
  exit 1
fi
echo "${EDB_SUBSCRIPTION_TOKEN}" |
  docker login --username k8s --password-stdin docker.enterprisedb.com 2>/dev/null || {
  echo "Error: docker login to docker.enterprisedb.com failed." >&2
  exit 1
}

# Create the AES-256 master key (the official edb_tde_kmip_client.py has no
# key-creation command; create_master_key.py fills that gap).
EDB_MASTER_KEY_UID=$(env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  python "$REPO_ROOT/.mise/scripts/edb_tde/create_master_key.py" \
  --pykmip-config-file="$REPO_ROOT/.mise/scripts/edb_tde/pykmip.conf" 2>/dev/null)
if [ -z "$EDB_MASTER_KEY_UID" ]; then
  echo "Error: Failed to create EDB master key (empty UID)." >&2
  exit 1
fi
export EDB_MASTER_KEY_UID
echo "EDB master key UID: $EDB_MASTER_KEY_UID"

# Stop and remove any existing container to guarantee a clean PGDATA.
docker compose --project-directory "$REPO_ROOT" stop edb-tde 2>/dev/null || true
docker compose --project-directory "$REPO_ROOT" rm -f edb-tde 2>/dev/null || true

# Start the EDB Postgres TDE container.  initdb runs inside the container and
# calls PGDATAKEYWRAPCMD (edb_tde_kmip_client.py encrypt) to seal the cluster DEK.
echo "Starting EDB Postgres TDE container (initdb will wrap the cluster DEK)…"
docker compose --project-directory "$REPO_ROOT" up -d edb-tde || {
  echo "Error: docker compose up edb-tde failed." >&2
  exit 1
}

# Resolve the actual container name (docker compose prefixes the project name,
# e.g. the repo directory "kms" → "kms-edb-tde-1").
CONTAINER_NAME=$(docker compose --project-directory "$REPO_ROOT" ps \
  --format "{{.Name}}" edb-tde 2>/dev/null | head -1)
export CONTAINER_NAME="${CONTAINER_NAME:-edb-tde}"
echo "EDB container: $CONTAINER_NAME"

# Run the EDB TDE test suite (container is up; CONTAINER_NAME + EDB_MASTER_KEY_UID exported).
echo "Running EDB TDE tests…"
export PYTHON_CMD="python"
env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  bash "$REPO_ROOT/.mise/scripts/edb_tde/test_edb_tde.sh" all
EDB_TDE_STATUS=$?

popd >/dev/null
exit $EDB_TDE_STATUS
