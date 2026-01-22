#!/usr/bin/env bash
set -euo pipefail
set -x

# Utimaco-only tests (Linux only)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging

# Use a writable runtime directory for the Utimaco simulator (moved)
export UTIMACO_RUNTIME_DIR="${REPO_ROOT}/.utimaco"

# Migrate old runtime directory if present
if [ -d "${REPO_ROOT}/.utimaco-runtime" ] && [ ! -d "${REPO_ROOT}/.utimaco" ]; then
  echo "Migrating .utimaco-runtime to .utimaco"
  mv "${REPO_ROOT}/.utimaco-runtime" "${REPO_ROOT}/.utimaco"
fi

# Use the Nix-provided toolchain from shell.nix; no overrides needed

echo "========================================="
echo "Running Utimaco HSM tests"
echo "========================================="

[ ! -f /etc/lsb-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

export HSM_USER_PASSWORD="12345678"

# Ensure OpenSSL runtime is available for tests needing libcrypto
if [ -n "${NIX_OPENSSL_OUT:-}" ] && [ -d "${NIX_OPENSSL_OUT}/lib" ]; then
  export LD_LIBRARY_PATH="${NIX_OPENSSL_OUT}/lib:${LD_LIBRARY_PATH:-}"
fi

# In pure Nix shell, Utimaco package and env are provided by shell.nix (WITH_HSM=1)

# Setup Utimaco HSM simulator
# If running in Nix shell with Utimaco package, use it; otherwise fall back to download
if command -v utimaco-simulator >/dev/null 2>&1; then
  echo "Using Nix-packaged Utimaco HSM simulator"

  # Start simulator (tolerate already-running instance)
  utimaco-simulator || echo "Utimaco simulator already running; continuing"

  # Initialize with default PINs
  utimaco-init || echo "Utimaco init skipped (already initialized)"

  # Environment variables are already set by the Nix package's setupHook
  : "${UTIMACO_PKCS11_LIB:?UTIMACO_PKCS11_LIB not set}"
  : "${CS_PKCS11_R3_CFG:?CS_PKCS11_R3_CFG not set}"
else
  echo "Error: utimaco-simulator not found in PATH."
  echo "Run inside nix-shell --pure with WITH_HSM=1 to include the Utimaco package."
  exit 1
fi

UTIMACO_LIB_DIR="$(dirname "$UTIMACO_PKCS11_LIB")"

# Utimaco integration test (KMS)

env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES \
  PATH="$PATH" \
  LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
  HSM_MODEL="utimaco" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="0" \
  UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" \
  CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" \
  cargo test \
  -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  ${RELEASE_FLAG:+$RELEASE_FLAG} \
  tests::hsm::test_hsm_all \
  -- --ignored

# Utimaco loader test (pure Nix, scoped runtime)

env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES \
  PATH="$PATH" \
  LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
  HSM_MODEL="utimaco" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="0" \
  UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" \
  CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" \
  cargo test \
  -p utimaco_pkcs11_loader \
  ${RELEASE_FLAG:+$RELEASE_FLAG} \
  --features utimaco \
  tests::test_hsm_utimaco_all \
  -- --ignored

# Optionally run Google CSE CLI tests if environment is provided
if [ -n "${TEST_GOOGLE_OAUTH_CLIENT_ID:-}" ] && [ -n "${TEST_GOOGLE_OAUTH_CLIENT_SECRET:-}" ] && [ -n "${TEST_GOOGLE_OAUTH_REFRESH_TOKEN:-}" ]; then
  # shellcheck disable=SC2086
  env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES "PATH=$PATH" \
    LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
    HSM_MODEL="utimaco" \
    HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
    HSM_SLOT_ID="0" \
    UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" \
    CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" \
    TEST_GOOGLE_OAUTH_CLIENT_ID="$TEST_GOOGLE_OAUTH_CLIENT_ID" \
    TEST_GOOGLE_OAUTH_CLIENT_SECRET="$TEST_GOOGLE_OAUTH_CLIENT_SECRET" \
    TEST_GOOGLE_OAUTH_REFRESH_TOKEN="$TEST_GOOGLE_OAUTH_REFRESH_TOKEN" \
    cargo test -p cosmian_kms_cli \
    ${RELEASE_FLAG:+$RELEASE_FLAG} \
    ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
    -- --nocapture kmip_2_1_xml_pkcs11_m_1_21 --ignored

  # shellcheck disable=SC2086
  env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES "PATH=$PATH" \
    LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
    HSM_MODEL="utimaco" \
    HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
    HSM_SLOT_ID="0" \
    UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" \
    CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" \
    TEST_GOOGLE_OAUTH_CLIENT_ID="$TEST_GOOGLE_OAUTH_CLIENT_ID" \
    TEST_GOOGLE_OAUTH_CLIENT_SECRET="$TEST_GOOGLE_OAUTH_CLIENT_SECRET" \
    TEST_GOOGLE_OAUTH_REFRESH_TOKEN="$TEST_GOOGLE_OAUTH_REFRESH_TOKEN" \
    cargo test -p cosmian_kms_cli \
    ${RELEASE_FLAG:+$RELEASE_FLAG} \
    ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
    -- --nocapture hsm_google_cse --ignored
else
  echo "Skipping Google CSE CLI tests (env vars not provided)."
fi

echo "Utimaco HSM tests completed successfully."
