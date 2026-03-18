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

env -u LD_PRELOAD \
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
  tests::hsm::test_hsm_all \
  -- --ignored

# Utimaco loader test (pure Nix, scoped runtime)
#
# NOTE — Issue #745 (CKA_ID on KMS-created keys):
# The `tests::test_hsm_utimaco_generate_aes_key` and
# `tests::test_hsm_utimaco_generate_rsa_keypair` tests (called from test_hsm_utimaco_all
# below) now assert that every key created via the base_hsm session has CKA_ID set to the
# key-id bytes.  A failure here means the fix for issue #745 regressed.

env -u LD_PRELOAD \
  PATH="$PATH" \
  LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
  HSM_MODEL="utimaco" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="0" \
  UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" \
  CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" \
  cargo test \
  -p utimaco_pkcs11_loader \
  --features utimaco \
  tests::test_hsm_utimaco_all \
  -- --ignored

# Optionally run Google CSE CLI tests if environment is provided
if [ -n "${TEST_GOOGLE_OAUTH_CLIENT_ID:-}" ] && [ -n "${TEST_GOOGLE_OAUTH_CLIENT_SECRET:-}" ] && [ -n "${TEST_GOOGLE_OAUTH_REFRESH_TOKEN:-}" ]; then
  # shellcheck disable=SC2086
  env -u LD_PRELOAD "PATH=$PATH" \
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
    ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
    -- --nocapture kmip_2_1_xml_pkcs11_m_1_21 --ignored

  # shellcheck disable=SC2086
  env -u LD_PRELOAD "PATH=$PATH" \
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
    ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
    -- --nocapture hsm_google_cse --ignored
else
  echo "Skipping Google CSE CLI tests (env vars not provided)."
fi

# ─── pkcs11-tool warning check ────────────────────────────────────────────────
# Spin up a KMS server, create AES and RSA keys via ckms, then run
# pkcs11-tool --list-objects to confirm no warnings appear.
# This is the integration-level regression test for issue #745
# (KMS was not setting CKA_ID on HSM-created keys).
test_pkcs11tool_no_warnings() {
  if ! command -v pkcs11-tool >/dev/null 2>&1; then
    echo "Skipping pkcs11-tool warning test: pkcs11-tool not in PATH."
    echo "  Run with WITH_HSM=1 inside nix-shell to include pkgs.opensc."
    return 0
  fi

  echo "========================================="
  echo "pkcs11-tool: checking KMS-created HSM keys for warnings"
  echo "========================================="

  # Build server + CLI binaries (reuses any already-built artifacts)
  local -a build_args=(-p cosmian_kms_server -p ckms)
  if [ ${#FEATURES_FLAG[@]} -gt 0 ]; then
    build_args+=("${FEATURES_FLAG[@]}")
  fi
  cargo build "${build_args[@]}"

  local cargo_target_dir
  cargo_target_dir="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
  local kms_bin="$cargo_target_dir/debug/cosmian_kms"
  local ckms_bin="$cargo_target_dir/debug/ckms"

  local tmp_dir
  tmp_dir=$(mktemp -d)
  local kms_pid=""
  local slot=0

  _cleanup_pkcs11_test() {
    [ -n "${kms_pid:-}" ] && { kill "$kms_pid" 2>/dev/null || true; wait "$kms_pid" 2>/dev/null || true; }
    rm -rf "${tmp_dir:-}"
  }
  trap _cleanup_pkcs11_test EXIT

  local kms_port=19998
  local sqlite_path="$tmp_dir/kms-data"
  local ts
  ts=$(date +%s)
  local aes_label="pkcs11tool_aes_${ts}"
  local rsa_label="pkcs11tool_rsa_${ts}"
  local aes_uid="hsm::0::${aes_label}"
  local rsa_uid="hsm::0::${rsa_label}"

  # Start KMS server (HTTP, no TLS, SQLite, Utimaco HSM on slot 0)
  # OPENSSL_MODULES must point to the Nix-provided ossl-modules directory so the
  # dev-build binary (which has OPENSSLDIR=/usr/local/cosmian baked in) can load
  # the legacy and fips providers from the Nix store instead.
  local nix_ossl_modules="${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib/ossl-modules}"
  env -u LD_PRELOAD \
    PATH="$PATH" \
    LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
    ${nix_ossl_modules:+OPENSSL_MODULES="$nix_ossl_modules"} \
    UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" \
    CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" \
    "$kms_bin" \
      --database-type sqlite \
      --sqlite-path "$sqlite_path" \
      --port "$kms_port" \
      --hostname "127.0.0.1" \
      --hsm-model utimaco \
      --hsm-admin admin \
      --hsm-slot 0 \
      --hsm-password "$HSM_USER_PASSWORD" \
    >"$tmp_dir/kms.log" 2>&1 &
  kms_pid=$!

  # Wait for server readiness (up to 60 s).
  # The KMIP endpoint returns 422 for the minimal "{}" probe body, which is
  # correct behaviour – any HTTP response means the server is accepting
  # connections, so do NOT use `curl -f` (it would treat 4xx as failure).
  local probe_url="http://127.0.0.1:${kms_port}/kmip/2_1"
  local i
  for i in $(seq 1 60); do
    if curl -sS --max-time 2 -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" -d '{}' "$probe_url" 2>/dev/null \
        | grep -Eq '^[0-9]{3}$'; then
      break
    fi
    sleep 1
    if ! ps -p "$kms_pid" >/dev/null 2>&1; then
      echo "ERROR: KMS server process exited early; log:" >&2
      cat "$tmp_dir/kms.log" >&2
      exit 1
    fi
    if [ "$i" -eq 60 ]; then
      echo "ERROR: KMS server did not start in 60 s; log:" >&2
      cat "$tmp_dir/kms.log" >&2
      exit 1
    fi
  done

  local base_args=(--url "http://127.0.0.1:${kms_port}")

  # Create AES-256 key on HSM slot 0
  env -u LD_PRELOAD PATH="$PATH" \
    "$ckms_bin" "${base_args[@]}" sym keys create \
      --algorithm aes \
      --number-of-bits 256 \
      --sensitive \
      "$aes_uid"

  # Create RSA-2048 key pair on HSM slot 0 (admin-only operation)
  env -u LD_PRELOAD PATH="$PATH" \
    "$ckms_bin" "${base_args[@]}" rsa keys create \
      --size_in_bits 2048 \
      --sensitive \
      "$rsa_uid"

  # Stop the KMS server; keys remain in the HSM slot
  kill "$kms_pid" 2>/dev/null || true
  wait "$kms_pid" 2>/dev/null || true
  kms_pid=""

  # List all objects in the Utimaco slot and capture both stdout and stderr
  # NOTE: do NOT include NIX_OPENSSL_OUT/lib here — pkcs11-tool (opensc) is linked
  # against OpenSSL 3.2+ and the FIPS NIX_OPENSSL_OUT is 3.1.2, which causes:
  #   pkcs11-tool: .../libcrypto.so.3: version `OPENSSL_3.2.0' not found
  local pkcs11_output
  pkcs11_output=$(
    env LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${LD_LIBRARY_PATH:-}" \
    pkcs11-tool \
      --module "$UTIMACO_PKCS11_LIB" \
      --login --pin "$HSM_USER_PASSWORD" \
      --slot "$slot" \
      --list-objects 2>&1
  )
  echo "--- pkcs11-tool --list-objects output ---"
  echo "$pkcs11_output"
  echo "-----------------------------------------"

  # Fail if any warnings are reported that are NOT the expected
  # "CKR_ATTRIBUTE_SENSITIVE" message (pkcs11-tool always emits that when
  # reading sensitive-attribute keys, and it is harmless).
  local warnings
  warnings=$(echo "$pkcs11_output" | grep -i "[Ww]arning" | grep -v "CKR_ATTRIBUTE_SENSITIVE" || true)
  if [ -n "$warnings" ]; then
    echo "FAIL: pkcs11-tool reported unexpected warnings for KMS-created HSM keys:" >&2
    echo "$warnings" >&2
    exit 1
  fi

  echo "OK: no pkcs11-tool warnings on KMS-created HSM keys."

  # Clean up: remove the test keys from the HSM using pkcs11-tool
  # (same LD_LIBRARY_PATH rule: no NIX_OPENSSL_OUT/lib for pkcs11-tool)
  env LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${LD_LIBRARY_PATH:-}" \
    pkcs11-tool --module "$UTIMACO_PKCS11_LIB" --login --pin "$HSM_USER_PASSWORD" \
      --slot "$slot" --delete-object --type secrkey \
      --label "$aes_label" 2>/dev/null || true
  env LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${LD_LIBRARY_PATH:-}" \
    pkcs11-tool --module "$UTIMACO_PKCS11_LIB" --login --pin "$HSM_USER_PASSWORD" \
      --slot "$slot" --delete-object --type privkey \
      --label "$rsa_label" 2>/dev/null || true
  env LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${LD_LIBRARY_PATH:-}" \
    pkcs11-tool --module "$UTIMACO_PKCS11_LIB" --login --pin "$HSM_USER_PASSWORD" \
      --slot "$slot" --delete-object --type pubkey \
      --label "${rsa_label}_pk" 2>/dev/null || true

  trap - EXIT
  rm -rf "$tmp_dir"
  echo "pkcs11-tool warning test passed."
}

test_pkcs11tool_no_warnings

echo "Utimaco HSM tests completed successfully."
