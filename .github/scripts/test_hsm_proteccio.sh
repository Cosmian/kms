#!/usr/bin/env bash
set -eo pipefail
set -x

# Proteccio-only tests (Linux only)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running Proteccio HSM tests"
echo "========================================="

# Proteccio tests require external credentials/configuration. In CI/Nix environments
# these are often not provided; skip with success rather than failing under `set -u`.
if [[ -z "${PROTECCIO_PASSWORD-}" || -z "${PROTECCIO_SLOT-}" ]]; then
  echo "Skipping Proteccio HSM tests (missing PROTECCIO_PASSWORD and/or PROTECCIO_SLOT)."
  exit 0
fi

[ ! -f /etc/lsb-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

# Disable trace to avoid leaking password in logs
set +x
export HSM_USER_PASSWORD="${PROTECCIO_PASSWORD}"
HSM_SLOT_ID_VALUE="${PROTECCIO_SLOT}"
set -x

# Setup Proteccio HSM client tools
if ! source "$REPO_ROOT/.github/reusable_scripts/prepare_proteccio.sh"; then
  echo "Warning: Failed to source prepare_proteccio.sh, nethsmstatus may be failing. with return code $?."
fi

# PROTECCIO integration test (KMS)
# Unset Nix OpenSSL environment to use system libraries for Proteccio HSM
env -u LD_PRELOAD -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  PATH="$PATH" \
  HSM_MODEL="proteccio" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  RUST_LOG="cosmian_kms_server=trace" \
  HSM_SLOT_ID="$HSM_SLOT_ID_VALUE" \
  cargo test \
  -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  -- tests::hsm::test_hsm_all --ignored --exact

set +x
env -u LD_PRELOAD -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  PATH="$PATH" \
  HSM_MODEL="proteccio" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="$HSM_SLOT_ID_VALUE" \
  RUST_LOG="cosmian_kms_server=trace" \
  cargo test \
  -p proteccio_pkcs11_loader \
  --features proteccio \
  -- tests::test_hsm_proteccio_all --ignored --exact
set -x

# ─── pkcs11-tool warning check ────────────────────────────────────────────────
# Spin up a KMS server, create AES and RSA keys via ckms, then run
# pkcs11-tool --list-objects to confirm no warnings appear.
# This is the integration-level regression test for issue #745
# (KMS was not setting CKA_ID on HSM-created keys).
test_pkcs11tool_no_warnings() {
  if ! command -v pkcs11-tool >/dev/null 2>&1; then
    echo "Skipping pkcs11-tool warning test: pkcs11-tool not in PATH."
    return 0
  fi

  echo "========================================="
  echo "pkcs11-tool: checking KMS-created HSM keys for warnings (Proteccio)"
  echo "========================================="

  # Build server + CLI binaries (reuses any already-built artifacts)
  local -a build_args=(-p cosmian_kms_server -p ckms)
  if [ ${#FEATURES_FLAG[@]} -gt 0 ]; then
    build_args+=("${FEATURES_FLAG[@]}")
  fi
  env -u LD_PRELOAD -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    cargo build "${build_args[@]}"

  local cargo_target_dir
  cargo_target_dir="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
  local kms_bin="$cargo_target_dir/debug/cosmian_kms"
  local ckms_bin="$cargo_target_dir/debug/ckms"

  # Proteccio PKCS11 module is always at /lib/libnethsm.so (installed by prepare_proteccio.sh)
  local proteccio_lib="/lib/libnethsm.so"

  local tmp_dir
  tmp_dir=$(mktemp -d)
  local kms_pid=""

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
  local aes_uid="hsm::${HSM_SLOT_ID_VALUE}::${aes_label}"
  local rsa_uid="hsm::${HSM_SLOT_ID_VALUE}::${rsa_label}"

  # Start KMS server (HTTP, no TLS, SQLite, Proteccio HSM).
  # Keep OPENSSL_CONF/OPENSSL_MODULES from the Nix shell so the binary can find
  # its OpenSSL providers (legacy.so etc.).  Only strip LD_PRELOAD.
  # /lib/libnethsm.so is on the system library path and does not require changes to
  # LD_LIBRARY_PATH.
  env -u LD_PRELOAD \
    PATH="$PATH" \
    "$kms_bin" \
      --database-type sqlite \
      --sqlite-path "$sqlite_path" \
      --port "$kms_port" \
      --hostname "127.0.0.1" \
      --hsm-model proteccio \
      --hsm-admin admin \
      --hsm-slot "$HSM_SLOT_ID_VALUE" \
      --hsm-password "$HSM_USER_PASSWORD" \
    >"$tmp_dir/kms.log" 2>&1 &
  kms_pid=$!

  local probe_url="http://127.0.0.1:${kms_port}/kmip/2_1"
  kms_wait_ready "$probe_url" "$kms_pid" "$tmp_dir/kms.log" 60

  local base_args=(--url "http://127.0.0.1:${kms_port}")

  # Create AES-256 and RSA-2048 keys on the Proteccio HSM.
  # Keys are intentionally NOT created with --sensitive so that pkcs11-tool can
  # read CKA_VALUE without receiving CKR_ATTRIBUTE_SENSITIVE, keeping the
  # pkcs11-tool output clean for the warning check below.
  env -u LD_PRELOAD PATH="$PATH" \
    "$ckms_bin" "${base_args[@]}" sym keys create \
      --algorithm aes \
      --number-of-bits 256 \
      "$aes_uid"

  env -u LD_PRELOAD PATH="$PATH" \
    "$ckms_bin" "${base_args[@]}" rsa keys create \
      --size_in_bits 2048 \
      "$rsa_uid"

  kill "$kms_pid" 2>/dev/null || true
  wait "$kms_pid" 2>/dev/null || true
  kms_pid=""

  # Run pkcs11-tool --list-objects without any Nix OpenSSL override so it uses
  # system libraries (pkcs11-tool from the OS is linked against the system OpenSSL)
  local pkcs11_output
  set +x
  pkcs11_output=$(
    env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    pkcs11-tool \
      --module "$proteccio_lib" \
      --login --pin "$HSM_USER_PASSWORD" \
      --slot "$HSM_SLOT_ID_VALUE" \
      --list-objects 2>&1
  )
  set -x
  echo "--- pkcs11-tool --list-objects output ---"
  echo "$pkcs11_output"
  echo "-----------------------------------------"

  # Proteccio does not implement CKA_VERIFY_RECOVER at all: both
  # C_GetAttributeValue and C_SetAttributeValue return CKR_ATTRIBUTE_TYPE_INVALID
  # for it.  pkcs11-tool always probes this attribute on RSA public keys, so the
  # warning is an inherent Proteccio library limitation, not a KMS bug.
  pkcs11_check_warnings "$pkcs11_output" "VERIFY_RECOVER" || exit 1

  echo "OK: no pkcs11-tool warnings on KMS-created HSM keys."

  # Clean up test keys from the HSM
  set +x
  env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    pkcs11-tool --module "$proteccio_lib" --login --pin "$HSM_USER_PASSWORD" \
      --slot "$HSM_SLOT_ID_VALUE" --delete-object --type secrkey \
      --label "$aes_label" 2>/dev/null || true
  env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    pkcs11-tool --module "$proteccio_lib" --login --pin "$HSM_USER_PASSWORD" \
      --slot "$HSM_SLOT_ID_VALUE" --delete-object --type privkey \
      --label "$rsa_label" 2>/dev/null || true
  env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    pkcs11-tool --module "$proteccio_lib" --login --pin "$HSM_USER_PASSWORD" \
      --slot "$HSM_SLOT_ID_VALUE" --delete-object --type pubkey \
      --label "${rsa_label}_pk" 2>/dev/null || true
  set -x

  trap - EXIT
  rm -rf "$tmp_dir"
  echo "pkcs11-tool warning test passed."
}

test_pkcs11tool_no_warnings

echo "Proteccio HSM tests completed successfully."
