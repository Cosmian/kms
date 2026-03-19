#!/usr/bin/env bash
set -euo pipefail
set -x

# SoftHSM2-only tests (Linux only)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running SoftHSM2 HSM tests"
echo "========================================="

[ ! -f /etc/lsb-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

export HSM_USER_PASSWORD="12345678"

# Prepare SoftHSM2 token
export SOFTHSM2_HOME="$REPO_ROOT/.softhsm2"
mkdir -p "$SOFTHSM2_HOME/tokens"
export SOFTHSM2_CONF="$SOFTHSM2_HOME/softhsm2.conf"
echo "directories.tokendir = $SOFTHSM2_HOME/tokens" >"$SOFTHSM2_CONF"

softhsm2-util --version
SOFTHSM2_BIN_PATH="$(command -v softhsm2-util || true)"
if [ -n "$SOFTHSM2_BIN_PATH" ]; then
  SOFTHSM2_PREFIX="$(dirname "$(dirname "$SOFTHSM2_BIN_PATH")")"
  if [ -d "$SOFTHSM2_PREFIX/lib/softhsm" ]; then
    SOFTHSM2_LIB_DIR="$SOFTHSM2_PREFIX/lib/softhsm"
  elif [ -d "$SOFTHSM2_PREFIX/lib" ]; then
    SOFTHSM2_LIB_DIR="$SOFTHSM2_PREFIX/lib"
  else
    SOFTHSM2_LIB_DIR=""
  fi
fi
SOFTHSM2_PKCS11_LIB_PATH="${SOFTHSM2_LIB_DIR:+$SOFTHSM2_LIB_DIR/libsofthsm2.so}"
INIT_OUT=$(softhsm2-util --init-token --free --label "my_token_1" --so-pin "$HSM_USER_PASSWORD" --pin "$HSM_USER_PASSWORD" 2>&1 | tee /dev/stderr)

SOFTHSM2_HSM_SLOT_ID=$(echo "$INIT_OUT" | grep -o 'reassigned to slot [0-9]*' | awk '{print $4}')
if [ -z "${SOFTHSM2_HSM_SLOT_ID:-}" ]; then
  SOFTHSM2_HSM_SLOT_ID=$(softhsm2-util --show-slots | awk 'BEGIN{sid=""} /^Slot/ {sid=$2} /Token label/ && $0 ~ /my_token_1/ {print sid; exit}')
fi
[ -n "${SOFTHSM2_HSM_SLOT_ID:-}" ] || {
  echo "Error: Could not determine SoftHSM2 slot id" >&2
  exit 1
}

env \
  PATH="$PATH" \
  LD_LIBRARY_PATH="${SOFTHSM2_LIB_DIR:+$SOFTHSM2_LIB_DIR:}${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
  SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH:-}" \
  HSM_MODEL="softhsm2" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="$SOFTHSM2_HSM_SLOT_ID" \
  cargo test \
  -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  -- tests::hsm::test_hsm_all --ignored --exact

echo "SoftHSM2 KMS server tests completed successfully."

env \
  PATH="$PATH" \
  LD_LIBRARY_PATH="${SOFTHSM2_LIB_DIR:+$SOFTHSM2_LIB_DIR:}${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
  SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH:-}" \
  HSM_MODEL="softhsm2" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="$SOFTHSM2_HSM_SLOT_ID" \
  cargo test \
  -p softhsm2_pkcs11_loader \
  --features softhsm2 \
  -- tests::test_hsm_softhsm2_all --ignored

echo "SoftHSM2 Loader tests completed successfully."

# ─── pkcs11-tool warning check ────────────────────────────────────────────────
# Spin up a KMS server, create AES and RSA keys via ckms, then run
# pkcs11-tool --list-objects to confirm no unexpected attribute warnings appear.
# This is the integration-level regression test for issue #745
# (KMS was not setting CKA_ID on HSM-created keys).
test_pkcs11tool_no_warnings() {
  if ! command -v pkcs11-tool >/dev/null 2>&1; then
    echo "Skipping pkcs11-tool warning test: pkcs11-tool not in PATH."
    return 0
  fi

  echo "========================================="
  echo "pkcs11-tool: checking KMS-created HSM keys for warnings (SoftHSM2)"
  echo "========================================="

  # Build server + CLI binaries (reuses any already-built artifacts)
  local -a build_args=(-p cosmian_kms_server -p ckms)
  if [ ${#FEATURES_FLAG[@]} -gt 0 ]; then
    build_args+=("${FEATURES_FLAG[@]}")
  fi
  env PATH="$PATH" \
    LD_LIBRARY_PATH="${SOFTHSM2_LIB_DIR:+$SOFTHSM2_LIB_DIR:}${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
    cargo build "${build_args[@]}"

  local cargo_target_dir
  cargo_target_dir="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
  local kms_bin="$cargo_target_dir/debug/cosmian_kms"
  local ckms_bin="$cargo_target_dir/debug/ckms"

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
  local aes_uid="hsm::${SOFTHSM2_HSM_SLOT_ID}::${aes_label}"
  local rsa_uid="hsm::${SOFTHSM2_HSM_SLOT_ID}::${rsa_label}"

  # Start KMS server (HTTP, no TLS, SQLite, SoftHSM2).
  # The KMS reads SOFTHSM2_PKCS11_LIB to locate the PKCS#11 module, and
  # SOFTHSM2_CONF to locate the token database.
  env PATH="$PATH" \
    LD_LIBRARY_PATH="${SOFTHSM2_LIB_DIR:+$SOFTHSM2_LIB_DIR:}${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
    SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH:-}" \
    SOFTHSM2_CONF="$SOFTHSM2_CONF" \
    "$kms_bin" \
      --database-type sqlite \
      --sqlite-path "$sqlite_path" \
      --port "$kms_port" \
      --hostname "127.0.0.1" \
      --hsm-model softhsm2 \
      --hsm-admin admin \
      --hsm-slot "$SOFTHSM2_HSM_SLOT_ID" \
      --hsm-password "$HSM_USER_PASSWORD" \
    >"$tmp_dir/kms.log" 2>&1 &
  kms_pid=$!

  kms_wait_ready "http://127.0.0.1:${kms_port}/kmip/2_1" "$kms_pid" "$tmp_dir/kms.log" 60

  local base_args=(--url "http://127.0.0.1:${kms_port}")

  # Create AES-256 and RSA-2048 keys on SoftHSM2.
  # No --sensitive flag: SoftHSM2 supports CKA_VALUE reads and we want clean output.
  env PATH="$PATH" SOFTHSM2_CONF="$SOFTHSM2_CONF" \
    "$ckms_bin" "${base_args[@]}" sym keys create \
      --algorithm aes \
      --number-of-bits 256 \
      "$aes_uid"

  env PATH="$PATH" SOFTHSM2_CONF="$SOFTHSM2_CONF" \
    "$ckms_bin" "${base_args[@]}" rsa keys create \
      --size_in_bits 2048 \
      "$rsa_uid"

  kill "$kms_pid" 2>/dev/null || true
  wait "$kms_pid" 2>/dev/null || true
  kms_pid=""

  # Run pkcs11-tool --list-objects; SoftHSM2 implements all PKCS#11 attributes
  # so no CKR_ATTRIBUTE_* warnings should appear.
  local pkcs11_output pkcs11_rc=0
  set +x
  pkcs11_output=$(
    SOFTHSM2_CONF="$SOFTHSM2_CONF" \
    pkcs11-tool \
      --module "$SOFTHSM2_PKCS11_LIB_PATH" \
      --login --pin "$HSM_USER_PASSWORD" \
      --slot "$SOFTHSM2_HSM_SLOT_ID" \
      --list-objects 2>&1
  ) || pkcs11_rc=$?
  set -x
  if [ "$pkcs11_rc" -ne 0 ]; then
    echo "WARNING: pkcs11-tool exited with code $pkcs11_rc" >&2
  fi
  echo "--- pkcs11-tool --list-objects output ---"
  echo "$pkcs11_output"
  echo "-----------------------------------------"

  # SoftHSM2 v2.6 does not implement CKA_VERIFY_RECOVER (related to the
  # CKM_RSA_9796 mechanism, which is not widely supported).  pkcs11-tool always
  # probes this attribute on RSA public keys and emits a warning when the library
  # returns CKR_ATTRIBUTE_TYPE_INVALID.  Exclude it; all other attribute errors
  # indicate a real KMS key-template defect.
  pkcs11_check_warnings "$pkcs11_output" "VERIFY_RECOVER" || exit 1

  echo "OK: no pkcs11-tool warnings on KMS-created HSM keys."

  # Clean up test keys from SoftHSM2
  set +x
  SOFTHSM2_CONF="$SOFTHSM2_CONF" pkcs11-tool --module "$SOFTHSM2_PKCS11_LIB_PATH" \
    --login --pin "$HSM_USER_PASSWORD" --slot "$SOFTHSM2_HSM_SLOT_ID" \
    --delete-object --type secrkey --label "$aes_label" 2>/dev/null || true
  SOFTHSM2_CONF="$SOFTHSM2_CONF" pkcs11-tool --module "$SOFTHSM2_PKCS11_LIB_PATH" \
    --login --pin "$HSM_USER_PASSWORD" --slot "$SOFTHSM2_HSM_SLOT_ID" \
    --delete-object --type privkey --label "$rsa_label" 2>/dev/null || true
  SOFTHSM2_CONF="$SOFTHSM2_CONF" pkcs11-tool --module "$SOFTHSM2_PKCS11_LIB_PATH" \
    --login --pin "$HSM_USER_PASSWORD" --slot "$SOFTHSM2_HSM_SLOT_ID" \
    --delete-object --type pubkey --label "${rsa_label}_pk" 2>/dev/null || true
  set -x

  trap - EXIT
  rm -rf "$tmp_dir"
  echo "pkcs11-tool warning test passed."
}

test_pkcs11tool_no_warnings

echo "SoftHSM2 HSM tests completed successfully."
