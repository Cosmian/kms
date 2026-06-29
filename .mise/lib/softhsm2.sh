#!/usr/bin/env bash
# .mise/lib/softhsm2.sh — SoftHSM2 token initialization helpers.
#
# Extracts the token setup pattern duplicated in test_hsm_softhsm2.sh and test_ui.sh.
#
# Source this from a task file:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/softhsm2.sh"
#
# Provides:
#   softhsm2_setup [token_dir] [conf_file]
#   softhsm2_init_token <label> <pin> <so_pin>
#   softhsm2_get_slot_id <label>
#   softhsm2_init_standard_tokens [prefix]
#   softhsm2_detect_lib
#
# Globals set:
#   SOFTHSM2_HOME, SOFTHSM2_CONF, SOFTHSM2_LIB_DIR, SOFTHSM2_PKCS11_LIB_PATH,
#   HSM_USER_PASSWORD, SOFTHSM2_HSM_SLOT_ID, SOFTHSM2_HSM_SLOT_ID_2, SOFTHSM2_HSM_SLOT_ID_3

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_SOFTHSM2_SH_LOADED:-}" ] && return 0
_MISE_SOFTHSM2_SH_LOADED=1

# ── Require common.sh ─────────────────────────────────────────────────────────
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  source "${MISE_CONFIG_ROOT:-.}/.mise/lib/common.sh"
fi

# ── State ─────────────────────────────────────────────────────────────────────
SOFTHSM2_HOME=""
SOFTHSM2_CONF=""
SOFTHSM2_LIB_DIR=""
SOFTHSM2_PKCS11_LIB_PATH=""
SOFTHSM2_UTIL=""
HSM_USER_PASSWORD="12345678"
SOFTHSM2_HSM_SLOT_ID=""
SOFTHSM2_HSM_SLOT_ID_2=""
SOFTHSM2_HSM_SLOT_ID_3=""

# Detect the SoftHSM2 library directory and set SOFTHSM2_LIB_DIR, SOFTHSM2_PKCS11_LIB_PATH, and SOFTHSM2_UTIL.
#
# Inside the Nix shell the PATH already contains the Nix-built SoftHSM2, which
# links against the same Nix OpenSSL FIPS 3.1.2 as the KMS server.  Always
# prefer the softhsm2-util found on PATH (Nix first) so that both the token
# utility and the PKCS#11 library use the same OpenSSL build — avoiding the
# version mismatch that causes CKR_PIN_INCORRECT in C_Login.
softhsm2_detect_lib() {
  require_cmd softhsm2-util "SoftHSM2 is required. Please install it."

  local bin_path prefix
  bin_path="$(command -v softhsm2-util)"
  SOFTHSM2_UTIL="$bin_path"
  prefix="$(dirname "$(dirname "$bin_path")")"

  if [ -d "$prefix/lib/softhsm" ]; then
    SOFTHSM2_LIB_DIR="$prefix/lib/softhsm"
  elif [ -d "$prefix/lib" ]; then
    SOFTHSM2_LIB_DIR="$prefix/lib"
  else
    SOFTHSM2_LIB_DIR=""
  fi

  if [ -n "$SOFTHSM2_LIB_DIR" ]; then
    if [ "$(uname -s)" = "Darwin" ]; then
      SOFTHSM2_PKCS11_LIB_PATH="${SOFTHSM2_LIB_DIR}/libsofthsm2.dylib"
      # Fallback to .so if .dylib doesn't exist
      [ -f "$SOFTHSM2_PKCS11_LIB_PATH" ] || SOFTHSM2_PKCS11_LIB_PATH="${SOFTHSM2_LIB_DIR}/libsofthsm2.so"
    else
      SOFTHSM2_PKCS11_LIB_PATH="${SOFTHSM2_LIB_DIR}/libsofthsm2.so"
    fi
  fi
}

# Initialize SoftHSM2 directories and config file.
# Usage: softhsm2_setup [token_dir] [conf_file]
# Sets: SOFTHSM2_HOME, SOFTHSM2_CONF (exported)
softhsm2_setup() {
  local repo_root
  repo_root="$(get_repo_root)"
  local token_dir="${1:-${repo_root}/.softhsm2/tokens}"
  local conf_file="${2:-${repo_root}/.softhsm2/softhsm2.conf}"

  SOFTHSM2_HOME="$(dirname "$token_dir")"
  mkdir -p "$token_dir"
  # Remove any leftover token directories from a previous run so every task
  # starts with a clean PKCS#11 state.  SoftHSM2 slots are identified by
  # slot-ID, not by label, so stale token subdirectories from an earlier task
  # (e.g. test:db:sqlite running before test:db:psql) can leave duplicate
  # labels in the same tokendir — which confuses C_Login and causes CKR_PIN_INCORRECT.
  find "$token_dir" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} + 2>/dev/null || true
  SOFTHSM2_CONF="$conf_file"
  echo "directories.tokendir = $token_dir" >"$SOFTHSM2_CONF"

  export SOFTHSM2_HOME SOFTHSM2_CONF

  softhsm2_detect_lib
  "$SOFTHSM2_UTIL" --version
}

# Initialize a single SoftHSM2 token.
# Usage: softhsm2_init_token <label> <pin> <so_pin>
# Outputs: init output (for slot-id extraction)
softhsm2_init_token() {
  local label="$1" pin="$2" so_pin="$3"
  "$SOFTHSM2_UTIL" --init-token --free \
    --label "$label" \
    --so-pin "$so_pin" \
    --pin "$pin" 2>&1 | tee /dev/stderr
}

# Extract slot ID for a given token label.
# Usage: softhsm2_get_slot_id <init_output> <label>
softhsm2_get_slot_id() {
  local init_out="$1" label="$2"
  local slot_id

  # Try to extract from init-token output first
  slot_id=$(echo "$init_out" | grep -o 'reassigned to slot [0-9]*' | awk '{print $4}')

  # Fallback: query softhsm2-util --show-slots
  if [ -z "${slot_id:-}" ]; then
    slot_id=$("$SOFTHSM2_UTIL" --show-slots |
      awk -v lbl="$label" 'BEGIN{sid=""} /^Slot/ {sid=$2} /Token label/ && index($0,lbl) {print sid; exit}')
  fi

  if [ -z "${slot_id:-}" ]; then
    echo "Error: Could not determine SoftHSM2 slot id for label '$label'" >&2
    return 1
  fi
  echo "$slot_id"
}

# Initialize the 3 standard test tokens used by both HSM tests and UI E2E tests.
# Usage: softhsm2_init_standard_tokens [label_prefix]
# Sets: SOFTHSM2_HSM_SLOT_ID, SOFTHSM2_HSM_SLOT_ID_2, SOFTHSM2_HSM_SLOT_ID_3
softhsm2_init_standard_tokens() {
  local prefix="${1:-my_token}"
  local pin="${HSM_USER_PASSWORD}"

  local out1 out2 out3
  out1=$(softhsm2_init_token "${prefix}_1" "$pin" "$pin")
  out2=$(softhsm2_init_token "${prefix}_2" "$pin" "$pin")
  out3=$(softhsm2_init_token "${prefix}_3" "$pin" "$pin")

  SOFTHSM2_HSM_SLOT_ID=$(softhsm2_get_slot_id "$out1" "${prefix}_1")
  SOFTHSM2_HSM_SLOT_ID_2=$(softhsm2_get_slot_id "$out2" "${prefix}_2")
  SOFTHSM2_HSM_SLOT_ID_3=$(softhsm2_get_slot_id "$out3" "${prefix}_3")

  echo "==> SoftHSM2 slot ids: ${SOFTHSM2_HSM_SLOT_ID} / ${SOFTHSM2_HSM_SLOT_ID_2} / ${SOFTHSM2_HSM_SLOT_ID_3}"
}

# Get the library path env var name for the current OS.
softhsm2_lib_path_var() {
  if [ "$(uname -s)" = "Darwin" ]; then
    echo "DYLD_LIBRARY_PATH"
  else
    echo "LD_LIBRARY_PATH"
  fi
}

# Build a combined library search path suitable for cargo test / KMS runtime.
# Usage: softhsm2_lib_search_path
# Returns a colon-separated path including SOFTHSM2_LIB_DIR and NIX_OPENSSL_OUT/lib.
softhsm2_lib_search_path() {
  local base_var
  base_var=$(softhsm2_lib_path_var)
  local existing="${!base_var:-}"
  local parts=""
  [ -n "${SOFTHSM2_LIB_DIR:-}" ] && parts="${SOFTHSM2_LIB_DIR}:"
  [ -n "${NIX_OPENSSL_OUT:-}" ] && parts="${parts}${NIX_OPENSSL_OUT}/lib:"
  echo "${parts}${existing}"
}

# Run the DB × SoftHSM2 integration test for the current backend.
#
# KMS_TEST_DB and all DB connection env vars (KMS_POSTGRES_URL, REDIS_HOST, …)
# must already be exported by the caller — typically done by _run_workspace_tests
# or check_and_test_db inside common.sh.
#
# Hard-fails (via require_cmd) if softhsm2-util is absent — there is no silent skip.
#
# Usage: run_db_softhsm2_tests <test_fn_suffix>
#   test_fn_suffix:  sqlite_softhsm2
#                    postgresql_softhsm2
#                    mysql_softhsm2
#                    redis_with_findex_softhsm2
run_db_softhsm2_tests() {
  local suffix="$1"

  require_cmd softhsm2-util \
    "SoftHSM2 (softhsm2-util) is required for DB+HSM integration tests. Install: brew install softhsm (macOS) or apt install softhsm2 (Linux)"

  local repo_root
  repo_root="$(get_repo_root)"

  softhsm2_setup "${repo_root}/.softhsm2/tokens" "${repo_root}/.softhsm2/softhsm2.conf"
  softhsm2_init_standard_tokens "db_hsm_test"

  export HSM_MODEL="softhsm2"
  export HSM_SLOT_ID="$SOFTHSM2_HSM_SLOT_ID"
  export HSM_USER_PASSWORD
  export SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH:-}"
  export WITH_HSM=1

  local lib_path
  lib_path="$(softhsm2_lib_search_path)"

  print_header "DB×SoftHSM2: test_db_${suffix} (KMS_TEST_DB=${KMS_TEST_DB:-unset})"

  env \
    PATH="$PATH" \
    LD_LIBRARY_PATH="$lib_path" \
    DYLD_LIBRARY_PATH="$lib_path" \
    SOFTHSM2_CONF="${SOFTHSM2_CONF:-}" \
    SOFTHSM2_HOME="${SOFTHSM2_HOME:-}" \
    SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH:-}" \
    HSM_MODEL="softhsm2" \
    HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
    HSM_SLOT_ID="$SOFTHSM2_HSM_SLOT_ID" \
    KMS_TEST_DB="${KMS_TEST_DB:-sqlite}" \
    ${KMS_POSTGRES_URL:+KMS_POSTGRES_URL="$KMS_POSTGRES_URL"} \
    ${KMS_MYSQL_URL:+KMS_MYSQL_URL="$KMS_MYSQL_URL"} \
    ${REDIS_HOST:+REDIS_HOST="$REDIS_HOST"} \
    ${REDIS_PORT:+REDIS_PORT="$REDIS_PORT"} \
    cargo test \
    -p test_kms_server \
    ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
    -- "test_db_${suffix}" --ignored --nocapture
}
