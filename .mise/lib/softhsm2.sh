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
HSM_USER_PASSWORD="12345678"
SOFTHSM2_HSM_SLOT_ID=""
SOFTHSM2_HSM_SLOT_ID_2=""
SOFTHSM2_HSM_SLOT_ID_3=""

# Detect the SoftHSM2 library directory and set SOFTHSM2_LIB_DIR + SOFTHSM2_PKCS11_LIB_PATH.
softhsm2_detect_lib() {
  require_cmd softhsm2-util "SoftHSM2 is required. Please install it."

  local bin_path prefix
  bin_path="$(command -v softhsm2-util)"
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
  SOFTHSM2_CONF="$conf_file"
  echo "directories.tokendir = $token_dir" >"$SOFTHSM2_CONF"

  export SOFTHSM2_HOME SOFTHSM2_CONF

  softhsm2_detect_lib
  softhsm2-util --version
}

# Initialize a single SoftHSM2 token.
# Usage: softhsm2_init_token <label> <pin> <so_pin>
# Outputs: init output (for slot-id extraction)
softhsm2_init_token() {
  local label="$1" pin="$2" so_pin="$3"
  softhsm2-util --init-token --free \
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
    slot_id=$(softhsm2-util --show-slots |
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
