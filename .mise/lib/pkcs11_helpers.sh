#!/usr/bin/env bash
# .mise/lib/pkcs11_helpers.sh — Shared helpers for PKCS#11 integration tests.
#
# Source this from any MISE task script that tests PKCS#11 providers:
#   source "${SCRIPT_DIR}/../../lib/pkcs11_helpers.sh"
#
# Provides:
#   get_cosmian_pkcs11_lib   — resolve + validate path to libcosmian_pkcs11.{so,dylib}
#   install_veracrypt        — download and install VeraCrypt from GitHub releases
#   hsm_kek_bootstrap        — SoftHSM2 token + HSM-resident KEK + KMS server restart
#
# Globals set by hsm_kek_bootstrap:
#   HSM_USER_PASSWORD, HSM_SLOT_ID, KEK_ID, CKMS_CONF (via KMS_URL/KMS_CKMS_CONF,
#   see .mise/lib/kms_server.sh)

# ── Guard against double-sourcing ─────────────────────────────────────────────
[ -n "${_MISE_PKCS11_HELPERS_SH_LOADED:-}" ] && return 0
_MISE_PKCS11_HELPERS_SH_LOADED=1

# ── Ensure lib/common.sh is loaded (provides get_repo_root, require_cmd, etc.) ──
_PKCS11_HELPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.mise/lib/common.sh
source "${_PKCS11_HELPERS_DIR}/common.sh"
# shellcheck source=.mise/lib/softhsm2.sh
source "${_PKCS11_HELPERS_DIR}/softhsm2.sh"
# shellcheck source=.mise/lib/kms_server.sh
source "${_PKCS11_HELPERS_DIR}/kms_server.sh"

# Return the path to the built cosmian_pkcs11 shared library and verify it
# exists.  Exits with an error message if the library has not been compiled.
# Usage:
#   pkcs11_lib=$(get_cosmian_pkcs11_lib)
#   pkcs11_lib=$(get_cosmian_pkcs11_lib "$cargo_target_dir")
get_cosmian_pkcs11_lib() {
  local cargo_target_dir="${1:-${CARGO_TARGET_DIR:-}}"
  if [ -z "$cargo_target_dir" ]; then
    cargo_target_dir="$(get_repo_root)/target"
  fi
  local lib
  if [ "$(uname)" = "Darwin" ]; then
    lib="$cargo_target_dir/debug/libcosmian_pkcs11.dylib"
  else
    lib="$cargo_target_dir/debug/libcosmian_pkcs11.so"
  fi
  if [ ! -f "$lib" ]; then
    echo "ERROR: PKCS#11 library not found: $lib" >&2
    echo "       Run: cargo build -p cosmian_pkcs11 --features non-fips" >&2
    exit 1
  fi
  echo "$lib"
}

# Install VeraCrypt from the official GitHub releases page.
# Uses the Ubuntu-specific .deb when available; falls back to the console
# setup bundle.  Installs libfuse2 and fuse as prerequisites on Ubuntu 24.04.
#
# Pinned version is controlled by VERACRYPT_VERSION (default: 1.26.20).
# Returns non-zero if installation fails — with set -e this aborts the caller.
#
# Usage:
#   install_veracrypt             # uses VERACRYPT_VERSION or 1.26.20
#   install_veracrypt "1.26.20"
install_veracrypt() {
  local version="${1:-${VERACRYPT_VERSION:-1.26.20}}"
  local ubuntu_ver
  ubuntu_ver=$(lsb_release -rs 2>/dev/null || echo "24.04")
  echo "Installing VeraCrypt ${version} on Ubuntu ${ubuntu_ver}..."

  # VeraCrypt 1.26.x requires libfuse2 on Ubuntu 24.04 (which ships FUSE3).
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libfuse2 fuse 2>/dev/null || true

  local gh_base="https://github.com/veracrypt/VeraCrypt/releases/download/VeraCrypt_${version}"

  # Try the distro-specific .deb first (preferred: handles all deps automatically).
  local deb_name="veracrypt-${version}-Ubuntu-${ubuntu_ver}-amd64.deb"
  if curl -fsSL --max-time 120 --retry 3 --retry-delay 5 \
    "${gh_base}/${deb_name}" -o "/tmp/${deb_name}" 2>/dev/null; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "/tmp/${deb_name}"
    rm -f "/tmp/${deb_name}"
    return 0
  fi

  echo "WARN: distro-specific .deb not found; trying console setup bundle..."
  local bundle="veracrypt-${version}-setup.tar.bz2"
  if curl -fsSL --max-time 120 --retry 3 --retry-delay 5 \
    "${gh_base}/${bundle}" -o "/tmp/${bundle}" 2>/dev/null; then
    tar xjf "/tmp/${bundle}" -C /tmp/
    local setup_bin="/tmp/veracrypt-${version}-setup-console-x64"
    if [ -f "$setup_bin" ]; then
      # Non-interactively: accept EULA ("yes") then choose install ("1").
      printf 'yes\n1\n' | sudo "$setup_bin" 2>/dev/null || true
    fi
    rm -f "/tmp/${bundle}" "$setup_bin" 2>/dev/null || true
    return 0
  fi

  echo "ERROR: Failed to install VeraCrypt ${version} — no download succeeded." >&2
  return 1
}

# Write a minimal KMS TOML with root-level HSM keys (must precede any [section]
# header — kms_write_config's fixed template only supports appending extra lines
# *after* [logging], which is too late for root-table keys, so the config is
# written directly here). Internal helper for hsm_kek_bootstrap; not meant to be
# called directly by task scripts.
#
# Usage: _hsm_kek_write_config <work_dir> <hsm_slot_id> <hsm_password> <port> <sqlite_dir> <kek_line>
_hsm_kek_write_config() {
  local work_dir="$1" hsm_slot_id="$2" hsm_password="$3" port="$4" sqlite_dir="$5" kek_line="$6"
  mkdir -p "${sqlite_dir}"
  KMS_PORT="${port}"
  KMS_URL="http://127.0.0.1:${KMS_PORT}"
  KMS_CONFIG_FILE="${work_dir}/kms.toml"
  # shellcheck disable=SC2034  # read by kms_start_from_bin (.mise/lib/kms_server.sh)
  KMS_LOG_FILE="${work_dir}/kms.log"
  cat >"${KMS_CONFIG_FILE}" <<EOF
default_username = "admin"

hsm_model = "softhsm2"
hsm_admin = ["admin"]
hsm_slot = [${hsm_slot_id}]
hsm_password = ["${hsm_password}"]
${kek_line}

[db]
database_type = "sqlite"
sqlite_path = "${sqlite_dir}"
clear_database = true

[http]
hostname = "127.0.0.1"
port = ${KMS_PORT}

[logging]
rust_log = "info,cosmian_kms=info"
ansi_colors = false
EOF
}

# Set up a SoftHSM2 token, bootstrap an HSM-resident AES-256 Key-Encryption-Key
# (KEK) via `ckms sym keys create`, then restart the KMS server with
# `key_encryption_key` set to that KEK — the two-phase pattern shared by every
# HSM-KEK PKCS#11 conformance script (bootstrap the KEK with a KEK-less server,
# then restart so every subsequently-created key is transparently wrapped by it).
#
# Requires the caller to have already:
#   - created a working directory and exported it in WORK_DIR
#   - built the KMS server/ckms binaries (kms_build_all)
#   - registered a cleanup trap that calls kms_stop, removes WORK_DIR, and removes
#     SOFTHSM2_HOME (this function does not register its own trap, since the
#     caller owns WORK_DIR's lifetime)
#
# Usage: hsm_kek_bootstrap <repo_root> <test_name> <work_dir> <kms_bin> <ckms_bin>
#
# On return, exports/sets:
#   HSM_USER_PASSWORD, HSM_SLOT_ID, KEK_ID  — the bootstrapped HSM-KEK's identity
#   KMS_URL, CKMS_CONF                       — the running, KEK-enabled KMS server
#   LD_LIBRARY_PATH, DYLD_LIBRARY_PATH       — extended with the SoftHSM2 lib path
hsm_kek_bootstrap() {
  local repo_root="$1" test_name="$2" work_dir="$3" kms_bin="$4" ckms_bin="$5"

  softhsm2_setup "${repo_root}/.softhsm2-${test_name}/tokens" "${repo_root}/.softhsm2-${test_name}/softhsm2.conf"
  HSM_USER_PASSWORD="12345678"
  local init_out
  init_out=$(softhsm2_init_token "${test_name}_kek" "${HSM_USER_PASSWORD}" "${HSM_USER_PASSWORD}")
  HSM_SLOT_ID=$(softhsm2_get_slot_id "${init_out}" "${test_name}_kek")
  KEK_ID="hsm::${HSM_SLOT_ID}::kek"
  export HSM_USER_PASSWORD HSM_SLOT_ID KEK_ID

  local lib_path
  lib_path="$(softhsm2_lib_search_path)"
  export LD_LIBRARY_PATH="${lib_path}:${LD_LIBRARY_PATH:-}"
  export DYLD_LIBRARY_PATH="${lib_path}:${DYLD_LIBRARY_PATH:-}"

  local port sqlite_dir
  port="$(kms_pick_free_port)"
  sqlite_dir="${work_dir}/kms-data"

  print_header "Phase A: bootstrapping HSM-KEK ${KEK_ID}"
  _hsm_kek_write_config "${work_dir}" "${HSM_SLOT_ID}" "${HSM_USER_PASSWORD}" "${port}" "${sqlite_dir}" ""
  kms_start_from_bin "${kms_bin}"
  kms_write_ckms_conf "${KMS_URL}"
  export CKMS_CONF="${KMS_CKMS_CONF}"
  "${ckms_bin}" sym keys create --algorithm aes --number-of-bits 256 "${KEK_ID}"
  kms_stop

  print_header "Phase B: restarting KMS server with HSM-KEK enabled"
  _hsm_kek_write_config "${work_dir}" "${HSM_SLOT_ID}" "${HSM_USER_PASSWORD}" "${port}" "${sqlite_dir}" "key_encryption_key = \"${KEK_ID}\""
  kms_start_from_bin "${kms_bin}"
  kms_write_ckms_conf "${KMS_URL}"
  export CKMS_CONF="${KMS_CKMS_CONF}"
}
