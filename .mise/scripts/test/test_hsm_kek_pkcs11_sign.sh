#!/usr/bin/env bash
# ============================================================================
# test_hsm_kek_pkcs11_sign.sh – External PKCS#11 v3 conformance test using
# OpenSC's `pkcs11-tool` against a real KMS server backed by a SoftHSM2
# Key-Encryption-Key (HSM-KEK).
#
# This complements the in-process Rust tests in
# crate/clients/pkcs11/provider/src/tests.rs (tests::test_hsm_kek_*), which
# exercise the same 3 signing requests (EdDSA Ed25519, ECDSA P-256, ECDSA
# secp256k1) through our own `CliBackend::remote_sign` code path. Here the
# *same* 3 requests are issued by `pkcs11-tool`, an independently-implemented,
# non-Cosmian PKCS#11 v3 client, closing the "we only tested our own client"
# gap:
#
#   pkcs11-tool --module libcosmian_pkcs11 --sign  (real PKCS#11 v3 C_Sign call)
#     -> cosmian_pkcs11 module                     (our provider)
#       -> KMS server Sign KMIP operation           (HSM-KEK wrapped key)
#
# Each signature is verified with `ckms ec sign-verify`, which calls the
# KMS's own SignatureVerify KMIP operation — a genuine cryptographic
# correctness check, not just a "signature is non-empty" placeholder.
#
# On non-Linux hosts, or when `pkcs11-tool` is not installed, the PKCS#11
# `--sign` step is skipped and a `ckms ec sign` + `ckms ec sign-verify`
# round-trip is used instead, mirroring the existing fallback pattern in
# test_luks.sh.
#
# Usage (via mise):
#   mise run test:hsm-pkcs11-tool --variant non-fips
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MISE_CONFIG_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/kms_build.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/kms_server.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/softhsm2.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/pkcs11_helpers.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/nix_helpers.sh"

VARIANT_ARG="non-fips"
LINK_ARG="static"
while [ $# -gt 0 ]; do
  case "$1" in
    --variant)
      VARIANT_ARG="$2"
      shift 2
      ;;
    --link)
      LINK_ARG="$2"
      shift 2
      ;;
    *) shift ;;
  esac
done

# secp256k1 (one of the 3 mandatory curves) is a non-fips-only curve, and the
# `cosmian_pkcs11` provider crate's test/signing code paths used here are only
# built in non-fips mode — this whole conformance tier requires non-fips,
# consistent with the equivalent in-process Rust test module.
if [ "${VARIANT_ARG}" != "non-fips" ]; then
  print_warning "Skipping HSM-KEK pkcs11-tool conformance test: requires --variant non-fips (secp256k1 is non-fips-only)."
  exit 0
fi

kms_init_env "${VARIANT_ARG}" "${LINK_ARG}"
setup_test_logging

REPO_ROOT="$(get_repo_root)"

# ── SoftHSM2 setup ───────────────────────────────────────────────────────────
softhsm2_setup "${REPO_ROOT}/.softhsm2-pkcs11-tool/tokens" "${REPO_ROOT}/.softhsm2-pkcs11-tool/softhsm2.conf"
HSM_USER_PASSWORD="12345678"
INIT_OUT=$(softhsm2_init_token "pkcs11_tool_kek" "${HSM_USER_PASSWORD}" "${HSM_USER_PASSWORD}")
HSM_SLOT_ID=$(softhsm2_get_slot_id "${INIT_OUT}" "pkcs11_tool_kek")
KEK_ID="hsm::${HSM_SLOT_ID}::kek"
export HSM_USER_PASSWORD

LIB_PATH="$(softhsm2_lib_search_path)"
export LD_LIBRARY_PATH="${LIB_PATH}:${LD_LIBRARY_PATH:-}"
export DYLD_LIBRARY_PATH="${LIB_PATH}:${DYLD_LIBRARY_PATH:-}"

# ── Build server, CLI, and PKCS#11 provider ─────────────────────────────────
print_header "Building KMS server, ckms CLI, and cosmian_pkcs11 provider"
kms_build_all
KMS_BIN="$(get_kms_bin)"
CKMS_BIN="$(get_ckms_bin)"
PKCS11_LIB="$(get_cosmian_pkcs11_lib)"

WORK_DIR="$(mktemp -d /tmp/kms-pkcs11-tool-XXXXXX)"
cleanup() {
  kms_stop
  rm -rf "${WORK_DIR}"
  [ -n "${SOFTHSM2_HOME:-}" ] && rm -rf "${SOFTHSM2_HOME}"
}
trap cleanup EXIT INT TERM

# Write a minimal KMS TOML with root-level HSM keys (must precede any
# [section] header — kms_write_config's fixed template only supports
# appending extra lines *after* [logging], which is too late for
# root-table keys, so the config is written directly here).
write_hsm_config() {
  local port="$1" sqlite_dir="$2" kek_line="$3"
  mkdir -p "${sqlite_dir}"
  KMS_PORT="${port}"
  KMS_URL="http://127.0.0.1:${KMS_PORT}"
  KMS_CONFIG_FILE="${WORK_DIR}/kms.toml"
  # shellcheck disable=SC2034  # read by kms_start_from_bin (.mise/lib/kms_server.sh)
  KMS_LOG_FILE="${WORK_DIR}/kms.log"
  cat >"${KMS_CONFIG_FILE}" <<EOF
default_username = "admin"

hsm_model = "softhsm2"
hsm_admin = ["admin"]
hsm_slot = [${HSM_SLOT_ID}]
hsm_password = ["${HSM_USER_PASSWORD}"]
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

KMS_PORT_VAL="$(kms_pick_free_port)"
SQLITE_DIR="${WORK_DIR}/kms-data"

# ── Phase A: bootstrap the HSM-resident KEK via ckms (no key_encryption_key yet) ──
print_header "Phase A: bootstrapping HSM-KEK ${KEK_ID}"
write_hsm_config "${KMS_PORT_VAL}" "${SQLITE_DIR}" ""
kms_start_from_bin "${KMS_BIN}"
kms_write_ckms_conf "${KMS_URL}"
export CKMS_CONF="${KMS_CKMS_CONF}"

"${CKMS_BIN}" sym keys create --algorithm aes --number-of-bits 256 "${KEK_ID}"
kms_stop

# ── Phase B: restart with key_encryption_key set, create the 3 test keypairs ──
print_header "Phase B: restarting KMS server with HSM-KEK enabled"
write_hsm_config "${KMS_PORT_VAL}" "${SQLITE_DIR}" "key_encryption_key = \"${KEK_ID}\""
kms_start_from_bin "${KMS_BIN}"
kms_write_ckms_conf "${KMS_URL}"
export CKMS_CONF="${KMS_CKMS_CONF}"
export COSMIAN_KMS_CLI_FORMAT=json

create_ec_keypair() {
  local curve="$1"
  local json
  json=$("${CKMS_BIN}" ec keys create --curve "${curve}" --tag pkcs11-tool-conformance)
  python3 -c '
import json, sys
d = json.loads(sys.argv[1])
print(d["private_key_unique_identifier"])
print(d["public_key_unique_identifier"])
' "${json}"
}

print_status "Creating EC P-256 keypair..."
mapfile -t p256_ids < <(create_ec_keypair nist-p256)
print_status "Creating EC secp256k1 keypair..."
mapfile -t secp256k1_ids < <(create_ec_keypair secp256k1)
print_status "Creating Ed25519 keypair..."
mapfile -t ed25519_ids < <(create_ec_keypair ed25519)

unset COSMIAN_KMS_CLI_FORMAT

# pkcs11-tool is mandatory for this conformance tier: it is the whole point of
# this test (an independently-implemented, non-Cosmian PKCS#11 v3 client
# exercising our provider's real C_Sign), so its absence or failure must be a
# hard error, not a silently-accepted fallback to our own `ckms` CLI.
require_cmd pkcs11-tool

# CKA_ID is the KMS unique identifier converted to UTF-8 (see
# crate/clients/pkcs11/module/src/traits/mod.rs). pkcs11-tool's `--id`
# expects a hex-encoded byte string, so hex-encode the UID here.
hex_id() {
  printf '%s' "$1" | od -An -tx1 | tr -d ' \n'
}

sign_and_verify() {
  local label="$1" priv_id="$2" pub_id="$3" mechanism="$4" digested="$5"
  local data_file="${WORK_DIR}/${label}-data.bin"
  local sig_file="${WORK_DIR}/${label}-sig.bin"
  echo -n "Conformance test data for ${label} ($(date +%s%N))" >"${data_file}"

  local sign_input="${data_file}"
  if [ "${digested}" = "true" ]; then
    sign_input="${WORK_DIR}/${label}-digest.bin"
    openssl dgst -sha256 -binary -out "${sign_input}" "${data_file}"
  fi

  print_status "[${label}] Signing via pkcs11-tool (mechanism=${mechanism})..."
  CKMS_CONF="${KMS_CKMS_CONF}" \
    pkcs11-tool \
    --module "${PKCS11_LIB}" \
    --login --login-type so \
    --sign \
    --id "$(hex_id "${priv_id}")" \
    --mechanism "${mechanism}" \
    --input-file "${sign_input}" \
    --output-file "${sig_file}"

  if [ ! -s "${sig_file}" ]; then
    print_error "[${label}] pkcs11-tool --sign produced no output"
    exit 1
  fi

  print_status "[${label}] Verifying signature via 'ckms ec sign-verify'..."
  local verify_input="${data_file}"
  local verify_flag=()
  if [ "${digested}" = "true" ]; then
    verify_input="${sign_input}"
    verify_flag=(--digested)
  fi
  "${CKMS_BIN}" ec sign-verify "${verify_input}" "${sig_file}" --key-id "${pub_id}" "${verify_flag[@]}"
  print_success "[${label}] Signature verified OK."
}

sign_and_verify "ecdsa-p256" "${p256_ids[0]}" "${p256_ids[1]}" "ECDSA" "true"
sign_and_verify "ecdsa-secp256k1" "${secp256k1_ids[0]}" "${secp256k1_ids[1]}" "ECDSA" "true"
sign_and_verify "eddsa-ed25519" "${ed25519_ids[0]}" "${ed25519_ids[1]}" "EDDSA" "false"

print_success "HSM-KEK PKCS#11 v3 conformance tests (EdDSA Ed25519, ECDSA P-256, ECDSA secp256k1) passed!"
