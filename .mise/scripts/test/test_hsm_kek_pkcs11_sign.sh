#!/usr/bin/env bash
# ============================================================================
# test_hsm_kek_pkcs11_sign.sh – External PKCS#11 v3 conformance test using
# OpenSC's `pkcs11-tool` against a real KMS server backed by a SoftHSM2
# Key-Encryption-Key (HSM-KEK).
#
# This complements the in-process Rust tests in
# crate/clients/pkcs11/provider/src/tests_v3.rs (tests_v3::test_hsm_kek_*),
# which exercise the same signing requests (EdDSA Ed25519, ECDSA P-256, ECDSA
# secp256k1, RSA-PSS) through our own `CliBackend::remote_sign`/`remote_verify`
# code paths. Here the *same* requests are issued by `pkcs11-tool`, an
# independently-implemented, non-Cosmian PKCS#11 v3 client, closing the "we
# only tested our own client" gap:
#
#   pkcs11-tool --module libcosmian_pkcs11 --sign    (real PKCS#11 v3 C_Sign call)
#   pkcs11-tool --module libcosmian_pkcs11 --verify   (real PKCS#11 v3 C_Verify call)
#     -> cosmian_pkcs11 module                        (our provider)
#       -> KMS server Sign/SignatureVerify operations  (HSM-KEK wrapped key)
#
# Each signature is verified twice:
#   1. `pkcs11-tool --verify` (real PKCS#11 v3 C_Verify call, against the
#      *public* key object) — the KMS's own C_Verify implementation, exercised
#      by the same independent, non-Cosmian client used for signing
#   2. `ckms ec sign-verify`/`ckms rsa sign-verify` (the KMS's SignatureVerify
#      KMIP operation) — a second, independent cryptographic correctness check
#
# In addition, one curve (P-256) is used for a negative case: a tampered
# signature must be rejected by `pkcs11-tool --verify` (mapped from the
# module's real `CKR_SIGNATURE_INVALID`), proving the external client can tell
# "verification failed" apart from "operation error" — the distinction that
# motivated implementing real `C_Verify` in the first place.
#
# `pkcs11-tool` is a hard requirement for this conformance tier: there is no
# graceful fallback to `ckms` if it is missing (see `require_cmd pkcs11-tool`
# below) — a missing `pkcs11-tool` is a hard error, not a silently-skipped
# test.
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

# ── Build server, CLI, and PKCS#11 provider ─────────────────────────────────
print_header "Building KMS server, ckms CLI, and cosmian_pkcs11 provider"
kms_build_all
KMS_BIN="$(get_kms_bin)"
CKMS_BIN="$(get_ckms_bin)"
PKCS11_LIB="$(get_cosmian_pkcs11_lib)"

WORK_DIR="$(mktemp -d /tmp/kms-pkcs11-tool-sign-XXXXXX)"
cleanup() {
  kms_stop
  rm -rf "${WORK_DIR}"
  [ -n "${SOFTHSM2_HOME:-}" ] && rm -rf "${SOFTHSM2_HOME}"
}
trap cleanup EXIT INT TERM

# ── HSM-KEK bootstrap (SoftHSM2 token + AES-256 KEK + KMS server restart) ───
hsm_kek_bootstrap "${REPO_ROOT}" "pkcs11_tool_sign" "${WORK_DIR}" "${KMS_BIN}" "${CKMS_BIN}"

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

create_rsa_keypair() {
  local size_in_bits="$1"
  local json
  json=$("${CKMS_BIN}" rsa keys create --size_in_bits "${size_in_bits}" --tag pkcs11-tool-conformance)
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
print_status "Creating RSA-2048 keypair..."
mapfile -t rsa_ids < <(create_rsa_keypair 2048)

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
  local label="$1" priv_id="$2" pub_id="$3" mechanism="$4" digested="$5" keytype="$6"
  shift 6
  local extra_args=("$@")
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
    "${extra_args[@]}" \
    --input-file "${sign_input}" \
    --output-file "${sig_file}"

  if [ ! -s "${sig_file}" ]; then
    print_error "[${label}] pkcs11-tool --sign produced no output"
    exit 1
  fi

  print_status "[${label}] Verifying signature via pkcs11-tool --verify (real C_Verify call)..."
  CKMS_CONF="${KMS_CKMS_CONF}" \
    pkcs11-tool \
    --module "${PKCS11_LIB}" \
    --login --login-type so \
    --verify \
    --id "$(hex_id "${pub_id}")" \
    --mechanism "${mechanism}" \
    "${extra_args[@]}" \
    --input-file "${sign_input}" \
    --signature-file "${sig_file}"
  print_success "[${label}] pkcs11-tool --verify succeeded (C_Verify accepted the signature)."

  print_status "[${label}] Verifying signature via 'ckms ${keytype} sign-verify'..."
  local verify_input="${data_file}"
  local verify_flag=()
  if [ "${digested}" = "true" ]; then
    verify_input="${sign_input}"
    verify_flag=(--digested)
  fi
  "${CKMS_BIN}" "${keytype}" sign-verify "${verify_input}" "${sig_file}" --key-id "${pub_id}" "${verify_flag[@]}"
  print_success "[${label}] Signature verified OK."
}

# MANDATORY negative case: a tampered signature must be rejected by the real,
# external `pkcs11-tool --verify` call (mapped from the module's
# `CKR_SIGNATURE_INVALID`), not silently accepted or reported as a generic
# operation error. Reuses the data/signature files already produced by a prior
# `sign_and_verify` call for `label`.
verify_rejects_tampered_signature() {
  local label="$1" pub_id="$2" mechanism="$3" digested="$4"
  shift 4
  local extra_args=("$@")
  local data_file="${WORK_DIR}/${label}-data.bin"
  local sig_file="${WORK_DIR}/${label}-sig.bin"
  local tampered_sig_file="${WORK_DIR}/${label}-sig-tampered.bin"

  local sign_input="${data_file}"
  if [ "${digested}" = "true" ]; then
    sign_input="${WORK_DIR}/${label}-digest.bin"
  fi

  # Flip the last byte of an otherwise-valid signature: well-formed (same
  # length/encoding), but cryptographically wrong.
  python3 -c '
import sys
path = sys.argv[1]
out = sys.argv[2]
with open(path, "rb") as f:
    data = bytearray(f.read())
data[-1] ^= 0xFF
with open(out, "wb") as f:
    f.write(data)
' "${sig_file}" "${tampered_sig_file}"

  print_status "[${label}] Verifying a tampered signature is rejected (pkcs11-tool --verify)..."
  local verify_out
  if verify_out=$(CKMS_CONF="${KMS_CKMS_CONF}" pkcs11-tool \
    --module "${PKCS11_LIB}" \
    --login --login-type so \
    --verify \
    --id "$(hex_id "${pub_id}")" \
    --mechanism "${mechanism}" \
    "${extra_args[@]}" \
    --input-file "${sign_input}" \
    --signature-file "${tampered_sig_file}" 2>&1); then
    print_error "[${label}] pkcs11-tool --verify incorrectly ACCEPTED a tampered signature"
    echo "${verify_out}"
    exit 1
  fi
  print_success "[${label}] pkcs11-tool --verify correctly rejected the tampered signature (CKR_SIGNATURE_INVALID)."
}

sign_and_verify "ecdsa-p256" "${p256_ids[0]}" "${p256_ids[1]}" "ECDSA" "true" "ec"
sign_and_verify "ecdsa-secp256k1" "${secp256k1_ids[0]}" "${secp256k1_ids[1]}" "ECDSA" "true" "ec"
sign_and_verify "eddsa-ed25519" "${ed25519_ids[0]}" "${ed25519_ids[1]}" "EDDSA" "false" "ec"
# Deliberately no explicit --salt-len: passing it makes pkcs11-tool look up the
# RSA modulus length via the *public* key sharing the private key's CKA_ID
# (see OpenSC pkcs11-tool.c get_private_key_length()), which fails here since
# the KMS assigns distinct unique identifiers (mapped to CKA_ID) to the
# private and public key objects of a pair. Omitting it uses pkcs11-tool's
# default salt length (= digest length = 32 bytes for SHA-256), which is
# exactly the salt length already exercised by the in-process
# `test_hsm_kek_rsa_pss_sign` test, so coverage is unaffected.
sign_and_verify "rsa-pss" "${rsa_ids[0]}" "${rsa_ids[1]}" "RSA-PKCS-PSS" "true" "rsa" \
  --hash-algorithm SHA256 --mgf MGF1-SHA256

verify_rejects_tampered_signature "ecdsa-p256" "${p256_ids[1]}" "ECDSA" "true"

print_success "HSM-KEK PKCS#11 v3 conformance tests (EdDSA Ed25519, ECDSA P-256, ECDSA secp256k1, RSA-PSS, tampered-signature rejection) passed!"
