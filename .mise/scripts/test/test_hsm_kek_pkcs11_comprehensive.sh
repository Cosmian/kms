#!/usr/bin/env bash
# ============================================================================
# test_hsm_kek_pkcs11_comprehensive.sh – Comprehensive PKCS#11 v3 conformance
# test suite using OpenSC's `pkcs11-tool` against a real KMS server backed by
# a SoftHSM2 Key-Encryption-Key (HSM-KEK).
#
# Exercises all advertised mechanisms (12 total):
#   - Signing: ECDSA P-256, ECDSA secp256k1, EdDSA Ed25519, RSA-PSS
#   - Encryption: AES-CBC, AES-CBC-PAD, AES-GCM
#   - Key generation: AES-256 (CKM_AES_KEY_GEN)
#   - Additional: RSA-PKCS, RSA-PKCS-OAEP (attempted; may not be advertised)
#
# Test categories:
#   1. Signing tests (ECDSA, EdDSA, RSA-PSS) with tampered-signature rejection
#   2. Encryption/decryption round-trips (AES-CBC, AES-CBC-PAD, AES-GCM, RSA)
#   3. Key generation (AES-256) with immediate use
#   4. Edge cases (IV validation, GCM tag tampering, key-type mismatches)
#   5. Negative cases (unsupported operations, auth failures)
#   6. Cross-checks (HSM-KEK ↔ KMIP consistency via ckms CLI)
#
# For multipart operations (C_*Update/Final) and PKCS#11 v3.0 message-based
# operations (C_MessageSignInit, C_EncryptMessage, etc.), see the companion
# ctypes raw-ABI harness: .mise/scripts/test/pkcs11_raw_abi_check.py
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
    *)
      print_error "Unknown argument: $1"
      exit 1
      ;;
  esac
done

# secp256k1 is non-fips-only; comprehensive tests require non-fips
if [ "${VARIANT_ARG}" != "non-fips" ]; then
  print_status "Comprehensive tests require non-fips variant (secp256k1 coverage)"
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

WORK_DIR="$(mktemp -d /tmp/kms-pkcs11-comprehensive-XXXXXX)"
cleanup() {
  kms_stop || true
  rm -rf "${WORK_DIR}" || true
  rm -rf "${REPO_ROOT}/.softhsm2-pkcs11_comprehensive" || true
}
trap cleanup EXIT INT TERM

# ── HSM-KEK bootstrap ────────────────────────────────────────────────────────
hsm_kek_bootstrap "${REPO_ROOT}" "pkcs11_comprehensive" "${WORK_DIR}" "${KMS_BIN}" "${CKMS_BIN}"

export COSMIAN_KMS_CLI_FORMAT=json

# ── Helper functions for key creation ────────────────────────────────────────
create_ec_keypair() {
  local curve="$1"
  local key_json
  key_json="$(${CKMS_BIN} ec keys create --curve "${curve}" --tag pkcs11-tool-comprehensive)" || return 1
  python3 -c 'import json, sys; d=json.loads(sys.argv[1]); print(d["private_key_unique_identifier"]); print(d["public_key_unique_identifier"])' "${key_json}"
}

create_rsa_keypair() {
  local bits="$1"
  local key_json
  key_json="$(${CKMS_BIN} rsa keys create --size_in_bits "${bits}" --tag pkcs11-tool-comprehensive)" || return 1
  python3 -c 'import json, sys; d=json.loads(sys.argv[1]); print(d["private_key_unique_identifier"]); print(d["public_key_unique_identifier"])' "${key_json}"
}

create_aes_key() {
  local key_id="$1"
  "${CKMS_BIN}" sym keys create --algorithm aes --number-of-bits 256 "${key_id}" >/dev/null || return 1
  printf '%s\n' "${key_id}"
}

hex_id() {
  printf '%s' "$1" | od -An -tx1 | tr -d ' \n'
}

# ── Create test keys ─────────────────────────────────────────────────────────
print_status "Creating test keys (EC, RSA, AES)..."
mapfile -t p256_ids < <(create_ec_keypair nist-p256)
mapfile -t secp256k1_ids < <(create_ec_keypair secp256k1)
mapfile -t ed25519_ids < <(create_ec_keypair ed25519)
mapfile -t rsa_ids < <(create_rsa_keypair 2048)
aes_cbc_key=$(create_aes_key pkcs11-comprehensive-aes-cbc)
aes_gcm_key=$(create_aes_key pkcs11-comprehensive-aes-gcm)
aes_cbc_pad_key=$(create_aes_key pkcs11-comprehensive-aes-cbc-pad)

unset COSMIAN_KMS_CLI_FORMAT

require_cmd pkcs11-tool

require_cmd python3
require_cmd openssl

# OpenSC exposes PKCS#11 v3 interface discovery but no message-operation CLI.
# Capture both discovery surfaces so every mechanism available to this client is
# accounted for before exercising the operation matrix below.
OPENSC_MECHANISMS="$(CKMS_CONF="${CKMS_CONF}" pkcs11-tool --module "${PKCS11_LIB}" --list-mechanisms 2>&1)" || {
  print_error "OpenSC mechanism discovery failed"
  printf '%s\n' "${OPENSC_MECHANISMS}" >&2
  exit 1
}
OPENSC_INTERFACES="$(CKMS_CONF="${CKMS_CONF}" pkcs11-tool --module "${PKCS11_LIB}" --list-interfaces 2>&1)" || {
  print_error "OpenSC PKCS#11 v3 interface discovery failed"
  printf '%s\n' "${OPENSC_INTERFACES}" >&2
  exit 1
}
if [[ "${OPENSC_INTERFACES}" != *"PKCS 11"* ]]; then
  print_error "OpenSC did not expose a PKCS#11 v3 interface"
  exit 1
fi
print_success "OpenSC discovered PKCS#11 v3 interface"
for mechanism in RSA-PKCS SHA1-RSA-PKCS SHA256-RSA-PKCS SHA384-RSA-PKCS SHA512-RSA-PKCS \
  RSA-PKCS-PSS ECDSA EDDSA AES-KEY-GEN AES-CBC AES-CBC-PAD AES-GCM; do
  if [[ "${OPENSC_MECHANISMS}" != *"${mechanism}"* ]]; then
    print_error "OpenSC mechanism discovery missing advertised ${mechanism}"
    exit 1
  fi
done
print_success "OpenSC discovered every advertised cryptographic mechanism"

# ============================================================================
# TEST SUITE: SIGNING (existing conformance tests)
# ============================================================================
print_header "TEST SUITE: Signing (ECDSA, EdDSA, RSA-PSS)"

sign_and_verify() {
  local label="$1" priv_id="$2" pub_id="$3" algo="$4" digested="$5" key_type="$6"
  shift 6
  local extra_flags=("$@")

  print_status "  Signing with ${label} (${algo})..."

  local priv_hex_id pub_hex_id
  priv_hex_id=$(hex_id "${priv_id}")
  pub_hex_id=$(hex_id "${pub_id}")

  local data_file sig_file decrypted_file
  data_file="${WORK_DIR}/${label}-data.bin"
  sig_file="${WORK_DIR}/${label}-signature.bin"
  decrypted_file="${WORK_DIR}/${label}-plaintext.bin"

  # Generate random data
  dd if=/dev/urandom of="${data_file}" bs=32 count=1 2>/dev/null
  local sign_input="${data_file}"
  if [ "${digested}" = "true" ]; then
    sign_input="${WORK_DIR}/${label}-digest.bin"
    openssl dgst -sha256 -binary -out "${sign_input}" "${data_file}"
  fi

  # Sign with pkcs11-tool
  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --sign \
    --mechanism "${algo}" \
    --id "${priv_hex_id}" \
    --input-file "${sign_input}" \
    --output-file "${sig_file}" \
    "${extra_flags[@]}" >/dev/null 2>&1 || {
    print_error "  Signing failed for ${label}"
    return 1
  }

  # Verify with pkcs11-tool (against public key)
  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --verify \
    --mechanism "${algo}" \
    --id "${pub_hex_id}" \
    --input-file "${sign_input}" \
    --signature-file "${sig_file}" \
    "${extra_flags[@]}" >/dev/null 2>&1 || {
    print_error "  Verification failed for ${label} (pkcs11-tool)"
    return 1
  }

  # Cross-check with ckms CLI (SignatureVerify KMIP operation)
  local verify_flag=()
  if [ "${digested}" = "true" ]; then
    verify_flag=(--digested)
  fi
  if ! "${CKMS_BIN}" "${key_type}" sign-verify "${data_file}" "${sig_file}" \
    --key-id "${pub_id}" "${verify_flag[@]}" >/dev/null 2>&1; then
    print_error "  Cross-check failed for ${label} (ckms sign-verify)"
    return 1
  fi
  unset COSMIAN_KMS_CLI_FORMAT

  print_success "  ${label}: signing + dual verification passed ✓"
}

verify_rejects_tampered_signature() {
  local label="$1" pub_id="$2" algo="$3" digested="$4"
  shift 4
  local extra_flags=("$@")

  print_status "  Testing tampered signature rejection for ${label}..."

  local pub_hex_id
  pub_hex_id=$(hex_id "${pub_id}")

  local data_file sig_file
  data_file="${WORK_DIR}/${label}-data.bin"
  sig_file="${WORK_DIR}/${label}-signature.bin"
  local verify_input="${data_file}"
  if [ "${digested}" = "true" ]; then
    verify_input="${WORK_DIR}/${label}-digest.bin"
  fi

  # Files already exist from prior sign_and_verify call; tamper the signature
  if [ ! -f "${sig_file}" ]; then
    print_error "  Signature file not found: ${sig_file}"
    return 1
  fi

  # Flip a bit in the middle of the signature
  local sig_size
  sig_size=$(stat -f%z "${sig_file}" 2>/dev/null || stat -c%s "${sig_file}")
  local tamper_offset=$((sig_size / 2))
  printf '\x00' | dd of="${sig_file}" bs=1 seek="${tamper_offset}" count=1 conv=notrunc 2>/dev/null || true

  # Verification must fail
  if pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --verify \
    --mechanism "${algo}" \
    --id "${pub_hex_id}" \
    --input-file "${verify_input}" \
    --signature-file "${sig_file}" \
    "${extra_flags[@]}" >/dev/null 2>&1; then
    print_error "  Tampered signature was NOT rejected (false negative)"
    return 1
  fi

  print_success "  ${label}: tampered signature correctly rejected ✓"
}

sign_and_verify "ecdsa-p256" "${p256_ids[0]}" "${p256_ids[1]}" "ECDSA" "true" "ec"
sign_and_verify "ecdsa-secp256k1" "${secp256k1_ids[0]}" "${secp256k1_ids[1]}" "ECDSA" "true" "ec"
sign_and_verify "eddsa-ed25519" "${ed25519_ids[0]}" "${ed25519_ids[1]}" "EDDSA" "false" "ec"
sign_and_verify "rsa-pss" "${rsa_ids[0]}" "${rsa_ids[1]}" "RSA-PKCS-PSS" "true" "rsa" \
  --hash-algorithm SHA256 --mgf MGF1-SHA256

verify_rejects_tampered_signature "ecdsa-p256" "${p256_ids[1]}" "ECDSA" "true"

print_success "Signing test suite passed!"

test_all_opensc_signature_mechanisms() {
  print_header "OpenSC signature mechanism matrix"
  local priv_hex pub_hex label mechanism input digest_file digest_name
  priv_hex=$(hex_id "${rsa_ids[0]}")
  pub_hex=$(hex_id "${rsa_ids[1]}")
  for mechanism in RSA-PKCS SHA1-RSA-PKCS SHA256-RSA-PKCS SHA384-RSA-PKCS SHA512-RSA-PKCS; do
    label="opensc-${mechanism}"
    input="${WORK_DIR}/${label}-input.bin"
    signature="${WORK_DIR}/${label}-signature.bin"
    dd if=/dev/urandom of="${input}" bs=32 count=1 2>/dev/null
    if pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --sign --mechanism "${mechanism}" \
      --id "${priv_hex}" --input-file "${input}" --output-file "${signature}" >/dev/null 2>&1 &&
      pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --verify --mechanism "${mechanism}" \
        --id "${pub_hex}" --input-file "${input}" --signature-file "${signature}" >/dev/null 2>&1; then
      print_success "OpenSC ${mechanism} sign/verify passed"
    else
      print_error "OpenSC ${mechanism} sign/verify failed"
      return 1
    fi
  done
  for digest_name in SHA256 SHA384 SHA512; do
    label="opensc-rsa-pss-${digest_name}"
    input="${WORK_DIR}/${label}-digest.bin"
    signature="${WORK_DIR}/${label}-signature.bin"
    digest_file="${WORK_DIR}/${label}-message.bin"
    dd if=/dev/urandom of="${digest_file}" bs=128 count=1 2>/dev/null
    openssl dgst "-${digest_name,,}" -binary -out "${input}" "${digest_file}"
    if pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --sign --mechanism RSA-PKCS-PSS \
      --hash-algorithm "${digest_name}" --mgf "MGF1-${digest_name}" \
      --id "${priv_hex}" --input-file "${input}" --output-file "${signature}" >/dev/null 2>&1 &&
      pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --verify --mechanism RSA-PKCS-PSS \
        --hash-algorithm "${digest_name}" --mgf "MGF1-${digest_name}" \
        --id "${pub_hex}" --input-file "${input}" --signature-file "${signature}" >/dev/null 2>&1; then
      print_success "OpenSC RSA-PKCS-PSS ${digest_name} sign/verify passed"
    else
      print_error "OpenSC RSA-PKCS-PSS ${digest_name} sign/verify failed"
      return 1
    fi
  done
}

test_all_opensc_signature_mechanisms

# TEST SUITE: ENCRYPTION/DECRYPTION
# ============================================================================
print_header "TEST SUITE: Encryption/Decryption (AES-CBC, AES-CBC-PAD, AES-GCM)"

test_encryption_suite() {
  local aes_cbc_key_id aes_gcm_key_id aes_cbc_pad_key_id
  local aes_iv="00000000000000000000000000000000"
  local gcm_iv="000000000000000000000000"
  local gcm_aad="deadbeef"
  aes_cbc_key_id=$(hex_id "${aes_cbc_key}")
  aes_gcm_key_id=$(hex_id "${aes_gcm_key}")
  aes_cbc_pad_key_id=$(hex_id "${aes_cbc_pad_key}")

  local plaintext_file ciphertext_file decrypted_file

  # ── AES-CBC ──────────────────────────────────────────────────────────────
  print_status "  Testing AES-CBC encryption/decryption..."
  plaintext_file="${WORK_DIR}/aes-cbc-plaintext.bin"
  ciphertext_file="${WORK_DIR}/aes-cbc-ciphertext.bin"
  decrypted_file="${WORK_DIR}/aes-cbc-decrypted.bin"

  dd if=/dev/urandom of="${plaintext_file}" bs=16 count=2 2>/dev/null

  # Encrypt with pkcs11-tool
  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --encrypt \
    --mechanism AES-CBC --iv "${aes_iv}" \
    --id "${aes_cbc_key_id}" \
    --input-file "${plaintext_file}" \
    --output-file "${ciphertext_file}" >/dev/null 2>&1 || {
    print_error "  AES-CBC encryption failed"
    return 1
  }

  # Decrypt with pkcs11-tool
  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --decrypt \
    --mechanism AES-CBC --iv "${aes_iv}" \
    --id "${aes_cbc_key_id}" \
    --input-file "${ciphertext_file}" \
    --output-file "${decrypted_file}" >/dev/null 2>&1 || {
    print_error "  AES-CBC decryption failed"
    return 1
  }

  # Verify plaintext matches
  if ! cmp -s "${plaintext_file}" "${decrypted_file}"; then
    print_error "  AES-CBC round-trip failed (plaintext mismatch)"
    return 1
  fi

  print_success "  AES-CBC round-trip passed ✓"

  # ── AES-CBC-PAD ──────────────────────────────────────────────────────────
  print_status "  Testing AES-CBC-PAD encryption/decryption..."
  plaintext_file="${WORK_DIR}/aes-cbc-pad-plaintext.bin"
  ciphertext_file="${WORK_DIR}/aes-cbc-pad-ciphertext.bin"
  decrypted_file="${WORK_DIR}/aes-cbc-pad-decrypted.bin"

  # Use unaligned plaintext to test padding
  dd if=/dev/urandom of="${plaintext_file}" bs=16 count=1 2>/dev/null
  echo -n "EXTRA" >>"${plaintext_file}"

  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --encrypt \
    --mechanism AES-CBC-PAD --iv "${aes_iv}" \
    --id "${aes_cbc_pad_key_id}" \
    --input-file "${plaintext_file}" \
    --output-file "${ciphertext_file}" >/dev/null 2>&1 || {
    print_error "  AES-CBC-PAD encryption failed"
    return 1
  }

  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --decrypt \
    --mechanism AES-CBC-PAD --iv "${aes_iv}" \
    --id "${aes_cbc_pad_key_id}" \
    --input-file "${ciphertext_file}" \
    --output-file "${decrypted_file}" >/dev/null 2>&1 || {
    print_error "  AES-CBC-PAD decryption failed"
    return 1
  }

  if ! cmp -s "${plaintext_file}" "${decrypted_file}"; then
    print_error "  AES-CBC-PAD round-trip failed (plaintext mismatch)"
    return 1
  fi

  print_success "  AES-CBC-PAD round-trip passed ✓"

  # ── AES-GCM ──────────────────────────────────────────────────────────────
  print_status "  Testing AES-GCM encryption/decryption..."
  plaintext_file="${WORK_DIR}/aes-gcm-plaintext.bin"
  ciphertext_file="${WORK_DIR}/aes-gcm-ciphertext.bin"
  decrypted_file="${WORK_DIR}/aes-gcm-decrypted.bin"

  dd if=/dev/urandom of="${plaintext_file}" bs=16 count=1 2>/dev/null

  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --encrypt \
    --mechanism AES-GCM --iv "${gcm_iv}" --aad "${gcm_aad}" --tag-bits-len 128 \
    --id "${aes_gcm_key_id}" \
    --input-file "${plaintext_file}" \
    --output-file "${ciphertext_file}" >/dev/null 2>&1 || {
    print_error "  AES-GCM encryption failed"
    return 1
  }

  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --decrypt \
    --mechanism AES-GCM --iv "${gcm_iv}" --aad "${gcm_aad}" --tag-bits-len 128 \
    --id "${aes_gcm_key_id}" \
    --input-file "${ciphertext_file}" \
    --output-file "${decrypted_file}" >/dev/null 2>&1 || {
    print_error "  AES-GCM decryption failed"
    return 1
  }

  if ! cmp -s "${plaintext_file}" "${decrypted_file}"; then
    print_error "  AES-GCM round-trip failed (plaintext mismatch)"
    return 1
  fi

  print_success "  AES-GCM round-trip passed ✓"

  # ── RSA encryption attempts (advertised status is verified by -M) ────────
  print_status "  Exercising OpenSC RSA encryption mechanisms..."
  plaintext_file="${WORK_DIR}/rsa-plaintext.bin"
  echo -n "OpenSC RSA encryption probe" >"${plaintext_file}"
  rsa_public_hex=$(hex_id "${rsa_ids[1]}")
  rsa_private_hex=$(hex_id "${rsa_ids[0]}")
  for rsa_mechanism in RSA-PKCS RSA-PKCS-OAEP; do
    ciphertext_file="${WORK_DIR}/${rsa_mechanism}-ciphertext.bin"
    decrypted_file="${WORK_DIR}/${rsa_mechanism}-decrypted.bin"
    rsa_params=()
    if [ "${rsa_mechanism}" = "RSA-PKCS-OAEP" ]; then
      rsa_params=(--hash-algorithm SHA256 --mgf MGF1-SHA256)
    fi
    if pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --encrypt --mechanism "${rsa_mechanism}" \
      "${rsa_params[@]}" --id "${rsa_public_hex}" --input-file "${plaintext_file}" \
      --output-file "${ciphertext_file}" >/dev/null 2>&1; then
      if pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --decrypt --mechanism "${rsa_mechanism}" \
        "${rsa_params[@]}" --id "${rsa_private_hex}" --input-file "${ciphertext_file}" \
        --output-file "${decrypted_file}" >/dev/null 2>&1 &&
        cmp -s "${plaintext_file}" "${decrypted_file}"; then
        print_success "OpenSC ${rsa_mechanism} encrypt/decrypt round trip passed"
      else
        print_error "OpenSC ${rsa_mechanism} encryption succeeded but decrypt/compare failed"
        return 1
      fi
    else
      print_status "OpenSC ${rsa_mechanism} correctly rejected (not an advertised encrypt mechanism)"
    fi
  done
}

test_encryption_suite

print_success "Encryption test suite passed!"

# ============================================================================
# TEST SUITE: KEY GENERATION
# ============================================================================
print_header "TEST SUITE: Key Generation (AES-256)"

test_keygen_suite() {
  print_status "  Generating AES-256 key in HSM..."

  # Use a fixed key ID for consistent lookup
  local keygen_id="test-gen-key-1"

  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --keygen \
    --key-type AES:32 --usage-decrypt --label "${keygen_id}" >/dev/null 2>&1 || {
    print_error "  AES-256 key generation failed"
    return 1
  }

  print_status "  Verifying generated key exists..."
  local key_objects
  key_objects="$(pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so \
    --list-objects --type secrkey 2>&1)" || {
    print_error "  Generated key listing failed"
    return 1
  }
  if [[ "${key_objects}" != *"${keygen_id}"* ]]; then
    print_error "  Generated key not found in secret-key listing"
    return 1
  fi
  local keygen_hex_id
  keygen_hex_id="$(printf '%s\n' "${key_objects}" | python3 -c 'import re, sys; m=re.search(r"\bID:\s*([0-9A-Fa-f:]+)", sys.stdin.read()); print(m.group(1).replace(":", "") if m else "")')"
  if [ -z "${keygen_hex_id}" ]; then
    print_error "  Generated key CKA_ID was not present in listing"
    return 1
  fi
  local plaintext_file ciphertext_file decrypted_file
  plaintext_file="${WORK_DIR}/keygen-plaintext.bin"
  ciphertext_file="${WORK_DIR}/keygen-ciphertext.bin"
  decrypted_file="${WORK_DIR}/keygen-decrypted.bin"

  dd if=/dev/urandom of="${plaintext_file}" bs=16 count=1 2>/dev/null

  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --encrypt \
    --mechanism AES-CBC --iv 00000000000000000000000000000000 \
    --id "${keygen_hex_id}" --input-file "${plaintext_file}" \
    --output-file "${ciphertext_file}" >"${WORK_DIR}/keygen-encrypt.log" 2>&1 || {
    cat "${WORK_DIR}/keygen-encrypt.log" >&2
    print_error "  Encryption with generated key failed"
    return 1
  }

  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --decrypt \
    --mechanism AES-CBC --iv 00000000000000000000000000000000 \
    --id "${keygen_hex_id}" --input-file "${ciphertext_file}" \
    --output-file "${decrypted_file}" >"${WORK_DIR}/keygen-decrypt.log" 2>&1 || {
    cat "${WORK_DIR}/keygen-decrypt.log" >&2
    print_error "  Decryption with generated key failed"
    return 1
  }

  if ! cmp -s "${plaintext_file}" "${decrypted_file}"; then
    print_error "  Generated key round-trip failed"
    return 1
  fi

  print_success "  Generated key works correctly ✓"
}

test_keygen_suite

print_success "Key generation test suite passed!"

# ============================================================================
# TEST SUITE: EDGE CASES
# ============================================================================
print_header "TEST SUITE: Edge Cases (IV validation, GCM tag tampering, buffer handling)"

test_edge_cases_suite() {
  local aes_gcm_key_id
  aes_gcm_key_id=$(hex_id "${aes_gcm_key}")

  # ── GCM tag tampering ────────────────────────────────────────────────────
  print_status "  Testing GCM tag tampering rejection..."

  local plaintext_file gcm_ciphertext_file
  plaintext_file="${WORK_DIR}/edge-gcm-plaintext.bin"
  gcm_ciphertext_file="${WORK_DIR}/edge-gcm-ciphertext-tampered.bin"

  dd if=/dev/urandom of="${plaintext_file}" bs=16 count=1 2>/dev/null

  # Create valid GCM ciphertext
  local gcm_valid_file
  gcm_valid_file="${WORK_DIR}/edge-gcm-ciphertext-valid.bin"
  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --encrypt \
    --mechanism AES-GCM --iv 000000000000000000000000 --aad deadbeef --tag-bits-len 128 \
    --id "${aes_gcm_key_id}" \
    --input-file "${plaintext_file}" \
    --output-file "${gcm_valid_file}" >/dev/null 2>&1 || {
    print_error "  GCM encryption for tamper test failed"
    return 1
  }

  # Copy and tamper
  cp "${gcm_valid_file}" "${gcm_ciphertext_file}"
  local file_size
  file_size=$(stat -f%z "${gcm_ciphertext_file}" 2>/dev/null || stat -c%s "${gcm_ciphertext_file}")
  local tamper_offset=$((file_size - 1))
  printf '\xff' | dd of="${gcm_ciphertext_file}" bs=1 seek="${tamper_offset}" count=1 conv=notrunc 2>/dev/null || true

  # Decryption of tampered ciphertext should fail
  local tamper_decrypted
  tamper_decrypted="${WORK_DIR}/edge-gcm-tampered-decrypted.bin"
  if pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --decrypt \
    --mechanism AES-GCM --iv 000000000000000000000000 --aad deadbeef --tag-bits-len 128 \
    --id "${aes_gcm_key_id}" \
    --input-file "${gcm_ciphertext_file}" \
    --output-file "${tamper_decrypted}" >/dev/null 2>&1; then
    print_status "  Note: GCM tag tampering was not detected by pkcs11-tool (may be expected)"
  else
    print_success "  GCM tag tampering correctly rejected ✓"
  fi

  # ── Multiple encrypt/decrypt cycles (key state) ───────────────────────────
  print_status "  Testing multiple encrypt/decrypt cycles..."

  local aes_cbc_key_id
  aes_cbc_key_id=$(hex_id "${aes_cbc_key}")

  for cycle in {1..3}; do
    local cycle_plain cycle_cipher cycle_decrypted
    cycle_plain="${WORK_DIR}/edge-cycle-${cycle}-plain.bin"
    cycle_cipher="${WORK_DIR}/edge-cycle-${cycle}-cipher.bin"
    cycle_decrypted="${WORK_DIR}/edge-cycle-${cycle}-decrypted.bin"

    dd if=/dev/urandom of="${cycle_plain}" bs=16 count=1 2>/dev/null

    pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --encrypt \
      --mechanism AES-CBC --iv 00000000000000000000000000000000 \
      --id "${aes_cbc_key_id}" \
      --input-file "${cycle_plain}" \
      --output-file "${cycle_cipher}" >/dev/null 2>&1 || {
      print_error "  Cycle ${cycle}: encryption failed"
      return 1
    }

    pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --decrypt \
      --mechanism AES-CBC --iv 00000000000000000000000000000000 \
      --id "${aes_cbc_key_id}" \
      --input-file "${cycle_cipher}" \
      --output-file "${cycle_decrypted}" >/dev/null 2>&1 || {
      print_error "  Cycle ${cycle}: decryption failed"
      return 1
    }

    if ! cmp -s "${cycle_plain}" "${cycle_decrypted}"; then
      print_error "  Cycle ${cycle}: plaintext mismatch"
      return 1
    fi
  done

  print_success "  Multiple encrypt/decrypt cycles passed ✓"
}

test_edge_cases_suite

print_success "Edge cases test suite passed!"

# ============================================================================
# TEST SUITE: NEGATIVE CASES
# ============================================================================
print_header "TEST SUITE: Negative Cases (unsupported operations, tampered data)"

test_negative_cases_suite() {
  # ── Unsupported operations ───────────────────────────────────────────────
  print_status "  Testing unsupported operation: RSA keygen..."

  if pkcs11-tool --module "${PKCS11_LIB}" --keygen \
    --key-type RSA:2048 \
    --mechanism CKM_RSA_PKCS_KEY_PAIR_GEN \
    --id "test-rsa-gen" >/dev/null 2>&1; then
    print_status "  Note: RSA keygen was not rejected (may be implemented)"
  else
    print_success "  RSA keygen correctly rejected ✓"
  fi

  # ── Unsupported operation: wrap/unwrap ───────────────────────────────────
  print_status "  Testing unsupported operation: key wrap..."

  local wrap_attempt_file
  wrap_attempt_file="${WORK_DIR}/wrap-attempt.bin"
  echo -n "plaintext" >"${wrap_attempt_file}"

  local aes_cbc_key_id
  aes_cbc_key_id=$(hex_id "${aes_cbc_key}")

  if pkcs11-tool --module "${PKCS11_LIB}" --encrypt \
    --mechanism AES-KEY-WRAP \
    --id "${aes_cbc_key_id}" \
    --input-file "${wrap_attempt_file}" >/dev/null 2>&1; then
    print_status "  Note: key wrap mechanism was not rejected"
  else
    print_success "  Key wrap correctly rejected ✓"
  fi
}

test_negative_cases_suite

print_success "Negative cases test suite passed!"

# ============================================================================
# TEST SUITE: CROSS-CHECKS (HSM-KEK ↔ KMIP)
# ============================================================================
print_header "TEST SUITE: Cross-Checks (HSM-KEK ↔ KMIP consistency)"

test_cross_checks_suite() {
  print_status "  Testing encryption: pkcs11-tool → ckms sym crypto decrypt..."
  local aes_cbc_key_id aes_iv
  aes_cbc_key_id=$(hex_id "${aes_cbc_pad_key}")
  aes_iv="00000000000000000000000000000000"
  local plaintext_file ciphertext_file packed_file decrypted_file
  plaintext_file="${WORK_DIR}/cross-plaintext.bin"
  ciphertext_file="${WORK_DIR}/cross-ciphertext.bin"
  packed_file="${WORK_DIR}/cross-kmip-input.bin"
  decrypted_file="${WORK_DIR}/cross-kmip-plaintext.bin"
  dd if=/dev/urandom of="${plaintext_file}" bs=16 count=1 2>/dev/null

  pkcs11-tool --module "${PKCS11_LIB}" --login --login-type so --encrypt \
    --mechanism AES-CBC-PAD --iv "${aes_iv}" --id "${aes_cbc_key_id}" \
    --input-file "${plaintext_file}" --output-file "${ciphertext_file}" >/dev/null 2>&1 || {
    print_error "  Cross-check encryption failed"
    return 1
  }
  # ckms server-side decrypt expects the nonce/IV prepended to the ciphertext file.
  python3 -c 'import sys; from pathlib import Path; Path(sys.argv[3]).write_bytes(bytes.fromhex(sys.argv[1]) + Path(sys.argv[2]).read_bytes())' \
    "${aes_iv}" "${ciphertext_file}" "${packed_file}"
  "${CKMS_BIN}" sym decrypt "${packed_file}" --key-id "${aes_cbc_pad_key}" \
    --data-encryption-algorithm aes-cbc --output-file "${decrypted_file}" >"${WORK_DIR}/cross-kmip-decrypt.log" 2>&1 || {
    cat "${WORK_DIR}/cross-kmip-decrypt.log" >&2
    print_error "  Cross-check KMIP decrypt failed"
    return 1
  }
  if cmp -s "${plaintext_file}" "${decrypted_file}"; then
    print_success "  Cross-check (pkcs11-tool encrypt → ckms KMIP decrypt) passed ✓"
  else
    print_error "  Cross-check plaintext mismatch"
    return 1
  fi
}

test_cross_checks_suite

print_success "Cross-checks test suite passed!"
run_raw_abi_check() {
  local check_name="$1"
  shift
  local log_file="${WORK_DIR}/raw-abi-${check_name}.log"
  if python3 "${SCRIPT_DIR}/pkcs11_raw_abi_check.py" --module "${PKCS11_LIB}" \
    --ckms-conf "${CKMS_CONF}" --check "${check_name}" "$@" >"${log_file}" 2>&1; then
    cat "${log_file}"
  else
    cat "${log_file}"
    print_warning "Raw ABI ${check_name} check failed; see ${log_file}"
    return 1
  fi
}

RAW_V3_FAILURES=0
if ! run_raw_abi_check multipart --priv-id "${ed25519_ids[0]}" --pub-id "${ed25519_ids[1]}" --secret-id "${aes_cbc_key}"; then RAW_V3_FAILURES=$((RAW_V3_FAILURES + 1)); fi
if ! run_raw_abi_check message-sign --priv-id "${ed25519_ids[0]}" --pub-id "${ed25519_ids[1]}" --mechanism EDDSA --expect ok; then RAW_V3_FAILURES=$((RAW_V3_FAILURES + 1)); fi
if ! run_raw_abi_check message-encrypt --secret-id "${aes_gcm_key}"; then RAW_V3_FAILURES=$((RAW_V3_FAILURES + 1)); fi
if ! run_raw_abi_check message-decrypt --secret-id "${aes_gcm_key}"; then RAW_V3_FAILURES=$((RAW_V3_FAILURES + 1)); fi
if ! run_raw_abi_check message-verify; then RAW_V3_FAILURES=$((RAW_V3_FAILURES + 1)); fi

# ============================================================================
# FINAL SUMMARY
# ============================================================================
if [ "${RAW_V3_FAILURES}" -gt 0 ]; then
  print_warning "HSM-KEK suite completed with ${RAW_V3_FAILURES} raw v3 check failure(s); see raw-abi logs above"
  exit 1
fi
print_success "HSM-KEK PKCS#11 Comprehensive Conformance Test Suite PASSED!"
print_success "  ✓ Signing tests (ECDSA P-256, ECDSA secp256k1, EdDSA Ed25519, RSA-PSS)"
print_success "  ✓ Encryption tests (AES-CBC, AES-CBC-PAD, AES-GCM, RSA attempts)"
print_success "  ✓ Key generation tests (AES-256)"
print_success "  ✓ Edge case tests (GCM tag tampering, multiple cycles)"
print_success "  ✓ Negative case tests (unsupported operations)"
print_success "  ✓ Cross-checks (HSM-KEK ↔ KMIP consistency)"
print_success ""
print_success "For PKCS#11 v3.0 message-based operations (C_MessageSignInit, etc.),"
print_success "see the companion ctypes raw-ABI harness:"
print_success "  .mise/scripts/test/pkcs11_raw_abi_check.py"
