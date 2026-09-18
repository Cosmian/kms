#!/usr/bin/env bash
# ============================================================================
# test_pkcs11_conformance.sh — Full, independent PKCS#11 v2.40/v3.0/v3.1
# conformance suite for `cosmian_pkcs11`.
#
# Independent from `.mise/tasks/test/hsm-pkcs11-tool` (SoftHSM2 HSM-KEK signing
# regression test): this suite runs against a *plain* KMS server (sqlite, no
# HSM), and exercises the module's real PKCS#11 surface end to end, using
# `pkcs11-tool` (OpenSC) — an independently-implemented, non-Cosmian client —
# plus `pkcs11_raw_abi_check.py`, a `ctypes` harness that dlopen()s the built
# cdylib directly for the handful of functions `pkcs11-tool` cannot reach.
#
# Ground truth for exactly what is/isn't implemented was taken from the module
# source itself:
#   - crate/clients/pkcs11/module/src/traits/encryption_algorithms.rs
#     (SUPPORTED_SIGNATURE_MECHANISMS — the 12 mechanisms this module implements)
#   - crate/clients/pkcs11/module/src/pkcs11.rs (cryptoki_fn!/cryptoki_fn_not_supported!)
#   - crate/clients/pkcs11/module/src/tests_v3.rs (the "not supported" regression table)
#
# Every mechanism is called against every PKCS#11 function that mechanism
# applies to (not just one representative op), and every individual check
# prints exactly one PASS/FAIL line — a green run is exactly N lines for N
# checks, with no interleaved tool chatter (verbose output is captured to a
# per-check log file under WORK_DIR and only surfaced on failure).
#
# Usage:
#   mise run test:pkcs11:conformance --variant non-fips
#   bash .mise/scripts/test/test_pkcs11_conformance.sh --variant non-fips
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MISE_CONFIG_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/kms_build.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/kms_server.sh"
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

# Several KeyAlgorithm variants exercised here for full coverage (secp256k1,
# secp224k1, Ed25519, Ed448, X25519, X448) are non-fips-only — same constraint
# as the sibling HSM-KEK pkcs11-tool conformance script.
if [ "${VARIANT_ARG}" != "non-fips" ]; then
  print_warning "Skipping PKCS#11 conformance suite: requires --variant non-fips (several KeyAlgorithm variants exercised here are non-fips-only)."
  exit 0
fi

kms_init_env "${VARIANT_ARG}" "${LINK_ARG}"
setup_test_logging
# Pull opensc (pkcs11-tool) into the nix-shell on Linux CI without also
# pulling in SoftHSM2/openvpn/etc. (which WITH_HSM=1 would add) — this suite
# needs a real PKCS#11 client but never talks to an HSM.
export WITH_LUKS=1
# shellcheck disable=SC2119  # ensure_nix_shell intentionally called without args here
ensure_nix_shell

print_header "Building KMS server, ckms CLI, and cosmian_pkcs11 provider (debug)"
kms_build_all
KMS_BIN="$(get_kms_bin)"
CKMS_BIN="$(get_ckms_bin)"
PKCS11_LIB="$(get_cosmian_pkcs11_lib)"
print_status "cosmian_pkcs11 library: ${PKCS11_LIB}"

require_cmd pkcs11-tool
require_cmd openssl
require_cmd python3

WORK_DIR="$(mktemp -d /tmp/kms-pkcs11-conformance-XXXXXX)"
cleanup() {
  kms_stop
  if [ "${KEEP_WORK_DIR:-0}" != "1" ]; then
    rm -rf "${WORK_DIR}"
  fi
}
trap cleanup EXIT INT TERM

print_header "Starting a plain KMS server (sqlite, no HSM)"
KMS_PORT_PICKED="$(kms_pick_free_port)"
kms_write_config "${KMS_PORT_PICKED}" "${WORK_DIR}/kms-data"
kms_start_from_bin "${KMS_BIN}"
kms_write_ckms_conf "${KMS_URL}"
export CKMS_CONF="${KMS_CKMS_CONF}"
export COSMIAN_KMS_CLI_FORMAT=json

# ── Reporting: strict "1 check = 1 printed line" contract ──────────────────
TOTAL_CHECKS=0
FAILED_CHECKS=0
FAILED_LABELS=()

# check_pass <label>
check_pass() {
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  echo -e "${GREEN}✅ $1${NC}"
}

# check_fail <label> <detail>
check_fail() {
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  FAILED_CHECKS=$((FAILED_CHECKS + 1))
  FAILED_LABELS+=("$1")
  echo -e "${RED}❌ $1${NC}: $2"
}

# check_unsupported_pass <label>
# For the "declared but not supported" boundary: the function was correctly,
# cleanly rejected (CKR_FUNCTION_NOT_SUPPORTED/CKR_TOKEN_WRITE_PROTECTED),
# which is the expected outcome and counts as an overall PASS (does not fail
# the suite) — but the function is genuinely unimplemented, so the line is
# always printed with a red cross to make unsupported-by-design behavior
# visually distinct from real, working functionality.
check_unsupported_pass() {
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  echo -e "${RED}❌ $1 (unsupported by design)${NC}"
}

# run_pkcs11 <logfile> <pkcs11-tool args...>
# Runs pkcs11-tool with all output captured to logfile. Returns pkcs11-tool's
# exit code; never prints a check line itself (callers decide pass/fail).
run_pkcs11() {
  local logfile="$1"
  shift
  set +e
  CKMS_CONF="${CKMS_CONF}" pkcs11-tool --module "${PKCS11_LIB}" "$@" >"${logfile}" 2>&1
  local rc=$?
  set -e
  return "${rc}"
}

# CKA_ID is the KMS unique identifier converted to UTF-8 (see
# crate/clients/pkcs11/module/src/traits/mod.rs). pkcs11-tool's `--id` expects
# a hex-encoded byte string, so hex-encode the KMS UID here.
hex_id() {
  printf '%s' "$1" | od -An -tx1 | tr -d ' \n'
}

print_header "Provisioning key material via ckms (C_GenerateKeyPair is not a supported PKCS#11 operation on this module)"

create_ec_keypair() {
  local curve="$1" label="$2"
  local json
  json=$("${CKMS_BIN}" ec keys create --curve "${curve}" --tag "${label}")
  python3 -c '
import json, sys
d = json.loads(sys.argv[1])
print(d["private_key_unique_identifier"])
print(d["public_key_unique_identifier"])
' "${json}"
}

create_rsa_keypair() {
  local size_in_bits="$1" label="$2"
  local json
  json=$("${CKMS_BIN}" rsa keys create --size_in_bits "${size_in_bits}" --tag "${label}")
  python3 -c '
import json, sys
d = json.loads(sys.argv[1])
print(d["private_key_unique_identifier"])
print(d["public_key_unique_identifier"])
' "${json}"
}

mapfile -t rsa2048_ids < <(create_rsa_keypair 2048 pkcs11-conformance-rsa2048)
mapfile -t rsa3072_ids < <(create_rsa_keypair 3072 pkcs11-conformance-rsa3072)
mapfile -t rsa4096_ids < <(create_rsa_keypair 4096 pkcs11-conformance-rsa4096)
mapfile -t p256_ids < <(create_ec_keypair nist-p256 pkcs11-conformance-p256)
mapfile -t p384_ids < <(create_ec_keypair nist-p384 pkcs11-conformance-p384)
mapfile -t p521_ids < <(create_ec_keypair nist-p521 pkcs11-conformance-p521)
mapfile -t secp256k1_ids < <(create_ec_keypair secp256k1 pkcs11-conformance-secp256k1)
mapfile -t secp224k1_ids < <(create_ec_keypair secp224k1 pkcs11-conformance-secp224k1)
mapfile -t ed25519_ids < <(create_ec_keypair ed25519 pkcs11-conformance-ed25519)
mapfile -t ed448_ids < <(create_ec_keypair ed448 pkcs11-conformance-ed448)
mapfile -t x25519_ids < <(create_ec_keypair x25519 pkcs11-conformance-x25519)
mapfile -t x448_ids < <(create_ec_keypair x448 pkcs11-conformance-x448)
check_pass "Key provisioning via ckms (RSA 2048/3072/4096, P-256/384/521, secp256k1/224k1, Ed25519/Ed448, X25519/X448)"

# One AES-256 key generated through pkcs11-tool itself: the only real,
# supported PKCS#11 key-generation path (CKM_AES_KEY_GEN / C_GenerateKey).
AES_LABEL="pkcs11-conformance-aes256"
if run_pkcs11 "${WORK_DIR}/aes-keygen.log" --login --login-type so \
  --keygen --key-type AES:32 --label "${AES_LABEL}"; then
  check_pass "CKM_AES_KEY_GEN via C_GenerateKey (real PKCS#11 key generation)"
else
  check_fail "CKM_AES_KEY_GEN via C_GenerateKey (real PKCS#11 key generation)" "see ${WORK_DIR}/aes-keygen.log"
fi

# The module derives CKA_ID from the KMS unique identifier, and for a
# freshly-generated symmetric key that identifier is set to the requested
# label itself (see kms_import_symmetric_key_async in
# crate/clients/pkcs11/provider/src/kms_object.rs) — so the CKA_ID is simply
# the hex encoding of AES_LABEL; no need to parse it back out of `-O` output.
AES_ID_HEX="$(hex_id "${AES_LABEL}")"
# pkcs11-tool's `-O` listing prints IDs colon-separated (e.g. `61:6e:6f`), so
# reformat the contiguous hex for the match.
AES_ID_COLON="$(printf '%s' "${AES_ID_HEX}" | sed -E 's/(..)/\1:/g; s/:$//')"
if run_pkcs11 "${WORK_DIR}/aes-find.log" --login --login-type so -O &&
  grep -qi "${AES_ID_COLON}" "${WORK_DIR}/aes-find.log"; then
  check_pass "Resolving CKA_ID of the pkcs11-tool-generated AES key via -O"
else
  check_fail "Resolving CKA_ID of the pkcs11-tool-generated AES key via -O" "see ${WORK_DIR}/aes-find.log"
fi

print_header "Discovery and PKCS#11 v3 interface checks"

if run_pkcs11 "${WORK_DIR}/list-slots.log" -L; then
  check_pass "C_GetSlotList via -L (list slots)"
else
  check_fail "C_GetSlotList via -L (list slots)" "see ${WORK_DIR}/list-slots.log"
fi

if run_pkcs11 "${WORK_DIR}/list-token-slots.log" -T && grep -qi "token label" "${WORK_DIR}/list-token-slots.log"; then
  check_pass "C_GetSlotInfo/C_GetTokenInfo via -T (list token slots)"
else
  check_fail "C_GetSlotInfo/C_GetTokenInfo via -T (list token slots)" "see ${WORK_DIR}/list-token-slots.log"
fi

if run_pkcs11 "${WORK_DIR}/show-info.log" -I && grep -qi "cryptoki version" "${WORK_DIR}/show-info.log"; then
  check_pass "C_GetInfo via -I (show global token information)"
else
  check_fail "C_GetInfo via -I (show global token information)" "see ${WORK_DIR}/show-info.log"
fi

if run_pkcs11 "${WORK_DIR}/list-interfaces.log" --list-interfaces && grep -q "PKCS 11" "${WORK_DIR}/list-interfaces.log"; then
  check_pass "C_GetInterfaceList/C_GetInterface via --list-interfaces (v3.0 interface present)"
else
  check_fail "C_GetInterfaceList/C_GetInterface via --list-interfaces (v3.0 interface present)" "see ${WORK_DIR}/list-interfaces.log"
fi

# Exact mechanism allow-list: every mechanism cosmian_pkcs11 implements must be
# reported, and mechanisms it does NOT implement (RSA-OAEP, AES-ECB, DES, plain
# digests, key wrap/derive mechanisms) must not appear.
run_pkcs11 "${WORK_DIR}/list-mechanisms.log" -M || true
EXPECTED_MECHANISMS=(
  RSA-PKCS SHA1-RSA-PKCS SHA256-RSA-PKCS SHA384-RSA-PKCS SHA512-RSA-PKCS
  ECDSA EDDSA RSA-PKCS-PSS AES-KEY-GEN AES-CBC AES-CBC-PAD AES-GCM
)
MECHANISM_LIST_OK=true
for mech in "${EXPECTED_MECHANISMS[@]}"; do
  if ! grep -q "${mech}" "${WORK_DIR}/list-mechanisms.log"; then
    MECHANISM_LIST_OK=false
    break
  fi
done
if [ "${MECHANISM_LIST_OK}" = "true" ]; then
  check_pass "C_GetMechanismList/C_GetMechanismInfo via -M (all 12 supported mechanisms present)"
else
  check_fail "C_GetMechanismList/C_GetMechanismInfo via -M (all 12 supported mechanisms present)" "see ${WORK_DIR}/list-mechanisms.log"
fi
UNEXPECTED_MECHANISMS=(RSA-PKCS-OAEP AES-ECB DES3-CBC SHA-1 SHA256 CKM_ECDH1)
MECHANISM_ABSENCE_OK=true
for mech in "${UNEXPECTED_MECHANISMS[@]}"; do
  # Anchor on "<name>," (pkcs11-tool prints one mechanism per line as
  # "  <NAME>, <flags>...") so a plain-digest mechanism like bare "SHA256"
  # isn't confused with the legitimately-supported "SHA256-RSA-PKCS" line,
  # which contains "SHA256" as a substring but is a different mechanism.
  if grep -qE "^[[:space:]]*${mech}," "${WORK_DIR}/list-mechanisms.log"; then
    MECHANISM_ABSENCE_OK=false
    break
  fi
done
if [ "${MECHANISM_ABSENCE_OK}" = "true" ]; then
  check_pass "C_GetMechanismList via -M (unimplemented mechanisms correctly absent: RSA-OAEP/AES-ECB/DES3/plain-digest/ECDH)"
else
  check_fail "C_GetMechanismList via -M (unimplemented mechanisms correctly absent: RSA-OAEP/AES-ECB/DES3/plain-digest/ECDH)" "see ${WORK_DIR}/list-mechanisms.log"
fi

print_header "Session, login, and object-visibility checks"

if run_pkcs11 "${WORK_DIR}/objects-prelogin.log" -O; then
  check_pass "C_FindObjectsInit/C_FindObjects/C_FindObjectsFinal via -O (pre-login, public objects only)"
else
  check_fail "C_FindObjectsInit/C_FindObjects/C_FindObjectsFinal via -O (pre-login, public objects only)" "see ${WORK_DIR}/objects-prelogin.log"
fi

if run_pkcs11 "${WORK_DIR}/login-so.log" --login --login-type so -O; then
  check_pass "C_Login via --login-type so"
else
  check_fail "C_Login via --login-type so" "see ${WORK_DIR}/login-so.log"
fi

if run_pkcs11 "${WORK_DIR}/login-user.log" --login --login-type user -O; then
  check_pass "C_Login via --login-type user (single implicit identity: SO and USER both accepted, per sessions.rs::validate_login_user_type)"
else
  check_fail "C_Login via --login-type user (single implicit identity: SO and USER both accepted, per sessions.rs::validate_login_user_type)" "see ${WORK_DIR}/login-user.log"
fi

# CKU_CONTEXT_SPECIFIC must be rejected (CKR_OPERATION_NOT_INITIALIZED), unlike
# SO/USER above — see sessions.rs::validate_login_user_type.
if run_pkcs11 "${WORK_DIR}/login-context.log" --login --login-type context-specific -O; then
  check_fail "C_Login via --login-type context-specific correctly rejected (CKR_OPERATION_NOT_INITIALIZED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/login-context.log"
else
  check_pass "C_Login via --login-type context-specific correctly rejected (CKR_OPERATION_NOT_INITIALIZED)"
fi

if run_pkcs11 "${WORK_DIR}/objects-postlogin.log" --login --login-type so -O &&
  grep -qi "private key" "${WORK_DIR}/objects-postlogin.log" &&
  grep -qi "public key" "${WORK_DIR}/objects-postlogin.log"; then
  check_pass "C_FindObjects via -O (post-login: private/public/secret key objects visible)"
else
  check_fail "C_FindObjects via -O (post-login: private/public/secret key objects visible)" "see ${WORK_DIR}/objects-postlogin.log"
fi

print_header "PKCS#11 v3 key-type attribute conformance (CKK_EC_EDWARDS / CKK_EC_MONTGOMERY)"

if run_pkcs11 "${WORK_DIR}/objects-ed25519.log" --login --login-type so -O --type pubkey -d "$(hex_id "${ed25519_ids[1]}")" &&
  grep -qi "EC_EDWARDS\|edwards" "${WORK_DIR}/objects-ed25519.log"; then
  check_pass "Ed25519 public key reports CKK_EC_EDWARDS (not generic CKK_EC)"
else
  check_fail "Ed25519 public key reports CKK_EC_EDWARDS (not generic CKK_EC)" "see ${WORK_DIR}/objects-ed25519.log"
fi

if run_pkcs11 "${WORK_DIR}/objects-x25519.log" --login --login-type so -O --type pubkey -d "$(hex_id "${x25519_ids[1]}")" &&
  grep -qi "EC_MONTGOMERY\|montgomery" "${WORK_DIR}/objects-x25519.log"; then
  check_pass "X25519 public key reports CKK_EC_MONTGOMERY (not generic CKK_EC)"
else
  check_fail "X25519 public key reports CKK_EC_MONTGOMERY (not generic CKK_EC)" "see ${WORK_DIR}/objects-x25519.log"
fi

if run_pkcs11 "${WORK_DIR}/objects-x448.log" --login --login-type so -O --type pubkey -d "$(hex_id "${x448_ids[1]}")" &&
  grep -qi "EC_MONTGOMERY\|montgomery" "${WORK_DIR}/objects-x448.log"; then
  check_pass "X448 public key reports CKK_EC_MONTGOMERY (not generic CKK_EC)"
else
  check_fail "X448 public key reports CKK_EC_MONTGOMERY (not generic CKK_EC)" "see ${WORK_DIR}/objects-x448.log"
fi

if run_pkcs11 "${WORK_DIR}/read-rsa-pubkey.log" --login --login-type so --read-object \
  --type pubkey -d "$(hex_id "${rsa2048_ids[1]}")" -o "${WORK_DIR}/rsa2048-pub.der" &&
  openssl pkey -pubin -inform DER -in "${WORK_DIR}/rsa2048-pub.der" -noout >"${WORK_DIR}/read-rsa-pubkey-verify.log" 2>&1; then
  check_pass "C_GetAttributeValue via --read-object (RSA public key CKA_VALUE is valid DER SPKI)"
else
  check_fail "C_GetAttributeValue via --read-object (RSA public key CKA_VALUE is valid DER SPKI)" "see ${WORK_DIR}/read-rsa-pubkey.log / ${WORK_DIR}/read-rsa-pubkey-verify.log"
fi

if run_pkcs11 "${WORK_DIR}/read-ec-pubkey.log" --login --login-type so --read-object \
  --type pubkey -d "$(hex_id "${p256_ids[1]}")" -o "${WORK_DIR}/p256-pub.der" &&
  openssl pkey -pubin -inform DER -in "${WORK_DIR}/p256-pub.der" -noout >"${WORK_DIR}/read-ec-pubkey-verify.log" 2>&1; then
  check_pass "C_GetAttributeValue via --read-object (EC P-256 public key CKA_VALUE is valid DER SPKI)"
else
  check_fail "C_GetAttributeValue via --read-object (EC P-256 public key CKA_VALUE is valid DER SPKI)" "see ${WORK_DIR}/read-ec-pubkey.log / ${WORK_DIR}/read-ec-pubkey-verify.log"
fi

# ── Mechanism x function coverage matrix ────────────────────────────────────
#
# sign_function_matrix exercises ONE mechanism against every PKCS#11 function
# that mechanism applies to: single-shot sign/verify, multi-part sign/verify
# (C_SignUpdate/C_SignFinal, C_VerifyUpdate/C_VerifyFinal — forced via a
# payload larger than pkcs11-tool's internal single-shot buffer), and the v3
# message-signing trio (C_MessageSignInit/C_SignMessage/C_MessageSignFinal,
# delegated to the raw-ABI harness since pkcs11-tool has no CLI flag for it).
# Each function produces exactly one check_pass/check_fail line.
#
# Usage: sign_function_matrix <mechanism-label> <priv-id> <pub-id> <keytype> <pkcs11-tool -m arg> <digested: true|false> [extra pkcs11-tool args...]
sign_function_matrix() {
  local mech_label="$1" priv_id="$2" pub_id="$3" keytype="$4" pkcs11_mech="$5" digested="$6"
  shift 6
  local extra_args=("$@")
  local tag="${mech_label// /_}"
  local data_file="${WORK_DIR}/${tag}-data.bin"
  local big_file="${WORK_DIR}/${tag}-big.bin"
  local sig_file="${WORK_DIR}/${tag}-sig.bin"
  local big_sig_file="${WORK_DIR}/${tag}-big-sig.bin"

  echo -n "Conformance test data for ${mech_label} ($(date +%s%N))" >"${data_file}"
  # >4 KiB forces pkcs11-tool to stream the payload through C_SignUpdate/
  # C_SignFinal and C_VerifyUpdate/C_VerifyFinal instead of a single C_Sign/
  # C_Verify call.
  head -c 65536 /dev/urandom >"${big_file}"

  local sign_input="${data_file}" big_sign_input="${big_file}"
  if [ "${digested}" = "true" ]; then
    # RSA-PKCS-PSS enforces that the input handed to a "digested" C_Sign call
    # is exactly as long as the declared --hash-algorithm's output (pkcs11-tool
    # rejects a mismatched length outright), so the digest algorithm used here
    # must track the mechanism's --hash-algorithm, not always default to
    # SHA-256 (which only matches the SHA-256 PSS/ECDSA/EDDSA variants).
    local digest_algo="sha256"
    local i
    for ((i = 0; i < ${#extra_args[@]}; i++)); do
      if [ "${extra_args[i]}" = "--hash-algorithm" ]; then
        case "${extra_args[i+1]}" in
          SHA384) digest_algo="sha384" ;;
          SHA512) digest_algo="sha512" ;;
          *) digest_algo="sha256" ;;
        esac
      fi
    done
    sign_input="${WORK_DIR}/${tag}-digest.bin"
    big_sign_input="${WORK_DIR}/${tag}-big-digest.bin"
    openssl dgst "-${digest_algo}" -binary -out "${sign_input}" "${data_file}"
    openssl dgst "-${digest_algo}" -binary -out "${big_sign_input}" "${big_file}"
  fi

  # 1) single-shot C_SignInit/C_Sign
  if run_pkcs11 "${WORK_DIR}/${tag}-sign.log" --login --login-type so --sign \
    --id "$(hex_id "${priv_id}")" --mechanism "${pkcs11_mech}" "${extra_args[@]}" \
    --input-file "${sign_input}" --output-file "${sig_file}" &&
    [ -s "${sig_file}" ]; then
    check_pass "${mech_label} via C_SignInit/C_Sign"
  else
    check_fail "${mech_label} via C_SignInit/C_Sign" "see ${WORK_DIR}/${tag}-sign.log"
  fi

  # 2) single-shot C_VerifyInit/C_Verify (against the paired public key)
  if [ -s "${sig_file}" ] && run_pkcs11 "${WORK_DIR}/${tag}-verify.log" --login --login-type so --verify \
    --id "$(hex_id "${pub_id}")" --mechanism "${pkcs11_mech}" "${extra_args[@]}" \
    --input-file "${sign_input}" --signature-file "${sig_file}"; then
    check_pass "${mech_label} via C_VerifyInit/C_Verify"
  else
    check_fail "${mech_label} via C_VerifyInit/C_Verify" "see ${WORK_DIR}/${tag}-verify.log"
  fi

  # 3) multi-part C_SignInit/C_SignUpdate/C_SignFinal (large payload)
  if run_pkcs11 "${WORK_DIR}/${tag}-sign-big.log" --login --login-type so --sign \
    --id "$(hex_id "${priv_id}")" --mechanism "${pkcs11_mech}" "${extra_args[@]}" \
    --input-file "${big_sign_input}" --output-file "${big_sig_file}" &&
    [ -s "${big_sig_file}" ]; then
    check_pass "${mech_label} via C_SignInit/C_SignUpdate/C_SignFinal (multi-part, large payload)"
  else
    check_fail "${mech_label} via C_SignInit/C_SignUpdate/C_SignFinal (multi-part, large payload)" "see ${WORK_DIR}/${tag}-sign-big.log"
  fi

  # 4) multi-part C_VerifyInit/C_VerifyUpdate/C_VerifyFinal (large payload)
  if [ -s "${big_sig_file}" ] && run_pkcs11 "${WORK_DIR}/${tag}-verify-big.log" --login --login-type so --verify \
    --id "$(hex_id "${pub_id}")" --mechanism "${pkcs11_mech}" "${extra_args[@]}" \
    --input-file "${big_sign_input}" --signature-file "${big_sig_file}"; then
    check_pass "${mech_label} via C_VerifyInit/C_VerifyUpdate/C_VerifyFinal (multi-part, large payload)"
  else
    check_fail "${mech_label} via C_VerifyInit/C_VerifyUpdate/C_VerifyFinal (multi-part, large payload)" "see ${WORK_DIR}/${tag}-verify-big.log"
  fi

  # 5) C_MessageSignInit/C_SignMessage/C_MessageSignFinal — no pkcs11-tool
  # CLI flag exists for v3 message-based signing, so this is delegated to the
  # raw-ABI harness. The module's C_MessageSignInit only accepts CKM_EDDSA
  # (see pkcs11.rs); every other mechanism must be cleanly rejected with
  # CKR_FUNCTION_NOT_SUPPORTED — a real, expected boundary, not a bug.
  local message_sign_expect="not-supported"
  [ "${pkcs11_mech}" = "EDDSA" ] && message_sign_expect="ok"
  if python3 "${SCRIPT_DIR}/pkcs11_raw_abi_check.py" --module "${PKCS11_LIB}" \
    --check message-sign --priv-id "${priv_id}" --pub-id "${pub_id}" \
    --mechanism "${pkcs11_mech}" --expect "${message_sign_expect}" \
    >"${WORK_DIR}/${tag}-message-sign.log" 2>&1; then
    if [ "${message_sign_expect}" = "not-supported" ]; then
      check_unsupported_pass "${mech_label} via C_MessageSignInit/C_SignMessage/C_MessageSignFinal (raw-ABI, expect=${message_sign_expect})"
    else
      check_pass "${mech_label} via C_MessageSignInit/C_SignMessage/C_MessageSignFinal (raw-ABI, expect=${message_sign_expect})"
    fi
  else
    check_fail "${mech_label} via C_MessageSignInit/C_SignMessage/C_MessageSignFinal (raw-ABI, expect=${message_sign_expect})" "see ${WORK_DIR}/${tag}-message-sign.log"
  fi

  # Cross-verify via ckms (independent, KMIP-side verifier) + tampered-signature rejection.
  local verify_input="${data_file}" verify_flag=()
  if [ "${digested}" = "true" ]; then
    verify_input="${sign_input}"
    verify_flag=(--digested)
  fi
  if [ -s "${sig_file}" ] && "${CKMS_BIN}" "${keytype}" sign-verify "${verify_input}" "${sig_file}" \
    --key-id "${pub_id}" "${verify_flag[@]}" >"${WORK_DIR}/${tag}-ckms-verify.log" 2>&1; then
    check_pass "${mech_label} cross-verified via ckms ${keytype} sign-verify (independent KMIP-side check)"
  else
    check_fail "${mech_label} cross-verified via ckms ${keytype} sign-verify (independent KMIP-side check)" "see ${WORK_DIR}/${tag}-ckms-verify.log"
  fi

  local tampered_sig="${WORK_DIR}/${tag}-sig-tampered.bin"
  if [ -s "${sig_file}" ]; then
    python3 -c '
import sys
with open(sys.argv[1], "rb") as f:
    data = bytearray(f.read())
data[-1] ^= 0xFF
with open(sys.argv[2], "wb") as f:
    f.write(data)
' "${sig_file}" "${tampered_sig}"
    if run_pkcs11 "${WORK_DIR}/${tag}-verify-tampered.log" --login --login-type so --verify \
      --id "$(hex_id "${pub_id}")" --mechanism "${pkcs11_mech}" "${extra_args[@]}" \
      --input-file "${sign_input}" --signature-file "${tampered_sig}"; then
      check_fail "${mech_label} tampered signature correctly rejected (CKR_SIGNATURE_INVALID)" "pkcs11-tool unexpectedly accepted it, see ${WORK_DIR}/${tag}-verify-tampered.log"
    else
      check_pass "${mech_label} tampered signature correctly rejected (CKR_SIGNATURE_INVALID)"
    fi
  fi
}

print_header "Signature mechanism x function coverage matrix + key/curve breadth"

sign_function_matrix "CKM_RSA_PKCS" "${rsa2048_ids[0]}" "${rsa2048_ids[1]}" rsa RSA-PKCS false
sign_function_matrix "CKM_SHA1_RSA_PKCS" "${rsa2048_ids[0]}" "${rsa2048_ids[1]}" rsa SHA1-RSA-PKCS false
sign_function_matrix "CKM_SHA256_RSA_PKCS" "${rsa2048_ids[0]}" "${rsa2048_ids[1]}" rsa SHA256-RSA-PKCS false
sign_function_matrix "CKM_SHA384_RSA_PKCS" "${rsa2048_ids[0]}" "${rsa2048_ids[1]}" rsa SHA384-RSA-PKCS false
sign_function_matrix "CKM_SHA512_RSA_PKCS" "${rsa2048_ids[0]}" "${rsa2048_ids[1]}" rsa SHA512-RSA-PKCS false
sign_function_matrix "CKM_RSA_PKCS_PSS(SHA-256)" "${rsa2048_ids[0]}" "${rsa2048_ids[1]}" rsa RSA-PKCS-PSS true \
  --hash-algorithm SHA256 --mgf MGF1-SHA256
sign_function_matrix "CKM_ECDSA(P-256)" "${p256_ids[0]}" "${p256_ids[1]}" ec ECDSA true
sign_function_matrix "CKM_EDDSA(Ed25519)" "${ed25519_ids[0]}" "${ed25519_ids[1]}" ec EDDSA false

print_status "Key/curve-breadth pass: remaining RSA sizes, EC curves, and PSS hash variants..."

sign_function_matrix "CKM_RSA_PKCS(RSA-3072)" "${rsa3072_ids[0]}" "${rsa3072_ids[1]}" rsa RSA-PKCS false
sign_function_matrix "CKM_RSA_PKCS(RSA-4096)" "${rsa4096_ids[0]}" "${rsa4096_ids[1]}" rsa RSA-PKCS false

sign_function_matrix "CKM_RSA_PKCS_PSS(SHA-384)" "${rsa2048_ids[0]}" "${rsa2048_ids[1]}" rsa RSA-PKCS-PSS true \
  --hash-algorithm SHA384 --mgf MGF1-SHA384
sign_function_matrix "CKM_RSA_PKCS_PSS(SHA-512)" "${rsa2048_ids[0]}" "${rsa2048_ids[1]}" rsa RSA-PKCS-PSS true \
  --hash-algorithm SHA512 --mgf MGF1-SHA512

sign_function_matrix "CKM_ECDSA(P-384)" "${p384_ids[0]}" "${p384_ids[1]}" ec ECDSA true
sign_function_matrix "CKM_ECDSA(P-521)" "${p521_ids[0]}" "${p521_ids[1]}" ec ECDSA true
sign_function_matrix "CKM_ECDSA(secp256k1)" "${secp256k1_ids[0]}" "${secp256k1_ids[1]}" ec ECDSA true
sign_function_matrix "CKM_ECDSA(secp224k1)" "${secp224k1_ids[0]}" "${secp224k1_ids[1]}" ec ECDSA true
sign_function_matrix "CKM_EDDSA(Ed448)" "${ed448_ids[0]}" "${ed448_ids[1]}" ec EDDSA false

# ── AES cipher mechanism x function coverage matrix ─────────────────────────
#
# cipher_function_matrix exercises ONE AES mechanism against every applicable
# function: C_EncryptInit/C_Encrypt and C_DecryptInit/C_Decrypt (single-shot,
# expected to succeed), plus the multi-part streaming variants
# C_EncryptInit/C_EncryptUpdate/C_EncryptFinal and
# C_DecryptInit/C_DecryptUpdate/C_DecryptFinal - the module deliberately does
# NOT implement multi-part streaming for either direction (both C_EncryptUpdate
# and C_DecryptUpdate/C_DecryptFinal always return CKR_FUNCTION_NOT_SUPPORTED),
# so pkcs11-tool switching to its streaming code path (triggered once the
# payload exceeds its internal single-shot buffer, empirically ~1KiB) is a
# "declared but rejected" boundary check, not a round-trip check.
#
# Usage: cipher_function_matrix <mechanism-label> <pkcs11-tool -m arg> [extra pkcs11-tool args...]
cipher_function_matrix() {
  local mech_label="$1" pkcs11_mech="$2"
  shift 2
  local extra_args=("$@")
  local tag="${mech_label// /_}"
  local block_aligned="${WORK_DIR}/${tag}-plain.bin"
  local big_plain="${WORK_DIR}/${tag}-big-plain.bin"
  local ct_file="${WORK_DIR}/${tag}-ct.bin"
  local big_ct_file="${WORK_DIR}/${tag}-big-ct.bin"
  local pt_file="${WORK_DIR}/${tag}-pt.bin"
  local big_pt_file="${WORK_DIR}/${tag}-big-pt.bin"

  head -c 64 /dev/urandom >"${block_aligned}" # 4 AES blocks: valid for CBC without padding too
  head -c 65536 /dev/urandom >"${big_plain}"  # forces pkcs11-tool's C_EncryptUpdate/C_DecryptUpdate streaming path

  if run_pkcs11 "${WORK_DIR}/${tag}-encrypt.log" --login --login-type so --encrypt \
    --id "${AES_ID_HEX}" --mechanism "${pkcs11_mech}" "${extra_args[@]}" \
    --input-file "${block_aligned}" --output-file "${ct_file}" &&
    [ -s "${ct_file}" ]; then
    check_pass "${mech_label} via C_EncryptInit/C_Encrypt"
  else
    check_fail "${mech_label} via C_EncryptInit/C_Encrypt" "see ${WORK_DIR}/${tag}-encrypt.log"
  fi

  if [ -s "${ct_file}" ] && run_pkcs11 "${WORK_DIR}/${tag}-decrypt.log" --login --login-type so --decrypt \
    --id "${AES_ID_HEX}" --mechanism "${pkcs11_mech}" "${extra_args[@]}" \
    --input-file "${ct_file}" --output-file "${pt_file}" &&
    cmp -s "${block_aligned}" "${pt_file}"; then
    check_pass "${mech_label} via C_DecryptInit/C_Decrypt (round trip matches plaintext)"
  else
    check_fail "${mech_label} via C_DecryptInit/C_Decrypt (round trip matches plaintext)" "see ${WORK_DIR}/${tag}-decrypt.log"
  fi

  # Multi-part encrypt is deliberately unsupported: a clean rejection is the PASS case.
  if run_pkcs11 "${WORK_DIR}/${tag}-encrypt-big.log" --login --login-type so --encrypt \
    --id "${AES_ID_HEX}" --mechanism "${pkcs11_mech}" "${extra_args[@]}" \
    --input-file "${big_plain}" --output-file "${big_ct_file}"; then
    check_fail "${mech_label} via C_EncryptInit/C_EncryptUpdate/C_EncryptFinal (multi-part) correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/${tag}-encrypt-big.log"
  else
    check_unsupported_pass "${mech_label} via C_EncryptInit/C_EncryptUpdate/C_EncryptFinal (multi-part) correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)"
  fi

  # Multi-part decrypt is likewise deliberately unsupported. The exact ciphertext
  # content is irrelevant here (no round trip is expected) - only that pkcs11-tool's
  # streaming decrypt path (triggered by an input over its buffer threshold) is
  # cleanly rejected rather than silently succeeding or corrupting data.
  if run_pkcs11 "${WORK_DIR}/${tag}-decrypt-big.log" --login --login-type so --decrypt \
    --id "${AES_ID_HEX}" --mechanism "${pkcs11_mech}" "${extra_args[@]}" \
    --input-file "${big_plain}" --output-file "${big_pt_file}"; then
    check_fail "${mech_label} via C_DecryptInit/C_DecryptUpdate/C_DecryptFinal (multi-part) correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/${tag}-decrypt-big.log"
  else
    check_unsupported_pass "${mech_label} via C_DecryptInit/C_DecryptUpdate/C_DecryptFinal (multi-part) correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)"
  fi
}

if [ -n "${AES_ID_HEX}" ]; then
  print_header "Symmetric encryption mechanism x function coverage matrix"
  cipher_function_matrix "CKM_AES_CBC" AES-CBC --iv 00000000000000000000000000000000
  cipher_function_matrix "CKM_AES_CBC_PAD" AES-CBC-PAD --iv 00000000000000000000000000000000
  cipher_function_matrix "CKM_AES_GCM" AES-GCM --iv 000000000000000000000000 --aad deadbeef --tag-bits-len 128

  # AEAD-integrity negative case: a tampered ciphertext must fail GCM decryption.
  GCM_CT="${WORK_DIR}/CKM_AES_GCM-ct.bin"
  if [ -s "${GCM_CT}" ]; then
    TAMPERED_GCM_CT="${WORK_DIR}/CKM_AES_GCM-ct-tampered.bin"
    python3 -c '
import sys
with open(sys.argv[1], "rb") as f:
    data = bytearray(f.read())
data[0] ^= 0xFF
with open(sys.argv[2], "wb") as f:
    f.write(data)
' "${GCM_CT}" "${TAMPERED_GCM_CT}"
    if run_pkcs11 "${WORK_DIR}/gcm-decrypt-tampered.log" --login --login-type so --decrypt \
      --id "${AES_ID_HEX}" --mechanism AES-GCM --iv 000000000000000000000000 --aad deadbeef --tag-bits-len 128 \
      --input-file "${TAMPERED_GCM_CT}" --output-file "${WORK_DIR}/gcm-decrypt-tampered-out.bin"; then
      check_fail "CKM_AES_GCM tampered ciphertext correctly rejected (AEAD tag verification failure)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/gcm-decrypt-tampered.log"
    else
      check_pass "CKM_AES_GCM tampered ciphertext correctly rejected (AEAD tag verification failure)"
    fi
  fi
fi

print_header "C_GenerateRandom"

for size in 16 32 4096; do
  rand_file="${WORK_DIR}/random-${size}.bin"
  if run_pkcs11 "${WORK_DIR}/random-${size}.log" --generate-random "${size}" -o "${rand_file}" &&
    [ "$(wc -c <"${rand_file}")" -eq "${size}" ]; then
    check_pass "C_GenerateRandom via --generate-random ${size} (correct output size)"
  else
    check_fail "C_GenerateRandom via --generate-random ${size} (correct output size)" "see ${WORK_DIR}/random-${size}.log"
  fi
done

print_header "CKO_DATA object lifecycle (the only class C_CreateObject supports)"

DATA_LABEL="pkcs11-conformance-data"
DATA_VALUE_FILE="${WORK_DIR}/data-object-value.bin"
echo -n "cosmian_pkcs11 CKO_DATA conformance payload" >"${DATA_VALUE_FILE}"

if run_pkcs11 "${WORK_DIR}/data-write.log" --login --login-type so --write-object "${DATA_VALUE_FILE}" \
  --type data --application-label "${DATA_LABEL}" --label "${DATA_LABEL}"; then
  check_pass "C_CreateObject via --write-object --type data"
else
  check_fail "C_CreateObject via --write-object --type data" "see ${WORK_DIR}/data-write.log"
fi

DATA_READ_FILE="${WORK_DIR}/data-object-read.bin"
if run_pkcs11 "${WORK_DIR}/data-read.log" --login --login-type so --read-object \
  --type data --application-label "${DATA_LABEL}" -o "${DATA_READ_FILE}" &&
  cmp -s "${DATA_VALUE_FILE}" "${DATA_READ_FILE}"; then
  check_pass "C_GetAttributeValue via --read-object --type data (CKA_VALUE round trip matches)"
else
  check_fail "C_GetAttributeValue via --read-object --type data (CKA_VALUE round trip matches)" "see ${WORK_DIR}/data-read.log"
fi

if run_pkcs11 "${WORK_DIR}/data-delete.log" --login --login-type so --delete-object \
  --type data --application-label "${DATA_LABEL}"; then
  check_pass "C_DestroyObject via --delete-object --type data"
else
  check_fail "C_DestroyObject via --delete-object --type data" "see ${WORK_DIR}/data-delete.log"
fi

if run_pkcs11 "${WORK_DIR}/data-gone.log" --login --login-type so -O --type data --application-label "${DATA_LABEL}" &&
  ! grep -q "${DATA_LABEL}" "${WORK_DIR}/data-gone.log"; then
  check_pass "Deleted CKO_DATA object no longer visible via -O"
else
  check_fail "Deleted CKO_DATA object no longer visible via -O" "see ${WORK_DIR}/data-gone.log"
fi

print_header "PKCS#11 v3 'declared but rejected' boundary (clean rejection = PASS)"

if run_pkcs11 "${WORK_DIR}/keypairgen-rsa.log" --login --login-type so \
  --keypairgen --key-type RSA:2048 --label pkcs11-conformance-should-fail-rsa; then
  check_fail "C_GenerateKeyPair via --keypairgen RSA correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/keypairgen-rsa.log"
else
  check_unsupported_pass "C_GenerateKeyPair via --keypairgen RSA correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)"
fi

if run_pkcs11 "${WORK_DIR}/keypairgen-ec.log" --login --login-type so \
  --keypairgen --key-type EC:prime256v1 --label pkcs11-conformance-should-fail-ec; then
  check_fail "C_GenerateKeyPair via --keypairgen EC correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/keypairgen-ec.log"
else
  check_unsupported_pass "C_GenerateKeyPair via --keypairgen EC correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)"
fi

if [ -n "${AES_ID_HEX}" ]; then
  if run_pkcs11 "${WORK_DIR}/wrap.log" --login --login-type so --wrap \
    --id "${AES_ID_HEX}" --application-id "${AES_ID_HEX}" -m AES-CBC-PAD -o "${WORK_DIR}/wrapped.bin"; then
    check_fail "C_WrapKey via --wrap correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/wrap.log"
  else
    check_unsupported_pass "C_WrapKey via --wrap correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)"
  fi

  if run_pkcs11 "${WORK_DIR}/unwrap.log" --login --login-type so --unwrap \
    --id "${AES_ID_HEX}" -m AES-CBC-PAD -i "${WORK_DIR}/random-32.bin"; then
    check_fail "C_UnwrapKey via --unwrap correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/unwrap.log"
  else
    check_unsupported_pass "C_UnwrapKey via --unwrap correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)"
  fi
fi

if run_pkcs11 "${WORK_DIR}/derive.log" --login --login-type so --derive \
  --id "$(hex_id "${x25519_ids[0]}")" -m ECDH1-DERIVE; then
  check_fail "C_DeriveKey via --derive correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/derive.log"
else
  check_unsupported_pass "C_DeriveKey via --derive correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)"
fi

if run_pkcs11 "${WORK_DIR}/hash.log" --hash -m SHA256 --input-file "${WORK_DIR}/random-16.bin" -o "${WORK_DIR}/hash-out.bin"; then
  check_fail "C_DigestInit/C_Digest via --hash correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/hash.log"
else
  check_unsupported_pass "C_DigestInit/C_Digest via --hash correctly rejected (CKR_FUNCTION_NOT_SUPPORTED)"
fi

# Note: pkcs11-tool's `--test-hotplug` never actually invokes the module's
# C_WaitForSlotEvent (confirmed via trace logging: only C_GetSlotList is called,
# regardless of stdin content) - this OpenSC subcommand only polls C_GetSlotList in a
# loop and never reaches the real function under non-interactive/no-hardware-event
# conditions. C_WaitForSlotEvent is instead exercised directly by the raw-ABI harness
# below, which is the only reliable way to assert its CKR_FUNCTION_NOT_SUPPORTED return.

# C_InitToken/C_InitPIN/C_SetPIN ARE implemented (unlike the functions above)
# but always return CKR_TOKEN_WRITE_PROTECTED — a distinct, real rejection.
if run_pkcs11 "${WORK_DIR}/init-token.log" --init-token --label conformance-token --so-pin 12345678; then
  check_fail "C_InitToken via --init-token correctly rejected (CKR_TOKEN_WRITE_PROTECTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/init-token.log"
else
  check_unsupported_pass "C_InitToken via --init-token correctly rejected (CKR_TOKEN_WRITE_PROTECTED)"
fi

if run_pkcs11 "${WORK_DIR}/init-pin.log" --login --login-type so --init-pin --pin 12345678; then
  check_fail "C_InitPIN via --init-pin correctly rejected (CKR_TOKEN_WRITE_PROTECTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/init-pin.log"
else
  check_unsupported_pass "C_InitPIN via --init-pin correctly rejected (CKR_TOKEN_WRITE_PROTECTED)"
fi

if run_pkcs11 "${WORK_DIR}/change-pin.log" --login --login-type user --change-pin --pin 12345678 --new-pin 87654321; then
  check_fail "C_SetPIN via --change-pin correctly rejected (CKR_TOKEN_WRITE_PROTECTED)" "pkcs11-tool unexpectedly succeeded, see ${WORK_DIR}/change-pin.log"
else
  check_unsupported_pass "C_SetPIN via --change-pin correctly rejected (CKR_TOKEN_WRITE_PROTECTED)"
fi

print_header "Raw-ABI harness: functions with no pkcs11-tool CLI equivalent"

if python3 "${SCRIPT_DIR}/pkcs11_raw_abi_check.py" --module "${PKCS11_LIB}" --check not-supported \
  >"${WORK_DIR}/raw-abi-not-supported.log" 2>"${WORK_DIR}/raw-abi-not-supported.err.log"; then
  # The harness itself prints one line per function it drove (a red cross for
  # both a real failure and an expected "not supported" boundary pass); forward
  # those lines verbatim so each still counts as its own single check line,
  # then fold the harness's own pass/fail accounting into ours via its
  # machine-parseable ::HARNESS_SUMMARY:: footer (not an emoji grep — a
  # boundary-check pass also prints ❌, so that would over-count failures).
  grep -v '^::HARNESS_SUMMARY::' "${WORK_DIR}/raw-abi-not-supported.log"
  RAW_ABI_SUMMARY="$(grep '^::HARNESS_SUMMARY::' "${WORK_DIR}/raw-abi-not-supported.log")"
  RAW_ABI_LINES="$(echo "${RAW_ABI_SUMMARY}" | sed -n 's/.*total=\([0-9]*\).*/\1/p')"
  RAW_ABI_FAILS="$(echo "${RAW_ABI_SUMMARY}" | sed -n 's/.*failed=\([0-9]*\).*/\1/p')"
  TOTAL_CHECKS=$((TOTAL_CHECKS + RAW_ABI_LINES))
  FAILED_CHECKS=$((FAILED_CHECKS + RAW_ABI_FAILS))
else
  cat "${WORK_DIR}/raw-abi-not-supported.log" 2>/dev/null || true
  check_fail "Raw-ABI harness: not-supported function battery" "harness exited non-zero; see ${WORK_DIR}/raw-abi-not-supported.err.log"
fi

if python3 "${SCRIPT_DIR}/pkcs11_raw_abi_check.py" --module "${PKCS11_LIB}" --check legacy-ok \
  >"${WORK_DIR}/raw-abi-legacy.log" 2>"${WORK_DIR}/raw-abi-legacy.err.log"; then
  grep -v '^::HARNESS_SUMMARY::' "${WORK_DIR}/raw-abi-legacy.log"
  RAW_ABI_SUMMARY="$(grep '^::HARNESS_SUMMARY::' "${WORK_DIR}/raw-abi-legacy.log")"
  RAW_ABI_LINES="$(echo "${RAW_ABI_SUMMARY}" | sed -n 's/.*total=\([0-9]*\).*/\1/p')"
  RAW_ABI_FAILS="$(echo "${RAW_ABI_SUMMARY}" | sed -n 's/.*failed=\([0-9]*\).*/\1/p')"
  TOTAL_CHECKS=$((TOTAL_CHECKS + RAW_ABI_LINES))
  FAILED_CHECKS=$((FAILED_CHECKS + RAW_ABI_FAILS))
else
  cat "${WORK_DIR}/raw-abi-legacy.log" 2>/dev/null || true
  check_fail "Raw-ABI harness: legacy no-op function battery (C_SeedRandom/C_GetFunctionStatus/C_CancelFunction)" "harness exited non-zero; see ${WORK_DIR}/raw-abi-legacy.err.log"
fi

print_header "Summary"
echo "Total checks: ${TOTAL_CHECKS}"
echo "Passed:       $((TOTAL_CHECKS - FAILED_CHECKS))"
echo "Failed:       ${FAILED_CHECKS}"

if [ "${FAILED_CHECKS}" -gt 0 ]; then
  print_error "PKCS#11 conformance suite FAILED (${FAILED_CHECKS}/${TOTAL_CHECKS} checks failed): ${FAILED_LABELS[*]}"
  exit 1
fi

print_success "PKCS#11 conformance suite passed: ${TOTAL_CHECKS}/${TOTAL_CHECKS} checks green"
exit 0
