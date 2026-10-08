#!/usr/bin/env bash
# GnuPG smartcard (gnupg-pkcs11-scd) + Cosmian KMS PKCS#11 integration tests
#
# Validates that libcosmian_pkcs11 can be used as the PKCS#11 backend of
# gnupg-pkcs11-scd (a drop-in replacement for GnuPG's scdaemon), in two phases:
#
#   Part 1 — Rust unit test (always executed):
#     test_gnupg_card_key_discovery — an RSA key pair + self-signed certificate
#       tagged 'gnupg-card' are discovered, and the certificate's CKA_ID equals
#       the private key's CKA_ID (the invariant gnupg-pkcs11-scd requires).
#
#   Part 2 — Shell integration (SoftHSM2-backed KMS server):
#     Every key is wrapped at rest by a SoftHSM2-resident KEK (hsm_kek_bootstrap).
#     An RSA key pair is created and self-certified, then:
#       - pkcs11-tool (if available) confirms the CKA_ID of the certificate and
#         private key are identical;
#       - gnupg-pkcs11-scd (if available) is driven over its Assuan --server
#         protocol: LEARN discovers the certificate, PKSIGN signs with the KMS
#         key, and openssl verifies the signature.
#
# Runs non-fips only: the provider crate's test module is gated with
# #[cfg(feature = "non-fips")] (RSA/X.509 themselves are FIPS-legal).
#
# Usage:
#   mise run test:gnupg-smartcard --variant non-fips
#   bash .mise/scripts/test/test_gnupg_smartcard.sh
set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/pkcs11_helpers.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

echo "============================================="
echo "Running GnuPG smartcard PKCS#11 KMS integration tests"
echo "============================================="

if [ "${VARIANT}" != "non-fips" ]; then
  echo "Note: GnuPG smartcard PKCS#11 tests require non-fips (test helpers only compile with non-fips feature)."
fi
VARIANT="non-fips"
FEATURES_FLAG=(--features non-fips)

# ── Part 1: Rust unit test ───────────────────────────────────────────────────
echo "============================================="
echo "Part 1: GnuPG smartcard Rust unit test"
echo "============================================="
kms_build_all
cargo test -p cosmian_pkcs11 "${FEATURES_FLAG[@]}" -- test_gnupg_card_key_discovery --nocapture
echo "GnuPG smartcard Rust unit test passed."

# ── Part 2: Shell integration (SoftHSM2-backed KMS server) ───────────────────
echo "============================================="
echo "Part 2: Shell integration test"
echo "============================================="
REPO_ROOT="$(get_repo_root)"
KMS_BIN="$(get_kms_bin)"
CKMS_BIN="$(get_ckms_bin)"
PKCS11_LIB="$(get_cosmian_pkcs11_lib)"
require_cmd openssl
require_cmd python3

WORK_DIR="$(mktemp -d /tmp/kms-gnupg-smartcard-XXXXXX)"
SCD_HOME="$(mktemp -d /tmp/kms-gnupg-scd-XXXXXX)"
cleanup() {
  kms_stop || true
  rm -rf "${WORK_DIR}" "${SCD_HOME}" "${REPO_ROOT}/.softhsm2-gnupg_smartcard" || true
}
trap cleanup EXIT INT TERM

# "Use a SoftHSM as backend": every key created below is transparently wrapped
# at rest by a SoftHSM2-resident KEK, like every other HSM-KEK PKCS#11 script.
# On return CKMS_CONF points at the KEK-enabled server.
hsm_kek_bootstrap "${REPO_ROOT}" "gnupg_smartcard" "${WORK_DIR}" "${KMS_BIN}" "${CKMS_BIN}"

json_field() {
  python3 -c 'import json, sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"
}

echo "--- Creating RSA keypair tagged 'gnupg-card' ---"
rsa_json="$(COSMIAN_KMS_CLI_FORMAT=json "${CKMS_BIN}" rsa keys create --size_in_bits 2048 --tag gnupg-card)"
rsa_sk_id="$(json_field "${rsa_json}" private_key_unique_identifier)"
rsa_pk_id="$(json_field "${rsa_json}" public_key_unique_identifier)"
echo "RSA private key id: ${rsa_sk_id}, public key id: ${rsa_pk_id}"

# No issuer is given: the server self-signs using the PrivateKeyLink of the
# public key, which also makes the certificate's CKA_ID equal the private key's.
echo "--- Self-certifying the public key (subject: CN=gnupg-smartcard-test) ---"
cert_json="$(COSMIAN_KMS_CLI_FORMAT=json "${CKMS_BIN}" certificates certify \
  --public-key-id-to-certify "${rsa_pk_id}" \
  --subject-name "CN=gnupg-smartcard-test,O=Cosmian" \
  --days 1095 \
  --tag gnupg-card)"
cert_id="$(json_field "${cert_json}" unique_identifier)"
echo "Certificate id: ${cert_id}"

# ── pkcs11-tool cross-check: cert and private key share the identical CKA_ID ──
if command -v pkcs11-tool >/dev/null 2>&1; then
  echo "--- pkcs11-tool --list-objects (CKA_ID cross-check) ---"
  list_out="$(pkcs11-tool --module "${PKCS11_LIB}" --list-objects 2>&1)"
  echo "${list_out}"
  expected_id="$(printf '%s' "${rsa_sk_id}" | od -An -tx1 | tr -d ' \n')"
  # pkcs11-tool prints "ID: aa:bb:..." wrapped over several lines; for each
  # object of the given kind, rebuild the hex string and require an exact match
  # with the private key's KMS id: both the certificate and the private key
  # must carry it.
  for object_kind in "Certificate Object" "Private Key Object"; do
    object_ids="$(echo "${list_out}" | awk -v kind="${object_kind}" '
        function flush() { if (acc != "") { gsub(/:/, "", acc); print tolower(acc); acc = "" } }
        $0 ~ kind { flush(); inobj = 1; collecting = 0; next }
        /Object;/ { flush(); inobj = 0; collecting = 0 }
        inobj && /^ +ID:/ { s = $0; sub(/.*ID: */, "", s); acc = s; collecting = 1; next }
        inobj && collecting && /^ +[0-9a-fA-F:]+ *$/ { s = $0; gsub(/ /, "", s); acc = acc s; next }
        { collecting = 0 }
        END { flush() }')"
    if ! grep -qx "${expected_id}" <<<"${object_ids}"; then
      echo "ERROR: no '${object_kind}' with CKA_ID ${expected_id} (KMS id ${rsa_sk_id})" >&2
      exit 1
    fi
  done
  echo "OK: certificate and private key CKA_ID both match ${rsa_sk_id}."
else
  echo "pkcs11-tool not found — skipping raw CKA_ID cross-check (covered by Part 1's Rust test)."
fi

# ── gnupg-pkcs11-scd: drive the real consumer binary end-to-end ──────────────
if ! command -v gnupg-pkcs11-scd >/dev/null 2>&1; then
  echo "gnupg-pkcs11-scd not found — skipping Assuan protocol smoke test."
  echo "GnuPG smartcard PKCS#11 integration tests passed (partial: Rust/pkcs11-tool coverage only)."
  exit 0
fi

scd_conf="${SCD_HOME}/gnupg-pkcs11-scd.conf"
cat >"${scd_conf}" <<EOF
providers cosmian
provider-cosmian-library ${PKCS11_LIB}
provider-cosmian-allow-protected-auth
EOF

sig_out="${SCD_HOME}/signature.bin"
message="gnupg smartcard smoke test"
echo "--- Driving gnupg-pkcs11-scd --server (LEARN + PKSIGN) ---"
CKMS_CONF="${CKMS_CONF}" COSMIAN_PKCS11_LOGGING_LEVEL=warn python3 \
  "${SCRIPT_DIR}/gnupg_pkcs11_scd_driver.py" \
  --scd-bin "$(command -v gnupg-pkcs11-scd)" \
  --homedir "${SCD_HOME}" \
  --options "${scd_conf}" \
  --expect-subject "CN=gnupg-smartcard-test" \
  --sign --message "${message}" \
  --sig-out "${sig_out}"
echo "OK: gnupg-pkcs11-scd LEARN discovered the certificate and PKSIGN produced a signature."

# ── Verify the PKSIGN signature against the certified public key ─────────────
"${CKMS_BIN}" certificates export --certificate-id "${cert_id}" --format pem "${SCD_HOME}/cert.pem"
openssl x509 -in "${SCD_HOME}/cert.pem" -pubkey -noout >"${SCD_HOME}/pub.pem"
printf '%s' "${message}" >"${SCD_HOME}/message.txt"
openssl dgst -sha256 -verify "${SCD_HOME}/pub.pem" -signature "${sig_out}" "${SCD_HOME}/message.txt"
echo "OK: PKSIGN signature verifies against the certified public key with openssl."

echo "============================================="
echo "GnuPG smartcard PKCS#11 integration tests passed!"
echo "============================================="
