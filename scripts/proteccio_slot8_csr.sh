#!/usr/bin/env bash
set -euo pipefail

# ────────────────────────────────────────────────────────────────────────────────
# Generate a non-exportable RSA 4096 key pair INSIDE the Proteccio HSM slot 8
# and create an EV Code Signing CSR (Authenticode — Windows PE binaries)
# for the enterprise Eviden.
#
# SECURITY: The private key is generated on the HSM and never leaves it.
#   - CKA_SENSITIVE = true    (private key material cannot be revealed in plaintext)
#   - CKA_EXTRACTABLE = false (private key cannot be extracted, even wrapped)
#   - No --extractable flag is used
#   - No private key export step exists in this script
#
# To delete the key pair from the HSM (e.g. to re-run this script):
#   source ~/.cosmian/proteccio_8.sh
#   pkcs11-tool --module /lib/libnethsm.so --login --pin "$PROTECCIO_SLOT_8_PASSWORD" \
#     --slot "$PROTECCIO_SLOT_8" --delete-object --type privkey --label "eviden-codesign-YYYYMMDD"
#   pkcs11-tool --module /lib/libnethsm.so --login --pin "$PROTECCIO_SLOT_8_PASSWORD" \
#     --slot "$PROTECCIO_SLOT_8" --delete-object --type pubkey  --label "eviden-codesign-YYYYMMDD"
# ────────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# Source slot 8 credentials
# shellcheck source=/dev/null
source ~/.cosmian/proteccio_8.sh

# ── Configuration ─────────────────────────────────────────────────────────────
PKCS11_MODULE="/lib/libnethsm.so"
SLOT="${PROTECCIO_SLOT_8}"
LABEL="eviden-codesign-$(date +%Y%m%d)"
KEY_ID="01"
PIN="${PROTECCIO_SLOT_8_PASSWORD}"

CSR_OUTPUT="${SCRIPT_DIR}/${LABEL}.csr.pem"
PUBKEY_BACKUP="${SCRIPT_DIR}/${LABEL}.pubkey.pem"

if [[ -z "$PIN" ]]; then
  echo "ERROR: PROTECCIO_SLOT_8_PASSWORD not set by ~/.cosmian/proteccio_8.sh" >&2
  exit 1
fi

echo "========================================="
echo " Proteccio HSM Slot $SLOT — RSA 4096 + CSR"
echo "========================================="

# ── Step 1: Generate RSA 4096 key pair inside the HSM ────────────────────────
# The key pair is generated on the HSM hardware. The private key is
# non-extractable and sensitive by default (no --extractable flag).
echo ""
echo ">>> Generating RSA 4096 key pair inside HSM (label: $LABEL, id: $KEY_ID) ..."
pkcs11-tool \
  --module "$PKCS11_MODULE" \
  --login --pin "$PIN" \
  --slot "$SLOT" \
  --keypairgen \
  --key-type rsa:4096 \
  --label "$LABEL" \
  --id "$KEY_ID"

echo "Key pair generated inside HSM (private key is non-exportable)."

# ── Step 2: Export public key for reference ──────────────────────────────────
echo ""
echo ">>> Exporting public key (public keys are always exportable) ..."
pkcs11-tool \
  --module "$PKCS11_MODULE" \
  --login --pin "$PIN" \
  --slot "$SLOT" \
  --read-object --type pubkey \
  --label "$LABEL" \
  | openssl rsa -pubin -inform DER -outform PEM -out "$PUBKEY_BACKUP"

echo "  Public key saved to: $PUBKEY_BACKUP"

# ── Step 3: List objects on slot to confirm key presence ─────────────────────
echo ""
echo ">>> Listing objects on slot $SLOT ..."
pkcs11-tool \
  --module "$PKCS11_MODULE" \
  --login --pin "$PIN" \
  --slot "$SLOT" \
  --list-objects

# ── Step 4: Generate CSR via OpenSSL PKCS#11 engine ─────────────────────────
# The CSR is signed by the private key inside the HSM via the PKCS#11 engine.
# The private key never leaves the HSM boundary.
#
# EV Code Signing certificate for Authenticode (Windows PE binary signing)
# Subject fields follow CA/Browser Forum EV Guidelines §9.2

echo ""
echo ">>> Generating CSR for EV Code Signing (Authenticode) ..."

TMPDIR_WORK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_WORK"' EXIT

cat > "$TMPDIR_WORK/openssl-pkcs11.cnf" <<OPENSSL_CNF
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id   = pkcs11
MODULE_PATH = ${PKCS11_MODULE}
PIN         = ${PIN}
init        = 0

# ── CSR request configuration ───────────────────────────────────────────
[req]
default_md         = sha256
prompt             = no
distinguished_name = req_dn
req_extensions     = v3_req

# ── Subject (EV fields per CA/B Forum EV Guidelines §9.2) ───────────────
#   businessCategory     = Private Organization    (OID 2.5.4.15)
#   jurisdictionCountryName = FR                   (OID 1.3.6.1.4.1.311.60.2.1.3)
#   serialNumber         = 488241389               (SIREN — French business registry)
#   C  = FR    ST = Ile-de-France    L = Bezons
#   O  = Eviden    CN = Eviden
[req_dn]
businessCategory        = Private Organization
jurisdictionCountryName = FR
serialNumber            = 488241389
C                       = FR
ST                      = Ile-de-France
L                       = Bezons
O                       = Eviden
CN                      = Eviden

# ── Requested extensions ─────────────────────────────────────────────────
[v3_req]
keyUsage               = critical, digitalSignature
extendedKeyUsage       = critical, codeSigning
OPENSSL_CNF

# Use libp11 legacy key format: slot_<N>-id_<hex>
PKCS11_KEY_ID="slot_${SLOT}-id_${KEY_ID}"

OPENSSL_CONF="$TMPDIR_WORK/openssl-pkcs11.cnf" \
  openssl req -new \
    -engine pkcs11 \
    -keyform engine \
    -key "$PKCS11_KEY_ID" \
    -config "$TMPDIR_WORK/openssl-pkcs11.cnf" \
    -out "$CSR_OUTPUT"

echo ""
echo "========================================="
echo " CSR written to: $CSR_OUTPUT"
echo "========================================="
echo ""
echo ">>> CSR details:"
openssl req -in "$CSR_OUTPUT" -noout -text -nameopt utf8

# ── Step 5: Display full slot content ────────────────────────────────────────
echo ""
echo "========================================="
echo " Full content of HSM Slot $SLOT"
echo "========================================="
pkcs11-tool \
  --module "$PKCS11_MODULE" \
  --login --pin "$PIN" \
  --slot "$SLOT" \
  --list-objects

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "========================================="
echo " Summary"
echo "========================================="
echo "  CSR:        $CSR_OUTPUT"
echo "  Public key: $PUBKEY_BACKUP"
echo "  Private key: INSIDE HSM ONLY (non-exportable, CKA_SENSITIVE + CKA_NEVER_EXTRACTABLE)"
