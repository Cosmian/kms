#!/usr/bin/env bash
# JOSE / REST Crypto API end-to-end test suite.
#
# ALL key creation uses the JOSE REST endpoint (POST /v1/crypto/keys).
# No KMIP Create/Import is used for key provisioning.
#
# Phase 1: curl-based tests against every /v1/crypto/* endpoint (no external deps)
# Phase 2: JOSE interoperability tests — validates KMS outputs against Python jwcrypto
#           Direction A: KMS generates → KMS operates → jwcrypto validates
#           Direction B: jwcrypto generates → REST import → both sides operate
#           Direction C: KMS generates → export → jwcrypto operates → KMS validates
#
# Requires: curl, base64, Python 3.9+, pip (for jwcrypto install)
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"
setup_test_logging

HELPER="${SCRIPT_DIR}/jose_interop_helper.py"

# ── Configuration ────────────────────────────────────────────────────────────
KMS_PORT=9990
KMS_URL="http://127.0.0.1:${KMS_PORT}"

export KMS_HTTP_HOST="127.0.0.1"
export KMS_HTTP_PORT="${KMS_PORT}"

KMS_PID=""
SQLITE_PATH=""
KMS_CONF_PATH=""
VENV_DIR=""

cleanup() {
  [ -n "${KMS_PID:-}" ] && {
    kill "${KMS_PID}" 2>/dev/null || true
    wait "${KMS_PID}" 2>/dev/null || true
  }
  [ -n "${SQLITE_PATH:-}" ] && { rm -rf "${SQLITE_PATH}" || true; }
  [ -n "${KMS_CONF_PATH:-}" ] && { rm -f "${KMS_CONF_PATH}" || true; }
  [ -n "${VENV_DIR:-}" ] && { rm -rf "${VENV_DIR}" || true; }
}
trap cleanup EXIT

# ── Generic helpers ───────────────────────────────────────────────────────────

# Encode a literal string to base64url without padding.
b64url_encode() {
  printf '%s' "$1" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

# Extract a string-typed field from a flat JSON REST response.
json_str() {
  printf '%s' "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | sed 's/.*":"//;s/"$//'
}

# Extract a boolean field from a flat JSON REST response.
json_bool() {
  printf '%s' "$1" | grep -oE "\"$2\":(true|false)" | head -1 | sed 's/.*://'
}

# Extract a TextString value by KMIP tag name from a JSON-TTLV response.
kmip_tag() {
  printf '%s' "$1" |
    grep -o "\"tag\":\"$2\",\"type\":\"TextString\",\"value\":\"[^\"]*\"" |
    grep -o '"value":"[^"]*"' |
    sed 's/"value":"//;s/"$//'
}

# Extract a ByteString value (hex-encoded key material) from a JSON-TTLV response.
kmip_bytestring() {
  printf '%s' "$1" |
    grep -o "\"tag\":\"$2\",\"type\":\"ByteString\",\"value\":\"[^\"]*\"" |
    grep -o '"value":"[^"]*"' |
    sed 's/"value":"//;s/"$//'
}

# POST JSON to the KMIP 2.1 endpoint and return the full response body.
# NOTE: Only used for key EXPORT (Get), never for key creation.
kmip_post() {
  curl -sS -X POST "${KMS_URL}/kmip/2_1" \
    -H "Content-Type: application/json" \
    -d "$1"
}

# POST JSON to /v1/crypto/<endpoint> and return the full response body.
crypto_post() {
  local endpoint="$1" body="$2"
  curl -sS -X POST "${KMS_URL}/v1/crypto/${endpoint}" \
    -H "Content-Type: application/json" \
    -d "$body"
}

# Like crypto_post but return only the HTTP status code and discard the body.
crypto_status() {
  local endpoint="$1" body="$2"
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${KMS_URL}/v1/crypto/${endpoint}" \
    -H "Content-Type: application/json" \
    -d "$body"
}

assert_eq() {
  local got="$1" expected="$2" label="${3:-assertion}"
  if [ "$got" != "$expected" ]; then
    echo "FAIL [${label}]: expected '${expected}', got '${got}'" >&2
    exit 1
  fi
  echo "PASS: ${label}"
}

assert_status() {
  local got="$1" expected="$2" label="${3:-HTTP status}"
  assert_eq "$got" "$expected" "${label} (HTTP ${expected})"
}

# ── Key export helpers (KMIP Get only — no creation) ──────────────────────────

# Export a key as DER (PKCS8 for asymmetric, Raw for symmetric) and print hex.
export_key_der() {
  local uid="$1"
  local resp
  resp=$(kmip_post "$(
    cat <<JSON
{
  "tag": "Get", "type": "Structure",
  "value": [
    {"tag": "UniqueIdentifier", "type": "TextString", "value": "${uid}"},
    {"tag": "KeyFormatType", "type": "Enumeration", "value": "PKCS8"}
  ]
}
JSON
  )")
  kmip_bytestring "$resp" "KeyMaterial"
}

# Export a symmetric key as raw bytes (hex).
export_symmetric_key_raw() {
  local uid="$1"
  local resp
  resp=$(kmip_post "$(
    cat <<JSON
{
  "tag": "Get", "type": "Structure",
  "value": [
    {"tag": "UniqueIdentifier", "type": "TextString", "value": "${uid}"},
    {"tag": "KeyFormatType", "type": "Enumeration", "value": "Raw"}
  ]
}
JSON
  )")
  kmip_bytestring "$resp" "KeyMaterial"
}

# ── Server startup ────────────────────────────────────────────────────────────

SQLITE_PATH="$(mktemp -d -t kms-jose-test-XXXXXX)"
KMS_CONF_PATH="$(mktemp -t kms-jose-test-conf-XXXXXX.toml)"

cat >"${KMS_CONF_PATH}" <<EOF
[http]
hostname = "${KMS_HTTP_HOST}"
port = ${KMS_HTTP_PORT}

[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_PATH}"
clear_database = true
EOF

# shellcheck disable=SC2068
cargo build ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms

# shellcheck disable=SC2068
cargo run ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms -- \
  --config "${KMS_CONF_PATH}" \
  &
KMS_PID=$!

if ! _wait_for_port "${KMS_HTTP_HOST}" "${KMS_PORT}" 60; then
  echo "ERROR: KMS server failed to start on port ${KMS_PORT}" >&2
  exit 1
fi

# ── Create test keys via JOSE REST API ────────────────────────────────────────

echo "==> Creating test keys via JOSE REST API (POST /v1/crypto/keys)..."

# Symmetric keys for encryption
AES128_RESP=$(crypto_post "keys" '{"kty":"oct","alg":"A128GCM"}')
AES128_KID=$(json_str "$AES128_RESP" "kid")

AES192_RESP=$(crypto_post "keys" '{"kty":"oct","alg":"A192GCM"}')
AES192_KID=$(json_str "$AES192_RESP" "kid")

AES256_RESP=$(crypto_post "keys" '{"kty":"oct","alg":"A256GCM"}')
AES256_KID=$(json_str "$AES256_RESP" "kid")

# Symmetric keys for MAC
HMAC256_RESP=$(crypto_post "keys" '{"kty":"oct","alg":"HS256"}')
HMAC256_KID=$(json_str "$HMAC256_RESP" "kid")

HMAC384_RESP=$(crypto_post "keys" '{"kty":"oct","alg":"HS384"}')
HMAC384_KID=$(json_str "$HMAC384_RESP" "kid")

HMAC512_RESP=$(crypto_post "keys" '{"kty":"oct","alg":"HS512"}')
HMAC512_KID=$(json_str "$HMAC512_RESP" "kid")

# RSA keypair
RSA_RESP=$(crypto_post "keys" '{"kty":"RSA","alg":"RS256"}')
RSA_PRIV_UID=$(json_str "$RSA_RESP" "kid")
RSA_PUB_UID=$(json_str "$RSA_RESP" "kid_public")

# EC P-256 keypair
EC256_RESP=$(crypto_post "keys" '{"kty":"EC","alg":"ES256","crv":"P-256"}')
EC_PRIV_UID=$(json_str "$EC256_RESP" "kid")
EC_PUB_UID=$(json_str "$EC256_RESP" "kid_public")

# EC P-384 keypair
EC384_RESP=$(crypto_post "keys" '{"kty":"EC","alg":"ES384","crv":"P-384"}')
EC384_PRIV_UID=$(json_str "$EC384_RESP" "kid")
EC384_PUB_UID=$(json_str "$EC384_RESP" "kid_public")

# EC P-521 keypair
EC521_RESP=$(crypto_post "keys" '{"kty":"EC","alg":"ES512","crv":"P-521"}')
EC521_PRIV_UID=$(json_str "$EC521_RESP" "kid")
EC521_PUB_UID=$(json_str "$EC521_RESP" "kid_public")

# Ed25519 keypair (OKP)
ED_RESP=$(crypto_post "keys" '{"kty":"OKP","alg":"EdDSA","crv":"Ed25519"}')
ED_PRIV_UID=$(json_str "$ED_RESP" "kid")
ED_PUB_UID=$(json_str "$ED_RESP" "kid_public")

echo "    AES-128        ${AES128_KID}"
echo "    AES-192        ${AES192_KID}"
echo "    AES-256        ${AES256_KID}"
echo "    HMAC-256       ${HMAC256_KID}"
echo "    HMAC-384       ${HMAC384_KID}"
echo "    HMAC-512       ${HMAC512_KID}"
echo "    RSA-2048 priv  ${RSA_PRIV_UID}"
echo "    RSA-2048 pub   ${RSA_PUB_UID}"
echo "    EC P-256 priv  ${EC_PRIV_UID}"
echo "    EC P-256 pub   ${EC_PUB_UID}"
echo "    EC P-384 priv  ${EC384_PRIV_UID}"
echo "    EC P-384 pub   ${EC384_PUB_UID}"
echo "    EC P-521 priv  ${EC521_PRIV_UID}"
echo "    EC P-521 pub   ${EC521_PUB_UID}"
echo "    Ed25519 priv   ${ED_PRIV_UID}"
echo "    Ed25519 pub    ${ED_PUB_UID}"

PLAINTEXT="Hello REST crypto!"
PLAINTEXT_B64=$(b64url_encode "${PLAINTEXT}")

###############################################################################
# PHASE 1: Curl-based REST Crypto API tests
###############################################################################

echo ""
echo "==========================================="
echo "Phase 1: REST Crypto API E2E (curl-only)"
echo "==========================================="

# ── Section A: Encrypt / Decrypt ─────────────────────────────────────────────

run_enc_dec_roundtrip() {
  local kid="$1" enc="$2"
  local enc_resp protected iv ciphertext tag dec_resp got_data

  enc_resp=$(crypto_post "encrypt" \
    "{\"kid\":\"${kid}\",\"alg\":\"dir\",\"enc\":\"${enc}\",\"data\":\"${PLAINTEXT_B64}\"}")
  protected=$(json_str "$enc_resp" "protected")
  iv=$(json_str "$enc_resp" "iv")
  ciphertext=$(json_str "$enc_resp" "ciphertext")
  tag=$(json_str "$enc_resp" "tag")

  dec_resp=$(crypto_post "decrypt" \
    "{\"protected\":\"${protected}\",\"encrypted_key\":\"\",\"iv\":\"${iv}\",\"ciphertext\":\"${ciphertext}\",\"tag\":\"${tag}\"}")
  got_data=$(json_str "$dec_resp" "data")
  assert_eq "$got_data" "$PLAINTEXT_B64" "${enc} round-trip"
}

echo ""
echo "==> Section A: Encrypt / Decrypt"
echo "==> A1: A128GCM round-trip"
run_enc_dec_roundtrip "${AES128_KID}" "A128GCM"
echo "==> A2: A192GCM round-trip"
run_enc_dec_roundtrip "${AES192_KID}" "A192GCM"
echo "==> A3: A256GCM round-trip"
run_enc_dec_roundtrip "${AES256_KID}" "A256GCM"

echo "==> A4: A256GCM with AAD — round-trip"
AAD_B64=$(b64url_encode "context-data")
ENC_AAD=$(crypto_post "encrypt" \
  "{\"kid\":\"${AES256_KID}\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"${PLAINTEXT_B64}\",\"aad\":\"${AAD_B64}\"}")
P_AAD=$(json_str "$ENC_AAD" "protected")
IV_AAD=$(json_str "$ENC_AAD" "iv")
CT_AAD=$(json_str "$ENC_AAD" "ciphertext")
TAG_AAD=$(json_str "$ENC_AAD" "tag")
DEC_AAD=$(crypto_post "decrypt" \
  "{\"protected\":\"${P_AAD}\",\"encrypted_key\":\"\",\"iv\":\"${IV_AAD}\",\"ciphertext\":\"${CT_AAD}\",\"tag\":\"${TAG_AAD}\",\"aad\":\"${AAD_B64}\"}")
assert_eq "$(json_str "$DEC_AAD" "data")" "$PLAINTEXT_B64" "A256GCM AAD round-trip"

echo "==> A5: AAD tamper must fail (422)"
WRONG_AAD_B64=$(b64url_encode "tampered-context")
assert_status \
  "$(crypto_status "decrypt" "{\"protected\":\"${P_AAD}\",\"encrypted_key\":\"\",\"iv\":\"${IV_AAD}\",\"ciphertext\":\"${CT_AAD}\",\"tag\":\"${TAG_AAD}\",\"aad\":\"${WRONG_AAD_B64}\"}")" \
  "422" "AAD tamper"

echo "==> A6: Protected header tamper must fail (422)"
MOD_PROT=$(b64url_encode "{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"kid\":\"${AES256_KID}\",\"x\":1}")
assert_status \
  "$(crypto_status "decrypt" "{\"protected\":\"${MOD_PROT}\",\"encrypted_key\":\"\",\"iv\":\"${IV_AAD}\",\"ciphertext\":\"${CT_AAD}\",\"tag\":\"${TAG_AAD}\",\"aad\":\"${AAD_B64}\"}")" \
  "422" "Protected header tamper"

echo "==> A7: Unsupported enc (A128CBC-HS256) returns 400"
assert_status \
  "$(crypto_status "encrypt" "{\"kid\":\"${AES256_KID}\",\"alg\":\"dir\",\"enc\":\"A128CBC-HS256\",\"data\":\"${PLAINTEXT_B64}\"}")" \
  "400" "Unsupported enc"

echo "==> A8: Unsupported alg (A128KW) returns 400"
assert_status \
  "$(crypto_status "encrypt" "{\"kid\":\"${AES256_KID}\",\"alg\":\"A128KW\",\"enc\":\"A256GCM\",\"data\":\"${PLAINTEXT_B64}\"}")" \
  "400" "Unsupported alg"

echo "==> A9: Non-existent kid returns 404"
FAKE_PROT=$(b64url_encode '{"alg":"dir","enc":"A256GCM","kid":"does-not-exist"}')
assert_status \
  "$(crypto_status "decrypt" "{\"protected\":\"${FAKE_PROT}\",\"encrypted_key\":\"\",\"iv\":\"${IV_AAD}\",\"ciphertext\":\"${CT_AAD}\",\"tag\":\"${TAG_AAD}\"}")" \
  "404" "Non-existent kid"

# ── Section B: Sign / Verify ──────────────────────────────────────────────────

run_sign_verify() {
  local priv_kid="$1" alg="$2"
  local payload_b64 sign_resp protected signature ver_resp

  payload_b64=$(b64url_encode "sign me: ${alg}")
  sign_resp=$(crypto_post "sign" \
    "{\"kid\":\"${priv_kid}\",\"alg\":\"${alg}\",\"data\":\"${payload_b64}\"}")
  protected=$(json_str "$sign_resp" "protected")
  signature=$(json_str "$sign_resp" "signature")

  # Happy path
  ver_resp=$(crypto_post "verify" \
    "{\"protected\":\"${protected}\",\"data\":\"${payload_b64}\",\"signature\":\"${signature}\"}")
  assert_eq "$(json_bool "${ver_resp}" "valid")" "true" "${alg} sign/verify round-trip"

  # Tampered data → valid=false
  local tampered_b64
  tampered_b64=$(b64url_encode "tampered payload for ${alg}")
  ver_resp=$(crypto_post "verify" \
    "{\"protected\":\"${protected}\",\"data\":\"${tampered_b64}\",\"signature\":\"${signature}\"}")
  assert_eq "$(json_bool "${ver_resp}" "valid")" "false" "${alg} tampered data → invalid"

  # Corrupted signature → valid=false
  local bad_sig bad_char
  if [ "${signature:0:1}" = "A" ]; then bad_char="B"; else bad_char="A"; fi
  bad_sig="${bad_char}${signature:1}"
  ver_resp=$(crypto_post "verify" \
    "{\"protected\":\"${protected}\",\"data\":\"${payload_b64}\",\"signature\":\"${bad_sig}\"}")
  assert_eq "$(json_bool "${ver_resp}" "valid")" "false" "${alg} corrupted signature → invalid"
}

echo ""
echo "==> Section B: Sign / Verify"
echo "==> B1: RS256 round-trip + tamper checks"
run_sign_verify "$RSA_PRIV_UID" "RS256"
echo "==> B2: ES256 round-trip + tamper checks"
run_sign_verify "$EC_PRIV_UID" "ES256"

echo "==> B3: Unknown alg returns 400"
assert_status \
  "$(crypto_status "sign" "{\"kid\":\"${RSA_PRIV_UID}\",\"alg\":\"UNKNOWN\",\"data\":\"${PLAINTEXT_B64}\"}")" \
  "400" "Unknown sign alg"

# ── Section C: MAC ────────────────────────────────────────────────────────────

echo ""
echo "==> Section C: MAC"
MAC_DATA_B64=$(b64url_encode "mac test message")

echo "==> C1: HS256 compute + verify round-trip"
MAC_COMPUTE=$(crypto_post "mac" \
  "{\"kid\":\"${HMAC256_KID}\",\"alg\":\"HS256\",\"data\":\"${MAC_DATA_B64}\"}")
MAC_VALUE=$(json_str "$MAC_COMPUTE" "mac")
MAC_VER=$(crypto_post "mac" \
  "{\"kid\":\"${HMAC256_KID}\",\"alg\":\"HS256\",\"data\":\"${MAC_DATA_B64}\",\"mac\":\"${MAC_VALUE}\"}")
assert_eq "$(json_bool "${MAC_VER}" "valid")" "true" "HS256 compute + verify"

echo "==> C2: HS256 tampered data → invalid"
WRONG_DATA_B64=$(b64url_encode "different message")
MAC_WRONG=$(crypto_post "mac" \
  "{\"kid\":\"${HMAC256_KID}\",\"alg\":\"HS256\",\"data\":\"${WRONG_DATA_B64}\",\"mac\":\"${MAC_VALUE}\"}")
assert_eq "$(json_bool "${MAC_WRONG}" "valid")" "false" "HS256 tampered data"

echo "==> C3: HS256 corrupted mac → invalid"
if [ "${MAC_VALUE:0:1}" = "A" ]; then MAC_BAD_CHAR="B"; else MAC_BAD_CHAR="A"; fi
BAD_MAC="${MAC_BAD_CHAR}${MAC_VALUE:1}"
MAC_BAD=$(crypto_post "mac" \
  "{\"kid\":\"${HMAC256_KID}\",\"alg\":\"HS256\",\"data\":\"${MAC_DATA_B64}\",\"mac\":\"${BAD_MAC}\"}")
assert_eq "$(json_bool "${MAC_BAD}" "valid")" "false" "HS256 corrupted mac"

echo "==> C4: MAC with non-existent kid returns 404"
assert_status \
  "$(crypto_status "mac" "{\"kid\":\"no-such-key\",\"alg\":\"HS256\",\"data\":\"${MAC_DATA_B64}\"}")" \
  "404" "MAC non-existent kid"

# ── Section D: Error cases ────────────────────────────────────────────────────

echo ""
echo "==> Section D: Error cases"

echo "==> D1: Invalid base64url in data returns 400"
assert_status \
  "$(crypto_status "encrypt" "{\"kid\":\"${AES256_KID}\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"not!valid!!\"}")" \
  "400" "Invalid base64url"

echo "==> D2: Missing required field (kid) returns 400"
assert_status \
  "$(crypto_status "encrypt" "{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"${PLAINTEXT_B64}\"}")" \
  "400" "Missing kid"

echo "==> D3: Empty body returns 400"
assert_status \
  "$(crypto_status "encrypt" "{}")" \
  "400" "Empty body"

echo "==> D4: Error body has correct JSON schema"
ERR_RESP=$(crypto_post "encrypt" "{\"kid\":\"${AES256_KID}\",\"alg\":\"dir\",\"enc\":\"BOGUS\",\"data\":\"${PLAINTEXT_B64}\"}")
ERR_FIELD=$(json_str "$ERR_RESP" "error")
if [ -z "$ERR_FIELD" ]; then
  echo "FAIL [Error schema]: response missing 'error' field: ${ERR_RESP}" >&2
  exit 1
fi
echo "PASS: Error schema (error='${ERR_FIELD}')"

echo ""
echo "Phase 1 complete: all curl-based tests passed."

###############################################################################
# PHASE 2: JOSE interoperability tests (Python jwcrypto)
###############################################################################

echo ""
echo "==========================================="
echo "Phase 2: JOSE interoperability (jwcrypto)"
echo "==========================================="

# ── Python venv setup ────────────────────────────────────────────────────────

echo "==> Setting up Python virtualenv with jwcrypto..."
VENV_DIR="$(mktemp -d -t jose-interop-venv-XXXXXX)"
python3 -m venv "${VENV_DIR}"
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
pip install --quiet -r "${SCRIPT_DIR}/requirements-jose.txt"

python3 "${HELPER}" --help >/dev/null 2>&1 || {
  echo "ERROR: jose_interop_helper.py failed to load" >&2
  exit 1
}
echo "    Python venv OK ($(python3 --version), jwcrypto $(pip show jwcrypto | grep ^Version | awk '{print $2}'))"

# ── Import known symmetric keys via JOSE REST (for interop with known material)

echo ""
echo "==> Importing known symmetric keys via JOSE REST API..."

# Generate known key material and import via REST JWK
AES_KEY_HEX=$(python3 -c "import secrets; print(secrets.token_hex(32))")
AES_KEY_B64=$(python3 -c "
import binascii, base64
k = binascii.unhexlify('${AES_KEY_HEX}')
print(base64.urlsafe_b64encode(k).rstrip(b'=').decode(), end='')
")
AES_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"oct\",\"alg\":\"A256GCM\",\"k\":\"${AES_KEY_B64}\"}")
AES_KNOWN_KID=$(json_str "$AES_IMPORT_RESP" "kid")
echo "    AES-256 known key imported: ${AES_KNOWN_KID}"

AES128_KEY_HEX=$(python3 -c "import secrets; print(secrets.token_hex(16))")
AES128_KEY_B64=$(python3 -c "
import binascii, base64
k = binascii.unhexlify('${AES128_KEY_HEX}')
print(base64.urlsafe_b64encode(k).rstrip(b'=').decode(), end='')
")
AES128_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"oct\",\"alg\":\"A128GCM\",\"k\":\"${AES128_KEY_B64}\"}")
AES128_KNOWN_KID=$(json_str "$AES128_IMPORT_RESP" "kid")
echo "    AES-128 known key imported: ${AES128_KNOWN_KID}"

AES192_KEY_HEX=$(python3 -c "import secrets; print(secrets.token_hex(24))")
AES192_KEY_B64=$(python3 -c "
import binascii, base64
k = binascii.unhexlify('${AES192_KEY_HEX}')
print(base64.urlsafe_b64encode(k).rstrip(b'=').decode(), end='')
")
AES192_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"oct\",\"alg\":\"A192GCM\",\"k\":\"${AES192_KEY_B64}\"}")
AES192_KNOWN_KID=$(json_str "$AES192_IMPORT_RESP" "kid")
echo "    AES-192 known key imported: ${AES192_KNOWN_KID}"

# Known HMAC keys
HMAC256_KEY_HEX=$(python3 -c "import secrets; print(secrets.token_hex(32))")
HMAC256_KEY_B64=$(python3 -c "
import binascii, base64
k = binascii.unhexlify('${HMAC256_KEY_HEX}')
print(base64.urlsafe_b64encode(k).rstrip(b'=').decode(), end='')
")
HMAC256_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"${HMAC256_KEY_B64}\"}")
HMAC256_KNOWN_KID=$(json_str "$HMAC256_IMPORT_RESP" "kid")

HMAC384_KEY_HEX=$(python3 -c "import secrets; print(secrets.token_hex(48))")
HMAC384_KEY_B64=$(python3 -c "
import binascii, base64
k = binascii.unhexlify('${HMAC384_KEY_HEX}')
print(base64.urlsafe_b64encode(k).rstrip(b'=').decode(), end='')
")
HMAC384_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"oct\",\"alg\":\"HS384\",\"k\":\"${HMAC384_KEY_B64}\"}")
HMAC384_KNOWN_KID=$(json_str "$HMAC384_IMPORT_RESP" "kid")

HMAC512_KEY_HEX=$(python3 -c "import secrets; print(secrets.token_hex(64))")
HMAC512_KEY_B64=$(python3 -c "
import binascii, base64
k = binascii.unhexlify('${HMAC512_KEY_HEX}')
print(base64.urlsafe_b64encode(k).rstrip(b'=').decode(), end='')
")
HMAC512_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"oct\",\"alg\":\"HS512\",\"k\":\"${HMAC512_KEY_B64}\"}")
HMAC512_KNOWN_KID=$(json_str "$HMAC512_IMPORT_RESP" "kid")
echo "    HMAC-256/384/512 known keys imported OK"

# ── Export public/private DER for jwcrypto ────────────────────────────────────

echo ""
echo "==> Exporting keys as DER for jwcrypto interop..."

RSA_PUB_DER_HEX=$(export_key_der "${RSA_PUB_UID}")
echo "    RSA pub DER exported (${#RSA_PUB_DER_HEX} hex chars)"

EC_PUB_DER_HEX=$(export_key_der "${EC_PUB_UID}")
echo "    EC P-256 pub DER exported (${#EC_PUB_DER_HEX} hex chars)"

EC384_PUB_DER_HEX=$(export_key_der "${EC384_PUB_UID}")
echo "    EC P-384 pub DER exported (${#EC384_PUB_DER_HEX} hex chars)"

EC521_PUB_DER_HEX=$(export_key_der "${EC521_PUB_UID}")
echo "    EC P-521 pub DER exported (${#EC521_PUB_DER_HEX} hex chars)"

ED_PUB_DER_HEX=$(export_key_der "${ED_PUB_UID}")
echo "    Ed25519 pub DER exported (${#ED_PUB_DER_HEX} hex chars)"

RSA_PRIV_DER_HEX=$(export_key_der "${RSA_PRIV_UID}")
echo "    RSA priv DER exported (${#RSA_PRIV_DER_HEX} hex chars)"

EC_PRIV_DER_HEX=$(export_key_der "${EC_PRIV_UID}")
echo "    EC P-256 priv DER exported (${#EC_PRIV_DER_HEX} hex chars)"

EC384_PRIV_DER_HEX=$(export_key_der "${EC384_PRIV_UID}")
echo "    EC P-384 priv DER exported (${#EC384_PRIV_DER_HEX} hex chars)"

EC521_PRIV_DER_HEX=$(export_key_der "${EC521_PRIV_UID}")
echo "    EC P-521 priv DER exported (${#EC521_PRIV_DER_HEX} hex chars)"

ED_PRIV_DER_HEX=$(export_key_der "${ED_PRIV_UID}")
echo "    Ed25519 priv DER exported (${#ED_PRIV_DER_HEX} hex chars)"

###############################################################################
# ── Direction A: KMS sign → jwcrypto verify ───────────────────────────────────
###############################################################################

# Helper: KMS sign → jwcrypto verify for any algorithm
kms_sign_jwcrypto_verify() {
  local priv_kid="$1" alg="$2" pub_der_hex="$3" label="$4"
  local payload="JOSE interop test payload for ${alg}"
  local payload_b64 sign_resp sign_protected sign_signature compact verify_out

  payload_b64=$(b64url_encode "${payload}")
  sign_resp=$(crypto_post "sign" \
    "{\"kid\":\"${priv_kid}\",\"alg\":\"${alg}\",\"data\":\"${payload_b64}\"}")
  sign_protected=$(json_str "$sign_resp" "protected")
  sign_signature=$(json_str "$sign_resp" "signature")

  compact="${sign_protected}.${payload_b64}.${sign_signature}"

  verify_out=$(python3 "${HELPER}" verify-jws \
    --alg="${alg}" \
    --pub-der-hex="${pub_der_hex}" \
    --compact="${compact}" 2>&1) || true
  assert_eq "$(echo "${verify_out}" | head -1)" "valid=true" "${label}"
}

echo ""
echo "==> E1: JWS RS256 — KMS sign → jwcrypto verify"
kms_sign_jwcrypto_verify "$RSA_PRIV_UID" "RS256" "$RSA_PUB_DER_HEX" "E1: RS256 KMS sign → jwcrypto verify"

echo ""
echo "==> E2: JWS ES256 — KMS sign → jwcrypto verify"
kms_sign_jwcrypto_verify "$EC_PRIV_UID" "ES256" "$EC_PUB_DER_HEX" "E2: ES256 KMS sign → jwcrypto verify"

echo ""
echo "==> E6: JWS RS384 — KMS sign → jwcrypto verify"
kms_sign_jwcrypto_verify "$RSA_PRIV_UID" "RS384" "$RSA_PUB_DER_HEX" "E6: RS384 KMS sign → jwcrypto verify"

echo ""
echo "==> E7: JWS RS512 — KMS sign → jwcrypto verify"
kms_sign_jwcrypto_verify "$RSA_PRIV_UID" "RS512" "$RSA_PUB_DER_HEX" "E7: RS512 KMS sign → jwcrypto verify"

echo ""
echo "==> E8: JWS PS256 — KMS sign → jwcrypto verify"
kms_sign_jwcrypto_verify "$RSA_PRIV_UID" "PS256" "$RSA_PUB_DER_HEX" "E8: PS256 KMS sign → jwcrypto verify"

echo ""
echo "==> E9: JWS PS384 — KMS sign → jwcrypto verify"
kms_sign_jwcrypto_verify "$RSA_PRIV_UID" "PS384" "$RSA_PUB_DER_HEX" "E9: PS384 KMS sign → jwcrypto verify"

echo ""
echo "==> E10: JWS PS512 — KMS sign → jwcrypto verify"
kms_sign_jwcrypto_verify "$RSA_PRIV_UID" "PS512" "$RSA_PUB_DER_HEX" "E10: PS512 KMS sign → jwcrypto verify"

echo ""
echo "==> E11: JWS ES384 — KMS sign → jwcrypto verify"
kms_sign_jwcrypto_verify "$EC384_PRIV_UID" "ES384" "$EC384_PUB_DER_HEX" "E11: ES384 KMS sign → jwcrypto verify"

echo ""
echo "==> E12: JWS ES512 — KMS sign → jwcrypto verify"
kms_sign_jwcrypto_verify "$EC521_PRIV_UID" "ES512" "$EC521_PUB_DER_HEX" "E12: ES512 KMS sign → jwcrypto verify"

echo ""
echo "==> E18: JWS EdDSA — KMS sign → jwcrypto verify (non-FIPS)"
kms_sign_jwcrypto_verify "$ED_PRIV_UID" "EdDSA" "$ED_PUB_DER_HEX" "E18: EdDSA KMS sign → jwcrypto verify"

###############################################################################
# ── Direction C: jwcrypto sign → KMS verify ───────────────────────────────────
###############################################################################

# Helper: jwcrypto sign → KMS verify for any algorithm
jwcrypto_sign_kms_verify() {
  local priv_der_hex="$1" alg="$2" pub_kid="$3" label="$4"
  local payload="JOSE interop reverse test for ${alg}"
  # shellcheck disable=SC2034  # parts is kept for readability when destructuring the JWS
  local payload_b64 compact_jws parts protected signature ver_resp

  payload_b64=$(b64url_encode "${payload}")

  compact_jws=$(python3 "${HELPER}" sign-jws \
    --alg="${alg}" \
    --priv-der-hex="${priv_der_hex}" \
    --payload-b64url="${payload_b64}" \
    --kid="${pub_kid}")

  # Split compact JWS: header.payload.signature
  IFS='.' read -r protected _ signature <<<"${compact_jws}"

  ver_resp=$(crypto_post "verify" \
    "{\"protected\":\"${protected}\",\"data\":\"${payload_b64}\",\"signature\":\"${signature}\"}")
  assert_eq "$(json_bool "${ver_resp}" "valid")" "true" "${label}"
}

echo ""
echo "==> E13: JWS RS256 — jwcrypto sign → KMS verify"
jwcrypto_sign_kms_verify "$RSA_PRIV_DER_HEX" "RS256" "$RSA_PUB_UID" "E13: RS256 jwcrypto sign → KMS verify"

echo ""
echo "==> E14: JWS ES256 — jwcrypto sign → KMS verify"
jwcrypto_sign_kms_verify "$EC_PRIV_DER_HEX" "ES256" "$EC_PUB_UID" "E14: ES256 jwcrypto sign → KMS verify"

echo ""
echo "==> E15: JWS PS256 — jwcrypto sign → KMS verify"
jwcrypto_sign_kms_verify "$RSA_PRIV_DER_HEX" "PS256" "$RSA_PUB_UID" "E15: PS256 jwcrypto sign → KMS verify"

echo ""
echo "==> E16: JWS ES384 — jwcrypto sign → KMS verify"
jwcrypto_sign_kms_verify "$EC384_PRIV_DER_HEX" "ES384" "$EC384_PUB_UID" "E16: ES384 jwcrypto sign → KMS verify"

echo ""
echo "==> E17: JWS ES512 — jwcrypto sign → KMS verify"
jwcrypto_sign_kms_verify "$EC521_PRIV_DER_HEX" "ES512" "$EC521_PUB_UID" "E17: ES512 jwcrypto sign → KMS verify"

echo ""
echo "==> E18b: JWS EdDSA — jwcrypto sign → KMS verify (non-FIPS)"
jwcrypto_sign_kms_verify "$ED_PRIV_DER_HEX" "EdDSA" "$ED_PUB_UID" "E18b: EdDSA jwcrypto sign → KMS verify"

###############################################################################
# ── Direction A: KMS encrypt → jwcrypto decrypt (symmetric dir) ───────────────
###############################################################################

echo ""
echo "==> E3: JWE dir+A256GCM — KMS encrypt → jwcrypto decrypt"
JWE_PLAINTEXT="Encrypt me with AES-256-GCM via JOSE!"
JWE_PLAINTEXT_B64=$(b64url_encode "${JWE_PLAINTEXT}")
JWE_PLAINTEXT_HEX=$(python3 -c "print('${JWE_PLAINTEXT}'.encode().hex(), end='')")

ENC_RESP=$(crypto_post "encrypt" \
  "{\"kid\":\"${AES_KNOWN_KID}\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"${JWE_PLAINTEXT_B64}\"}")
ENC_PROTECTED=$(json_str "$ENC_RESP" "protected")
ENC_IV=$(json_str "$ENC_RESP" "iv")
ENC_CT=$(json_str "$ENC_RESP" "ciphertext")
ENC_TAG=$(json_str "$ENC_RESP" "tag")

DECRYPT_HEX=$(python3 "${HELPER}" decrypt-jwe \
  --key-hex="${AES_KEY_HEX}" \
  --protected="${ENC_PROTECTED}" \
  --iv="${ENC_IV}" \
  --ciphertext="${ENC_CT}" \
  --tag="${ENC_TAG}")
assert_eq "${DECRYPT_HEX}" "${JWE_PLAINTEXT_HEX}" "E3: A256GCM KMS encrypt → jwcrypto decrypt"

# ── Test E4: JWE dir+A128GCM — jwcrypto encrypt → KMS decrypt ────────────────

echo ""
echo "==> E4: JWE dir+A128GCM — jwcrypto encrypt → KMS decrypt"
E4_PLAINTEXT="Encrypt me with A128GCM from jwcrypto!"
E4_PLAINTEXT_HEX=$(python3 -c "print('${E4_PLAINTEXT}'.encode().hex(), end='')")

JWE_JSON=$(python3 "${HELPER}" encrypt-jwe \
  --key-hex="${AES128_KEY_HEX}" \
  --kid="${AES128_KNOWN_KID}" \
  --enc="A128GCM" \
  --plaintext-hex="${E4_PLAINTEXT_HEX}")

JWE_PROTECTED=$(json_str "$JWE_JSON" "protected")
JWE_IV=$(json_str "$JWE_JSON" "iv")
JWE_CT=$(json_str "$JWE_JSON" "ciphertext")
JWE_TAG=$(json_str "$JWE_JSON" "tag")

DEC_RESP=$(crypto_post "decrypt" \
  "{\"protected\":\"${JWE_PROTECTED}\",\"encrypted_key\":\"\",\"iv\":\"${JWE_IV}\",\"ciphertext\":\"${JWE_CT}\",\"tag\":\"${JWE_TAG}\"}")
DEC_DATA=$(json_str "$DEC_RESP" "data")

# Decode base64url → hex for comparison
DEC_RESULT=$(python3 -c "
import base64, sys
d = '${DEC_DATA}'
pad = (4 - len(d) % 4) % 4
print(base64.urlsafe_b64decode(d + '=' * pad).hex(), end='')
")
assert_eq "${DEC_RESULT}" "${E4_PLAINTEXT_HEX}" "E4: A128GCM jwcrypto encrypt → KMS decrypt"

# ── Test E19: JWE dir+A192GCM — KMS encrypt → jwcrypto decrypt ───────────────

echo ""
echo "==> E19: JWE dir+A192GCM — KMS encrypt → jwcrypto decrypt"
E19_PLAINTEXT="A192GCM interop test payload"
E19_PLAINTEXT_B64=$(b64url_encode "${E19_PLAINTEXT}")
E19_PLAINTEXT_HEX=$(python3 -c "print('${E19_PLAINTEXT}'.encode().hex(), end='')")

E19_ENC=$(crypto_post "encrypt" \
  "{\"kid\":\"${AES192_KNOWN_KID}\",\"alg\":\"dir\",\"enc\":\"A192GCM\",\"data\":\"${E19_PLAINTEXT_B64}\"}")
E19_P=$(json_str "$E19_ENC" "protected")
E19_IV=$(json_str "$E19_ENC" "iv")
E19_CT=$(json_str "$E19_ENC" "ciphertext")
E19_TAG=$(json_str "$E19_ENC" "tag")

E19_DEC=$(python3 "${HELPER}" decrypt-jwe \
  --key-hex="${AES192_KEY_HEX}" \
  --protected="${E19_P}" \
  --iv="${E19_IV}" \
  --ciphertext="${E19_CT}" \
  --tag="${E19_TAG}")
assert_eq "${E19_DEC}" "${E19_PLAINTEXT_HEX}" "E19: A192GCM KMS encrypt → jwcrypto decrypt"

# ── Test E20: JWE dir+A192GCM — jwcrypto encrypt → KMS decrypt ───────────────

echo ""
echo "==> E20: JWE dir+A192GCM — jwcrypto encrypt → KMS decrypt"
E20_PLAINTEXT="A192GCM reverse interop test"
E20_PLAINTEXT_HEX=$(python3 -c "print('${E20_PLAINTEXT}'.encode().hex(), end='')")

E20_JWE=$(python3 "${HELPER}" encrypt-jwe \
  --key-hex="${AES192_KEY_HEX}" \
  --kid="${AES192_KNOWN_KID}" \
  --enc="A192GCM" \
  --plaintext-hex="${E20_PLAINTEXT_HEX}")

E20_P=$(json_str "$E20_JWE" "protected")
E20_IV=$(json_str "$E20_JWE" "iv")
E20_CT=$(json_str "$E20_JWE" "ciphertext")
E20_TAG=$(json_str "$E20_JWE" "tag")

E20_DEC_RESP=$(crypto_post "decrypt" \
  "{\"protected\":\"${E20_P}\",\"encrypted_key\":\"\",\"iv\":\"${E20_IV}\",\"ciphertext\":\"${E20_CT}\",\"tag\":\"${E20_TAG}\"}")
E20_DATA=$(json_str "$E20_DEC_RESP" "data")
E20_RESULT=$(python3 -c "
import base64, sys
d = '${E20_DATA}'
pad = (4 - len(d) % 4) % 4
print(base64.urlsafe_b64decode(d + '=' * pad).hex(), end='')
")
assert_eq "${E20_RESULT}" "${E20_PLAINTEXT_HEX}" "E20: A192GCM jwcrypto encrypt → KMS decrypt"

# ── Test E21: JWE dir+A256GCM with AAD — KMS encrypt → jwcrypto decrypt ──────

echo ""
echo "==> E21: JWE dir+A256GCM with AAD — KMS encrypt → jwcrypto decrypt"
E21_PLAINTEXT="AAD interop payload"
E21_PLAINTEXT_B64=$(b64url_encode "${E21_PLAINTEXT}")
E21_PLAINTEXT_HEX=$(python3 -c "print('${E21_PLAINTEXT}'.encode().hex(), end='')")
E21_AAD_B64=$(b64url_encode "interop-aad-context")

E21_ENC=$(crypto_post "encrypt" \
  "{\"kid\":\"${AES_KNOWN_KID}\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"${E21_PLAINTEXT_B64}\",\"aad\":\"${E21_AAD_B64}\"}")
E21_P=$(json_str "$E21_ENC" "protected")
E21_IV=$(json_str "$E21_ENC" "iv")
E21_CT=$(json_str "$E21_ENC" "ciphertext")
E21_TAG=$(json_str "$E21_ENC" "tag")

E21_DEC=$(python3 "${HELPER}" decrypt-jwe \
  --key-hex="${AES_KEY_HEX}" \
  --protected="${E21_P}" \
  --iv="${E21_IV}" \
  --ciphertext="${E21_CT}" \
  --tag="${E21_TAG}" \
  --aad="${E21_AAD_B64}")
assert_eq "${E21_DEC}" "${E21_PLAINTEXT_HEX}" "E21: A256GCM+AAD KMS encrypt → jwcrypto decrypt"

# ── Test E22: JWE dir+A128GCM with AAD — jwcrypto encrypt → KMS decrypt ──────

echo ""
echo "==> E22: JWE dir+A128GCM with AAD — jwcrypto encrypt → KMS decrypt"
E22_PLAINTEXT="AAD reverse interop payload"
E22_PLAINTEXT_HEX=$(python3 -c "print('${E22_PLAINTEXT}'.encode().hex(), end='')")
E22_AAD_B64=$(b64url_encode "reverse-aad-context")

# jwcrypto encrypt-jwe doesn't support AAD directly, so we build it manually
E22_JWE=$(python3 -c "
import json, secrets, binascii, base64
from jwcrypto import jwe, jwk

key_hex = '${AES128_KEY_HEX}'
key_bytes = binascii.unhexlify(key_hex)
plaintext = binascii.unhexlify('${E22_PLAINTEXT_HEX}')
aad_b64 = '${E22_AAD_B64}'

key = jwk.JWK(kty='oct', k=base64.urlsafe_b64encode(key_bytes).rstrip(b'=').decode())

protected_header = json.dumps({'alg': 'dir', 'enc': 'A128GCM', 'kid': '${AES128_KNOWN_KID}'})

jwe_obj = jwe.JWE(plaintext, recipient=key, protected=protected_header, aad=aad_b64)
print(jwe_obj.serialize(compact=False))
")

E22_P=$(json_str "$E22_JWE" "protected")
E22_IV=$(json_str "$E22_JWE" "iv")
E22_CT=$(json_str "$E22_JWE" "ciphertext")
E22_TAG=$(json_str "$E22_JWE" "tag")
E22_AAD_FIELD=$(json_str "$E22_JWE" "aad")

E22_DEC_RESP=$(crypto_post "decrypt" \
  "{\"protected\":\"${E22_P}\",\"encrypted_key\":\"\",\"iv\":\"${E22_IV}\",\"ciphertext\":\"${E22_CT}\",\"tag\":\"${E22_TAG}\",\"aad\":\"${E22_AAD_FIELD}\"}")
E22_DATA=$(json_str "$E22_DEC_RESP" "data")
E22_RESULT=$(python3 -c "
import base64, sys
d = '${E22_DATA}'
pad = (4 - len(d) % 4) % 4
print(base64.urlsafe_b64decode(d + '=' * pad).hex(), end='')
")
assert_eq "${E22_RESULT}" "${E22_PLAINTEXT_HEX}" "E22: A128GCM+AAD jwcrypto encrypt → KMS decrypt"

###############################################################################
# ── Direction A/C: RSA-OAEP encryption interop ────────────────────────────────
###############################################################################

echo ""
echo "==> E23: JWE RSA-OAEP+A256GCM — KMS encrypt → jwcrypto decrypt"
E23_PLAINTEXT="RSA-OAEP interop test payload"
E23_PLAINTEXT_B64=$(b64url_encode "${E23_PLAINTEXT}")
E23_PLAINTEXT_HEX=$(python3 -c "print('${E23_PLAINTEXT}'.encode().hex(), end='')")

E23_ENC=$(crypto_post "encrypt" \
  "{\"kid\":\"${RSA_PUB_UID}\",\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\",\"data\":\"${E23_PLAINTEXT_B64}\"}")
E23_P=$(json_str "$E23_ENC" "protected")
E23_EK=$(json_str "$E23_ENC" "encrypted_key")
E23_IV=$(json_str "$E23_ENC" "iv")
E23_CT=$(json_str "$E23_ENC" "ciphertext")
E23_TAG=$(json_str "$E23_ENC" "tag")

E23_DEC=$(python3 "${HELPER}" decrypt-jwe-rsa \
  --priv-der-hex="${RSA_PRIV_DER_HEX}" \
  --protected="${E23_P}" \
  --encrypted-key="${E23_EK}" \
  --iv="${E23_IV}" \
  --ciphertext="${E23_CT}" \
  --tag="${E23_TAG}")
assert_eq "${E23_DEC}" "${E23_PLAINTEXT_HEX}" "E23: RSA-OAEP+A256GCM KMS encrypt → jwcrypto decrypt"

echo ""
echo "==> E24: JWE RSA-OAEP+A256GCM — jwcrypto encrypt → KMS decrypt"
E24_PLAINTEXT="RSA-OAEP reverse interop"
E24_PLAINTEXT_HEX=$(python3 -c "print('${E24_PLAINTEXT}'.encode().hex(), end='')")

E24_JWE=$(python3 "${HELPER}" encrypt-jwe-rsa \
  --pub-der-hex="${RSA_PUB_DER_HEX}" \
  --kid="${RSA_PRIV_UID}" \
  --alg="RSA-OAEP" \
  --enc="A256GCM" \
  --plaintext-hex="${E24_PLAINTEXT_HEX}")

E24_P=$(json_str "$E24_JWE" "protected")
E24_EK=$(json_str "$E24_JWE" "encrypted_key")
E24_IV=$(json_str "$E24_JWE" "iv")
E24_CT=$(json_str "$E24_JWE" "ciphertext")
E24_TAG=$(json_str "$E24_JWE" "tag")

E24_DEC_RESP=$(crypto_post "decrypt" \
  "{\"protected\":\"${E24_P}\",\"encrypted_key\":\"${E24_EK}\",\"iv\":\"${E24_IV}\",\"ciphertext\":\"${E24_CT}\",\"tag\":\"${E24_TAG}\"}")
E24_DATA=$(json_str "$E24_DEC_RESP" "data")
E24_RESULT=$(python3 -c "
import base64, sys
d = '${E24_DATA}'
pad = (4 - len(d) % 4) % 4
print(base64.urlsafe_b64decode(d + '=' * pad).hex(), end='')
")
assert_eq "${E24_RESULT}" "${E24_PLAINTEXT_HEX}" "E24: RSA-OAEP+A256GCM jwcrypto encrypt → KMS decrypt"

echo ""
echo "==> E25: JWE RSA-OAEP-256+A256GCM — KMS encrypt → jwcrypto decrypt"
E25_PLAINTEXT="RSA-OAEP-256 interop test"
E25_PLAINTEXT_B64=$(b64url_encode "${E25_PLAINTEXT}")
E25_PLAINTEXT_HEX=$(python3 -c "print('${E25_PLAINTEXT}'.encode().hex(), end='')")

E25_ENC=$(crypto_post "encrypt" \
  "{\"kid\":\"${RSA_PUB_UID}\",\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\",\"data\":\"${E25_PLAINTEXT_B64}\"}")
E25_P=$(json_str "$E25_ENC" "protected")
E25_EK=$(json_str "$E25_ENC" "encrypted_key")
E25_IV=$(json_str "$E25_ENC" "iv")
E25_CT=$(json_str "$E25_ENC" "ciphertext")
E25_TAG=$(json_str "$E25_ENC" "tag")

E25_DEC=$(python3 "${HELPER}" decrypt-jwe-rsa \
  --priv-der-hex="${RSA_PRIV_DER_HEX}" \
  --protected="${E25_P}" \
  --encrypted-key="${E25_EK}" \
  --iv="${E25_IV}" \
  --ciphertext="${E25_CT}" \
  --tag="${E25_TAG}")
assert_eq "${E25_DEC}" "${E25_PLAINTEXT_HEX}" "E25: RSA-OAEP-256+A256GCM KMS encrypt → jwcrypto decrypt"

echo ""
echo "==> E26: JWE RSA-OAEP-256+A256GCM — jwcrypto encrypt → KMS decrypt"
E26_PLAINTEXT="RSA-OAEP-256 reverse interop"
E26_PLAINTEXT_HEX=$(python3 -c "print('${E26_PLAINTEXT}'.encode().hex(), end='')")

E26_JWE=$(python3 "${HELPER}" encrypt-jwe-rsa \
  --pub-der-hex="${RSA_PUB_DER_HEX}" \
  --kid="${RSA_PRIV_UID}" \
  --alg="RSA-OAEP-256" \
  --enc="A256GCM" \
  --plaintext-hex="${E26_PLAINTEXT_HEX}")

E26_P=$(json_str "$E26_JWE" "protected")
E26_EK=$(json_str "$E26_JWE" "encrypted_key")
E26_IV=$(json_str "$E26_JWE" "iv")
E26_CT=$(json_str "$E26_JWE" "ciphertext")
E26_TAG=$(json_str "$E26_JWE" "tag")

E26_DEC_RESP=$(crypto_post "decrypt" \
  "{\"protected\":\"${E26_P}\",\"encrypted_key\":\"${E26_EK}\",\"iv\":\"${E26_IV}\",\"ciphertext\":\"${E26_CT}\",\"tag\":\"${E26_TAG}\"}")
E26_DATA=$(json_str "$E26_DEC_RESP" "data")
E26_RESULT=$(python3 -c "
import base64, sys
d = '${E26_DATA}'
pad = (4 - len(d) % 4) % 4
print(base64.urlsafe_b64decode(d + '=' * pad).hex(), end='')
")
assert_eq "${E26_RESULT}" "${E26_PLAINTEXT_HEX}" "E26: RSA-OAEP-256+A256GCM jwcrypto encrypt → KMS decrypt"

###############################################################################
# ── MAC interop ───────────────────────────────────────────────────────────────
###############################################################################

# Helper: KMS MAC compute → jwcrypto verify
kms_mac_jwcrypto_verify() {
  local kid="$1" alg="$2" key_hex="$3" label="$4"
  local data_msg="MAC interop data for ${alg}"
  local data_hex data_b64 compute_resp mac_value verify_out

  data_hex=$(python3 -c "print('${data_msg}'.encode().hex(), end='')")
  data_b64=$(b64url_encode "${data_msg}")

  compute_resp=$(crypto_post "mac" \
    "{\"kid\":\"${kid}\",\"alg\":\"${alg}\",\"data\":\"${data_b64}\"}")
  mac_value=$(json_str "$compute_resp" "mac")

  verify_out=$(python3 "${HELPER}" mac-verify \
    --alg="${alg}" \
    --key-hex="${key_hex}" \
    --data-hex="${data_hex}" \
    --mac-b64url="${mac_value}" 2>&1) || true
  assert_eq "$(echo "${verify_out}" | head -1)" "valid=true" "${label}"
}

# Helper: jwcrypto MAC compute → KMS verify
jwcrypto_mac_kms_verify() {
  local kid="$1" alg="$2" key_hex="$3" label="$4"
  local data_msg="MAC reverse interop for ${alg}"
  local data_hex data_b64 mac_value ver_resp

  data_hex=$(python3 -c "print('${data_msg}'.encode().hex(), end='')")
  data_b64=$(b64url_encode "${data_msg}")

  mac_value=$(python3 "${HELPER}" mac \
    --alg="${alg}" \
    --key-hex="${key_hex}" \
    --data-hex="${data_hex}")

  ver_resp=$(crypto_post "mac" \
    "{\"kid\":\"${kid}\",\"alg\":\"${alg}\",\"data\":\"${data_b64}\",\"mac\":\"${mac_value}\"}")
  assert_eq "$(json_bool "${ver_resp}" "valid")" "true" "${label}"
}

echo ""
echo "==> E27: HS256 — KMS compute → jwcrypto verify"
kms_mac_jwcrypto_verify "${HMAC256_KNOWN_KID}" "HS256" "${HMAC256_KEY_HEX}" "E27: HS256 KMS compute → jwcrypto verify"

echo ""
echo "==> E28: HS384 — KMS compute → jwcrypto verify"
kms_mac_jwcrypto_verify "${HMAC384_KNOWN_KID}" "HS384" "${HMAC384_KEY_HEX}" "E28: HS384 KMS compute → jwcrypto verify"

echo ""
echo "==> E29: HS512 — KMS compute → jwcrypto verify"
kms_mac_jwcrypto_verify "${HMAC512_KNOWN_KID}" "HS512" "${HMAC512_KEY_HEX}" "E29: HS512 KMS compute → jwcrypto verify"

echo ""
echo "==> E30: HS256 — jwcrypto compute → KMS verify"
jwcrypto_mac_kms_verify "${HMAC256_KNOWN_KID}" "HS256" "${HMAC256_KEY_HEX}" "E30: HS256 jwcrypto compute → KMS verify"

echo ""
echo "==> E31: HS384 — jwcrypto compute → KMS verify"
jwcrypto_mac_kms_verify "${HMAC384_KNOWN_KID}" "HS384" "${HMAC384_KEY_HEX}" "E31: HS384 jwcrypto compute → KMS verify"

echo ""
echo "==> E32: HS512 — jwcrypto compute → KMS verify"
jwcrypto_mac_kms_verify "${HMAC512_KNOWN_KID}" "HS512" "${HMAC512_KEY_HEX}" "E32: HS512 jwcrypto compute → KMS verify"

# ── Test E5: RFC 7515 §A.1 HS256 known-answer cross-validation ───────────────

echo ""
echo "==> E5: RFC 7515 §A.1 HS256 known-answer (jwcrypto)"

RFC_KEY_B64="AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
SIGNING_INPUT="eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
SIGNING_INPUT_HEX=$(python3 -c "print('${SIGNING_INPUT}'.encode().hex(), end='')")

JWCRYPTO_MAC=$(python3 "${HELPER}" mac-sha256 \
  --key-b64url="${RFC_KEY_B64}" \
  --data-hex="${SIGNING_INPUT_HEX}")

EXPECTED_MAC="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
assert_eq "${JWCRYPTO_MAC}" "${EXPECTED_MAC}" "E5: RFC 7515 §A.1 HS256 jwcrypto known-answer"

###############################################################################
# ── Direction B: jwcrypto generates key → import via REST → interop ───────────
###############################################################################

echo ""
echo "==========================================="
echo "Direction B: jwcrypto key generation → JOSE REST import"
echo "==========================================="

# ── E40: jwcrypto generates EC P-256 → import → jwcrypto signs → KMS verifies

echo ""
echo "==> E40: EC P-256 — jwcrypto generates → REST import → jwcrypto signs → KMS verifies"

E40_JWK=$(python3 "${HELPER}" generate-jwk --kty=EC --crv=P-256)
E40_D=$(printf '%s' "$E40_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['d'], end='')")
E40_X=$(printf '%s' "$E40_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['x'], end='')")
E40_Y=$(printf '%s' "$E40_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['y'], end='')")

E40_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"EC\",\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"${E40_D}\",\"x\":\"${E40_X}\",\"y\":\"${E40_Y}\"}")
E40_KID=$(json_str "$E40_IMPORT_RESP" "kid")
E40_KID_PUB=$(json_str "$E40_IMPORT_RESP" "kid_public")

# jwcrypto signs with private key material
E40_PAYLOAD_B64=$(b64url_encode "Direction B EC P-256 test")
E40_PRIV_DER_HEX=$(export_key_der "${E40_KID}")
E40_COMPACT=$(python3 "${HELPER}" sign-jws \
  --alg=ES256 \
  --priv-der-hex="${E40_PRIV_DER_HEX}" \
  --payload-b64url="${E40_PAYLOAD_B64}" \
  --kid="${E40_KID_PUB}")

IFS='.' read -r E40_PROT _ E40_SIG <<<"${E40_COMPACT}"
E40_VER=$(crypto_post "verify" \
  "{\"protected\":\"${E40_PROT}\",\"data\":\"${E40_PAYLOAD_B64}\",\"signature\":\"${E40_SIG}\"}")
assert_eq "$(json_bool "${E40_VER}" "valid")" "true" "E40: EC P-256 jwcrypto-gen → import → sign → KMS verify"

# ── E41: jwcrypto generates EC P-384 → import → jwcrypto signs → KMS verifies

echo ""
echo "==> E41: EC P-384 — jwcrypto generates → REST import → jwcrypto signs → KMS verifies"

E41_JWK=$(python3 "${HELPER}" generate-jwk --kty=EC --crv=P-384)
E41_D=$(printf '%s' "$E41_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['d'], end='')")
E41_X=$(printf '%s' "$E41_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['x'], end='')")
E41_Y=$(printf '%s' "$E41_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['y'], end='')")

E41_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"EC\",\"alg\":\"ES384\",\"crv\":\"P-384\",\"d\":\"${E41_D}\",\"x\":\"${E41_X}\",\"y\":\"${E41_Y}\"}")
E41_KID=$(json_str "$E41_IMPORT_RESP" "kid")
E41_KID_PUB=$(json_str "$E41_IMPORT_RESP" "kid_public")

E41_PAYLOAD_B64=$(b64url_encode "Direction B EC P-384 test")
E41_PRIV_DER_HEX=$(export_key_der "${E41_KID}")
E41_COMPACT=$(python3 "${HELPER}" sign-jws \
  --alg=ES384 \
  --priv-der-hex="${E41_PRIV_DER_HEX}" \
  --payload-b64url="${E41_PAYLOAD_B64}" \
  --kid="${E41_KID_PUB}")

IFS='.' read -r E41_PROT _ E41_SIG <<<"${E41_COMPACT}"
E41_VER=$(crypto_post "verify" \
  "{\"protected\":\"${E41_PROT}\",\"data\":\"${E41_PAYLOAD_B64}\",\"signature\":\"${E41_SIG}\"}")
assert_eq "$(json_bool "${E41_VER}" "valid")" "true" "E41: EC P-384 jwcrypto-gen → import → sign → KMS verify"

# ── E42: jwcrypto generates EC P-521 → import → jwcrypto signs → KMS verifies

echo ""
echo "==> E42: EC P-521 — jwcrypto generates → REST import → jwcrypto signs → KMS verifies"

E42_JWK=$(python3 "${HELPER}" generate-jwk --kty=EC --crv=P-521)
E42_D=$(printf '%s' "$E42_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['d'], end='')")
E42_X=$(printf '%s' "$E42_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['x'], end='')")
E42_Y=$(printf '%s' "$E42_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['y'], end='')")

E42_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"EC\",\"alg\":\"ES512\",\"crv\":\"P-521\",\"d\":\"${E42_D}\",\"x\":\"${E42_X}\",\"y\":\"${E42_Y}\"}")
E42_KID=$(json_str "$E42_IMPORT_RESP" "kid")
E42_KID_PUB=$(json_str "$E42_IMPORT_RESP" "kid_public")

E42_PAYLOAD_B64=$(b64url_encode "Direction B EC P-521 test")
E42_PRIV_DER_HEX=$(export_key_der "${E42_KID}")
E42_COMPACT=$(python3 "${HELPER}" sign-jws \
  --alg=ES512 \
  --priv-der-hex="${E42_PRIV_DER_HEX}" \
  --payload-b64url="${E42_PAYLOAD_B64}" \
  --kid="${E42_KID_PUB}")

IFS='.' read -r E42_PROT _ E42_SIG <<<"${E42_COMPACT}"
E42_VER=$(crypto_post "verify" \
  "{\"protected\":\"${E42_PROT}\",\"data\":\"${E42_PAYLOAD_B64}\",\"signature\":\"${E42_SIG}\"}")
assert_eq "$(json_bool "${E42_VER}" "valid")" "true" "E42: EC P-521 jwcrypto-gen → import → sign → KMS verify"

# ── E43: jwcrypto generates RSA → import → jwcrypto signs → KMS verifies

echo ""
echo "==> E43: RSA — jwcrypto generates → REST import → jwcrypto signs → KMS verifies"

E43_JWK=$(python3 "${HELPER}" generate-jwk --kty=RSA --bits=2048)
E43_D=$(printf '%s' "$E43_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['d'], end='')")
E43_N=$(printf '%s' "$E43_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['n'], end='')")
E43_E=$(printf '%s' "$E43_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['e'], end='')")
E43_P=$(printf '%s' "$E43_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['p'], end='')")
E43_Q=$(printf '%s' "$E43_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['q'], end='')")
E43_DP=$(printf '%s' "$E43_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['dp'], end='')")
E43_DQ=$(printf '%s' "$E43_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['dq'], end='')")
E43_QI=$(printf '%s' "$E43_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['qi'], end='')")

E43_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"n\":\"${E43_N}\",\"e\":\"${E43_E}\",\"d\":\"${E43_D}\",\"p\":\"${E43_P}\",\"q\":\"${E43_Q}\",\"dp\":\"${E43_DP}\",\"dq\":\"${E43_DQ}\",\"qi\":\"${E43_QI}\"}")
E43_KID=$(json_str "$E43_IMPORT_RESP" "kid")
E43_KID_PUB=$(json_str "$E43_IMPORT_RESP" "kid_public")

E43_PAYLOAD_B64=$(b64url_encode "Direction B RSA test")
E43_PRIV_DER_HEX=$(export_key_der "${E43_KID}")
E43_COMPACT=$(python3 "${HELPER}" sign-jws \
  --alg=RS256 \
  --priv-der-hex="${E43_PRIV_DER_HEX}" \
  --payload-b64url="${E43_PAYLOAD_B64}" \
  --kid="${E43_KID_PUB}")

IFS='.' read -r E43_PROT _ E43_SIG <<<"${E43_COMPACT}"
E43_VER=$(crypto_post "verify" \
  "{\"protected\":\"${E43_PROT}\",\"data\":\"${E43_PAYLOAD_B64}\",\"signature\":\"${E43_SIG}\"}")
assert_eq "$(json_bool "${E43_VER}" "valid")" "true" "E43: RSA jwcrypto-gen → import → sign → KMS verify"

# ── E44: jwcrypto generates RSA → import → jwcrypto encrypts → KMS decrypts

echo ""
echo "==> E44: RSA — jwcrypto generates → REST import → jwcrypto encrypts (RSA-OAEP) → KMS decrypts"

# Reuse E43 key for encryption
E44_PUB_DER_HEX=$(export_key_der "${E43_KID_PUB}")

E44_PLAINTEXT="Direction B RSA encryption test"
E44_PLAINTEXT_HEX=$(python3 -c "print('${E44_PLAINTEXT}'.encode().hex(), end='')")

E44_JWE=$(python3 "${HELPER}" encrypt-jwe-rsa \
  --pub-der-hex="${E44_PUB_DER_HEX}" \
  --kid="${E43_KID}" \
  --alg="RSA-OAEP-256" \
  --enc="A256GCM" \
  --plaintext-hex="${E44_PLAINTEXT_HEX}")

E44_P=$(json_str "$E44_JWE" "protected")
E44_EK=$(json_str "$E44_JWE" "encrypted_key")
E44_IV=$(json_str "$E44_JWE" "iv")
E44_CT=$(json_str "$E44_JWE" "ciphertext")
E44_TAG=$(json_str "$E44_JWE" "tag")

E44_DEC_RESP=$(crypto_post "decrypt" \
  "{\"protected\":\"${E44_P}\",\"encrypted_key\":\"${E44_EK}\",\"iv\":\"${E44_IV}\",\"ciphertext\":\"${E44_CT}\",\"tag\":\"${E44_TAG}\"}")
E44_DATA=$(json_str "$E44_DEC_RESP" "data")
E44_RESULT=$(python3 -c "
import base64, sys
d = '${E44_DATA}'
pad = (4 - len(d) % 4) % 4
print(base64.urlsafe_b64decode(d + '=' * pad).hex(), end='')
")
assert_eq "${E44_RESULT}" "${E44_PLAINTEXT_HEX}" "E44: RSA jwcrypto-gen → import → encrypt → KMS decrypt"

# ── E45: jwcrypto generates oct → import → jwcrypto encrypts → KMS decrypts

echo ""
echo "==> E45: oct — jwcrypto generates → REST import → jwcrypto encrypts (dir+A256GCM) → KMS decrypts"

E45_JWK=$(python3 "${HELPER}" generate-jwk --kty=oct --bits=256)
E45_K=$(printf '%s' "$E45_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['k'], end='')")
E45_KEY_HEX=$(python3 -c "
import base64
k = '${E45_K}'
k += '=' * (4 - len(k) % 4)
print(base64.urlsafe_b64decode(k).hex(), end='')
")

E45_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"oct\",\"alg\":\"A256GCM\",\"k\":\"${E45_K}\"}")
E45_KID=$(json_str "$E45_IMPORT_RESP" "kid")

E45_PLAINTEXT="Direction B symmetric encryption test"
E45_PLAINTEXT_HEX=$(python3 -c "print('${E45_PLAINTEXT}'.encode().hex(), end='')")

E45_JWE=$(python3 "${HELPER}" encrypt-jwe \
  --key-hex="${E45_KEY_HEX}" \
  --kid="${E45_KID}" \
  --enc="A256GCM" \
  --plaintext-hex="${E45_PLAINTEXT_HEX}")

E45_P=$(json_str "$E45_JWE" "protected")
E45_IV=$(json_str "$E45_JWE" "iv")
E45_CT=$(json_str "$E45_JWE" "ciphertext")
E45_TAG=$(json_str "$E45_JWE" "tag")

E45_DEC_RESP=$(crypto_post "decrypt" \
  "{\"protected\":\"${E45_P}\",\"encrypted_key\":\"\",\"iv\":\"${E45_IV}\",\"ciphertext\":\"${E45_CT}\",\"tag\":\"${E45_TAG}\"}")
E45_DATA=$(json_str "$E45_DEC_RESP" "data")
E45_RESULT=$(python3 -c "
import base64, sys
d = '${E45_DATA}'
pad = (4 - len(d) % 4) % 4
print(base64.urlsafe_b64decode(d + '=' * pad).hex(), end='')
")
assert_eq "${E45_RESULT}" "${E45_PLAINTEXT_HEX}" "E45: oct jwcrypto-gen → import → encrypt → KMS decrypt"

# ── E46: jwcrypto generates oct → import → jwcrypto MACs → KMS verifies

echo ""
echo "==> E46: oct — jwcrypto generates → REST import → jwcrypto MACs → KMS verifies"

E46_JWK=$(python3 "${HELPER}" generate-jwk --kty=oct --bits=256)
E46_K=$(printf '%s' "$E46_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['k'], end='')")
E46_KEY_HEX=$(python3 -c "
import base64
k = '${E46_K}'
k += '=' * (4 - len(k) % 4)
print(base64.urlsafe_b64decode(k).hex(), end='')
")

E46_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"${E46_K}\"}")
E46_KID=$(json_str "$E46_IMPORT_RESP" "kid")

E46_MSG="Direction B HMAC interop test"
E46_DATA_HEX=$(python3 -c "print('${E46_MSG}'.encode().hex(), end='')")
E46_DATA_B64=$(b64url_encode "${E46_MSG}")

E46_MAC_B64=$(python3 "${HELPER}" mac \
  --alg=HS256 \
  --key-hex="${E46_KEY_HEX}" \
  --data-hex="${E46_DATA_HEX}")

E46_VER=$(crypto_post "mac" \
  "{\"kid\":\"${E46_KID}\",\"alg\":\"HS256\",\"data\":\"${E46_DATA_B64}\",\"mac\":\"${E46_MAC_B64}\"}")
assert_eq "$(json_bool "${E46_VER}" "valid")" "true" "E46: oct jwcrypto-gen → import → MAC → KMS verify"

# ── E47: jwcrypto generates Ed25519 → import → jwcrypto signs → KMS verifies

echo ""
echo "==> E47: Ed25519 — jwcrypto generates → REST import → jwcrypto signs → KMS verifies (non-FIPS)"

E47_JWK=$(python3 "${HELPER}" generate-jwk --kty=OKP --crv=Ed25519)
E47_D=$(printf '%s' "$E47_JWK" | python3 -c "import sys,json; print(json.load(sys.stdin)['d'], end='')")

E47_IMPORT_RESP=$(crypto_post "keys" \
  "{\"kty\":\"OKP\",\"alg\":\"EdDSA\",\"crv\":\"Ed25519\",\"d\":\"${E47_D}\"}")
E47_KID=$(json_str "$E47_IMPORT_RESP" "kid")
E47_KID_PUB=$(json_str "$E47_IMPORT_RESP" "kid_public")

E47_PAYLOAD_B64=$(b64url_encode "Direction B Ed25519 test")
E47_PRIV_DER_HEX=$(export_key_der "${E47_KID}")
E47_COMPACT=$(python3 "${HELPER}" sign-jws \
  --alg=EdDSA \
  --priv-der-hex="${E47_PRIV_DER_HEX}" \
  --payload-b64url="${E47_PAYLOAD_B64}" \
  --kid="${E47_KID_PUB}")

IFS='.' read -r E47_PROT _ E47_SIG <<<"${E47_COMPACT}"
E47_VER=$(crypto_post "verify" \
  "{\"protected\":\"${E47_PROT}\",\"data\":\"${E47_PAYLOAD_B64}\",\"signature\":\"${E47_SIG}\"}")
assert_eq "$(json_bool "${E47_VER}" "valid")" "true" "E47: Ed25519 jwcrypto-gen → import → sign → KMS verify"

###############################################################################
# ── Key generation + interop via REST ─────────────────────────────────────────
###############################################################################

echo ""
echo "==> E33: Key generate (RSA) via REST → sign → jwcrypto verify"
E33_RESP=$(crypto_post "keys" '{"kty":"RSA","alg":"RS256"}')
E33_KID=$(json_str "$E33_RESP" "kid")
E33_KID_PUB=$(json_str "$E33_RESP" "kid_public")
E33_PUB_DER=$(export_key_der "${E33_KID_PUB}")

E33_PAYLOAD_B64=$(b64url_encode "REST key generation interop test")
E33_SIGN=$(crypto_post "sign" \
  "{\"kid\":\"${E33_KID}\",\"alg\":\"RS256\",\"data\":\"${E33_PAYLOAD_B64}\"}")
E33_PROT=$(json_str "$E33_SIGN" "protected")
E33_SIG=$(json_str "$E33_SIGN" "signature")
E33_COMPACT="${E33_PROT}.${E33_PAYLOAD_B64}.${E33_SIG}"

E33_VERIFY=$(python3 "${HELPER}" verify-jws \
  --alg=RS256 \
  --pub-der-hex="${E33_PUB_DER}" \
  --compact="${E33_COMPACT}" 2>&1) || true
assert_eq "$(echo "${E33_VERIFY}" | head -1)" "valid=true" "E33: REST RSA keygen → sign → jwcrypto verify"

echo ""
echo "==> E34: Key generate (EC P-256) via REST → sign → jwcrypto verify"
E34_RESP=$(crypto_post "keys" '{"kty":"EC","alg":"ES256","crv":"P-256"}')
E34_KID=$(json_str "$E34_RESP" "kid")
E34_KID_PUB=$(json_str "$E34_RESP" "kid_public")
E34_PUB_DER=$(export_key_der "${E34_KID_PUB}")

E34_PAYLOAD_B64=$(b64url_encode "REST EC key generation interop test")
E34_SIGN=$(crypto_post "sign" \
  "{\"kid\":\"${E34_KID}\",\"alg\":\"ES256\",\"data\":\"${E34_PAYLOAD_B64}\"}")
E34_PROT=$(json_str "$E34_SIGN" "protected")
E34_SIG=$(json_str "$E34_SIGN" "signature")
E34_COMPACT="${E34_PROT}.${E34_PAYLOAD_B64}.${E34_SIG}"

E34_VERIFY=$(python3 "${HELPER}" verify-jws \
  --alg=ES256 \
  --pub-der-hex="${E34_PUB_DER}" \
  --compact="${E34_COMPACT}" 2>&1) || true
assert_eq "$(echo "${E34_VERIFY}" | head -1)" "valid=true" "E34: REST EC keygen → sign → jwcrypto verify"

echo ""
echo "==> E35: Key generate (oct/A256GCM) via REST → encrypt → jwcrypto decrypt"
E35_RESP=$(crypto_post "keys" '{"kty":"oct","alg":"A256GCM"}')
E35_KID=$(json_str "$E35_RESP" "kid")

E35_PT="Symmetric key gen interop test"
E35_PT_B64=$(b64url_encode "${E35_PT}")
E35_PT_HEX=$(python3 -c "print('${E35_PT}'.encode().hex(), end='')")

E35_ENC=$(crypto_post "encrypt" \
  "{\"kid\":\"${E35_KID}\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"${E35_PT_B64}\"}")
E35_P=$(json_str "$E35_ENC" "protected")
E35_IV=$(json_str "$E35_ENC" "iv")
E35_CT=$(json_str "$E35_ENC" "ciphertext")
E35_TAG=$(json_str "$E35_ENC" "tag")

# Export the symmetric key material for jwcrypto decryption
E35_KEY_HEX=$(export_symmetric_key_raw "${E35_KID}")

E35_DEC=$(python3 "${HELPER}" decrypt-jwe \
  --key-hex="${E35_KEY_HEX}" \
  --protected="${E35_P}" \
  --iv="${E35_IV}" \
  --ciphertext="${E35_CT}" \
  --tag="${E35_TAG}")
assert_eq "${E35_DEC}" "${E35_PT_HEX}" "E35: REST oct keygen → encrypt → jwcrypto decrypt"

echo ""
echo "==> E36: Key import (JWK oct) via REST → encrypt → jwcrypto decrypt"
E36_KEY_HEX=$(python3 -c "import secrets; print(secrets.token_hex(32))")
E36_KEY_B64=$(python3 -c "
import binascii, base64
k = binascii.unhexlify('${E36_KEY_HEX}')
print(base64.urlsafe_b64encode(k).rstrip(b'=').decode(), end='')
")

E36_RESP=$(crypto_post "keys" \
  "{\"kty\":\"oct\",\"alg\":\"A256GCM\",\"k\":\"${E36_KEY_B64}\"}")
E36_KID=$(json_str "$E36_RESP" "kid")

E36_PT="JWK import interop payload"
E36_PT_B64=$(b64url_encode "${E36_PT}")
E36_PT_HEX=$(python3 -c "print('${E36_PT}'.encode().hex(), end='')")

E36_ENC=$(crypto_post "encrypt" \
  "{\"kid\":\"${E36_KID}\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"${E36_PT_B64}\"}")
E36_P=$(json_str "$E36_ENC" "protected")
E36_IV=$(json_str "$E36_ENC" "iv")
E36_CT=$(json_str "$E36_ENC" "ciphertext")
E36_TAG=$(json_str "$E36_ENC" "tag")

E36_DEC=$(python3 "${HELPER}" decrypt-jwe \
  --key-hex="${E36_KEY_HEX}" \
  --protected="${E36_P}" \
  --iv="${E36_IV}" \
  --ciphertext="${E36_CT}" \
  --tag="${E36_TAG}")
assert_eq "${E36_DEC}" "${E36_PT_HEX}" "E36: REST JWK oct import → encrypt → jwcrypto decrypt"

###############################################################################
# ── Key unwrap via REST ───────────────────────────────────────────────────────
###############################################################################

echo ""
echo "==> E37: Unwrap — jwcrypto wraps CEK (RSA-OAEP-256) → KMS unwrap → decrypt"

# Generate a CEK (AES-256 = 32 bytes)
E37_CEK_HEX=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Wrap CEK with RSA public key using jwcrypto
E37_WRAPPED_B64=$(python3 "${HELPER}" wrap-cek-rsa \
  --pub-der-hex="${RSA_PUB_DER_HEX}" \
  --cek-hex="${E37_CEK_HEX}" \
  --alg="RSA-OAEP-256")

# Build JWE protected header and unwrap via KMS REST API
E37_HDR_JSON="{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\",\"kid\":\"${RSA_PRIV_UID}\"}"
E37_HDR_B64=$(printf '%s' "$E37_HDR_JSON" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
E37_UNWRAP_RESP=$(crypto_post "keys/unwrap" \
  "{\"protected\":\"${E37_HDR_B64}\",\"encrypted_key\":\"${E37_WRAPPED_B64}\"}")
E37_UNWRAP_KID=$(json_str "$E37_UNWRAP_RESP" "kid")

# Encrypt with the unwrapped key
E37_PT="Unwrap interop payload"
E37_PT_B64=$(b64url_encode "${E37_PT}")
E37_PT_HEX=$(python3 -c "print('${E37_PT}'.encode().hex(), end='')")

E37_ENC=$(crypto_post "encrypt" \
  "{\"kid\":\"${E37_UNWRAP_KID}\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"${E37_PT_B64}\"}")
E37_P=$(json_str "$E37_ENC" "protected")
E37_IV=$(json_str "$E37_ENC" "iv")
E37_CT=$(json_str "$E37_ENC" "ciphertext")
E37_TAG=$(json_str "$E37_ENC" "tag")

# Decrypt with jwcrypto using the original CEK
E37_DEC=$(python3 "${HELPER}" decrypt-jwe \
  --key-hex="${E37_CEK_HEX}" \
  --protected="${E37_P}" \
  --iv="${E37_IV}" \
  --ciphertext="${E37_CT}" \
  --tag="${E37_TAG}")
assert_eq "${E37_DEC}" "${E37_PT_HEX}" "E37: jwcrypto wrap CEK → KMS unwrap → encrypt → jwcrypto decrypt"

echo ""
echo "==> E38: Unwrap — jwcrypto wraps CEK (RSA-OAEP) → KMS unwrap → decrypt"

E38_CEK_HEX=$(python3 -c "import secrets; print(secrets.token_hex(32))")

E38_WRAPPED_B64=$(python3 "${HELPER}" wrap-cek-rsa \
  --pub-der-hex="${RSA_PUB_DER_HEX}" \
  --cek-hex="${E38_CEK_HEX}" \
  --alg="RSA-OAEP")

# Build JWE protected header and unwrap via KMS REST API
E38_HDR_JSON="{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\",\"kid\":\"${RSA_PRIV_UID}\"}"
E38_HDR_B64=$(printf '%s' "$E38_HDR_JSON" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
E38_UNWRAP_RESP=$(crypto_post "keys/unwrap" \
  "{\"protected\":\"${E38_HDR_B64}\",\"encrypted_key\":\"${E38_WRAPPED_B64}\"}")
E38_UNWRAP_KID=$(json_str "$E38_UNWRAP_RESP" "kid")

E38_PT="RSA-OAEP unwrap test"
E38_PT_B64=$(b64url_encode "${E38_PT}")
E38_PT_HEX=$(python3 -c "print('${E38_PT}'.encode().hex(), end='')")

E38_ENC=$(crypto_post "encrypt" \
  "{\"kid\":\"${E38_UNWRAP_KID}\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"${E38_PT_B64}\"}")
E38_P=$(json_str "$E38_ENC" "protected")
E38_IV=$(json_str "$E38_ENC" "iv")
E38_CT=$(json_str "$E38_ENC" "ciphertext")
E38_TAG=$(json_str "$E38_ENC" "tag")

E38_DEC=$(python3 "${HELPER}" decrypt-jwe \
  --key-hex="${E38_CEK_HEX}" \
  --protected="${E38_P}" \
  --iv="${E38_IV}" \
  --ciphertext="${E38_CT}" \
  --tag="${E38_TAG}")
assert_eq "${E38_DEC}" "${E38_PT_HEX}" "E38: jwcrypto wrap CEK (RSA-OAEP) → KMS unwrap → encrypt → jwcrypto decrypt"

###############################################################################
# ── Key deletion via REST ─────────────────────────────────────────────────────
###############################################################################

echo ""
echo "==> E39: Key delete via REST → confirm gone"
E39_RESP=$(crypto_post "keys" '{"kty":"oct","alg":"A128GCM"}')
E39_KID=$(json_str "$E39_RESP" "kid")

# Verify we can encrypt with it
E39_ENC_STATUS=$(crypto_status "encrypt" \
  "{\"kid\":\"${E39_KID}\",\"alg\":\"dir\",\"enc\":\"A128GCM\",\"data\":\"$(b64url_encode 'test')\"}")
assert_status "$E39_ENC_STATUS" "200" "E39: key exists before delete"

# Delete it
E39_DEL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE "${KMS_URL}/v1/crypto/keys/${E39_KID}")
assert_status "$E39_DEL_STATUS" "204" "E39: DELETE returns 204"

# Confirm it's gone (should 404)
E39_GONE_STATUS=$(crypto_status "encrypt" \
  "{\"kid\":\"${E39_KID}\",\"alg\":\"dir\",\"enc\":\"A128GCM\",\"data\":\"$(b64url_encode 'test')\"}")
assert_status "$E39_GONE_STATUS" "404" "E39: key gone after delete"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "========================================="
echo "All JOSE / REST Crypto tests passed!"
echo "========================================="
