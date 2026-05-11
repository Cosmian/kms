#!/usr/bin/env bash
# JOSE / REST Crypto API end-to-end test suite.
#
# Phase 1: curl-based tests against every /v1/crypto/* endpoint (no external deps)
# Phase 2: JOSE interoperability tests — validates KMS outputs against Python jwcrypto
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
    [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" 2>/dev/null || true; wait "${KMS_PID}" 2>/dev/null || true; }
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
    printf '%s' "$1" | \
        grep -o "\"tag\":\"$2\",\"type\":\"TextString\",\"value\":\"[^\"]*\"" | \
        grep -o '"value":"[^"]*"' | \
        sed 's/"value":"//;s/"$//'
}

# Extract a ByteString value (hex-encoded key material) from a JSON-TTLV response.
kmip_bytestring() {
    printf '%s' "$1" | \
        grep -o "\"tag\":\"$2\",\"type\":\"ByteString\",\"value\":\"[^\"]*\"" | \
        grep -o '"value":"[^"]*"' | \
        sed 's/"value":"//;s/"$//'
}

# POST JSON to the KMIP 2.1 endpoint and return the full response body.
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

# ── KMIP key-creation helpers ─────────────────────────────────────────────────

activate_key() {
    kmip_post "{\"tag\":\"Activate\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"$1\"}]}" >/dev/null
}

create_aes_key() {
    local uid="$1" bits="$2"
    kmip_post "$(
        cat <<JSON
{
  "tag": "Create", "type": "Structure",
  "value": [
    {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
    {"tag": "Attributes", "type": "Structure", "value": [
      {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
      {"tag": "CryptographicLength",    "type": "Integer",     "value": ${bits}},
      {"tag": "CryptographicUsageMask", "type": "Integer",     "value": 12},
      {"tag": "KeyFormatType",          "type": "Enumeration", "value": "TransparentSymmetricKey"},
      {"tag": "UniqueIdentifier",       "type": "TextString",  "value": "${uid}"}
    ]}
  ]
}
JSON
    )" >/dev/null
    activate_key "$uid"
}

create_mac_key() {
    local uid="$1" bits="${2:-256}"
    kmip_post "$(
        cat <<JSON
{
  "tag": "Create", "type": "Structure",
  "value": [
    {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
    {"tag": "Attributes", "type": "Structure", "value": [
      {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
      {"tag": "CryptographicLength",    "type": "Integer",     "value": ${bits}},
      {"tag": "CryptographicUsageMask", "type": "Integer",     "value": 384},
      {"tag": "KeyFormatType",          "type": "Enumeration", "value": "TransparentSymmetricKey"},
      {"tag": "UniqueIdentifier",       "type": "TextString",  "value": "${uid}"}
    ]}
  ]
}
JSON
    )" >/dev/null
    activate_key "$uid"
}

create_rsa_keypair() {
    local resp
    resp=$(kmip_post '{"tag":"CreateKeyPair","type":"Structure","value":[
      {"tag":"CommonAttributes","type":"Structure","value":[
        {"tag":"CryptographicAlgorithm","type":"Enumeration","value":"RSA"},
        {"tag":"CryptographicLength","type":"Integer","value":2048}
      ]},
      {"tag":"PrivateKeyAttributes","type":"Structure","value":[
        {"tag":"CryptographicUsageMask","type":"Integer","value":1}
      ]},
      {"tag":"PublicKeyAttributes","type":"Structure","value":[
        {"tag":"CryptographicUsageMask","type":"Integer","value":2}
      ]}
    ]}')
    RSA_PRIV_UID=$(kmip_tag "$resp" "PrivateKeyUniqueIdentifier")
    RSA_PUB_UID=$(kmip_tag  "$resp" "PublicKeyUniqueIdentifier")
    activate_key "$RSA_PRIV_UID"
    activate_key "$RSA_PUB_UID"
}

create_ec_keypair() {
    local resp
    resp=$(kmip_post '{"tag":"CreateKeyPair","type":"Structure","value":[
      {"tag":"CommonAttributes","type":"Structure","value":[
        {"tag":"CryptographicAlgorithm","type":"Enumeration","value":"EC"},
        {"tag":"CryptographicDomainParameters","type":"Structure","value":[
          {"tag":"RecommendedCurve","type":"Enumeration","value":"P256"}
        ]}
      ]},
      {"tag":"PrivateKeyAttributes","type":"Structure","value":[
        {"tag":"CryptographicUsageMask","type":"Integer","value":1}
      ]},
      {"tag":"PublicKeyAttributes","type":"Structure","value":[
        {"tag":"CryptographicUsageMask","type":"Integer","value":2}
      ]}
    ]}')
    EC_PRIV_UID=$(kmip_tag "$resp" "PrivateKeyUniqueIdentifier")
    EC_PUB_UID=$(kmip_tag  "$resp" "PublicKeyUniqueIdentifier")
    activate_key "$EC_PRIV_UID"
    activate_key "$EC_PUB_UID"
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

# ── Create test keys ──────────────────────────────────────────────────────────

echo "==> Creating test keys..."
create_aes_key "aes-128" 128
create_aes_key "aes-192" 192
create_aes_key "aes-256" 256
create_mac_key "mac-hmac" 256

RSA_PRIV_UID="" RSA_PUB_UID=""
EC_PRIV_UID=""  EC_PUB_UID=""
create_rsa_keypair
create_ec_keypair

echo "    aes-128        OK"
echo "    aes-192        OK"
echo "    aes-256        OK"
echo "    mac-hmac       OK"
echo "    RSA-2048 priv  ${RSA_PRIV_UID}"
echo "    RSA-2048 pub   ${RSA_PUB_UID}"
echo "    EC P-256 priv  ${EC_PRIV_UID}"
echo "    EC P-256 pub   ${EC_PUB_UID}"

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
run_enc_dec_roundtrip "aes-128" "A128GCM"
echo "==> A2: A192GCM round-trip"
run_enc_dec_roundtrip "aes-192" "A192GCM"
echo "==> A3: A256GCM round-trip"
run_enc_dec_roundtrip "aes-256" "A256GCM"

echo "==> A4: A256GCM with AAD — round-trip"
AAD_B64=$(b64url_encode "context-data")
ENC_AAD=$(crypto_post "encrypt" \
    "{\"kid\":\"aes-256\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"${PLAINTEXT_B64}\",\"aad\":\"${AAD_B64}\"}")
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
MOD_PROT=$(b64url_encode "{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"kid\":\"aes-256\",\"x\":1}")
assert_status \
    "$(crypto_status "decrypt" "{\"protected\":\"${MOD_PROT}\",\"encrypted_key\":\"\",\"iv\":\"${IV_AAD}\",\"ciphertext\":\"${CT_AAD}\",\"tag\":\"${TAG_AAD}\",\"aad\":\"${AAD_B64}\"}")" \
    "422" "Protected header tamper"

echo "==> A7: Unsupported enc (A128CBC-HS256) returns 422"
assert_status \
    "$(crypto_status "encrypt" "{\"kid\":\"aes-256\",\"alg\":\"dir\",\"enc\":\"A128CBC-HS256\",\"data\":\"${PLAINTEXT_B64}\"}" )" \
    "422" "Unsupported enc"

echo "==> A8: Unsupported alg (RSA-OAEP) returns 422"
assert_status \
    "$(crypto_status "encrypt" "{\"kid\":\"aes-256\",\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\",\"data\":\"${PLAINTEXT_B64}\"}" )" \
    "422" "Unsupported alg"

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

echo "==> B3: Unknown alg returns 422"
assert_status \
    "$(crypto_status "sign" "{\"kid\":\"${RSA_PRIV_UID}\",\"alg\":\"UNKNOWN\",\"data\":\"${PLAINTEXT_B64}\"}" )" \
    "422" "Unknown sign alg"

# ── Section C: MAC ────────────────────────────────────────────────────────────

echo ""
echo "==> Section C: MAC"
MAC_DATA_B64=$(b64url_encode "mac test message")

echo "==> C1: HS256 compute + verify round-trip"
MAC_COMPUTE=$(crypto_post "mac" \
    "{\"kid\":\"mac-hmac\",\"alg\":\"HS256\",\"data\":\"${MAC_DATA_B64}\"}")
MAC_VALUE=$(json_str "$MAC_COMPUTE" "mac")
MAC_VER=$(crypto_post "mac" \
    "{\"kid\":\"mac-hmac\",\"alg\":\"HS256\",\"data\":\"${MAC_DATA_B64}\",\"mac\":\"${MAC_VALUE}\"}")
assert_eq "$(json_bool "${MAC_VER}" "valid")" "true" "HS256 compute + verify"

echo "==> C2: HS256 tampered data → invalid"
WRONG_DATA_B64=$(b64url_encode "different message")
MAC_WRONG=$(crypto_post "mac" \
    "{\"kid\":\"mac-hmac\",\"alg\":\"HS256\",\"data\":\"${WRONG_DATA_B64}\",\"mac\":\"${MAC_VALUE}\"}")
assert_eq "$(json_bool "${MAC_WRONG}" "valid")" "false" "HS256 tampered data"

echo "==> C3: HS256 corrupted mac → invalid"
if [ "${MAC_VALUE:0:1}" = "A" ]; then MAC_BAD_CHAR="B"; else MAC_BAD_CHAR="A"; fi
BAD_MAC="${MAC_BAD_CHAR}${MAC_VALUE:1}"
MAC_BAD=$(crypto_post "mac" \
    "{\"kid\":\"mac-hmac\",\"alg\":\"HS256\",\"data\":\"${MAC_DATA_B64}\",\"mac\":\"${BAD_MAC}\"}")
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
    "$(crypto_status "encrypt" "{\"kid\":\"aes-256\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"not!valid!!\"}")" \
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
ERR_RESP=$(crypto_post "encrypt" "{\"kid\":\"aes-256\",\"alg\":\"dir\",\"enc\":\"BOGUS\",\"data\":\"${PLAINTEXT_B64}\"}")
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
pip install --quiet jwcrypto cryptography

python3 "${HELPER}" --help >/dev/null 2>&1 || {
    echo "ERROR: jose_interop_helper.py failed to load" >&2
    exit 1
}
echo "    Python venv OK ($(python3 --version), jwcrypto $(pip show jwcrypto | grep ^Version | awk '{print $2}'))"

# ── Import known AES keys for cross-tool interop ─────────────────────────────

echo ""
echo "==> Importing known AES keys for interop..."

AES_KEY_HEX=$(python3 -c "import secrets; print(secrets.token_hex(32))")

IMPORT_RESP=$(kmip_post "$(cat <<JSON
{
  "tag": "Import", "type": "Structure",
  "value": [
    {"tag": "UniqueIdentifier", "type": "TextString", "value": "jose-aes-256"},
    {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
    {"tag": "ReplaceExisting", "type": "Boolean", "value": false},
    {"tag": "SymmetricKey", "type": "Structure", "value": [
      {"tag": "KeyBlock", "type": "Structure", "value": [
        {"tag": "KeyFormatType", "type": "Enumeration", "value": "Raw"},
        {"tag": "KeyValue", "type": "Structure", "value": [
          {"tag": "KeyMaterial", "type": "ByteString", "value": "${AES_KEY_HEX}"}
        ]},
        {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
        {"tag": "CryptographicLength", "type": "Integer", "value": 256}
      ]}
    ]},
    {"tag": "Attributes", "type": "Structure", "value": [
      {"tag": "CryptographicUsageMask", "type": "Integer", "value": 12}
    ]}
  ]
}
JSON
)")
AES_UID=$(kmip_tag "$IMPORT_RESP" "UniqueIdentifier")
activate_key "${AES_UID}"
echo "    AES-256 (imported) ${AES_UID}"

AES128_KEY_HEX=$(python3 -c "import secrets; print(secrets.token_hex(16))")

kmip_post "$(cat <<JSON
{
  "tag": "Import", "type": "Structure",
  "value": [
    {"tag": "UniqueIdentifier", "type": "TextString", "value": "jose-aes-128"},
    {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
    {"tag": "ReplaceExisting", "type": "Boolean", "value": false},
    {"tag": "SymmetricKey", "type": "Structure", "value": [
      {"tag": "KeyBlock", "type": "Structure", "value": [
        {"tag": "KeyFormatType", "type": "Enumeration", "value": "Raw"},
        {"tag": "KeyValue", "type": "Structure", "value": [
          {"tag": "KeyMaterial", "type": "ByteString", "value": "${AES128_KEY_HEX}"}
        ]},
        {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
        {"tag": "CryptographicLength", "type": "Integer", "value": 128}
      ]}
    ]},
    {"tag": "Attributes", "type": "Structure", "value": [
      {"tag": "CryptographicUsageMask", "type": "Integer", "value": 12}
    ]}
  ]
}
JSON
)" >/dev/null
activate_key "jose-aes-128"
echo "    AES-128 (imported) jose-aes-128"

# ── Export public keys for jwcrypto verification ──────────────────────────────

RSA_GET_RESP=$(kmip_post "$(cat <<JSON
{
  "tag": "Get", "type": "Structure",
  "value": [
    {"tag": "UniqueIdentifier", "type": "TextString", "value": "${RSA_PUB_UID}"},
    {"tag": "KeyFormatType", "type": "Enumeration", "value": "PKCS8"}
  ]
}
JSON
)")
RSA_PUB_DER_HEX=$(kmip_bytestring "$RSA_GET_RESP" "KeyMaterial")
echo "    RSA pub DER exported (${#RSA_PUB_DER_HEX} hex chars)"

EC_GET_RESP=$(kmip_post "$(cat <<JSON
{
  "tag": "Get", "type": "Structure",
  "value": [
    {"tag": "UniqueIdentifier", "type": "TextString", "value": "${EC_PUB_UID}"},
    {"tag": "KeyFormatType", "type": "Enumeration", "value": "PKCS8"}
  ]
}
JSON
)")
EC_PUB_DER_HEX=$(kmip_bytestring "$EC_GET_RESP" "KeyMaterial")
echo "    EC pub DER exported (${#EC_PUB_DER_HEX} hex chars)"

# ── Test E1: JWS RS256 — KMS sign → jwcrypto verify ──────────────────────────

echo ""
echo "==> E1: JWS RS256 — KMS sign → jwcrypto verify"
PAYLOAD="JOSE interop test payload for RS256"
PAYLOAD_B64=$(b64url_encode "${PAYLOAD}")

SIGN_RESP=$(crypto_post "sign" \
    "{\"kid\":\"${RSA_PRIV_UID}\",\"alg\":\"RS256\",\"data\":\"${PAYLOAD_B64}\"}")
SIGN_PROTECTED=$(json_str "$SIGN_RESP" "protected")
SIGN_SIGNATURE=$(json_str "$SIGN_RESP" "signature")

COMPACT_JWS="${SIGN_PROTECTED}.${PAYLOAD_B64}.${SIGN_SIGNATURE}"

VERIFY_OUT=$(python3 "${HELPER}" verify-jws \
    --alg RS256 \
    --pub-der-hex "${RSA_PUB_DER_HEX}" \
    --compact "${COMPACT_JWS}" 2>&1) || true
assert_eq "$(echo "${VERIFY_OUT}" | head -1)" "valid=true" "E1: RS256 KMS sign → jwcrypto verify"

# ── Test E2: JWS ES256 — KMS sign → jwcrypto verify ──────────────────────────

echo ""
echo "==> E2: JWS ES256 — KMS sign → jwcrypto verify"
EC_PAYLOAD="JOSE interop test payload for ES256"
EC_PAYLOAD_B64=$(b64url_encode "${EC_PAYLOAD}")

EC_SIGN_RESP=$(crypto_post "sign" \
    "{\"kid\":\"${EC_PRIV_UID}\",\"alg\":\"ES256\",\"data\":\"${EC_PAYLOAD_B64}\"}")
EC_SIGN_PROTECTED=$(json_str "$EC_SIGN_RESP" "protected")
EC_SIGN_SIGNATURE=$(json_str "$EC_SIGN_RESP" "signature")

EC_COMPACT_JWS="${EC_SIGN_PROTECTED}.${EC_PAYLOAD_B64}.${EC_SIGN_SIGNATURE}"

EC_VERIFY_OUT=$(python3 "${HELPER}" verify-jws \
    --alg ES256 \
    --pub-der-hex "${EC_PUB_DER_HEX}" \
    --compact "${EC_COMPACT_JWS}" 2>&1) || true
assert_eq "$(echo "${EC_VERIFY_OUT}" | head -1)" "valid=true" "E2: ES256 KMS sign → jwcrypto verify"

# ── Test E3: JWE dir+A256GCM — KMS encrypt → jwcrypto decrypt ────────────────

echo ""
echo "==> E3: JWE dir+A256GCM — KMS encrypt → jwcrypto decrypt"
JWE_PLAINTEXT="Encrypt me with AES-256-GCM via JOSE!"
JWE_PLAINTEXT_B64=$(b64url_encode "${JWE_PLAINTEXT}")
JWE_PLAINTEXT_HEX=$(python3 -c "print('${JWE_PLAINTEXT}'.encode().hex(), end='')")

ENC_RESP=$(crypto_post "encrypt" \
    "{\"kid\":\"${AES_UID}\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"${JWE_PLAINTEXT_B64}\"}")
ENC_PROTECTED=$(json_str "$ENC_RESP" "protected")
ENC_IV=$(json_str "$ENC_RESP" "iv")
ENC_CT=$(json_str "$ENC_RESP" "ciphertext")
ENC_TAG=$(json_str "$ENC_RESP" "tag")

DECRYPT_HEX=$(python3 "${HELPER}" decrypt-jwe \
    --key-hex "${AES_KEY_HEX}" \
    --protected "${ENC_PROTECTED}" \
    --iv "${ENC_IV}" \
    --ciphertext "${ENC_CT}" \
    --tag "${ENC_TAG}")
assert_eq "${DECRYPT_HEX}" "${JWE_PLAINTEXT_HEX}" "E3: A256GCM KMS encrypt → jwcrypto decrypt"

# ── Test E4: JWE dir+A128GCM — jwcrypto encrypt → KMS decrypt ────────────────

echo ""
echo "==> E4: JWE dir+A128GCM — jwcrypto encrypt → KMS decrypt"
E4_PLAINTEXT="Encrypt me with A128GCM from jwcrypto!"
E4_PLAINTEXT_HEX=$(python3 -c "print('${E4_PLAINTEXT}'.encode().hex(), end='')")

JWE_JSON=$(python3 "${HELPER}" encrypt-jwe \
    --key-hex "${AES128_KEY_HEX}" \
    --kid "jose-aes-128" \
    --enc "A128GCM" \
    --plaintext-hex "${E4_PLAINTEXT_HEX}")

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

# ── Test E5: RFC 7515 §A.1 HS256 known-answer cross-validation ───────────────

echo ""
echo "==> E5: RFC 7515 §A.1 HS256 known-answer (jwcrypto)"

RFC_KEY_B64="AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
SIGNING_INPUT="eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
SIGNING_INPUT_HEX=$(python3 -c "print('${SIGNING_INPUT}'.encode().hex(), end='')")

JWCRYPTO_MAC=$(python3 "${HELPER}" mac-sha256 \
    --key-b64url "${RFC_KEY_B64}" \
    --data-hex "${SIGNING_INPUT_HEX}")

EXPECTED_MAC="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
assert_eq "${JWCRYPTO_MAC}" "${EXPECTED_MAC}" "E5: RFC 7515 §A.1 HS256 jwcrypto known-answer"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "========================================="
echo "All JOSE / REST Crypto tests passed!"
echo "========================================="
