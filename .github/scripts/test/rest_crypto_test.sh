#!/usr/bin/env bash
# REST Crypto API end-to-end smoke test.
#
# Starts a fresh KMS server (SQLite, no auth), creates test keys via KMIP
# JSON-TTLV, then exercises every /v1/crypto/* endpoint with curl.
#
# Tested paths:
#   POST /v1/crypto/encrypt   — dir + A{128,192,256}GCM, AAD binding, error cases
#   POST /v1/crypto/decrypt   — round-trips, tamper detection, error cases
#   POST /v1/crypto/sign      — RS256, ES256, tamper detection
#   POST /v1/crypto/verify    — valid/invalid outcomes
#   POST /v1/crypto/mac       — HS256 compute + verify, tamper detection
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"
setup_test_logging

# ── Configuration ────────────────────────────────────────────────────────────
KMS_PORT=9990
KMS_URL="http://127.0.0.1:${KMS_PORT}"

export KMS_HTTP_HOST="127.0.0.1"
export KMS_HTTP_PORT="${KMS_PORT}"

KMS_PID=""
SQLITE_PATH=""
KMS_CONF_PATH=""

cleanup() {
    [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" 2>/dev/null || true; wait "${KMS_PID}" 2>/dev/null || true; }
    [ -n "${SQLITE_PATH:-}" ] && { rm -rf "${SQLITE_PATH}" || true; }
    [ -n "${KMS_CONF_PATH:-}" ] && { rm -f "${KMS_CONF_PATH}" || true; }
}
trap cleanup EXIT

# ── Generic helpers ───────────────────────────────────────────────────────────

# Encode a literal string to base64url without padding.
b64url_encode() {
    printf '%s' "$1" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

# Extract a string-typed field from a flat JSON REST response.
# Example: json_str '{"iv":"abc","tag":"def"}' "iv"  →  abc
json_str() {
    printf '%s' "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | sed 's/.*":"//;s/"$//'
}

# Extract a boolean field from a flat JSON REST response.
# Returns the literal word: true or false.
json_bool() {
    printf '%s' "$1" | grep -oE "\"$2\":(true|false)" | head -1 | sed 's/.*://'
}

# Extract a TextString value by KMIP tag name from a JSON-TTLV response.
# Works on compact single-line JSON as returned by the KMS server.
kmip_tag() {
    printf '%s' "$1" | \
        grep -o "\"tag\":\"$2\",\"type\":\"TextString\",\"value\":\"[^\"]*\"" | \
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

# Activate a previously-created key so the KMS allows cryptographic operations.
activate_key() {
    kmip_post "{\"tag\":\"Activate\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"$1\"}]}" >/dev/null
}

# Create an AES symmetric key with Encrypt|Decrypt usage mask (12) and a known UID.
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

# Create an AES symmetric key with MACGenerate|MACVerify usage mask (384) for HMAC operations.
# MACGenerate=0x80 (128) and MACVerify=0x100 (256), so combined = 384.
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

# Create an RSA-2048 key pair.  Sets globals RSA_PRIV_UID and RSA_PUB_UID.
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

# Create an EC P-256 key pair.  Sets globals EC_PRIV_UID and EC_PUB_UID.
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

SQLITE_PATH="$(mktemp -d -t kms-rest-crypto-XXXXXX)"
KMS_CONF_PATH="$(mktemp -t kms-rest-crypto-conf-XXXXXX.toml)"

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

# Globals populated by helpers:
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

# ── Section A: Encrypt / Decrypt ─────────────────────────────────────────────

# Run an AES-GCM encrypt → decrypt round-trip and assert plaintext is recovered.
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
# Build a modified protected header with same kid/alg/enc but extra field → AAD differs
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

# Sign a payload with private_kid, then verify it with the protected header.
# Also asserts that tampered data and tampered signatures yield valid=false.
run_sign_verify() {
    local priv_kid="$1" alg="$2"
    local payload_b64 sign_resp protected signature ver_resp valid

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

    # Corrupted signature (flip one character) → valid=false
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

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "========================================="
echo "All REST crypto API E2E tests passed!"
echo "========================================="
