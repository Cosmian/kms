#!/usr/bin/env bash
# Azure EKM HTTP Smoke Test
# Builds the KMS, imports an AES-256 and an RSA-2048 key pair via the KMIP REST API,
# then validates the EKM /info, /metadata, /wrapkey and /unwrapkey endpoints.
#
# No TLS or mTLS is required: the server runs in plain HTTP mode with authentication
# disabled (--azure-ekm-disable-auth).  For a TLS + mTLS variant, see run_azure_ekm_mtls_test.sh.
#
# Usage:
#   bash .github/scripts/azure_ekm_test.sh [--profile debug|release] [--variant fips|non-fips]
set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

init_build_env "$@"
setup_test_logging

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KMS_PORT=9998
EKM_PREFIX="cosmian0"
KMS_URL="http://localhost:${KMS_PORT}"
KMIP_URL="${KMS_URL}/kmip/2_1"

AES_KEY_ID="aes256"
RSA_KEY_ID="rsa2048"

REQCTX='{"request_id":"test-001","correlation_id":"test-corr-001","pool_name":"test-pool"}'

KMS_PID=""

cleanup() {
    echo "==> Stopping KMS server (PID=${KMS_PID:-unknown})..."
    [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" 2>/dev/null || true; wait "${KMS_PID}" 2>/dev/null || true; }
    [ -n "${TMP_DIR:-}" ] && rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "==> Building KMS (${VARIANT_NAME}, ${BUILD_PROFILE})..."
# shellcheck disable=SC2068
cargo build ${RELEASE_FLAG} ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms

echo "==> Starting KMS on port ${KMS_PORT} (HTTP, no EKM auth)..."
# shellcheck disable=SC2068
cargo run ${RELEASE_FLAG} ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms -- \
    --port "${KMS_PORT}" \
    --azure-ekm-enable \
    --azure-ekm-disable-client-auth \
    --azure-ekm-path-prefix "${EKM_PREFIX}" \
    &
KMS_PID=$!

echo "==> Waiting for KMS to be ready on port ${KMS_PORT}..."
_wait_for_port localhost "${KMS_PORT}" 60
echo "==> KMS is ready."

# ---------------------------------------------------------------------------
# Helper: POST JSON to the KMIP endpoint; assert HTTP 200, return body
# Diagnostic output goes to stderr so that stdout carries only the body,
# allowing safe command substitution: result=$(kmip_post ...)
# ---------------------------------------------------------------------------
kmip_post() {
    local description="$1"
    local payload="$2"
    echo "==> KMIP: ${description}" >&2
    local response http_code body
    response=$(curl -sS -w "\n%{http_code}" \
        -H "Content-Type: application/json" \
        -d "${payload}" \
        "${KMIP_URL}")
    http_code=$(echo "${response}" | tail -n1)
    body=$(echo "${response}" | head -n-1)
    echo "    HTTP ${http_code}: ${body}" >&2
    [ "${http_code}" = "200" ] || { echo "ERROR: expected HTTP 200, got ${http_code}" >&2; exit 1; }
    echo "${body}"
}

# ---------------------------------------------------------------------------
# Helper: POST JSON to an EKM endpoint; assert expected HTTP code, return body
# Diagnostic output goes to stderr so that stdout carries only the body,
# allowing safe command substitution: result=$(ekm_post ...)
# ---------------------------------------------------------------------------
ekm_post() {
    local description="$1"
    local url="$2"
    local payload="$3"
    local expected_code="${4:-200}"
    echo "==> EKM: ${description}" >&2
    local response http_code body
    response=$(curl -sS -w "\n%{http_code}" \
        -H "Content-Type: application/json" \
        -d "${payload}" \
        "${url}")
    http_code=$(echo "${response}" | tail -n1)
    body=$(echo "${response}" | head -n-1)
    echo "    HTTP ${http_code}: ${body}" >&2
    [ "${http_code}" = "${expected_code}" ] || {
        echo "ERROR: expected HTTP ${expected_code}, got ${http_code}" >&2
        exit 1
    }
    echo "${body}"
}

# ---------------------------------------------------------------------------
# 2. Import a 256-bit AES key with a known unique identifier
#    32 zero bytes: base64-encoded (standard) → AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
# ---------------------------------------------------------------------------
AES_KEY_B64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

kmip_post "Import AES-256 key (uid=${AES_KEY_ID})" \
    "{\"tag\":\"Import\",\"value\":[
       {\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${AES_KEY_ID}\"},
       {\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"SymmetricKey\"},
       {\"tag\":\"ReplaceExisting\",\"type\":\"Boolean\",\"value\":true},
       {\"tag\":\"Attributes\",\"value\":[
         {\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"AES\"},
         {\"tag\":\"CryptographicLength\",\"type\":\"Integer\",\"value\":256},
         {\"tag\":\"CryptographicUsageMask\",\"type\":\"Integer\",\"value\":12},
         {\"tag\":\"ActivationDate\",\"type\":\"DateTime\",\"value\":\"1970-01-01T00:00:00.000Z\"}
       ]},
       {\"tag\":\"Object\",\"value\":[
         {\"tag\":\"SymmetricKey\",\"value\":[
           {\"tag\":\"KeyBlock\",\"value\":[
             {\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"TransparentSymmetricKey\"},
             {\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"AES\"},
             {\"tag\":\"CryptographicLength\",\"type\":\"Integer\",\"value\":256},
             {\"tag\":\"KeyValue\",\"value\":[
               {\"tag\":\"KeyMaterial\",\"type\":\"Structure\",\"value\":[
                 {\"tag\":\"TransparentSymmetricKey\",\"type\":\"Structure\",\"value\":[
                   {\"tag\":\"Key\",\"type\":\"ByteString\",\"value\":\"${AES_KEY_B64}\"}
                 ]}
               ]}
             ]}
           ]}
         ]}
       ]}
     ]}"

# ---------------------------------------------------------------------------
# 3. Import an RSA-2048 key pair with known unique identifiers
#    Generate an ephemeral pair and encode as PKCS#8 DER base64
# ---------------------------------------------------------------------------
echo "==> Generating ephemeral RSA-2048 key pair..."
TMP_DIR=$(mktemp -d)

openssl genrsa -out "${TMP_DIR}/rsa.pem" 2048 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "${TMP_DIR}/rsa.pem" -outform DER \
    | base64 -w 0 > "${TMP_DIR}/sk_b64.txt"
openssl rsa -in "${TMP_DIR}/rsa.pem" -pubout -outform DER 2>/dev/null \
    | base64 -w 0 > "${TMP_DIR}/pk_b64.txt"

RSA_SK_B64=$(cat "${TMP_DIR}/sk_b64.txt")
RSA_PK_B64=$(cat "${TMP_DIR}/pk_b64.txt")

# Private key  (uid = rsa2048)
kmip_post "Import RSA-2048 private key (uid=${RSA_KEY_ID})" \
    "{\"tag\":\"Import\",\"value\":[
       {\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${RSA_KEY_ID}\"},
       {\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"PrivateKey\"},
       {\"tag\":\"ReplaceExisting\",\"type\":\"Boolean\",\"value\":true},
       {\"tag\":\"Attributes\",\"value\":[
         {\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"RSA\"},
         {\"tag\":\"CryptographicLength\",\"type\":\"Integer\",\"value\":2048},
         {\"tag\":\"CryptographicUsageMask\",\"type\":\"Integer\",\"value\":4},
         {\"tag\":\"ActivationDate\",\"type\":\"DateTime\",\"value\":\"1970-01-01T00:00:00.000Z\"}
       ]},
       {\"tag\":\"Object\",\"value\":[
         {\"tag\":\"PrivateKey\",\"value\":[
           {\"tag\":\"KeyBlock\",\"value\":[
             {\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"PKCS8\"},
             {\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"RSA\"},
             {\"tag\":\"CryptographicLength\",\"type\":\"Integer\",\"value\":2048},
             {\"tag\":\"KeyValue\",\"value\":[
               {\"tag\":\"KeyMaterial\",\"type\":\"ByteString\",\"value\":\"${RSA_SK_B64}\"}
             ]}
           ]}
         ]}
       ]}
     ]}"

# Public key  (uid = rsa2048_pk, as required by the EKM wrapkey handler)
kmip_post "Import RSA-2048 public key (uid=${RSA_KEY_ID}_pk)" \
    "{\"tag\":\"Import\",\"value\":[
       {\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${RSA_KEY_ID}_pk\"},
       {\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"PublicKey\"},
       {\"tag\":\"ReplaceExisting\",\"type\":\"Boolean\",\"value\":true},
       {\"tag\":\"Attributes\",\"value\":[
         {\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"RSA\"},
         {\"tag\":\"CryptographicLength\",\"type\":\"Integer\",\"value\":2048},
         {\"tag\":\"CryptographicUsageMask\",\"type\":\"Integer\",\"value\":8},
         {\"tag\":\"ActivationDate\",\"type\":\"DateTime\",\"value\":\"1970-01-01T00:00:00.000Z\"}
       ]},
       {\"tag\":\"Object\",\"value\":[
         {\"tag\":\"PublicKey\",\"value\":[
           {\"tag\":\"KeyBlock\",\"value\":[
             {\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"PKCS8\"},
             {\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"RSA\"},
             {\"tag\":\"CryptographicLength\",\"type\":\"Integer\",\"value\":2048},
             {\"tag\":\"KeyValue\",\"value\":[
               {\"tag\":\"KeyMaterial\",\"type\":\"ByteString\",\"value\":\"${RSA_PK_B64}\"}
             ]}
           ]}
         ]}
       ]}
     ]}"

# ---------------------------------------------------------------------------
# 4. EKM /info endpoint
# ---------------------------------------------------------------------------
ekm_post "/info" \
    "${KMS_URL}/azureekm/${EKM_PREFIX}/info?api-version=0.1-preview" \
    "{\"request_context\":${REQCTX}}" \
    "200"

# ---------------------------------------------------------------------------
# 5. EKM /metadata — AES key
# ---------------------------------------------------------------------------
ekm_post "/metadata (AES)" \
    "${KMS_URL}/azureekm/${EKM_PREFIX}/${AES_KEY_ID}/metadata?api-version=0.1-preview" \
    "{\"request_context\":${REQCTX}}" \
    "200"

# ---------------------------------------------------------------------------
# 6. EKM /metadata — RSA key pair
# ---------------------------------------------------------------------------
ekm_post "/metadata (RSA)" \
    "${KMS_URL}/azureekm/${EKM_PREFIX}/${RSA_KEY_ID}/metadata?api-version=0.1-preview" \
    "{\"request_context\":${REQCTX}}" \
    "200"

# ---------------------------------------------------------------------------
# 7. EKM /wrapkey — AES wrap (A256KW)
#    DEK: 32 zero bytes, base64url-encoded without padding
# ---------------------------------------------------------------------------
DEK_B64URL="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

WRAP_AES_RESP=$(ekm_post "/wrapkey (AES A256KW)" \
    "${KMS_URL}/azureekm/${EKM_PREFIX}/${AES_KEY_ID}/wrapkey?api-version=0.1-preview" \
    "{\"alg\":\"A256KW\",\"value\":\"${DEK_B64URL}\",\"request_context\":${REQCTX}}" \
    "200")

WRAPPED_AES=$(echo "${WRAP_AES_RESP}" | grep -o '"value":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "${WRAPPED_AES}" ] || { echo "ERROR: wrapkey (AES) returned empty value"; exit 1; }

# ---------------------------------------------------------------------------
# 8. EKM /unwrapkey — AES round-trip
# ---------------------------------------------------------------------------
UNWRAP_AES_RESP=$(ekm_post "/unwrapkey (AES A256KW)" \
    "${KMS_URL}/azureekm/${EKM_PREFIX}/${AES_KEY_ID}/unwrapkey?api-version=0.1-preview" \
    "{\"alg\":\"A256KW\",\"value\":\"${WRAPPED_AES}\",\"request_context\":${REQCTX}}" \
    "200")

UNWRAPPED_AES=$(echo "${UNWRAP_AES_RESP}" | grep -o '"value":"[^"]*"' | head -1 | cut -d'"' -f4)
[ "${UNWRAPPED_AES}" = "${DEK_B64URL}" ] || {
    echo "ERROR: AES round-trip mismatch!"
    echo "  expected:  ${DEK_B64URL}"
    echo "  got:       ${UNWRAPPED_AES}"
    exit 1
}
echo "==> AES wrap/unwrap round-trip: OK"

# ---------------------------------------------------------------------------
# 9. EKM /wrapkey — RSA (RsaOaep256)
# ---------------------------------------------------------------------------
WRAP_RSA_RESP=$(ekm_post "/wrapkey (RSA-OAEP-256)" \
    "${KMS_URL}/azureekm/${EKM_PREFIX}/${RSA_KEY_ID}/wrapkey?api-version=0.1-preview" \
    "{\"alg\":\"RsaOaep256\",\"value\":\"${DEK_B64URL}\",\"request_context\":${REQCTX}}" \
    "200")

WRAPPED_RSA=$(echo "${WRAP_RSA_RESP}" | grep -o '"value":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "${WRAPPED_RSA}" ] || { echo "ERROR: wrapkey (RSA) returned empty value"; exit 1; }

# ---------------------------------------------------------------------------
# 10. EKM /unwrapkey — RSA round-trip
# ---------------------------------------------------------------------------
UNWRAP_RSA_RESP=$(ekm_post "/unwrapkey (RSA-OAEP-256)" \
    "${KMS_URL}/azureekm/${EKM_PREFIX}/${RSA_KEY_ID}/unwrapkey?api-version=0.1-preview" \
    "{\"alg\":\"RsaOaep256\",\"value\":\"${WRAPPED_RSA}\",\"request_context\":${REQCTX}}" \
    "200")

UNWRAPPED_RSA=$(echo "${UNWRAP_RSA_RESP}" | grep -o '"value":"[^"]*"' | head -1 | cut -d'"' -f4)
[ "${UNWRAPPED_RSA}" = "${DEK_B64URL}" ] || {
    echo "ERROR: RSA round-trip mismatch!"
    echo "  expected:  ${DEK_B64URL}"
    echo "  got:       ${UNWRAPPED_RSA}"
    exit 1
}
echo "==> RSA wrap/unwrap round-trip: OK"

# ---------------------------------------------------------------------------
# 11. Sad path: /metadata for a non-existent key must return 4xx
# ---------------------------------------------------------------------------
SAD_RESP=$(curl -sS -w "\n%{http_code}" \
    -H "Content-Type: application/json" \
    -d "{\"request_context\":${REQCTX}}" \
    "${KMS_URL}/azureekm/${EKM_PREFIX}/does-not-exist/metadata?api-version=0.1-preview")
SAD_CODE=$(echo "${SAD_RESP}" | tail -n1)
SAD_BODY=$(echo "${SAD_RESP}" | head -n-1)
echo "==> Sad path /metadata (non-existent key): HTTP ${SAD_CODE}: ${SAD_BODY}"
case "${SAD_CODE}" in
    4*) echo "==> Sad path OK (HTTP ${SAD_CODE})."; ;;
    *)  echo "ERROR: expected 4xx for non-existent key, got ${SAD_CODE}"; exit 1 ;;
esac

echo ""
echo "============================================================"
echo " Azure EKM smoke test PASSED"
echo "============================================================"
