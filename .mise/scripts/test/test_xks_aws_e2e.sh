#!/usr/bin/env bash
# End-to-end test of AWS XKS via the real AWS KMS API.
# AWS KMS routes encrypt/decrypt through the configured external key store,
# which in turn calls our proxy at aws-xks-kms.cosmian.dev.
#
# Required env vars:
#   AWS_ACCESS_KEY_ID        — IAM access key with kms:Encrypt / kms:Decrypt
#   AWS_SECRET_ACCESS_KEY    — matching secret
#   AWS_XKS_KEY_ARN          — ARN of the KMS key backed by the external key store
#
# Optional:
#   AWS_DEFAULT_REGION       — default: eu-west-1
set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

require_cmd aws "aws-cli v2 is required for the AWS KMS end-to-end test."
require_cmd jq "jq is required to parse describe-key output."
require_cmd curl "curl is required to grant proxy access."

: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"
: "${AWS_XKS_KEY_ARN:?AWS_XKS_KEY_ARN is required}"

AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-eu-west-1}"
KMS_ADMIN_URL="${KMS_ADMIN_URL:-https://aws-xks-kms.cosmian.dev}"
# Reserved identity the server uses to dispatch XKS operations from AWS KMS.
xks_service_user="[aws-xks-service]"
export AWS_DEFAULT_REGION

# Resolve the proxy-side key ID from the AWS key metadata.
proxy_key_id=$(aws kms describe-key --key-id "${AWS_XKS_KEY_ARN}" \
  --output json | jq -r '.KeyMetadata.XksKeyConfiguration.Id')
echo "Proxy key ID: ${proxy_key_id}"

# Grant encrypt/decrypt to the XKS service user so direct SigV4 calls work.
echo "=== Granting proxy access for [aws-xks-service] on ${proxy_key_id} ==="
curl -sS -H "Content-Type:application/json" -X POST "${KMS_ADMIN_URL}/access/grant" \
  --data-binary "{
    \"unique_identifier\": \"${proxy_key_id}\",
    \"user_id\": \"${xks_service_user}\",
    \"operation_types\": [\"getattributes\", \"encrypt\", \"decrypt\"]
  }"
echo

plaintext="Hello from AWS XKS CI end-to-end test"

echo "=== AWS KMS XKS end-to-end: encrypt via external key store ==="

cipher_b64=$(aws kms encrypt \
  --key-id "${AWS_XKS_KEY_ARN}" \
  --plaintext fileb://<(printf '%s' "${plaintext}") \
  --output text \
  --query CiphertextBlob)

if [[ -z "${cipher_b64}" ]]; then
  echo "ERROR: aws kms encrypt returned empty CiphertextBlob" >&2
  exit 1
fi
echo "Encrypt OK (ciphertext length: ${#cipher_b64})"

echo "=== AWS KMS XKS end-to-end: decrypt via external key store ==="

decrypted=$(aws kms decrypt \
  --ciphertext-blob fileb://<(printf '%s' "${cipher_b64}" | base64 -d) \
  --key-id "${AWS_XKS_KEY_ARN}" \
  --output text \
  --query Plaintext | base64 -d)

if [[ "${decrypted}" != "${plaintext}" ]]; then
  echo "ERROR: decrypted text does not match original plaintext" >&2
  echo "  expected: ${plaintext}" >&2
  echo "  got:      ${decrypted}" >&2
  exit 1
fi
echo "Decrypt OK — plaintext matches."
echo "=== AWS KMS XKS end-to-end test PASSED ==="
