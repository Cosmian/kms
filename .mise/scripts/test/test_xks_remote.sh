#!/usr/bin/env bash
# Run the vendored AWS XKS curl test suite against the persistent remote test
# server (https://aws-xks-kms.cosmian.dev). The server must already be running.
# No KMS binary is built or started.
set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")

setup_test_logging

require_cmd curl "curl is required for the XKS test client."
require_cmd jq "jq is required by the XKS test client."
require_cmd bash "bash 4.2+ is required by the XKS test client."

# ── Remote server configuration ───────────────────────────────────────────────
# Host only (no scheme) — all calls use HTTPS.
KMS_XKS_HOST="${KMS_XKS_HOST:-aws-xks-kms.cosmian.dev}"
KMS_XKS_URI_PREFIX="${KMS_XKS_URI_PREFIX:-aws}"
KMS_XKS_REGION="${KMS_XKS_REGION:-eu-west-1}"

# SigV4 credentials — required: set them in the environment or as CI secrets.
: "${KMS_XKS_SIGV4_ACCESS_KEY_ID:?KMS_XKS_SIGV4_ACCESS_KEY_ID is required}"
: "${KMS_XKS_SIGV4_SECRET_ACCESS_KEY:?KMS_XKS_SIGV4_SECRET_ACCESS_KEY is required}"

# Base URL for KMS admin operations (access/revoke).
KMS_ADMIN_URL="${KMS_ADMIN_URL:-https://${KMS_XKS_HOST}}"

# ── Helpers ───────────────────────────────────────────────────────────────────
aws_principal_arn="arn:aws:iam::123456789012:user/Alice"
# Reserved identity under which the server dispatches every XKS operation.
xks_service_user="[aws-xks-service]"

xks_create_key() {
  local key_id="$1"
  local request_id
  request_id="$(uuidgen 2>/dev/null | tr '[:upper:]' '[:lower:]' || date +%s)"

  local json_body
  json_body="$(
    cat <<EOF
{
  "requestMetadata": {
    "awsPrincipalArn": "${aws_principal_arn}",
    "kmsOperation": "CreateKey",
    "kmsRequestId": "${request_id}"
  }
}
EOF
  )"

  local url="https://${KMS_XKS_HOST}/${KMS_XKS_URI_PREFIX}/kms/xks/v1/keys/${key_id}/metadata"
  local response
  response="$(
    curl -sS \
      -H "Content-Type:application/json" \
      --aws-sigv4 "aws:amz:${KMS_XKS_REGION}:kms-xks-proxy" \
      --user "${KMS_XKS_SIGV4_ACCESS_KEY_ID}:${KMS_XKS_SIGV4_SECRET_ACCESS_KEY}" \
      --data-binary "${json_body}" \
      "${url}"
  )"

  if ! grep -q '"keyStatus"' <<<"${response}"; then
    echo "Failed to CreateKey for ${key_id}. Response:" >&2
    echo "${response}" >&2
    return 1
  fi
}

grant_xks_access() {
  local key_id="$1"

  # Re-grant unconditionally so runs against a persistent server are idempotent.
  # Needed because the old server code skips grant_access when the key already exists.
  # Grant to BOTH Alice (old server, <=5.26.0) and [aws-xks-service] (Manu's fix)
  # so that CI works regardless of which server version is currently deployed.
  for user in "${aws_principal_arn}" "${xks_service_user}"; do
    local grant_resp
    grant_resp="$(
      curl -sS \
        -H "Content-Type:application/json" \
        -X POST "${KMS_ADMIN_URL}/access/grant" \
        --data-binary "$(
          cat <<EOF
{
  "unique_identifier": "${key_id}",
  "user_id": "${user}",
  "operation_types": ["getattributes", "encrypt", "decrypt"]
}
EOF
        )"
    )"
    if ! grep -q '"success"' <<<"${grant_resp}"; then
      echo "Warning: grant for ${user} on ${key_id} may have failed. Response: ${grant_resp}" >&2
    fi
  done
}

revoke_xks_op() {
  local key_id="$1"
  local op="$2"

  # Revoke for BOTH Alice (old server, <=5.26.0) and [aws-xks-service] (Manu's fix)
  # so that encrypt-only / decrypt-only tests pass regardless of server version.
  for user in "${aws_principal_arn}" "${xks_service_user}"; do
    local response
    response="$(
      curl -sS \
        -H "Content-Type:application/json" \
        -X POST "${KMS_ADMIN_URL}/access/revoke" \
        --data-binary "$(
          cat <<EOF
{
  "unique_identifier": "${key_id}",
  "user_id": "${user}",
  "operation_types": ["${op}"]
}
EOF
        )"
    )"

    # Revoking an already-revoked permission is not fatal on a persistent server.
    if ! grep -q '"success"' <<<"${response}"; then
      echo "Warning: revoke ${op} for ${user} on ${key_id} — may already be applied. Response:" >&2
      echo "${response}" >&2
    fi
  done
}

# ── Provision test keys ───────────────────────────────────────────────────────
echo "========================================="
echo "Running AWS XKS tests against remote server"
echo "Host   : ${KMS_XKS_HOST}"
echo "Prefix : ${KMS_XKS_URI_PREFIX}"
echo "Region : ${KMS_XKS_REGION}"
echo "========================================="

echo "Provisioning XKS test keys on remote server..."
xks_create_key "aws_xks_kek"
grant_xks_access "aws_xks_kek"
xks_create_key "encrypt_only_key"
grant_xks_access "encrypt_only_key"
xks_create_key "decrypt_only_key"
grant_xks_access "decrypt_only_key"

echo "Enforcing usage restrictions..."
revoke_xks_op "encrypt_only_key" "decrypt"
revoke_xks_op "decrypt_only_key" "encrypt"

# ── Run vendored test suite ───────────────────────────────────────────────────
echo "Running vendored AWS XKS curl-based test client..."

cd "${REPO_ROOT}/test_data/aws_xks/scripts"

export XKS_PROXY_HOST="${KMS_XKS_HOST}"
export URI_PREFIX="${KMS_XKS_URI_PREFIX}"
export SIGV4_ACCESS_KEY_ID="${KMS_XKS_SIGV4_ACCESS_KEY_ID}"
export SIGV4_SECRET_ACCESS_KEY="${KMS_XKS_SIGV4_SECRET_ACCESS_KEY}"
export REGION="${KMS_XKS_REGION}"
export KEY_ID="aws_xks_kek"
export ENCRYPT_ONLY_KEY_ID="encrypt_only_key"
export DECRYPT_ONLY_KEY_ID="decrypt_only_key"
export SCHEME="https://"
export SECURE=""

BASH="$(command -v bash)"
export BASH

./test_all
