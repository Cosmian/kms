#!/usr/bin/env bash
# Deploy a locally-built cosmian_kms binary to the persistent XKS test server.
# Stops the systemd service, replaces the binary, restarts, then waits for HTTPS.
#
# Required env vars:
#   KMS_XKS_SSH_PRIVATE_KEY  — PEM-encoded private key (content, not path)
#   KMS_XKS_SSH_KNOWN_HOSTS  — output of: ssh-keyscan <host>
#   KMS_XKS_SSH_USER         — SSH login user (must be able to stop/start the service)
#   KMS_BIN                  — path to the cosmian_kms binary to upload
#
# Optional:
#   KMS_XKS_HOST             — server hostname (default: aws-xks-kms.cosmian.dev)
#   KMS_XKS_REMOTE_BIN       — remote path for the binary (default: /usr/sbin/cosmian_kms)
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

: "${KMS_XKS_SSH_PRIVATE_KEY:?KMS_XKS_SSH_PRIVATE_KEY is required}"
: "${KMS_XKS_SSH_KNOWN_HOSTS:?KMS_XKS_SSH_KNOWN_HOSTS is required}"
: "${KMS_XKS_SSH_USER:?KMS_XKS_SSH_USER is required}"
: "${KMS_BIN:?KMS_BIN is required (path to the cosmian_kms binary)}"

KMS_XKS_HOST="${KMS_XKS_HOST:-aws-xks-kms.cosmian.dev}"
KMS_XKS_REMOTE_BIN="${KMS_XKS_REMOTE_BIN:-/usr/sbin/cosmian_kms}"

SSH_DIR="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf ${SSH_DIR}" EXIT

KEY_FILE="${SSH_DIR}/id"
printf '%s\n' "${KMS_XKS_SSH_PRIVATE_KEY}" >"${KEY_FILE}"
chmod 600 "${KEY_FILE}"

KNOWN_HOSTS_FILE="${SSH_DIR}/known_hosts"
printf '%s\n' "${KMS_XKS_SSH_KNOWN_HOSTS}" >"${KNOWN_HOSTS_FILE}"
chmod 600 "${KNOWN_HOSTS_FILE}"

SSH_OPTS=(-i "${KEY_FILE}" -o "UserKnownHostsFile=${KNOWN_HOSTS_FILE}" -o "BatchMode=yes")
REMOTE="${KMS_XKS_SSH_USER}@${KMS_XKS_HOST}"

echo "Uploading binary to ${REMOTE}:${KMS_XKS_REMOTE_BIN} ..."
scp "${SSH_OPTS[@]}" "${KMS_BIN}" "${REMOTE}:/tmp/cosmian_kms_deploy"

echo "Replacing binary and restarting service ..."
ssh "${SSH_OPTS[@]}" "${REMOTE}" \
  env REMOTE_BIN="${KMS_XKS_REMOTE_BIN}" \
  bash -c 'systemctl stop cosmian_kms \
              && mv /tmp/cosmian_kms_deploy "$REMOTE_BIN" \
              && chmod 755 "$REMOTE_BIN" \
              && systemctl start cosmian_kms'

# Wait for HTTPS endpoint to respond.
echo "Waiting for server at https://${KMS_XKS_HOST} ..."
for _ in $(seq 1 60); do
  http_code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" -d '{}' \
    "https://${KMS_XKS_HOST}/kmip/2_1" 2>/dev/null || true)
  if [[ "${http_code}" =~ ^[0-9]{3}$ ]]; then
    echo "Server ready (HTTP ${http_code})."
    exit 0
  fi
  sleep 3
done

echo "Server did not respond within 180 s." >&2
exit 1
