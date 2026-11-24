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
#   KMS_XKS_REMOTE_CONF      — remote server configuration file (default: /etc/cosmian/kms.toml)
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../../common.sh"

: "${KMS_XKS_SSH_PRIVATE_KEY:?KMS_XKS_SSH_PRIVATE_KEY is required}"
: "${KMS_XKS_SSH_KNOWN_HOSTS:?KMS_XKS_SSH_KNOWN_HOSTS is required}"
: "${KMS_XKS_SSH_USER:?KMS_XKS_SSH_USER is required}"
: "${KMS_BIN:?KMS_BIN is required (path to the cosmian_kms binary)}"

KMS_XKS_HOST="${KMS_XKS_HOST:-aws-xks-kms.cosmian.dev}"
KMS_XKS_REMOTE_BIN="${KMS_XKS_REMOTE_BIN:-/usr/sbin/cosmian_kms}"
KMS_XKS_REMOTE_CONF="${KMS_XKS_REMOTE_CONF:-/etc/cosmian/kms.toml}"

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
# Pass script via stdin so SSH argument-joining doesn't break quoting.
# Single-quoted heredoc delimiter prevents client-side expansion; REMOTE_BIN
# is set by `env` on the remote side. Back up the currently-deployed binary
# first so a failed deployment can be rolled back below.
# A server started from a configuration file ignores environment variables, and without
# authentication on a non-loopback address it refuses to start unless the file carries
# `insecure_allow_unauthenticated = true` under `[http]` (issue #1486). This shared XKS test
# host is such a server (SigV4 on the XKS routes only): the opt-in is added to its config only
# for the start of the new binary. The original config is restored once the server is healthy,
# or on rollback, because binaries without this setting reject the unknown key.
# shellcheck disable=SC2087
ssh "${SSH_OPTS[@]}" "${REMOTE}" env REMOTE_BIN="${KMS_XKS_REMOTE_BIN}" REMOTE_CONF="${KMS_XKS_REMOTE_CONF}" bash <<'REMOTE_SCRIPT'
set -euo pipefail
if [ -f "$REMOTE_BIN" ]; then
  sudo cp -f "$REMOTE_BIN" "${REMOTE_BIN}.bak"
fi
# Drop a key a cancelled run may have left behind, then keep a pristine backup of the config.
sudo rm -f "${REMOTE_CONF}.bak"
if sudo test -f "$REMOTE_CONF"; then
  sudo sed -i '/^insecure_allow_unauthenticated/d' "$REMOTE_CONF"
  sudo cp -f "$REMOTE_CONF" "${REMOTE_CONF}.bak"
  if sudo grep -q '^\[http\]' "$REMOTE_CONF"; then
    sudo sed -i '/^\[http\]/a insecure_allow_unauthenticated = true' "$REMOTE_CONF"
  else
    printf '\n[http]\ninsecure_allow_unauthenticated = true\n' | sudo tee -a "$REMOTE_CONF" >/dev/null
  fi
else
  echo "WARNING: $REMOTE_CONF not found on the host; the service must opt in by other means." >&2
fi
sudo systemctl stop cosmian_kms
sudo mv /tmp/cosmian_kms_deploy "$REMOTE_BIN"
sudo chmod 755 "$REMOTE_BIN"
sudo systemctl start cosmian_kms
REMOTE_SCRIPT

# Restores the previously-deployed binary and restarts the service. Called
# when the new deployment fails to become healthy below, so a broken build
# never leaves the shared XKS test server unavailable for later jobs.
rollback_deployment() {
  echo "Rolling back to the previous binary ..." >&2
  # shellcheck disable=SC2087
  ssh "${SSH_OPTS[@]}" "${REMOTE}" env REMOTE_BIN="${KMS_XKS_REMOTE_BIN}" REMOTE_CONF="${KMS_XKS_REMOTE_CONF}" bash <<'ROLLBACK_SCRIPT'
set -euo pipefail
if sudo test -f "${REMOTE_CONF}.bak"; then
  sudo mv -f "${REMOTE_CONF}.bak" "$REMOTE_CONF"
fi
if [ -f "${REMOTE_BIN}.bak" ]; then
  sudo systemctl stop cosmian_kms || true
  sudo mv -f "${REMOTE_BIN}.bak" "$REMOTE_BIN"
  sudo chmod 755 "$REMOTE_BIN"
  sudo systemctl start cosmian_kms
  echo "Rollback complete: restored previous binary and restarted service." >&2
else
  echo "No backup binary found; cannot roll back automatically." >&2
fi
ROLLBACK_SCRIPT
}

# The opt-in key is unknown to every other binary (`deny_unknown_fields`): once the server runs,
# put the original config back so a later deployment of another branch can still parse it.
restore_remote_conf() {
  # shellcheck disable=SC2087
  ssh "${SSH_OPTS[@]}" "${REMOTE}" env REMOTE_CONF="${KMS_XKS_REMOTE_CONF}" bash <<'RESTORE_SCRIPT'
set -euo pipefail
if sudo test -f "${REMOTE_CONF}.bak"; then
  sudo mv -f "${REMOTE_CONF}.bak" "$REMOTE_CONF"
fi
RESTORE_SCRIPT
}

# Wait for HTTPS endpoint to respond with the expected KMIP validation error.
# A POST of an empty JSON body to /kmip/2_1 is rejected by request parsing
# before reaching any business logic, so a correctly running server always
# replies 422 (Unprocessable Entity) — see AGENTS.md's smoke-test convention.
# Any other status (in particular 5xx, which a broken/panicking KMIP handler
# would return) must NOT be treated as healthy, or a broken binary would stay
# deployed and silently break the shared server for every later CI run.
EXPECTED_HTTP_CODE=422

echo "Waiting for server at https://${KMS_XKS_HOST} ..."
for _ in $(seq 1 60); do
  http_code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" -d '{}' \
    "https://${KMS_XKS_HOST}/kmip/2_1" 2>/dev/null || true)
  if [[ "${http_code}" == "${EXPECTED_HTTP_CODE}" ]]; then
    echo "Server ready (HTTP ${http_code})."
    restore_remote_conf
    exit 0
  fi
  if [[ "${http_code}" =~ ^[0-9]{3}$ ]]; then
    echo "Server responded HTTP ${http_code} (expected ${EXPECTED_HTTP_CODE}); waiting ..."
  fi
  sleep 3
done

echo "Server did not return the expected HTTP ${EXPECTED_HTTP_CODE} within 180 s." >&2
rollback_deployment
exit 1
