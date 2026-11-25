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
#   KMS_XKS_REMOTE_CONF      — remote server configuration file (default: read from the unit)
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../../common.sh"

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
# Pass script via stdin so SSH argument-joining doesn't break quoting.
# Single-quoted heredoc delimiter prevents client-side expansion; REMOTE_BIN
# is set by `env` on the remote side. Back up the currently-deployed binary
# first so a failed deployment can be rolled back below.
# Without any authentication method on a non-loopback address the new binary refuses to start
# unless the setting `insecure_allow_unauthenticated` is on (issue #1486). The shared XKS test
# host is such a server (SigV4 on the XKS routes only). The deployment mimics the server's own
# configuration lookup: `-c`/`--config` in ExecStart, else COSMIAN_KMS_CONF if that file
# exists, else /etc/cosmian/kms.toml if it exists (`KMS_XKS_REMOTE_CONF` overrides all).
#  - A configuration file ignores environment variables: the key is added to it (tagged, unless
#    the file already has it) and the original file is restored once the server is healthy or
#    on rollback.
#  - With no configuration file, the server reads its environment: a systemd drop-in sets
#    KMS_INSECURE_ALLOW_UNAUTHENTICATED, and is removed the same way.
# Either way the host is left as found, because binaries without the setting reject the TOML
# key. This can be dropped once every deployable branch has the setting and the operator keeps
# it in the host configuration.
# The remote script prints the resolved configuration path (`-` for the drop-in mode) on
# stdout; nothing else does. The Actions log is public: no unit argument, environment value or
# file content is ever printed.
KMS_XKS_DROPIN=/etc/systemd/system/cosmian_kms.service.d/zz-xks-deploy-optin.conf
# shellcheck disable=SC2087
KMS_XKS_REMOTE_CONF="$(
  ssh "${SSH_OPTS[@]}" "${REMOTE}" env REMOTE_BIN="${KMS_XKS_REMOTE_BIN}" CONF_OVERRIDE="${KMS_XKS_REMOTE_CONF:-}" DROPIN="${KMS_XKS_DROPIN}" bash <<'REMOTE_SCRIPT'
set -euo pipefail
tag='# added by deploy_xks_remote.sh'
conf="$CONF_OVERRIDE"
if [ -z "$conf" ]; then
  conf="$(systemctl show -p ExecStart --value cosmian_kms | grep -oE -- '(-c|--config)[ =][^ ;]+' | head -n1 | sed -E 's/^(-c|--config)[ =]//')" || true
fi
if [ -z "$conf" ]; then
  env_conf="$(systemctl show -p Environment --value cosmian_kms | tr ' ' '\n' | sed -n 's/^COSMIAN_KMS_CONF=//p' | head -n1)" || true
  if [ -n "$env_conf" ] && sudo test -f "$env_conf"; then
    conf="$env_conf"
  elif sudo test -f /etc/cosmian/kms.toml; then
    conf=/etc/cosmian/kms.toml
  fi
fi
if [ -n "$conf" ] && ! sudo test -f "$conf"; then
  echo "ERROR: the configuration file given by the unit or KMS_XKS_REMOTE_CONF does not exist: '${conf}'" >&2
  exit 1
fi
if [ -f "$REMOTE_BIN" ]; then
  sudo cp -f "$REMOTE_BIN" "${REMOTE_BIN}.bak"
fi
if [ -n "$conf" ]; then
  # Drop an opt-in a cancelled run left behind (tagged lines only), then keep a pristine backup.
  sudo rm -f "${conf}.bak"
  sudo sed -i "\|${tag}\$|d" "$conf"
  if ! sudo grep -q '^insecure_allow_unauthenticated' "$conf"; then
    sudo cp -f "$conf" "${conf}.bak"
    line="insecure_allow_unauthenticated = true ${tag}"
    if sudo grep -q '^\[http\]' "$conf"; then
      sudo sed -i "/^\[http\]/a ${line}" "$conf"
    else
      printf '\n[http]\n%s\n' "$line" | sudo tee -a "$conf" >/dev/null
    fi
  fi
else
  conf=-
  sudo mkdir -p "$(dirname "$DROPIN")"
  printf '[Service]\nEnvironment=KMS_INSECURE_ALLOW_UNAUTHENTICATED=true\n' | sudo tee "$DROPIN" >/dev/null
  sudo systemctl daemon-reload
fi
sudo systemctl stop cosmian_kms
sudo mv /tmp/cosmian_kms_deploy "$REMOTE_BIN"
sudo chmod 755 "$REMOTE_BIN"
sudo systemctl start cosmian_kms
echo "$conf"
REMOTE_SCRIPT
)"

# Restores the previously-deployed binary and restarts the service. Called
# when the new deployment fails to become healthy below, so a broken build
# never leaves the shared XKS test server unavailable for later jobs.
rollback_deployment() {
  echo "Rolling back to the previous binary ..." >&2
  # shellcheck disable=SC2087
  ssh "${SSH_OPTS[@]}" "${REMOTE}" env REMOTE_BIN="${KMS_XKS_REMOTE_BIN}" REMOTE_CONF="${KMS_XKS_REMOTE_CONF}" DROPIN="${KMS_XKS_DROPIN}" bash <<'ROLLBACK_SCRIPT'
set -euo pipefail
if [ "$REMOTE_CONF" = "-" ]; then
  sudo rm -f "$DROPIN"
  sudo systemctl daemon-reload
elif sudo test -f "${REMOTE_CONF}.bak"; then
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

# The opt-in is unknown to binaries without this setting (`deny_unknown_fields` for the TOML key):
# once the server runs, put the host back as it was so a later deployment of another branch works.
restore_remote_conf() {
  # shellcheck disable=SC2087
  ssh "${SSH_OPTS[@]}" "${REMOTE}" env REMOTE_CONF="${KMS_XKS_REMOTE_CONF}" DROPIN="${KMS_XKS_DROPIN}" bash <<'RESTORE_SCRIPT'
set -euo pipefail
if [ "$REMOTE_CONF" = "-" ]; then
  sudo rm -f "$DROPIN"
  sudo systemctl daemon-reload
elif sudo test -f "${REMOTE_CONF}.bak"; then
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
