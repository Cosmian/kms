#!/usr/bin/env bash
set -euo pipefail

# End-to-end test of the KMS short-lived SSH certificates against a real OpenSSH server.
#
# Identities (mTLS client certificates from test_data): `owner.client` is a Crypto Officer that
# creates the CA key and configures the CA and the role; `user.client` is the only role user and
# has no grant on the CA key; `co3.client` is neither.
#
# An unprivileged `sshd` trusts the KMS SSH CA (`TrustedUserCAKeys`). It runs in inetd mode as the
# ssh ProxyCommand, so no TCP port is picked, released and raced for. For a software RSA CA and
# a software ECDSA CA the scenario checks that:
#   - the role user obtains a certificate through REST without any right on the CA key, while its
#     raw KMIP Sign with that key is refused and a caller outside the role is refused;
#   - `ssh-keygen -L` parses the issued certificate, reports the CA public key and a Key ID
#     naming the requester and the role;
#   - sshd accepts the certificate for an allowed principal before it expires;
#   - sshd rejects new authentication once the certificate has expired;
#   - a certificate whose principal is not the login name is rejected by sshd;
#   - the KMS refuses a disallowed principal, a TTL above the role maximum and a weak RSA key.
#
# Required: the KMS server and ckms binaries (built by the calling task), ssh, sshd, ssh-keygen,
# curl and python3. Usage: test_ssh_certificates.sh --variant <fips|non-fips> --link <static|dynamic>

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

VARIANT_ARG="fips"
LINK_ARG="static"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --variant) VARIANT_ARG="$2" && shift 2 ;;
    --link) LINK_ARG="$2" && shift 2 ;;
    *) print_error "Unknown argument: $1" ;;
  esac
done
kms_init_env "${VARIANT_ARG}" "${LINK_ARG}"

require_cmd ssh "OpenSSH client is required."
require_cmd ssh-keygen "ssh-keygen is required."
require_cmd curl "curl is required."
require_cmd python3 "python3 is required to build and parse JSON."

SSHD_BIN="$(command -v sshd || true)"
[[ -x "${SSHD_BIN}" ]] || SSHD_BIN="/usr/sbin/sshd"
[[ -x "${SSHD_BIN}" ]] || print_error "sshd was not found in PATH or /usr/sbin."

REPO_ROOT="$(get_repo_root)"
CERTS_DIR="${REPO_ROOT}/test_data/certificates/client_server"
WORK_DIR="$(mktemp -d /tmp/kms-ssh-cert-XXXXXX)"
cleanup() {
  local rc=$?
  if [[ "${rc}" -ne 0 && -s "${KMS_LOG_FILE:-}" ]]; then tail -n 40 "${KMS_LOG_FILE}" >&2 || true; fi
  kms_stop
  rm -rf -- "${WORK_DIR:?}"
  exit "${rc}"
}
trap cleanup EXIT

LOGIN_USER="$(id -un)"
CERT_TTL_SECS=6
FAILURES=0

fail() {
  echo -e "${RED}[FAIL]${NC} $*"
  FAILURES=$((FAILURES + 1))
}
pass() { print_success "$*"; }

# From rule://test-configs section 3: fails when the key is absent from the fixture.
set_toml_value() { # <file> <key> <already-quoted-value>
  grep -qE "^$2 *= " "$1" || print_error "key '$2' missing in $1"
  sed -E "s|^($2 *= *).*|\1$3|" "$1" >"$1.tmp" && mv "$1.tmp" "$1"
}

# json_get <json> <dotted.path>: print a string value or nothing.
json_get() {
  python3 - "$1" "$2" <<'PY'
import json, sys
try:
    value = json.loads(sys.argv[1])
    for part in sys.argv[2].split("."):
        value = value[part]
    print(value)
except (ValueError, KeyError, TypeError):
    pass
PY
}

# kms_call <owner|user|co3> <method> <path> <json-body>: print "<body>\n<status>".
# -k: loopback server started by this script; its test certificate has no SAN for 127.0.0.1.
kms_call() {
  local who="$1" data=()
  if [[ -n "${4:-}" ]]; then data=(--header "Content-Type: application/json" --data "$4"); fi
  curl --silent --show-error -k --cert "${CERTS_DIR}/${who}/${who}.client.acme.com.crt" \
    --key "${CERTS_DIR}/${who}/${who}.client.acme.com.key" --write-out '\n%{http_code}' \
    --request "$2" "${data[@]+"${data[@]}"}" "${KMS_URL}$3"
}
status_of() { tail -n 1 <<<"$1"; }
body_of() { sed '$d' <<<"$1"; }

expect_status() {
  local description="$1" response="$2" expected="$3"
  if [[ "$(status_of "${response}")" == "${expected}" ]]; then
    pass "${description} (HTTP ${expected})"
  else
    fail "${description}: expected HTTP ${expected}, got $(status_of "${response}"): $(body_of "${response}")"
  fi
}
expect_denied() {
  local description="$1" response="$2"
  case "$(status_of "${response}")" in
    401 | 403 | 404) pass "${description} (HTTP $(status_of "${response}"))" ;;
    *) fail "${description}: expected a refusal, got HTTP $(status_of "${response}"): $(body_of "${response}")" ;;
  esac
}

print_header "SSH certificates integration test (${VARIANT_NAME})"

# --- KMS: complete mTLS + roles fixture, only scalar values changed --------------------------
KMS_CONFIG_FILE="${WORK_DIR}/kms.toml"
KMS_LOG_FILE="${WORK_DIR}/kms.log"
KMS_PORT="$(kms_pick_free_port)"
KMS_URL="https://127.0.0.1:${KMS_PORT}"
mkdir -p "${WORK_DIR}/kms-data" "${WORK_DIR}/workspace" "${WORK_DIR}/tmp"
cp "${REPO_ROOT}/test_data/configs/server/auth/cert_roles.toml" "${KMS_CONFIG_FILE}"
set_toml_value "${KMS_CONFIG_FILE}" port "${KMS_PORT}"
set_toml_value "${KMS_CONFIG_FILE}" hostname '"127.0.0.1"'
set_toml_value "${KMS_CONFIG_FILE}" kms_public_url "\"https://localhost:${KMS_PORT}/google_cse\""
set_toml_value "${KMS_CONFIG_FILE}" sqlite_path "\"${WORK_DIR}/kms-data\""
set_toml_value "${KMS_CONFIG_FILE}" root_data_path "\"${WORK_DIR}/workspace\""
set_toml_value "${KMS_CONFIG_FILE}" tmp_path "\"${WORK_DIR}/tmp\""
set_toml_value "${KMS_CONFIG_FILE}" tls_cert_file "\"${CERTS_DIR}/server/kmserver.acme.com.crt\""
set_toml_value "${KMS_CONFIG_FILE}" tls_key_file "\"${CERTS_DIR}/server/kmserver.acme.com.key\""
set_toml_value "${KMS_CONFIG_FILE}" clients_ca_cert_file "\"${CERTS_DIR}/ca/ca.crt\""
CKMS_CONF="${WORK_DIR}/ckms_owner.toml"
cp "${REPO_ROOT}/test_data/configs/client/cert_owner.toml" "${CKMS_CONF}"
set_toml_value "${CKMS_CONF}" server_url "\"${KMS_URL}\""
set_toml_value "${CKMS_CONF}" tls_client_pem_cert_path "\"${CERTS_DIR}/owner/owner.client.acme.com.crt\""
set_toml_value "${CKMS_CONF}" tls_client_pem_key_path "\"${CERTS_DIR}/owner/owner.client.acme.com.key\""

print_status "Building KMS server and ckms..."
kms_build_server "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
kms_build_cli "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
# kms_start_from_bin's readiness probe sends no client certificate and verifies the server
# certificate, so the server is started here and probed over mTLS. The fixture sets no rust_log:
# RUST_LOG applies, and verbose logging makes the "no private key in logs" check meaningful.
RUST_LOG="cosmian_kms_server=trace,cosmian_kms_server_database=trace" \
  "$(get_kms_bin)" --config "${KMS_CONFIG_FILE}" >"${KMS_LOG_FILE}" 2>&1 &
KMS_PID=$!
KMS_READY=false
for _ in $(seq 1 120); do
  if [[ "$(status_of "$(kms_call owner GET /me '' 2>/dev/null || true)")" == "200" ]]; then
    KMS_READY=true
    break
  fi
  kill -0 "${KMS_PID}" 2>/dev/null || print_error "the KMS server exited during startup"
  sleep 1
done
[[ "${KMS_READY}" == true ]] || print_error "the KMS server did not answer over mTLS within 120s"
CKMS_BIN="$(get_ckms_bin)"
run_ckms() { CKMS_CONF_PATH="${CKMS_CONF}" "${CKMS_BIN}" "$@"; }

ROLE_USER="$(json_get "$(body_of "$(kms_call user GET /me '')")" user)"
[[ -n "${ROLE_USER}" ]] || print_error "could not read the role user's KMS identity"

# create_ca <rsa|ec>: create a software CA key as the Crypto Officer and print its UID.
create_ca() {
  local output
  if [[ "$1" == "rsa" ]]; then
    output="$(run_ckms rsa keys create --size_in_bits 3072 --tag ssh-ca)"
  else
    output="$(run_ckms ec keys create --curve nist-p256 --tag ssh-ca)"
  fi
  grep -i "private key" <<<"${output}" |
    grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -n 1
}

# raw_sign_body <rsa|ec> <key-uid>: KMIP Sign request over a fixed message.
raw_sign_body() {
  local params=""
  if [[ "$1" == "rsa" ]]; then
    params='{"tag":"CryptographicParameters","type":"Structure","value":[
      {"tag":"DigitalSignatureAlgorithm","type":"Enumeration","value":"SHA256WithRSAEncryption"},
      {"tag":"PaddingMethod","type":"Enumeration","value":"PSS"},
      {"tag":"HashingAlgorithm","type":"Enumeration","value":"SHA256"}]},'
  fi
  printf '{"tag":"Sign","type":"Structure","value":[{"tag":"UniqueIdentifier","type":"TextString","value":"%s"},%s{"tag":"Data","type":"ByteString","value":"736B69702D636865636B"}]}' \
    "$2" "${params}"
}

# Host key, user keys and the sshd configuration are shared across the CA scenarios.
ssh-keygen -q -t ecdsa -b 256 -N "" -f "${WORK_DIR}/host_key"
ssh-keygen -q -t ecdsa -b 256 -N "" -f "${WORK_DIR}/user_key"
ssh-keygen -q -t rsa -b 2048 -N "" -f "${WORK_DIR}/weak_user_key"
: >"${WORK_DIR}/trusted_user_ca_keys"
cat >"${WORK_DIR}/sshd_config" <<EOF
HostKey ${WORK_DIR}/host_key
TrustedUserCAKeys ${WORK_DIR}/trusted_user_ca_keys
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
LogLevel DEBUG1
EOF
run_isolated "${SSHD_BIN}" -t -f "${WORK_DIR}/sshd_config" ||
  print_error "sshd rejected its test configuration"
# Each ssh connection runs its own `sshd -i` over the ProxyCommand pipes (inetd mode).
SSHD_PROXY="$(printf '%q ' "${SSHD_BIN}" -i -f "${WORK_DIR}/sshd_config" -E "${WORK_DIR}/sshd.log")"

# ssh_as_user <identity> <certificate>: succeeds when sshd accepts the certificate.
ssh_as_user() {
  run_isolated ssh -F /dev/null -o "ProxyCommand=${SSHD_PROXY}" -i "$1" -o "CertificateFile=$2" \
    -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 \
    "${LOGIN_USER}@127.0.0.1" true
}

run_scenario() {
  local kind="$1" ca_uid response
  print_header "Scenario: ${kind} CA"
  ca_uid="$(create_ca "${kind}")"
  [[ -n "${ca_uid}" ]] || print_error "could not create the ${kind} CA key"

  expect_status "configure the ${kind} CA" \
    "$(kms_call owner PUT /v1/ssh/config/ca "{\"ca_key_uid\":\"${ca_uid}\"}")" 204
  expect_status "create the role" \
    "$(kms_call owner PUT /v1/ssh/roles/developers \
      "{\"allowed_principals\":[\"${LOGIN_USER}\",\"other-login\"],\"allowed_users\":[\"${ROLE_USER}\"],\"default_ttl\":\"15m\",\"max_ttl\":\"1h\"}")" 204

  # The role user signs only through the role: the CA key itself stays out of its reach.
  response="$(kms_call owner POST /kmip/2_1 "$(raw_sign_body "${kind}" "${ca_uid}")")"
  if [[ "$(status_of "${response}")" == "200" ]] && grep -q SignatureData <<<"${response}"; then
    pass "the CA key owner can sign raw data (control)"
  else
    fail "raw Sign control request failed: ${response}"
  fi
  response="$(kms_call user POST /kmip/2_1 "$(raw_sign_body "${kind}" "${ca_uid}")")"
  if [[ "$(status_of "${response}")" != "200" ]] && ! grep -q SignatureData <<<"${response}"; then
    pass "the role user cannot use the CA key for raw KMIP Sign"
  else
    fail "the role user signed raw data with the CA key: ${response}"
  fi

  curl --fail --silent --show-error -k "${KMS_URL}/v1/ssh/public_key" --output "${WORK_DIR}/trusted_user_ca_keys"
  sign_and_check
}

sign_and_check() {
  local pubkey_json signed issued_at response
  pubkey_json="$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read().strip()))' "${WORK_DIR}/user_key.pub")"

  expect_denied "a caller outside the role is refused" "$(kms_call co3 POST /v1/ssh/sign/developers \
    "{\"public_key\":${pubkey_json},\"valid_principals\":[\"${LOGIN_USER}\"],\"ttl\":\"1m\"}")"
  # Bare seconds are a valid TTL.
  response="$(kms_call user POST /v1/ssh/sign/developers \
    "{\"public_key\":${pubkey_json},\"valid_principals\":[\"${LOGIN_USER}\"],\"ttl\":\"${CERT_TTL_SECS}\"}")"
  expect_status "the role user signs a ${CERT_TTL_SECS}s certificate" "${response}" 200
  signed="$(json_get "$(body_of "${response}")" data.signed_key)"
  [[ -n "${signed}" ]] || print_error "the KMS did not return a signed_key"
  printf '%s\n' "${signed}" >"${WORK_DIR}/user_key-cert.pub"
  issued_at=$SECONDS
  check_certificate

  # sshd runs in inetd mode: its log file only exists after the first connection.
  log_before="$(wc -l <"${WORK_DIR}/sshd.log" 2>/dev/null || echo 0)"
  if ((SECONDS - issued_at < CERT_TTL_SECS - 2)) && ssh_as_user "${WORK_DIR}/user_key" "${WORK_DIR}/user_key-cert.pub"; then
    pass "sshd accepts the certificate before expiry"
  elif [[ "$(uname -s)" == Darwin ]] &&
    tail -n "+$((log_before + 1))" "${WORK_DIR}/sshd.log" | grep -q "^Accepted publickey for ${LOGIN_USER} .*ECDSA-CERT" &&
    tail -n "+$((log_before + 1))" "${WORK_DIR}/sshd.log" | grep -q "Could not create new audit session"; then
    # macOS sshd authenticates the certificate, then cannot open a BSM audit session for the
    # unprivileged test user and drops the connection: the authentication itself succeeded.
    pass "sshd accepts the certificate before expiry (macOS: authenticated, BSM audit session unavailable)"
  else
    fail "sshd rejected a valid certificate; see the sshd log below"
    tail -n 20 "${WORK_DIR}/sshd.log" || true
  fi

  # A principal that is allowed by the role but is not the login name is rejected by sshd.
  response="$(kms_call user POST /v1/ssh/sign/developers \
    "{\"public_key\":${pubkey_json},\"valid_principals\":[\"other-login\"],\"ttl\":\"1m\"}")"
  expect_status "sign for another allowed principal" "${response}" 200
  json_get "$(body_of "${response}")" data.signed_key >"${WORK_DIR}/other-cert.pub"
  if ssh_as_user "${WORK_DIR}/user_key" "${WORK_DIR}/other-cert.pub"; then
    fail "sshd accepted a certificate whose principal is not the login name"
  else
    pass "sshd rejects a certificate for a different principal"
  fi

  check_refusals "${pubkey_json}"

  local wait_secs=$((CERT_TTL_SECS + 2 - (SECONDS - issued_at)))
  ((wait_secs > 0)) && sleep "${wait_secs}"
  if ssh_as_user "${WORK_DIR}/user_key" "${WORK_DIR}/user_key-cert.pub"; then
    fail "sshd accepted the certificate after expiry"
  else
    pass "sshd rejects new authentication after expiry"
  fi
}

check_certificate() {
  if ssh-keygen -L -f "${WORK_DIR}/user_key-cert.pub" >"${WORK_DIR}/cert.txt" 2>&1 &&
    grep -q "Principals:" "${WORK_DIR}/cert.txt" && grep -q "${LOGIN_USER}" "${WORK_DIR}/cert.txt"; then
    pass "ssh-keygen -L parses the certificate"
  else
    fail "ssh-keygen -L could not parse the certificate: $(cat "${WORK_DIR}/cert.txt")"
  fi
  if grep -qF "Key ID: \"${ROLE_USER}/developers/" "${WORK_DIR}/cert.txt"; then
    pass "the Key ID names the requester and the role"
  else
    fail "the Key ID does not name '${ROLE_USER}' and the role: $(grep 'Key ID' "${WORK_DIR}/cert.txt")"
  fi
  local ca_fingerprint cert_ca_fingerprint
  ca_fingerprint="$(ssh-keygen -l -f "${WORK_DIR}/trusted_user_ca_keys" | awk '{print $2}')"
  cert_ca_fingerprint="$(grep -oE 'Signing CA: .* (SHA256:[^ ]+)' "${WORK_DIR}/cert.txt" | grep -oE 'SHA256:[^ ]+')"
  if [[ "${ca_fingerprint}" == "${cert_ca_fingerprint}" ]]; then
    pass "the certificate is signed by the published CA key"
  else
    fail "CA fingerprint mismatch: published ${ca_fingerprint}, certificate ${cert_ca_fingerprint}"
  fi
}

# check_refusals <public-key-json>: the KMS enforces the role limits and the subject key policy.
check_refusals() {
  expect_status "disallowed principal is refused" "$(kms_call user POST /v1/ssh/sign/developers \
    "{\"public_key\":$1,\"valid_principals\":[\"root\"],\"ttl\":\"1m\"}")" 401
  expect_status "ttl above max_ttl is refused" "$(kms_call user POST /v1/ssh/sign/developers \
    "{\"public_key\":$1,\"valid_principals\":[\"${LOGIN_USER}\"],\"ttl\":\"2h\"}")" 422
  local weak_json
  weak_json="$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read().strip()))' "${WORK_DIR}/weak_user_key.pub")"
  expect_status "RSA-2048 subject key is refused" "$(kms_call user POST /v1/ssh/sign/developers \
    "{\"public_key\":${weak_json},\"valid_principals\":[\"${LOGIN_USER}\"],\"ttl\":\"1m\"}")" 422
}

run_scenario ec
run_scenario rsa

if grep -q "PRIVATE KEY" "${KMS_LOG_FILE}"; then
  fail "private key material found in the KMS log"
else
  pass "no private key material in the KMS log"
fi

if ((FAILURES > 0)); then
  print_error "${FAILURES} SSH certificate check(s) failed"
fi
print_success "SSH certificates integration tests completed"
