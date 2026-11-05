#!/usr/bin/env bash
set -euo pipefail

# End-to-end test of the KMS short-lived SSH certificates against a real OpenSSH server.
#
# An unprivileged `sshd` trusts the KMS SSH CA (`TrustedUserCAKeys`). For a software RSA CA
# and a software ECDSA CA the scenario checks that:
#   - `ssh-keygen -L` parses the issued certificate and reports the CA public key;
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

WORK_DIR="$(mktemp -d /tmp/kms-ssh-cert-XXXXXX)"
SSHD_PID=""
cleanup() {
  local rc=$?
  if [[ -n "${SSHD_PID}" ]]; then kill "${SSHD_PID}" 2>/dev/null || true; fi
  kms_stop
  rm -rf "${WORK_DIR}"
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

# kms_call <method> <path> <json-body>: print "<status>\n<body>".
kms_call() {
  curl --silent --show-error --write-out '\n%{http_code}' --request "$1" \
    --header "Content-Type: application/json" --data "$3" "${KMS_URL}$2"
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

# ssh_as_user <identity> <certificate>: succeeds when sshd accepts the certificate.
ssh_as_user() {
  ssh -F /dev/null -p "${SSHD_PORT}" -i "$1" -o "CertificateFile=$2" \
    -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 \
    "${LOGIN_USER}@127.0.0.1" true
}

print_header "SSH certificates integration test (${VARIANT_NAME})"

kms_write_config "$(kms_pick_free_port)" "${WORK_DIR}/kms-data" \
  "[roles]" "crypto_officer_users = [\"admin\"]"
print_status "Building KMS server and ckms..."
kms_build_server "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
kms_build_cli "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
# Verbose logging makes the "no private key in logs" check below meaningful.
RUST_LOG="cosmian_kms_server=trace,cosmian_kms_server_database=trace" kms_start_from_bin "$(get_kms_bin)"
CKMS_BIN="$(get_ckms_bin)"
CKMS_CONF="$(kms_write_ckms_conf)"
run_ckms() { CKMS_CONF_PATH="${CKMS_CONF}" "${CKMS_BIN}" "$@"; }

# create_ca <rsa|ec>: create a software CA key and print its private-key UID.
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

# Host key and user keys are shared across the CA scenarios.
ssh-keygen -q -t ecdsa -b 256 -N "" -f "${WORK_DIR}/host_key"
ssh-keygen -q -t ecdsa -b 256 -N "" -f "${WORK_DIR}/user_key"
ssh-keygen -q -t rsa -b 2048 -N "" -f "${WORK_DIR}/weak_user_key"
SSHD_PORT="$(kms_pick_free_port)"

run_scenario() {
  local kind="$1" ca_uid response signed
  print_header "Scenario: ${kind} CA"
  ca_uid="$(create_ca "${kind}")"
  [[ -n "${ca_uid}" ]] || print_error "could not create the ${kind} CA key"

  expect_status "configure the ${kind} CA" \
    "$(kms_call PUT /v1/ssh/config/ca "{\"ca_key_uid\":\"${ca_uid}\"}")" 204
  expect_status "create the role" \
    "$(kms_call PUT /v1/ssh/roles/developers \
      "{\"allowed_principals\":[\"${LOGIN_USER}\",\"other-login\"],\"default_ttl\":\"15m\",\"max_ttl\":\"1h\"}")" 204

  curl --fail --silent --show-error "${KMS_URL}/v1/ssh/public_key" --output "${WORK_DIR}/trusted_user_ca_keys"
  cat >"${WORK_DIR}/sshd_config" <<EOF
Port ${SSHD_PORT}
ListenAddress 127.0.0.1
HostKey ${WORK_DIR}/host_key
PidFile ${WORK_DIR}/sshd.pid
TrustedUserCAKeys ${WORK_DIR}/trusted_user_ca_keys
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
LogLevel DEBUG1
EOF
  if [[ -n "${SSHD_PID}" ]]; then
    kill "${SSHD_PID}" 2>/dev/null || true
    wait "${SSHD_PID}" 2>/dev/null || true
  fi
  "${SSHD_BIN}" -D -f "${WORK_DIR}/sshd_config" -E "${WORK_DIR}/sshd.log" &
  SSHD_PID=$!
  for _ in $(seq 1 30); do
    (exec 3<>"/dev/tcp/127.0.0.1/${SSHD_PORT}") 2>/dev/null && break
    sleep 0.5
  done

  local pubkey_json
  pubkey_json="$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read().strip()))' "${WORK_DIR}/user_key.pub")"

  response="$(kms_call POST /v1/ssh/sign/developers \
    "{\"public_key\":${pubkey_json},\"valid_principals\":[\"${LOGIN_USER}\"],\"ttl\":\"${CERT_TTL_SECS}s\"}")"
  expect_status "sign a ${CERT_TTL_SECS}s certificate" "${response}" 200
  signed="$(json_get "$(body_of "${response}")" data.signed_key)"
  [[ -n "${signed}" ]] || print_error "the KMS did not return a signed_key"
  printf '%s\n' "${signed}" >"${WORK_DIR}/user_key-cert.pub"
  local issued_at=$SECONDS

  if ssh-keygen -L -f "${WORK_DIR}/user_key-cert.pub" >"${WORK_DIR}/cert.txt" 2>&1 &&
    grep -q "Principals:" "${WORK_DIR}/cert.txt" && grep -q "${LOGIN_USER}" "${WORK_DIR}/cert.txt"; then
    pass "ssh-keygen -L parses the certificate"
  else
    fail "ssh-keygen -L could not parse the certificate: $(cat "${WORK_DIR}/cert.txt")"
  fi
  local ca_fingerprint cert_ca_fingerprint
  ca_fingerprint="$(ssh-keygen -l -f "${WORK_DIR}/trusted_user_ca_keys" | awk '{print $2}')"
  cert_ca_fingerprint="$(grep -oE 'Signing CA: .* (SHA256:[^ ]+)' "${WORK_DIR}/cert.txt" | grep -oE 'SHA256:[^ ]+')"
  if [[ "${ca_fingerprint}" == "${cert_ca_fingerprint}" ]]; then
    pass "the certificate is signed by the published CA key"
  else
    fail "CA fingerprint mismatch: published ${ca_fingerprint}, certificate ${cert_ca_fingerprint}"
  fi

  if ((SECONDS - issued_at < CERT_TTL_SECS - 2)) && ssh_as_user "${WORK_DIR}/user_key" "${WORK_DIR}/user_key-cert.pub"; then
    pass "sshd accepts the certificate before expiry"
  else
    fail "sshd rejected a valid certificate; see ${WORK_DIR}/sshd.log"
    tail -n 20 "${WORK_DIR}/sshd.log" || true
  fi

  # A principal that is allowed by the role but is not the login name is rejected by sshd.
  response="$(kms_call POST /v1/ssh/sign/developers \
    "{\"public_key\":${pubkey_json},\"valid_principals\":[\"other-login\"],\"ttl\":\"1m\"}")"
  expect_status "sign for another allowed principal" "${response}" 200
  json_get "$(body_of "${response}")" data.signed_key >"${WORK_DIR}/other-cert.pub"
  if ssh_as_user "${WORK_DIR}/user_key" "${WORK_DIR}/other-cert.pub"; then
    fail "sshd accepted a certificate whose principal is not the login name"
  else
    pass "sshd rejects a certificate for a different principal"
  fi

  expect_status "disallowed principal is refused" "$(kms_call POST /v1/ssh/sign/developers \
    "{\"public_key\":${pubkey_json},\"valid_principals\":[\"root\"],\"ttl\":\"1m\"}")" 401
  expect_status "ttl above max_ttl is refused" "$(kms_call POST /v1/ssh/sign/developers \
    "{\"public_key\":${pubkey_json},\"valid_principals\":[\"${LOGIN_USER}\"],\"ttl\":\"2h\"}")" 422
  local weak_json
  weak_json="$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read().strip()))' "${WORK_DIR}/weak_user_key.pub")"
  expect_status "RSA-2048 subject key is refused" "$(kms_call POST /v1/ssh/sign/developers \
    "{\"public_key\":${weak_json},\"valid_principals\":[\"${LOGIN_USER}\"],\"ttl\":\"1m\"}")" 422

  local wait_secs=$((CERT_TTL_SECS + 2 - (SECONDS - issued_at)))
  ((wait_secs > 0)) && sleep "${wait_secs}"
  if ssh_as_user "${WORK_DIR}/user_key" "${WORK_DIR}/user_key-cert.pub"; then
    fail "sshd accepted the certificate after expiry"
  else
    pass "sshd rejects new authentication after expiry"
  fi
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
