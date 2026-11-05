#!/usr/bin/env bash
set -euo pipefail

# External PostgreSQL password rotation published to the KMS KV v2 store.
#
# The KMS only generates the password (POST /v1/secrets/password) and stores the published
# secret (POST /v1/kv/data/...). PostgreSQL is administered here, outside the KMS, exactly as the
# guide documentation/docs/integrations/ssh_certificates_and_secret_rotation.md describes.
#
# Scenarios:
#   1. Rotation: the new password authenticates, the old one is refused for a new connection and
#      an authorized KV consumer reads the new value.
#   2. Recovery: the database change succeeds but the KV write fails. Rotation is not reported
#      complete, the pending password is kept, and retrying only the publication with the same
#      password completes it without a second database change.
#
# Requires: docker, curl, python3, and the KMS server binary built by the calling task.
# Usage: test_secret_rotation.sh --variant <fips|non-fips> --link <static|dynamic>

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

require_cmd docker "Docker is required to run PostgreSQL and the OpenBao token verifier."
require_cmd curl "curl is required."
require_cmd python3 "python3 is required to build and parse JSON."

BAO_IMAGE="${BAO_IMAGE:-ghcr.io/openbao/openbao:2.7.1}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
KV_PATH="database/app"
DB_ADMIN_PASSWORD="admin-$$-secret"
INITIAL_PASSWORD="initial-$$-password"
RUN_ID="$$"
VERIFIER_NAME="kms-rotation-verifier-${RUN_ID}"
POSTGRES_NAME="kms-rotation-postgres-${RUN_ID}"
WORK_DIR="$(mktemp -d /tmp/kms-rotation-XXXXXX)"
PROXY_PID=""
FAILURES=0

cleanup() {
  local rc=$?
  kms_stop
  if [[ -n "${PROXY_PID}" ]]; then kill "${PROXY_PID}" 2>/dev/null || true; fi
  docker rm -f "${VERIFIER_NAME}" "${POSTGRES_NAME}" >/dev/null 2>&1 || true
  rm -rf "${WORK_DIR}"
  exit "${rc}"
}
trap cleanup EXIT

fail() {
  echo -e "${RED}[FAIL]${NC} $*"
  FAILURES=$((FAILURES + 1))
}
pass() { print_success "$*"; }
check() {
  local description="$1"
  shift
  if "$@"; then pass "${description}"; else fail "${description}"; fi
}
check_not() {
  local description="$1"
  shift
  if "$@"; then fail "${description}"; else pass "${description}"; fi
}

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

print_header "PostgreSQL password rotation to KMS KV (${VARIANT_NAME})"

# --- OpenBao token verifier: gives the KMS two distinct identities -------------------------
VERIFIER_PORT="$(kms_pick_free_port)"
PROXY_PORT="$(kms_pick_free_port)"
docker run -d --name "${VERIFIER_NAME}" -p "127.0.0.1:${VERIFIER_PORT}:8200" \
  -e BAO_DEV_ROOT_TOKEN_ID=verifier-root -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  "${BAO_IMAGE}" >/dev/null
verifier_bao() {
  docker exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=verifier-root "${VERIFIER_NAME}" bao "$@"
}
for _ in $(seq 1 30); do
  verifier_bao status >/dev/null 2>&1 && break
  sleep 1
done
verifier_bao status >/dev/null 2>&1 || print_error "the OpenBao token verifier did not start"
verifier_bao auth enable userpass >/dev/null
verifier_login() {
  verifier_bao write auth/userpass/users/"$1" password=rotation-test-password >/dev/null
  verifier_bao write -format=json auth/userpass/login/"$1" password=rotation-test-password |
    python3 -c "import sys, json; print(json.load(sys.stdin)['auth']['client_token'])"
}
python3 "${SCRIPT_DIR}/bao_lookup_proxy.py" "${PROXY_PORT}" "http://127.0.0.1:${VERIFIER_PORT}" &
PROXY_PID=$!
ROTATOR_TOKEN="$(verifier_login rotator)"
CONSUMER_TOKEN="${ROTATOR_TOKEN}"
BAD_TOKEN="invalid-token-for-failure-injection"

# --- KMS with the KV store -----------------------------------------------------------------
kms_write_config "$(kms_pick_free_port)" "${WORK_DIR}/kms-data" \
  "[kv]" "kv_enabled = true" 'kv_mount = "kv"' \
  "[vault]" "vault_api_enabled = true" "vault_auth_verifier_url = \"http://127.0.0.1:${PROXY_PORT}\""
print_status "Building KMS server..."
kms_build_server "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
# Verbose logging makes the "no secret in logs" check below meaningful.
RUST_LOG="cosmian_kms_server=trace,cosmian_kms_server_database=trace" kms_start_from_bin "$(get_kms_bin)"

# --- PostgreSQL ----------------------------------------------------------------------------
docker run -d --name "${POSTGRES_NAME}" -e POSTGRES_PASSWORD="${DB_ADMIN_PASSWORD}" "${POSTGRES_IMAGE}" >/dev/null
for _ in $(seq 1 60); do
  docker exec "${POSTGRES_NAME}" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done
sleep 2
# Connections go through the container address so that password authentication is enforced.
db_psql() {
  docker exec -e PGPASSWORD="$1" "${POSTGRES_NAME}" sh -c \
    "psql -h \$(hostname -i) -U \"$2\" -d postgres --no-psqlrc -v ON_ERROR_STOP=1 -tAc 'select 1'" >/dev/null 2>&1
}
db_admin_alter_password() {
  docker exec -i -e PGPASSWORD="${DB_ADMIN_PASSWORD}" -e NEW_DB_PASSWORD="$1" "${POSTGRES_NAME}" sh -c \
    "psql -h \$(hostname -i) -U postgres -d postgres --no-psqlrc -v ON_ERROR_STOP=1" <<'SQL' >/dev/null
\getenv new_password NEW_DB_PASSWORD
ALTER ROLE app_user PASSWORD :'new_password';
SQL
}
docker exec -e PGPASSWORD="${DB_ADMIN_PASSWORD}" "${POSTGRES_NAME}" psql -U postgres -d postgres --no-psqlrc \
  -v ON_ERROR_STOP=1 -c "CREATE ROLE app_user LOGIN PASSWORD '${INITIAL_PASSWORD}'" >/dev/null
check "initial password authenticates" db_psql "${INITIAL_PASSWORD}" app_user

# --- Rotation building blocks (the guide's example) ----------------------------------------
generate_password() {
  curl --fail --silent --show-error --request POST "${KMS_URL}/v1/secrets/password" \
    --header "Content-Type: application/json" --data '{}' |
    python3 -c "import sys, json; print(json.load(sys.stdin)['data']['password'])"
}
kv_write() { # kv_write <token> <password>
  python3 -c 'import json,sys; print(json.dumps({"data": {"username": "app_user", "password": sys.argv[1]}}))' "$2" |
    curl --fail --silent --show-error --request POST "${KMS_URL}/v1/kv/data/${KV_PATH}" \
      --header "X-Vault-Token: $1" --header "Content-Type: application/json" --data-binary @- >/dev/null
}
kv_read_password() { # kv_read_password <token>
  local body
  body="$(curl --silent --request GET "${KMS_URL}/v1/kv/data/${KV_PATH}" --header "X-Vault-Token: $1")"
  json_get "${body}" data.data.password
}
# publish <token> <pending-file>: publish the pending password; delete the file only on success.
publish() {
  kv_write "$1" "$(<"$2")" && rm -f "$2"
}
# rotate <kv-token> <pending-file>: generate, change the database, then publish.
# Returns 0 only when both steps succeeded.
rotate() {
  local token="$1" pending_file="$2"
  umask 077
  # Chained with && because callers use `if rotate`, which disables `set -e`.
  generate_password >"${pending_file}" &&
    db_admin_alter_password "$(<"${pending_file}")" &&
    publish "${token}" "${pending_file}"
}

# --- Scenario 1: rotation ------------------------------------------------------------------
print_header "Scenario 1: rotate and publish"
kv_write "${ROTATOR_TOKEN}" "${INITIAL_PASSWORD}"
PENDING_1="${WORK_DIR}/pending-1"
if rotate "${ROTATOR_TOKEN}" "${PENDING_1}"; then
  pass "rotation completed"
else
  fail "rotation did not complete"
fi
check "pending file removed after publication" test ! -e "${PENDING_1}"
PUBLISHED="$(kv_read_password "${CONSUMER_TOKEN}")"
check "the KV consumer reads a new password" test -n "${PUBLISHED}" -a "${PUBLISHED}" != "${INITIAL_PASSWORD}"
check "the new password authenticates" db_psql "${PUBLISHED}" app_user
check_not "the old password is refused for a new connection" db_psql "${INITIAL_PASSWORD}" app_user
check "the generated password is 32 alphanumeric characters" python3 -c \
  'import re,sys; sys.exit(0 if re.fullmatch(r"[A-Za-z0-9]{32}", sys.argv[1]) else 1)' "${PUBLISHED}"

# --- Scenario 2: database changed, KV write fails ------------------------------------------
print_header "Scenario 2: KV write fails after the database change"
PENDING_2="${WORK_DIR}/pending-2"
if rotate "${BAD_TOKEN}" "${PENDING_2}"; then
  fail "rotation was reported complete although the KV write failed"
else
  pass "rotation is not reported complete when the KV write fails"
fi
check "the pending password is kept" test -s "${PENDING_2}"
RECOVERED="$(<"${PENDING_2}")"
check "the pending password authenticates (database already changed)" db_psql "${RECOVERED}" app_user
check_not "the previous password no longer authenticates" db_psql "${PUBLISHED}" app_user
check "the KV still holds the previous value" test "$(kv_read_password "${CONSUMER_TOKEN}")" = "${PUBLISHED}"
if publish "${ROTATOR_TOKEN}" "${PENDING_2}"; then
  pass "retrying only the KV publication succeeds"
else
  fail "the KV publication retry failed"
fi
check "the pending file is removed after the retry" test ! -e "${PENDING_2}"
check "the KV consumer now reads the working password" test "$(kv_read_password "${CONSUMER_TOKEN}")" = "${RECOVERED}"
check "the published password authenticates" db_psql "$(kv_read_password "${CONSUMER_TOKEN}")" app_user

print_header "No secret in the KMS log"
for secret in "${INITIAL_PASSWORD}" "${PUBLISHED}" "${RECOVERED}"; do
  check_not "a password is absent from the KMS log" grep -qF -- "${secret}" "${KMS_LOG_FILE}"
done

if ((FAILURES > 0)); then
  print_error "${FAILURES} rotation check(s) failed"
fi
print_success "Secret rotation integration tests completed"
