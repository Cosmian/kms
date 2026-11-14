#!/usr/bin/env bash
set -euo pipefail

# External database password rotation published to the KMS KV v2 store.
#
# The KMS only generates the password (POST /v1/secrets/password) and stores the published
# secret (POST /v1/kv/data/...). The database is administered here, outside the KMS, exactly as
# the guide documentation/docs/integrations/ssh_certificates_and_secret_rotation.md describes.
# The KMS neither knows nor cares which engine is rotated: only the few db_* functions below are
# engine-specific (--db postgres|mysql); every scenario runs unchanged on each engine.
#
# Identities: a rotator, which owns the KV path, and a distinct consumer that only receives a
# `Get` grant on the path's metadata object, both authenticated with `X-Vault-Token`.
#
# Scenarios:
#   0. Only authenticated callers can generate passwords.
#   1. Consumer: before the grant it cannot read; with the read-only grant it reads but cannot
#      overwrite (with or without options.expected_owner), soft-delete or hard-delete the secret.
#   2. Rotation: the new password authenticates, the old one is refused for a new connection and
#      the consumer reads the new value.
#   3. Recovery: the database change succeeds but the KV write fails. Rotation is not reported
#      complete, the pending password is kept, and retrying only the publication with the same
#      password completes it without a second database change.
#
# Requires: docker, curl, python3, and the KMS server binary built by the calling task.
# Usage: test_secret_rotation.sh --variant <fips|non-fips> --link <static|dynamic> [--db <postgres|mysql>]

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"
source "${SCRIPT_DIR}/bao_verifier.sh"

VARIANT_ARG="fips"
LINK_ARG="static"
DB_ENGINE="postgres"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --variant) VARIANT_ARG="$2" && shift 2 ;;
    --link) LINK_ARG="$2" && shift 2 ;;
    --db) DB_ENGINE="$2" && shift 2 ;;
    *) print_error "Unknown argument: $1" ;;
  esac
done
kms_init_env "${VARIANT_ARG}" "${LINK_ARG}"

case "${DB_ENGINE}" in postgres | mysql) ;; *) print_error "Unsupported --db '${DB_ENGINE}' (postgres or mysql)" ;; esac
require_cmd docker "Docker is required to run the database and the OpenBao token verifier."
require_cmd curl "curl is required."
require_cmd python3 "python3 is required to build and parse JSON."

REPO_ROOT="$(get_repo_root)"
KV_PATH="database/app"
DB_ADMIN_PASSWORD="admin-$$-secret"
INITIAL_PASSWORD="initial-$$-password"
FORGED_PASSWORD="forged-$$-password"
RUN_ID="$$"
DB_NAME="kms-rotation-db-${RUN_ID}"
WORK_DIR="$(mktemp -d /tmp/kms-rotation-XXXXXX)"
FAILURES=0

cleanup() {
  local rc=$?
  kms_stop
  bao_verifier_stop
  docker rm -f "${DB_NAME}" >/dev/null 2>&1 || true
  rm -rf -- "${WORK_DIR:?}"
  exit "${rc}"
}
trap cleanup EXIT

# From rule://test-configs section 3: fails when the key is absent from the fixture.
set_toml_value() { # <file> <key> <already-quoted-value>
  grep -qE "^$2 *= " "$1" || print_error "key '$2' missing in $1"
  sed -E "s|^($2 *= *).*|\1$3|" "$1" >"$1.tmp" && mv "$1.tmp" "$1"
}

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

print_header "${DB_ENGINE} password rotation to KMS KV (${VARIANT_NAME})"
run_isolated python3 "${SCRIPT_DIR}/test_bao_lookup_proxy.py"

# --- OpenBao token verifier: authenticates the rotator and the consumer ---------------------
bao_verifier_start "kms-rotation-verifier-${RUN_ID}" "${WORK_DIR}"
ROTATOR_TOKEN="$(bao_verifier_login rotator)"
CONSUMER_TOKEN="$(bao_verifier_login consumer)"
BAD_TOKEN="invalid-token-for-failure-injection"

# --- KMS with the KV store: complete fixture, only scalar values changed --------------------
KMS_CONFIG_FILE="${WORK_DIR}/kms.toml"
KMS_LOG_FILE="${WORK_DIR}/kms.log"
KMS_PORT="$(kms_pick_free_port)"
KMS_URL="http://127.0.0.1:${KMS_PORT}"
mkdir -p "${WORK_DIR}/kms-data" "${WORK_DIR}/workspace" "${WORK_DIR}/tmp"
cp "${REPO_ROOT}/test_data/configs/server/auth/vault_kv.toml" "${KMS_CONFIG_FILE}"
set_toml_value "${KMS_CONFIG_FILE}" port "${KMS_PORT}"
set_toml_value "${KMS_CONFIG_FILE}" sqlite_path "\"${WORK_DIR}/kms-data\""
set_toml_value "${KMS_CONFIG_FILE}" root_data_path "\"${WORK_DIR}/workspace\""
set_toml_value "${KMS_CONFIG_FILE}" tmp_path "\"${WORK_DIR}/tmp\""
set_toml_value "${KMS_CONFIG_FILE}" vault_auth_verifier_url "\"${BAO_VERIFIER_URL}\""
print_status "Building KMS server..."
kms_build_server "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
# The fixture sets no rust_log, so RUST_LOG applies: verbose logging makes the "no secret in
# logs" check below meaningful.
RUST_LOG="cosmian_kms_server=trace,cosmian_kms_server_database=trace" kms_start_from_bin "$(get_kms_bin)"

# kms_user <token>: the identity the KMS derives from the token.
kms_user() {
  curl --fail --silent --show-error "${KMS_URL}/me" --header "X-Vault-Token: $1" |
    python3 -c "import sys, json; print(json.load(sys.stdin)['user'])"
}
ROTATOR_ID="$(kms_user "${ROTATOR_TOKEN}")"
CONSUMER_ID="$(kms_user "${CONSUMER_TOKEN}")"
[[ -n "${ROTATOR_ID}" && -n "${CONSUMER_ID}" && "${ROTATOR_ID}" != "${CONSUMER_ID}" ]] ||
  print_error "the rotator and the consumer must be distinct KMS identities ('${ROTATOR_ID}', '${CONSUMER_ID}')"
print_status "rotator: ${ROTATOR_ID}, consumer: ${CONSUMER_ID}"

# --- Database under rotation -----------------------------------------------------------------
# The only engine-specific part. Contract used by the scenarios below:
#   db_login <password> <user>        succeeds iff a NEW TCP connection authenticates
#   db_admin_login                    the same, as the administrator
#   db_create_app_user <password>     creates the application account `app_user`
#   db_admin_alter_password <password> changes the password of `app_user` (the rotation step)
# Connections go through the container address so that password authentication is enforced; the
# images' init phase serves the Unix socket only, so a TCP login means the final server is up.
case "${DB_ENGINE}" in
  postgres)
    ROTATION_IMAGE="${POSTGRES_IMAGE:-$(compose_image postgres-rotation)}"
    docker run -d --name "${DB_NAME}" -e POSTGRES_PASSWORD="${DB_ADMIN_PASSWORD}" \
      "${ROTATION_IMAGE}" >/dev/null
    db_login() {
      docker exec -e PGPASSWORD="$1" "${DB_NAME}" sh -c \
        "psql -h \$(hostname -i) -U \"$2\" -d postgres --no-psqlrc -v ON_ERROR_STOP=1 -tAc 'select 1'" >/dev/null 2>&1
    }
    db_admin_login() { db_login "${DB_ADMIN_PASSWORD}" postgres; }
    db_create_app_user() {
      docker exec -e PGPASSWORD="${DB_ADMIN_PASSWORD}" "${DB_NAME}" psql -U postgres -d postgres --no-psqlrc \
        -v ON_ERROR_STOP=1 -c "CREATE ROLE app_user LOGIN PASSWORD '$1'" >/dev/null
    }
    db_admin_alter_password() {
      docker exec -i -e PGPASSWORD="${DB_ADMIN_PASSWORD}" -e NEW_DB_PASSWORD="$1" "${DB_NAME}" sh -c \
        "psql -h \$(hostname -i) -U postgres -d postgres --no-psqlrc -v ON_ERROR_STOP=1" <<'SQL' >/dev/null
\getenv new_password NEW_DB_PASSWORD
ALTER ROLE app_user PASSWORD :'new_password';
SQL
    }
    ;;
  mysql)
    ROTATION_IMAGE="${MYSQL_IMAGE:-$(compose_image mysql-rotation)}"
    docker run -d --name "${DB_NAME}" -e MYSQL_ROOT_PASSWORD="${DB_ADMIN_PASSWORD}" \
      "${ROTATION_IMAGE}" >/dev/null
    db_login() {
      docker exec -e MYSQL_PWD="$1" "${DB_NAME}" sh -c \
        "mysql -h 127.0.0.1 -u\"$2\" -e 'select 1'" >/dev/null 2>&1
    }
    db_admin_login() { db_login "${DB_ADMIN_PASSWORD}" root; }
    # printf is a shell builtin and the SQL travels on stdin: the password is on no command line.
    # Generated passwords are alphanumeric, so single-quoting them in SQL is safe.
    db_create_app_user() {
      printf "CREATE USER 'app_user'@'%%' IDENTIFIED BY '%s';" "$1" |
        docker exec -i -e MYSQL_PWD="${DB_ADMIN_PASSWORD}" "${DB_NAME}" sh -c "mysql -h 127.0.0.1 -uroot" >/dev/null
    }
    db_admin_alter_password() {
      printf "ALTER USER 'app_user'@'%%' IDENTIFIED BY '%s';" "$1" |
        docker exec -i -e MYSQL_PWD="${DB_ADMIN_PASSWORD}" "${DB_NAME}" sh -c "mysql -h 127.0.0.1 -uroot" >/dev/null
    }
    ;;
esac
DB_READY=false
for _ in $(seq 1 240); do
  if db_admin_login; then
    DB_READY=true
    break
  fi
  sleep 0.5
done
[[ "${DB_READY}" == true ]] ||
  print_error "${DB_ENGINE} did not accept TCP logins within 120s: $(docker logs "${DB_NAME}" 2>&1 | tail -n 20)"
db_create_app_user "${INITIAL_PASSWORD}"
check "initial password authenticates" db_login "${INITIAL_PASSWORD}" app_user

# --- KMS calls -------------------------------------------------------------------------------
# password_status [token]: HTTP status of POST /v1/secrets/password, with the token when given.
password_status() {
  local token_header=()
  [[ -n "${1:-}" ]] && token_header=(--header "X-Vault-Token: $1")
  curl --silent --output /dev/null --write-out '%{http_code}' --request POST \
    "${KMS_URL}/v1/secrets/password" --header "Content-Type: application/json" \
    "${token_header[@]+"${token_header[@]}"}" --data '{}'
}
generate_password() {
  curl --fail --silent --show-error --request POST "${KMS_URL}/v1/secrets/password" \
    --header "X-Vault-Token: ${ROTATOR_TOKEN}" --header "Content-Type: application/json" --data '{}' |
    python3 -c "import sys, json; print(json.load(sys.stdin)['data']['password'])"
}
# kv_body <password> [expected-owner]: Vault KV v2 write body.
kv_body() {
  python3 - "$@" <<'PY'
import json, sys
body = {"data": {"username": "app_user", "password": sys.argv[1]}}
if len(sys.argv) > 2:
    body["options"] = {"expected_owner": sys.argv[2]}
print(json.dumps(body))
PY
}
kv_write() { # kv_write <token> <password>
  kv_body "$2" |
    curl --fail --silent --show-error --request POST "${KMS_URL}/v1/kv/data/${KV_PATH}" \
      --header "X-Vault-Token: $1" --header "Content-Type: application/json" --data-binary @- >/dev/null
}
kv_read_password() { # kv_read_password <token>
  local body
  body="$(curl --silent --request GET "${KMS_URL}/v1/kv/data/${KV_PATH}" --header "X-Vault-Token: $1")"
  json_get "${body}" data.data.password
}
# kv_status <token> <method> <uri> [json-body]: HTTP status of a KV call.
kv_status() {
  local args=(--silent --output /dev/null --write-out '%{http_code}' --request "$2"
    --header "X-Vault-Token: $1" --header "Content-Type: application/json")
  if [[ -n "${4:-}" ]]; then args+=(--data "$4"); fi
  curl "${args[@]}" "${KMS_URL}$3"
}
# denied <status>: the KMS refused the call without revealing more than "unavailable".
denied() { [[ "$1" == 403 || "$1" == 404 ]]; }
# metadata_uid <owner-token>: UID of the path's metadata object, found by its KV tag.
metadata_uid() {
  python3 - "_kv::meta::${KV_PATH}" <<'PY' |
import json, sys
attribute = [
    {"tag": "VendorIdentification", "type": "TextString", "value": "cosmian"},
    {"tag": "AttributeName", "type": "TextString", "value": "tag"},
    {"tag": "AttributeValue", "type": "TextString", "value": json.dumps([sys.argv[1]])},
]
print(json.dumps({"tag": "Locate", "type": "Structure", "value": [
    {"tag": "Attributes", "type": "Structure", "value": [
        {"tag": "Attribute", "type": "Structure", "value": attribute}]}]}))
PY
    curl --fail --silent --show-error --request POST "${KMS_URL}/kmip/2_1" \
      --header "X-Vault-Token: $1" --header "Content-Type: application/json" --data-binary @- |
    python3 -c '
import json, sys
uids = [item["value"] for item in json.load(sys.stdin)["value"] if item["tag"] == "UniqueIdentifier"]
if len(uids) != 1:
    sys.exit(f"expected exactly one KV metadata object, located {len(uids)}")
print(uids[0])'
}
grant_get() { # grant_get <owner-token> <object-uid> <user>
  python3 -c 'import json, sys; print(json.dumps({"unique_identifier": sys.argv[1], "user_id": sys.argv[2], "operation_types": ["get"]}))' "$2" "$3" |
    curl --fail --silent --show-error --request POST "${KMS_URL}/access/grant" \
      --header "X-Vault-Token: $1" --header "Content-Type: application/json" --data-binary @- >/dev/null
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

# --- Scenario 0: only authenticated callers can generate passwords --------------------------
print_header "Scenario 0: password generation requires authentication"
check "an anonymous caller is refused (401)" test "$(password_status)" = "401"
check "an invalid token is refused (403)" test "$(password_status "${BAD_TOKEN}")" = "403"
check "an authenticated caller is served (200)" test "$(password_status "${ROTATOR_TOKEN}")" = "200"

# --- Scenario 1: read-only consumer ---------------------------------------------------------
print_header "Scenario 1: the consumer reads with a Get grant and cannot change the secret"
DATA_URI="/v1/kv/data/${KV_PATH}"
kv_write "${ROTATOR_TOKEN}" "${INITIAL_PASSWORD}"
check "the consumer cannot read before the grant" denied "$(kv_status "${CONSUMER_TOKEN}" GET "${DATA_URI}")"
METADATA_UID="$(metadata_uid "${ROTATOR_TOKEN}")"
grant_get "${ROTATOR_TOKEN}" "${METADATA_UID}" "${CONSUMER_ID}"
check "the consumer reads with the Get grant" test "$(kv_read_password "${CONSUMER_TOKEN}")" = "${INITIAL_PASSWORD}"
check "the consumer cannot overwrite" \
  denied "$(kv_status "${CONSUMER_TOKEN}" POST "${DATA_URI}" "$(kv_body "${FORGED_PASSWORD}")")"
check "the consumer cannot overwrite even naming the owner (expected_owner)" \
  denied "$(kv_status "${CONSUMER_TOKEN}" POST "${DATA_URI}" "$(kv_body "${FORGED_PASSWORD}" "${ROTATOR_ID}")")"
check "the consumer cannot soft-delete" denied "$(kv_status "${CONSUMER_TOKEN}" DELETE "${DATA_URI}")"
check "the consumer cannot hard-delete" \
  denied "$(kv_status "${CONSUMER_TOKEN}" DELETE "/v1/kv/metadata/${KV_PATH}")"
check "the owner still reads the original value" test "$(kv_read_password "${ROTATOR_TOKEN}")" = "${INITIAL_PASSWORD}"

# --- Scenario 2: rotation ------------------------------------------------------------------
print_header "Scenario 2: rotate and publish"
PENDING_1="${WORK_DIR}/pending-1"
if rotate "${ROTATOR_TOKEN}" "${PENDING_1}"; then
  pass "rotation completed"
else
  fail "rotation did not complete"
fi
check "pending file removed after publication" test ! -e "${PENDING_1}"
PUBLISHED="$(kv_read_password "${CONSUMER_TOKEN}")"
check "the KV consumer reads a new password" test -n "${PUBLISHED}" -a "${PUBLISHED}" != "${INITIAL_PASSWORD}"
check "the new password authenticates" db_login "${PUBLISHED}" app_user
check_not "the old password is refused for a new connection" db_login "${INITIAL_PASSWORD}" app_user
check "the generated password is 32 alphanumeric characters" python3 -c \
  'import re,sys; sys.exit(0 if re.fullmatch(r"[A-Za-z0-9]{32}", sys.argv[1]) else 1)' "${PUBLISHED}"

# --- Scenario 3: database changed, KV write fails ------------------------------------------
print_header "Scenario 3: KV write fails after the database change"
PENDING_2="${WORK_DIR}/pending-2"
if rotate "${BAD_TOKEN}" "${PENDING_2}"; then
  fail "rotation was reported complete although the KV write failed"
else
  pass "rotation is not reported complete when the KV write fails"
fi
check "the pending password is kept" test -s "${PENDING_2}"
RECOVERED="$(<"${PENDING_2}")"
check "the pending password authenticates (database already changed)" db_login "${RECOVERED}" app_user
check_not "the previous password no longer authenticates" db_login "${PUBLISHED}" app_user
check "the KV still holds the previous value" test "$(kv_read_password "${CONSUMER_TOKEN}")" = "${PUBLISHED}"
if publish "${ROTATOR_TOKEN}" "${PENDING_2}"; then
  pass "retrying only the KV publication succeeds"
else
  fail "the KV publication retry failed"
fi
check "the pending file is removed after the retry" test ! -e "${PENDING_2}"
check "the KV consumer now reads the working password" test "$(kv_read_password "${CONSUMER_TOKEN}")" = "${RECOVERED}"
check "the published password authenticates" db_login "$(kv_read_password "${CONSUMER_TOKEN}")" app_user

print_header "No secret in the KMS log"
for secret in "${INITIAL_PASSWORD}" "${FORGED_PASSWORD}" "${PUBLISHED}" "${RECOVERED}"; do
  check_not "a password is absent from the KMS log" grep -qF -- "${secret}" "${KMS_LOG_FILE}"
done

if ((FAILURES > 0)); then
  print_error "${FAILURES} rotation check(s) failed"
fi
print_success "Secret rotation integration tests completed"
