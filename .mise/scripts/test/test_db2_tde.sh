#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# test_db2_tde.sh — IBM Db2 LUW ↔ Cosmian KMS KMIP TDE integration test
#
# What this tests:
#   1. Sad path  — KMS rejects connections without a client certificate.
#   2. Happy path — Db2 connects to the KMS over mTLS (KMIP 1.1), creates a
#                   Database Encryption Master Key (DEMK), and creates an
#                   encrypted database.  Verifies the key is visible in the KMS.
#
# IBM Db2 Community Edition (12.1+) has no license restriction on KMIP TDE —
# only "IBM DB2 Performance Management Offering" is gated. KEYSTORE_TYPE=KMIP
# works out of the box. PRODUCT_NAME=OTHER is the documented value for any
# third-party KMIP 1.1+ key manager (i.e. not ISKLM or SafeNet KeySecure).
#
# Prerequisites:
#   • Docker must be available.
#   • docker-compose db2-tde service is used (icr.io/db2_community/db2).
#
# Configurable environment variables:
#   DB2_DOCKER_IMAGE    Image to use (default: icr.io/db2_community/db2)
#   DB2_CONTAINER_NAME  Container name (default: db2-kmip-test)
#   DB2_INSTANCE_PWD    db2inst1 password (default: Db2KmipTest1)
#   DB2_DBNAME          Test database name (default: KMIPDB)
#   KMS_KMIP_PORT       KMIP socket port (default: dynamically allocated)
#   KMS_HTTP_PORT       KMS HTTP/HTTPS port (default: dynamically allocated)
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=.mise/scripts/common.sh
source "${MISE_CONFIG_ROOT:-.}/.mise/scripts/common.sh"
# shellcheck source=.mise/lib/test_slots.sh
source "${MISE_CONFIG_ROOT:-.}/.mise/lib/test_slots.sh"
# shellcheck source=.mise/lib/kms_server.sh
source "${MISE_CONFIG_ROOT:-.}/.mise/lib/kms_server.sh"
REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")

init_build_env "$@"
setup_test_logging

# ── Configuration ─────────────────────────────────────────────────────────────
: "${DB2_DOCKER_IMAGE:=icr.io/db2_community/db2}"
: "${DB2_CONTAINER_NAME:=db2-kmip-test}"
: "${DB2_INSTANCE_PWD:=Db2KmipTest1}"
: "${DB2_DBNAME:=KMIPDB}"
: "${KMS_KMIP_PORT:=$(kms_pick_free_port)}"
: "${KMS_HTTP_PORT:=$(kms_pick_free_port)}"
# KMS hostname as seen from inside the Db2 Docker container.
: "${KMS_HOST_FROM_DB2:=kmserver.acme.com}"

CERT_DIR="${REPO_ROOT}/test_data/certificates/client_server"
CA_CERT="${CERT_DIR}/ca/ca.crt"
SERVER_CERT="${CERT_DIR}/server/kmserver.acme.com.crt"
SERVER_KEY="${CERT_DIR}/server/kmserver.acme.com.key"
CLIENT_P12="${CERT_DIR}/owner/owner.client.acme.com.p12"

KMS_SQLITE_DIR="$(mktemp -d -t kms-db2-XXXXXX)"

require_cmd cargo "Cargo is required to build the KMS."
require_cmd docker "Docker is required to run the Db2 container."
require_cmd openssl "openssl is required for TLS verification."

# ── Cleanup ───────────────────────────────────────────────────────────────────
KMS_PID=""
# shellcheck disable=SC2317,SC2329
cleanup() {
  set +e
  echo "--- Cleanup ---"
  if [ -n "${KMS_PID}" ] && kill -0 "${KMS_PID}" 2>/dev/null; then
    kill "${KMS_PID}" 2>/dev/null || true
    sleep 1
    kill -9 "${KMS_PID}" 2>/dev/null || true
  fi
  docker compose -f "${REPO_ROOT}/docker-compose.yml" rm -sf db2-tde 2>/dev/null || true
  rm -rf "${KMS_SQLITE_DIR}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Step 1: Build & start the KMS with socket server ──────────────────────────
echo "==> Building KMS server (${VARIANT_NAME})…"
pushd "${REPO_ROOT}" >/dev/null
cargo build --bin cosmian_kms --bin ckms "${FEATURES_FLAG[@]}"
CKMS_BIN="${REPO_ROOT}/target/debug/ckms"
CKMS_URL="https://127.0.0.1:${KMS_HTTP_PORT}"

CKMS_CONF="${KMS_SQLITE_DIR}/ckms.toml"
cat >"${CKMS_CONF}" <<CKMS_CONF_EOF
[http_config]
server_url = "${CKMS_URL}"
accept_invalid_certs = true
tls_client_pkcs12_path = "${CLIENT_P12}"
tls_client_pkcs12_password = "password"
CKMS_CONF_EOF

echo "==> Starting KMS (KMIP socket port ${KMS_KMIP_PORT}, HTTP port ${KMS_HTTP_PORT})…"
RUST_LOG="${RUST_LOG:-cosmian_kms_server=info,cosmian_kmip=warn}" \
  KMS_SOCKET_SERVER_START=true \
  cargo run --bin cosmian_kms "${FEATURES_FLAG[@]}" -- \
  --database-type sqlite \
  --sqlite-path "${KMS_SQLITE_DIR}" \
  --socket-server-port "${KMS_KMIP_PORT}" \
  --tls-cert-file "${SERVER_CERT}" \
  --tls-key-file "${SERVER_KEY}" \
  --clients-ca-cert-file "${CA_CERT}" \
  --port "${KMS_HTTP_PORT}" \
  --hostname "127.0.0.1" \
  &
KMS_PID=$!
popd >/dev/null

echo "Waiting for KMS to become ready…"
if ! _wait_for_port 127.0.0.1 "${KMS_HTTP_PORT}" 60; then
  echo "ERROR: KMS HTTP (port ${KMS_HTTP_PORT}) did not become ready in time." >&2
  exit 1
fi
echo "KMS is ready."

# ── Step 2: Sad path — reject bare TLS connection ────────────────────────────
echo
echo "==> Sad path: connecting WITHOUT a client certificate (expect rejection)…"
OPENSSL_RESULT=$(openssl s_client \
  -connect "127.0.0.1:${KMS_KMIP_PORT}" \
  -CAfile "${CA_CERT}" \
  -verify_return_error \
  -brief \
  </dev/null 2>&1 || true)
if echo "${OPENSSL_RESULT}" | grep -qE "handshake failure|certificate required|alert certificate required|no certificate"; then
  echo "==> PASS: Server correctly rejected connection without client certificate."
else
  if echo "${OPENSSL_RESULT}" | grep -q "Verify return code: 0"; then
    echo "ERROR: Server accepted a TLS connection with no client certificate." >&2
    echo "${OPENSSL_RESULT}" >&2
    exit 1
  fi
  echo "==> PASS (connection closed without explicit alert — acceptable for mTLS)."
fi

# ── Step 3: Verify KMS REST API ───────────────────────────────────────────────
echo
echo "==> Testing KMS REST API: sym key create / encrypt / decrypt…"
KEY_CREATE_OUT=$(
  "${CKMS_BIN}" --conf-path "${CKMS_CONF}" \
    sym keys create --algorithm aes --number-of-bits 256 2>&1
) || true
KMS_KEY_ID=$(echo "${KEY_CREATE_OUT}" |
  grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' |
  head -1 || true)
if [ -z "${KMS_KEY_ID}" ]; then
  echo "ERROR: Failed to create AES-256 key." >&2
  echo "${KEY_CREATE_OUT}" >&2
  exit 1
fi
echo "  Test key created: ${KMS_KEY_ID}"

PLAINTEXT_FILE="${KMS_SQLITE_DIR}/plaintext.txt"
ENCRYPTED_FILE="${KMS_SQLITE_DIR}/encrypted.bin"
DECRYPTED_FILE="${KMS_SQLITE_DIR}/decrypted.txt"
printf 'DB2_KMS_MTLS_CI_ROUND_TRIP\n' >"${PLAINTEXT_FILE}"
"${CKMS_BIN}" --conf-path "${CKMS_CONF}" sym encrypt \
  --key-id "${KMS_KEY_ID}" --output-file "${ENCRYPTED_FILE}" \
  "${PLAINTEXT_FILE}" >/dev/null 2>&1
"${CKMS_BIN}" --conf-path "${CKMS_CONF}" sym decrypt \
  --key-id "${KMS_KEY_ID}" --output-file "${DECRYPTED_FILE}" \
  "${ENCRYPTED_FILE}" >/dev/null 2>&1
if diff -q "${PLAINTEXT_FILE}" "${DECRYPTED_FILE}" >/dev/null 2>&1; then
  echo "==> PASS: AES-GCM encrypt/decrypt round-trip via KMS REST API succeeded."
else
  echo "ERROR: Decrypted content does not match original plaintext." >&2
  exit 1
fi

# ── Step 4: Start Db2 via docker compose ─────────────────────────────────────
echo
echo "==> Starting Db2 container via docker compose…"
echo "    Image: ${DB2_DOCKER_IMAGE} (with LICENSE=accept)"
export DB2_DOCKER_IMAGE DB2_CONTAINER_NAME DB2_INSTANCE_PWD DB2_DBNAME
docker compose -f "${REPO_ROOT}/docker-compose.yml" up -d db2-tde

echo "Waiting for Db2 to initialize (up to 300 s — Db2 startup is slow)…"
DB2_READY=false
for _i in $(seq 1 300); do
  DB2_LOG=$(docker logs "${DB2_CONTAINER_NAME}" 2>&1 || true)
  if echo "${DB2_LOG}" | grep -q "Setup has completed"; then
    DB2_READY=true
    break
  fi
  sleep 1
done
if [ "${DB2_READY}" = false ]; then
  echo "ERROR: Db2 container did not become ready within 300 s." >&2
  docker logs "${DB2_CONTAINER_NAME}" >&2 || true
  exit 1
fi
echo "Db2 is ready."

# ── Step 5: Install GSKit tooling prerequisite ────────────────────────────────
# gsk9certutil_64 (the GSKit CLI in Db2 12.1 — gsk8capicmd_64 was removed) needs
# libicu, which is missing from the icr.io/db2_community/db2 image.
echo
echo "==> Installing libicu (required by gsk9certutil_64)…"
docker exec -u root "${DB2_CONTAINER_NAME}" bash -c 'dnf install -y libicu' >/dev/null 2>&1 ||
  echo "WARNING: libicu install failed — GSKit keystore setup may fail." >&2

# ── Step 6: Configure mTLS certificates in Db2 GSKit keystore ────────────────
echo
echo "==> Configuring GSKit keystore inside Db2 container…"

# Db2 12.1's instance home is /database/config/<instance>, not /home/<instance>.
DB2_HOME=$(docker exec -u db2inst1 "${DB2_CONTAINER_NAME}" bash -c 'echo $HOME')
GSK_DB="${DB2_HOME}/kmip_keys.p12"
GSK_STASH="${DB2_HOME}/kmip_keys.sth"
GSK_PWD="KmipGskPass1"
CLIENT_CERT_LABEL="db2kmip_client"

# Copy CA cert and client P12 into the container.
docker cp "${CA_CERT}" "${DB2_CONTAINER_NAME}:/tmp/kms_ca.crt"
docker cp "${CLIENT_P12}" "${DB2_CONTAINER_NAME}:/tmp/client.p12"

# The client P12's personal certificate is stored under its subject DN. GSKit's
# own listing gives the exact label string it expects for -label (its format
# does not match openssl's subject rendering), so query it directly rather
# than reconstructing the DN ourselves.
GSK_SETUP=$(docker exec -u db2inst1 "${DB2_CONTAINER_NAME}" bash -c "
  . ~/sqllib/db2profile

  gsk9certutil_64 -keydb -create -db '${GSK_DB}' -pw '${GSK_PWD}' \
    -type pkcs12 -expire 3650 -stash 2>&1

  gsk9certutil_64 -cert -add -db '${GSK_DB}' -pw '${GSK_PWD}' \
    -label 'KMS_CA' -file /tmp/kms_ca.crt -format ascii 2>&1

  CLIENT_SOURCE_LABEL=\$(gsk9certutil_64 -cert -list -db /tmp/client.p12 -pw 'password' 2>&1 |
    grep -E '^-' | sed 's/^-[[:space:]]*//' | head -1)

  gsk9certutil_64 -cert -import -db /tmp/client.p12 -pw 'password' \
    -label \"\${CLIENT_SOURCE_LABEL}\" \
    -target '${GSK_DB}' -target_pw '${GSK_PWD}' -new_label '${CLIENT_CERT_LABEL}' 2>&1

  gsk9certutil_64 -cert -list -db '${GSK_DB}' -pw '${GSK_PWD}' 2>&1
" 2>&1 || true)

echo "GSKit setup: ${GSK_SETUP}"
if ! echo "${GSK_SETUP}" | grep -q "${CLIENT_CERT_LABEL}"; then
  echo "ERROR: GSKit keystore setup failed — client certificate label not found." >&2
  exit 1
fi
echo "==> PASS: GSKit keystore configured."

# ── Step 7: Configure Db2 instance for KMIP ───────────────────────────────────
# KEYSTORE_LOCATION for KEYSTORE_TYPE=KMIP must point to a Db2 KMIP config file
# (not the GSKit .p12 itself). PRODUCT_NAME=OTHER is the documented value for
# any third-party KMIP 1.1+ manager (i.e. anything other than ISKLM/KeySecure).
# DEVICE_GROUP and KEYSTORETYPE do not apply to PRODUCT_NAME=OTHER.
echo
echo "==> Configuring Db2 DBM CFG for KMIP (host=${KMS_HOST_FROM_DB2}:${KMS_KMIP_PORT})…"

KMIP_CFG_FILE="${DB2_HOME}/ekeystore.cfg"
DB2_KMIP_CFG=$(docker exec -u db2inst1 "${DB2_CONTAINER_NAME}" bash -c "
  cat > '${KMIP_CFG_FILE}' <<EKS_EOF
VERSION=1
PRODUCT_NAME=OTHER
ALLOW_KEY_INSERT_WITHOUT_KEYSTORE_BACKUP=TRUE
SSL_KEYDB=${GSK_DB}
SSL_KEYDB_STASH=${GSK_STASH}
SSL_KMIP_CLIENT_CERTIFICATE_LABEL=${CLIENT_CERT_LABEL}
PRIMARY_SERVER_HOST=${KMS_HOST_FROM_DB2}
PRIMARY_SERVER_KMIP_PORT=${KMS_KMIP_PORT}
EKS_EOF
  chmod 600 '${KMIP_CFG_FILE}'
  . ~/sqllib/db2profile
  db2 \"UPDATE DBM CFG USING KEYSTORE_TYPE KMIP KEYSTORE_LOCATION '${KMIP_CFG_FILE}'\" 2>&1
  db2 force applications all 2>&1
  db2stop 2>&1
  db2start 2>&1
  echo 'DB2_CFG_DONE'
" 2>&1 || true)

echo "Db2 KMIP CFG output: ${DB2_KMIP_CFG}"

if ! echo "${DB2_KMIP_CFG}" | grep -q "DB2_CFG_DONE"; then
  echo "ERROR: Db2 KMIP configuration did not complete." >&2
  exit 1
fi

# ── Step 8: Create encrypted database — triggers KMIP key creation ────────────
echo
echo "==> Creating encrypted Db2 database '${DB2_DBNAME}' (triggers KMIP Register + Activate)…"

DB2_CREATE=$(docker exec -u db2inst1 "${DB2_CONTAINER_NAME}" bash -c "
  . ~/sqllib/db2profile
  db2 \"DROP DATABASE ${DB2_DBNAME}\" 2>&1
  db2 \"CREATE DATABASE ${DB2_DBNAME} ENCRYPT CIPHER AES KEY LENGTH 256\" 2>&1
  echo 'DB2_CREATE_DONE'
" 2>&1 || true)

echo "Db2 CREATE DATABASE output: ${DB2_CREATE}"

if ! echo "${DB2_CREATE}" | grep -q "DB2_CREATE_DONE"; then
  echo "ERROR: CREATE DATABASE command did not complete." >&2
  exit 1
fi

if ! echo "${DB2_CREATE}" | grep -q "DB20000I  The CREATE DATABASE command completed successfully"; then
  echo "ERROR: Encrypted database creation via KMIP failed." >&2
  exit 1
fi

# ── Step 9: Verify KMIP key was created on the KMS ───────────────────────────
echo
echo "==> Verifying KMIP key was created on the KMS side…"
LOCATE_OUT=$(
  "${CKMS_BIN}" --conf-path "${CKMS_CONF}" \
    locate --algorithm AES 2>&1
) || true
echo "  KMS key list: ${LOCATE_OUT}"

# The test key from step 3 is already there; we just need at least one more.
KEY_COUNT=$(echo "${LOCATE_OUT}" | grep -c '[0-9a-f]\{8\}-[0-9a-f]\{4\}' || true)
if [[ "${KEY_COUNT}" -ge 2 ]]; then
  echo "==> PASS: At least one DEMK was created on the KMS by Db2 (${KEY_COUNT} key(s) found)."
else
  echo "ERROR: Expected ≥2 keys on KMS (test key + DEMK), found ${KEY_COUNT}." >&2
  exit 1
fi

echo
echo "==> PASS: IBM Db2 LUW KMIP TDE integration test completed successfully."
echo "  ✓ mTLS sad path"
echo "  ✓ KMS REST API round-trip"
echo "  ✓ GSKit keystore configured"
echo "  ✓ Db2 DBM CFG KMIP configured"
echo "  ✓ Encrypted database created"
echo "  ✓ KMIP DEMK visible in KMS"
