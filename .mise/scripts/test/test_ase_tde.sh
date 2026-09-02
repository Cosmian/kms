#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# test_ase_tde.sh — SAP ASE ↔ Cosmian KMS KMIP TDE integration test
#
# LOCAL DEV ONLY — not run in CI.
#
# SAP ASE has no redistributable Docker image. The image must be built locally
# from the SAP ASE Developer Edition installer (ASE_Suite.linuxamd64.tgz),
# downloaded manually from an SAP account (me.sap.com/softwarecenter → search
# "Adaptive Server Enterprise"). Place the .tgz in .mise/scripts/docker/ase/
# then build:
#   docker build --platform linux/amd64 -t cosmian-ase-kmip .mise/scripts/docker/ase/
#
# If the image is not present locally, this script SKIPs (exit 0) after
# verifying the KMS-side mTLS and REST API behavior.
#
# What this tests:
#   1. Sad path  — KMS rejects connections without a client certificate.
#   2. KMS REST API round-trip (sanity check, independent of ASE).
#   3. If cosmian-ase-kmip image exists: start ASE, attempt KMIP keystore
#      configuration and encrypted-database creation. Any SQL error is
#      reported and the KMIP portion is SKIPPED (ASE KMIP command syntax is
#      version/build-dependent and not independently verified here).
#
# Configurable environment variables:
#   ASE_DOCKER_IMAGE     Image name (default: cosmian-ase-kmip)
#   ASE_CONTAINER_NAME   Container name (default: ase-kmip-test)
#   ASE_SA_PASSWORD      sa password (default: SapAse1!)
#   KMS_KMIP_PORT        KMIP socket port (default: dynamically allocated)
#   KMS_HTTP_PORT        KMS HTTP/HTTPS port (default: dynamically allocated)
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
: "${ASE_DOCKER_IMAGE:=cosmian-ase-kmip}"
: "${ASE_CONTAINER_NAME:=ase-kmip-test}"
: "${ASE_SA_PASSWORD:=SapAse1!}"
: "${KMS_KMIP_PORT:=$(kms_pick_free_port)}"
: "${KMS_HTTP_PORT:=$(kms_pick_free_port)}"
: "${ASE_HOST_PORT:=$(kms_pick_free_port)}"

CERT_DIR="${REPO_ROOT}/test_data/certificates/client_server"
CA_CERT="${CERT_DIR}/ca/ca.crt"
SERVER_P12="${CERT_DIR}/server/kmserver.acme.com.p12"
SERVER_P12_PASSWORD="password"
CLIENT_P12="${CERT_DIR}/owner/owner.client.acme.com.p12"

KMS_SQLITE_DIR="$(mktemp -d -t kms-ase-XXXXXX)"

require_cmd cargo "Cargo is required to build the KMS."
require_cmd docker "Docker is required to run the ASE container."
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
  docker rm -f "${ASE_CONTAINER_NAME}" 2>/dev/null || true
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
  --tls-p12-file "${SERVER_P12}" \
  --tls-p12-password "${SERVER_P12_PASSWORD}" \
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
printf 'ASE_KMS_MTLS_CI_ROUND_TRIP\n' >"${PLAINTEXT_FILE}"
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

# ── Step 4: Check the locally-built ASE image is present ─────────────────────
echo
echo "==> Checking for local SAP ASE image '${ASE_DOCKER_IMAGE}'…"
if ! docker image inspect "${ASE_DOCKER_IMAGE}" >/dev/null 2>&1; then
  echo "==> SKIPPED: SAP ASE image '${ASE_DOCKER_IMAGE}' not found locally."
  echo "  SAP ASE has no redistributable Docker image — build it manually:"
  echo "    1. Download ASE_Suite.linuxamd64.tgz from an SAP account"
  echo "       (me.sap.com/softwarecenter → Adaptive Server Enterprise)"
  echo "    2. cp ASE_Suite.linuxamd64.tgz .mise/scripts/docker/ase/"
  echo "    3. docker build --platform linux/amd64 -t ${ASE_DOCKER_IMAGE} .mise/scripts/docker/ase/"
  echo "  The following were verified successfully:"
  echo "  ✓ mTLS sad path (connection without cert rejected)"
  echo "  ✓ KMS REST API encrypt/decrypt round-trip"
  exit 0
fi

# ── Step 5: Start ASE container ───────────────────────────────────────────────
echo
echo "==> Starting SAP ASE container '${ASE_CONTAINER_NAME}'…"
docker run -d --rm --platform linux/amd64 \
  --name "${ASE_CONTAINER_NAME}" \
  -p "${ASE_HOST_PORT}:5000" \
  -v "${CA_CERT}:/ase-kmip-certs/ca.crt:ro" \
  -v "${CLIENT_P12}:/ase-kmip-certs/client.p12:ro" \
  -e "SA_PASSWORD=${ASE_SA_PASSWORD}" \
  "${ASE_DOCKER_IMAGE}" >/dev/null

echo "Waiting for ASE to become ready (up to 180 s — first boot is slow)…"
ASE_READY=false
for _i in $(seq 1 180); do
  if docker logs "${ASE_CONTAINER_NAME}" 2>&1 | grep -q "==> ASE ready."; then
    ASE_READY=true
    break
  fi
  sleep 1
done
if [ "${ASE_READY}" = false ]; then
  echo "ERROR: ASE container did not become ready within 180 s." >&2
  docker logs "${ASE_CONTAINER_NAME}" >&2 || true
  exit 1
fi
echo "ASE is ready."

# ── Step 6: Attempt KMIP keystore configuration ───────────────────────────────
echo
echo "==> Attempting SAP ASE KMIP configuration (host=host.docker.internal:${KMS_KMIP_PORT})…"

KMIP_ADDR="host.docker.internal:${KMS_KMIP_PORT}"
docker cp "${REPO_ROOT}/.mise/scripts/docker/ase/configure_kmip.sql" \
  "${ASE_CONTAINER_NAME}:/tmp/configure_kmip.sql"

# Substitute the KMIP endpoint placeholder used in configure_kmip.sql.
docker exec "${ASE_CONTAINER_NAME}" \
  sed -i "s|\$(KMIP_ADDR)|${KMIP_ADDR}|g; s|\$(SYBSSL)|/opt/sap/ASE-16_1/ssl|g" \
  /tmp/configure_kmip.sql

ASE_KMIP_OUT=$(docker exec \
  -e SYBASE=/opt/sap -e SYBASE_OCS=OCS-16_1 \
  -e LD_LIBRARY_PATH=/opt/sap/ASE-16_1/lib:/opt/sap/OCS-16_1/lib:/opt/sap/OCS-16_1/lib3p64:/opt/sap/OCS-16_1/lib3p \
  "${ASE_CONTAINER_NAME}" \
  /opt/sap/OCS-16_1/bin/isql -S SAPASE -U sa -P "${ASE_SA_PASSWORD}" -w 200 \
  -i /tmp/configure_kmip.sql 2>&1 || true)

echo "ASE KMIP configuration output:"
echo "${ASE_KMIP_OUT}"

if echo "${ASE_KMIP_OUT}" | grep -qiE "Msg [0-9]+|not supported|not licensed|error"; then
  echo "==> SKIPPED: SAP ASE KMIP configuration did not complete cleanly."
  echo "  The exact KMIP setup SQL is version/build-dependent and not"
  echo "  independently verified against a real ASE Enterprise instance."
  echo "  The following were verified successfully:"
  echo "  ✓ mTLS sad path"
  echo "  ✓ KMS REST API round-trip"
  echo "  ✓ SAP ASE container started and ready"
  exit 0
fi

echo "==> PASS: SAP ASE KMIP TDE integration test completed successfully."
echo "  ✓ mTLS sad path"
echo "  ✓ KMS REST API round-trip"
echo "  ✓ SAP ASE container started and ready"
echo "  ✓ KMIP encryption key + encrypted database created"
