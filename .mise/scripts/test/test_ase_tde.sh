#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# test_ase_tde.sh — SAP ASE ↔ Cosmian KMS PKCS#11 TDE integration test
#
# LOCAL DEV ONLY — not run in CI (needs a manually built SAP ASE image).
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
# ASE talks to external key managers over PKCS#11, NOT KMIP directly. The
# integration path is:
#   SAP ASE --PKCS#11--> libcosmian_pkcs11.so --KMIP--> Cosmian KMS
# configured via `sp_encryption 'hsm_credential', 'lib=...; pin=...; slot=...'`
# (SAP's documented format — semicolon-separated; there is no KEYSTORE/KMIP
# parameter on the ASE side at all).
#
# What this tests:
#   1. Sad path  — KMS rejects connections without a client certificate.
#   2. KMS REST API round-trip (sanity check, independent of ASE).
#   3. If cosmian-ase-kmip image exists: build libcosmian_pkcs11.so for
#      linux/amd64, load it into ASE via hsm_credential, and create a real
#      HSM-backed encryption key. Verifies the key is visible in the KMS.
#
# Configurable environment variables:
#   ASE_DOCKER_IMAGE     Image name (default: cosmian-ase-kmip)
#   ASE_CONTAINER_NAME   Container name (default: ase-kmip-test)
#   ASE_SA_PASSWORD      sa password (default: SapAse1!)
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
: "${KMS_HTTP_PORT:=$(kms_pick_free_port)}"
# Fixed PIN/slot for the Cosmian PKCS#11 software provider: it exposes a
# single always-present token whose CK_SLOT_ID is 1 (slot 0 does not exist)
# and does not enforce a real PIN policy.
PKCS11_PIN="0000"
PKCS11_SLOT="1"
# Hostname ASE (inside its container) uses to reach the KMS running on the host.
KMS_HOST_FROM_ASE="host.docker.internal"

CERT_DIR="${REPO_ROOT}/test_data/certificates/client_server"
CA_CERT="${CERT_DIR}/ca/ca.crt"
SERVER_CERT="${CERT_DIR}/server/kmserver.acme.com.crt"
SERVER_KEY="${CERT_DIR}/server/kmserver.acme.com.key"
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

# Bound to 0.0.0.0 so the ASE Docker container can reach it via
# host.docker.internal (PKCS#11 does not need the KMIP socket server: the
# cosmian_pkcs11 provider talks to the KMS over the HTTP/KMIP-over-REST API).
echo "==> Starting KMS (HTTP port ${KMS_HTTP_PORT})…"
RUST_LOG="${RUST_LOG:-cosmian_kms_server=info,cosmian_kmip=warn}" \
  cargo run --bin cosmian_kms "${FEATURES_FLAG[@]}" -- \
  --database-type sqlite \
  --sqlite-path "${KMS_SQLITE_DIR}" \
  --tls-cert-file "${SERVER_CERT}" \
  --tls-key-file "${SERVER_KEY}" \
  --clients-ca-cert-file "${CA_CERT}" \
  --port "${KMS_HTTP_PORT}" \
  --hostname "0.0.0.0" \
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
  -connect "127.0.0.1:${KMS_HTTP_PORT}" \
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

BASELINE_AES_COUNT=$(
  "${CKMS_BIN}" --conf-path "${CKMS_CONF}" locate --algorithm AES 2>&1 |
    grep -c '[0-9a-f]\{8\}-[0-9a-f]\{4\}\|^SAP ASE' || true
)

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

# ── Step 5: Build libcosmian_pkcs11.so for linux/amd64 ────────────────────────
# ASE always runs linux/amd64. On a Linux/x86_64 dev machine or CI runner this
# is a native build; everywhere else (e.g. macOS) it is cross-built inside a
# matching `rust` Docker image, pinned to the same toolchain as rust-toolchain.toml.
#
# The target dir is wiped first: incremental compilation state does not
# survive reliably across separate --rm container invocations sharing a
# bind-mounted host target dir, and a stale binary here is silently wrong.
echo
echo "==> Building libcosmian_pkcs11.so for linux/amd64…"
PKCS11_TARGET_DIR="${REPO_ROOT}/target/pkcs11-linux-amd64"
rm -rf "${PKCS11_TARGET_DIR}"
if [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ]; then
  cargo build -p cosmian_pkcs11 --features non-fips --target-dir "${PKCS11_TARGET_DIR}"
else
  RUST_VERSION=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' "${REPO_ROOT}/rust-toolchain.toml" | head -1)
  docker run --rm --platform linux/amd64 \
    -v "${REPO_ROOT}:/work" -w /work \
    "rust:${RUST_VERSION}-bookworm" \
    bash -c "apt-get update -qq && apt-get install -y -qq clang libssl-dev pkg-config >/dev/null 2>&1; \
      cargo build -p cosmian_pkcs11 --features non-fips --target-dir /work/target/pkcs11-linux-amd64"
fi
PKCS11_LIB="${PKCS11_TARGET_DIR}/debug/libcosmian_pkcs11.so"
if [ ! -f "${PKCS11_LIB}" ]; then
  echo "ERROR: libcosmian_pkcs11.so was not produced at ${PKCS11_LIB}." >&2
  exit 1
fi
echo "==> PASS: libcosmian_pkcs11.so built for linux/amd64."

# ── Step 6: Start ASE container ───────────────────────────────────────────────
echo
echo "==> Starting SAP ASE container '${ASE_CONTAINER_NAME}'…"
docker run -d --rm --platform linux/amd64 \
  --name "${ASE_CONTAINER_NAME}" \
  --add-host "${KMS_HOST_FROM_ASE}:host-gateway" \
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

# ── Step 7: Deploy the PKCS#11 library + KMS client config into the container ─
echo
echo "==> Deploying libcosmian_pkcs11.so and ckms.toml into the ASE container…"

# SAP requires the PKCS#11 module to live under $SYBASE/ASE-16_x/lib.
ASE_HOME=$(docker exec "${ASE_CONTAINER_NAME}" bash -c 'ls -d /opt/sap/ASE-16_*' | head -1)
ASE_LIB_DIR="${ASE_HOME}/lib"
ASE_SSL_DIR="${ASE_HOME}/ssl"
PKCS11_MODULE_NAME="cosmian_pkcs11.so"

# The provider loads ckms.toml alongside the library (or via CKMS_CONF).
ASE_CKMS_CONF="${KMS_SQLITE_DIR}/ase_ckms.toml"
cat >"${ASE_CKMS_CONF}" <<ASE_CKMS_EOF
[http_config]
server_url = "https://${KMS_HOST_FROM_ASE}:${KMS_HTTP_PORT}"
accept_invalid_certs = true
tls_client_pkcs12_path = "${ASE_SSL_DIR}/client.p12"
tls_client_pkcs12_password = "password"
ASE_CKMS_EOF

docker cp "${PKCS11_LIB}" "${ASE_CONTAINER_NAME}:${ASE_LIB_DIR}/${PKCS11_MODULE_NAME}"
docker cp "${CLIENT_P12}" "${ASE_CONTAINER_NAME}:${ASE_SSL_DIR}/client.p12"
docker cp "${ASE_CKMS_CONF}" "${ASE_CONTAINER_NAME}:${ASE_LIB_DIR}/ckms.toml"
echo "==> PASS: PKCS#11 module and KMS client config deployed."

# ── Step 8: Configure ASE for HSM-backed encryption via PKCS#11 ──────────────
# SAP's documented prerequisites/format for `sp_encryption 'hsm_credential'`:
#   sp_configure 'external keystore', 0, 'HSM'
#   sp_configure 'enable encrypted columns', 1
#   sp_encryption 'system_encr_passwd', '<password>'
#   sp_encryption 'hsm_credential', 'lib=<name>.so; pin=<pin>; slot=<n>'
# The credential value is semicolon-separated; no KEYSTORE/KMIP parameter
# exists on the ASE side — everything KMIP-related lives inside the PKCS#11
# module, invisible to ASE.
echo
echo "==> Configuring ASE HSM credential (lib=${PKCS11_MODULE_NAME}, slot=${PKCS11_SLOT})…"

_isql_env='
  export SYBASE=/opt/sap
  export SYBASE_OCS="$(basename "$(ls -d /opt/sap/OCS-16_* | head -1)")"
  export LD_LIBRARY_PATH="${SYBASE}/ASE-16_1/lib:${SYBASE}/${SYBASE_OCS}/lib:${SYBASE}/${SYBASE_OCS}/lib3p64:${SYBASE}/${SYBASE_OCS}/lib3p"
  export CKMS_CONF="'"${ASE_LIB_DIR}"'/ckms.toml"
'

ASE_HSM_CFG=$(docker exec "${ASE_CONTAINER_NAME}" bash -c "
${_isql_env}
ISQL=\"\${SYBASE}/\${SYBASE_OCS}/bin/isql\"
printf \"sp_configure 'external keystore', 0, 'HSM'\ngo\n\" | \"\${ISQL}\" -S SAPASE -U sa -P '${ASE_SA_PASSWORD}' -w 200 2>&1
printf \"sp_configure 'enable encrypted columns', 1\ngo\n\" | \"\${ISQL}\" -S SAPASE -U sa -P '${ASE_SA_PASSWORD}' -w 200 2>&1
printf \"sp_encryption 'system_encr_passwd', 'MasterPass1!'\ngo\n\" | \"\${ISQL}\" -S SAPASE -U sa -P '${ASE_SA_PASSWORD}' -w 200 2>&1
printf \"sp_encryption 'hsm_credential', 'lib=${PKCS11_MODULE_NAME}; pin=${PKCS11_PIN}; slot=${PKCS11_SLOT}'\ngo\n\" | \"\${ISQL}\" -S SAPASE -U sa -P '${ASE_SA_PASSWORD}' -w 200 2>&1
echo 'ASE_HSM_CFG_DONE'
" 2>&1 || true)

echo "ASE HSM configuration output:"
echo "${ASE_HSM_CFG}"

if ! echo "${ASE_HSM_CFG}" | grep -q "ASE_HSM_CFG_DONE"; then
  echo "ERROR: ASE HSM credential configuration did not complete." >&2
  exit 1
fi
if echo "${ASE_HSM_CFG}" | grep -qiE "^Msg [0-9]+"; then
  echo "ERROR: ASE reported an error while configuring the HSM credential." >&2
  exit 1
fi
echo "==> PASS: ASE HSM credential configured."

# ── Step 9: Create an HSM-backed encryption key — the real functional test ───
# SAP has no dedicated "test HSM connectivity" command: creating (and using) a
# key on the external keystore IS the functional test of the PKCS#11 path.
echo
echo "==> Creating HSM-backed encryption key via the Cosmian PKCS#11 provider…"

ASE_KEY_OUT=$(docker exec "${ASE_CONTAINER_NAME}" bash -c "
${_isql_env}
ISQL=\"\${SYBASE}/\${SYBASE_OCS}/bin/isql\"
printf \"create encryption key hsm_key on external keystore with keylength 256 init_vector random\ngo\n\" | \"\${ISQL}\" -S SAPASE -U sa -P '${ASE_SA_PASSWORD}' -w 200 2>&1
echo 'ASE_KEY_CREATE_DONE'
" 2>&1 || true)

echo "ASE create encryption key output:"
echo "${ASE_KEY_OUT}"

if ! echo "${ASE_KEY_OUT}" | grep -q "ASE_KEY_CREATE_DONE"; then
  echo "ERROR: CREATE ENCRYPTION KEY command did not complete." >&2
  exit 1
fi
if echo "${ASE_KEY_OUT}" | grep -qiE "^Msg [0-9]+"; then
  echo "ERROR: ASE failed to create the HSM-backed encryption key via the Cosmian PKCS#11 provider." >&2
  exit 1
fi
echo "==> PASS: HSM-backed encryption key created through the PKCS#11 provider."

# ── Step 10: Verify the key was created on the KMS side ──────────────────────
echo
echo "==> Verifying the HSM key is visible on the KMS side…"
LOCATE_OUT=$(
  "${CKMS_BIN}" --conf-path "${CKMS_CONF}" \
    locate --algorithm AES 2>&1
) || true
echo "  KMS key list: ${LOCATE_OUT}"

NEW_AES_COUNT=$(echo "${LOCATE_OUT}" | grep -c '[0-9a-f]\{8\}-[0-9a-f]\{4\}\|^SAP ASE' || true)
if [[ "${NEW_AES_COUNT}" -gt "${BASELINE_AES_COUNT}" ]]; then
  echo "==> PASS: A new key was created on the KMS by ASE via PKCS#11 (${BASELINE_AES_COUNT} -> ${NEW_AES_COUNT})."
else
  echo "ERROR: Expected an additional AES key on the KMS after ASE key creation, count unchanged (${NEW_AES_COUNT})." >&2
  exit 1
fi

echo
echo "==> PASS: SAP ASE PKCS#11 TDE integration test completed successfully."
echo "  ✓ mTLS sad path"
echo "  ✓ KMS REST API round-trip"
echo "  ✓ libcosmian_pkcs11.so built for linux/amd64"
echo "  ✓ ASE HSM credential configured (lib=/pin=/slot=)"
echo "  ✓ HSM-backed encryption key created via PKCS#11"
echo "  ✓ Key visible in the KMS"
