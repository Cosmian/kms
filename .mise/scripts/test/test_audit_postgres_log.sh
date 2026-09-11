#!/usr/bin/env bash
# PostgreSQL audit backend integration test.
#
# Proves the PostgreSQL audit backend is correctly wired end-to-end:
#
#   KMS audit middleware → PgAuditSink (PostgreSQL) → ckms audit verify --audit-postgres-url
#
# Unlike test_audit_log.sh (the file backend's equivalent), this does not re-derive
# hash-chain/field-coverage guards — those are already covered by
# crate/server_database's and crate/clients/clap's #[ignore]-gated unit tests (run via
# `mise run test audit-postgres`, which invokes this script). This test's job is proving
# the *wiring*: server config → PostgreSQL backend → CLI verify, none of which the unit
# tests exercise (they talk to PgAuditSink/PgAuditReader directly, never through a real
# running KMS server or its config file).
#
# Requires a running PostgreSQL instance reachable at KMS_AUDIT_POSTGRES_URL — see
# `mise run test audit-postgres`, which starts the dedicated `postgres-audit` Docker
# Compose service before calling this script.
#
# Usage:
#   KMS_AUDIT_POSTGRES_URL=postgresql://... bash .mise/scripts/test/test_audit_postgres_log.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

: "${KMS_AUDIT_POSTGRES_URL:?KMS_AUDIT_POSTGRES_URL must be set — see .mise/tasks/test/audit-postgres}"
INSTANCE_ID="audit-pg-e2e-$$"

cleanup() {
  kms_stop
}
trap cleanup EXIT

echo "==========================================="
echo "PostgreSQL audit backend integration test"
echo "Proves: KMS server + audit middleware + ckms audit verify, wired to PostgreSQL"
echo "==========================================="

echo "==> Building KMS server + ckms CLI..."
kms_build_all

kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

KMS_PORT="$(kms_pick_free_port)"
echo "==> Starting KMS server on port ${KMS_PORT} with the PostgreSQL audit backend..."
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-audit-pg-test-XXXXXX)"

cat >>"${KMS_CONFIG_FILE}" <<EOF

[audit]
enabled = true

[audit.postgres]
url = "${KMS_AUDIT_POSTGRES_URL}"
instance_id = "${INSTANCE_ID}"
EOF

kms_start_from_bin "${kms_bin}"
ckms_conf=$(kms_write_ckms_conf)

ckms_json() {
  COSMIAN_KMS_CLI_FORMAT=json "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null
}
ckms_run() {
  "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null || true
}
extract_uid() {
  grep -o '"unique_identifier": *"[^"]*"' | head -1 | sed 's/"unique_identifier": *"//;s/"$//'
}

echo "==> Exercising KMIP operations..."
CREATE_OUT=$(ckms_json sym keys create --algorithm aes --number-of-bits 256)
SYM_UID=$(echo "${CREATE_OUT}" | extract_uid)
echo "    Created AES-256 key: ${SYM_UID}"

TMPDIR_DATA="$(mktemp -d -t audit-pg-test-XXXXXX)"
PLAINTEXT="${TMPDIR_DATA}/plaintext.txt"
ENCRYPTED="${TMPDIR_DATA}/encrypted.bin"
echo "Hello, PostgreSQL audit backend test!" >"${PLAINTEXT}"
ckms_run sym encrypt "${PLAINTEXT}" --key-id "${SYM_UID}" --output "${ENCRYPTED}"
echo "    Encrypted."
ckms_run sym keys destroy --key-id "${SYM_UID}"
echo "    Destroyed key."
rm -rf "${TMPDIR_DATA}"

echo "==> Waiting for audit events to flush..."
sleep 2

# ── GUARD: ckms audit verify against the PostgreSQL backend ─────────────────

echo "==> Verifying the PostgreSQL audit chain (instance_id=${INSTANCE_ID})..."
if ! "${ckms_bin}" audit verify \
  --audit-postgres-url "${KMS_AUDIT_POSTGRES_URL}" \
  --audit-instance-id "${INSTANCE_ID}" 2>&1; then
  echo "ERROR: ckms audit verify failed against the PostgreSQL backend." >&2
  echo "       Either no events were persisted, or the hash chain is broken." >&2
  exit 1
fi
echo "GUARD OK: PostgreSQL audit chain verified for instance_id=${INSTANCE_ID}."

echo ""
echo "==========================================="
echo "PostgreSQL audit backend integration test PASSED"
echo "==========================================="
