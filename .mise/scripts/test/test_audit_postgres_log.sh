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
source "${SCRIPT_DIR}/../../lib/audit_e2e.sh"

init_build_env "$@"
setup_test_logging

: "${KMS_AUDIT_POSTGRES_URL:?KMS_AUDIT_POSTGRES_URL must be set — see .mise/tasks/test/audit-postgres}"
# A UUID, not $$: a reused PID across CI runners/containers could otherwise collide
# with a leftover instance_id from an earlier run against the same database.
INSTANCE_ID="audit-pg-e2e-$(python3 -c 'import uuid; print(uuid.uuid4())')"

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
# shellcheck disable=SC2034 # consumed by the audit_e2e.sh helpers sourced above
ckms_conf=$(kms_write_ckms_conf)

# ── Exercise KMIP operations ──────────────────────────────────────────────────

audit_exercise_kmip_ops

# ── GUARD: events actually reached PostgreSQL for this run's instance_id ─────
# Polls `ckms audit export` instead of a fixed sleep: the writer task is
# asynchronous, and a fixed delay is either too slow (flaky under load) or wastes
# time on every green run. Waits specifically for the Destroy event on this run's
# key — the last real (non-deliberate-failure) operation `audit_exercise_kmip_ops`
# issues — rather than a total row count, since an incidental startup-readiness
# probe (see kms_wait_ready) can add its own audit event and make any fixed total
# fragile.

echo "==> Waiting for the Destroy event to reach PostgreSQL (up to 30s)..."
export_jsonl="$(mktemp -t audit-pg-e2e-export-XXXXXX.jsonl)"
deadline=$((SECONDS + 30))
destroy_seen=false
while [ "${SECONDS}" -lt "${deadline}" ]; do
  "${ckms_bin}" audit export \
    --audit-postgres-url "${KMS_AUDIT_POSTGRES_URL}" \
    --audit-instance-id "${INSTANCE_ID}" \
    >"${export_jsonl}" 2>/dev/null || true
  if python3 -c "
import json
for l in open('${export_jsonl}'):
    if not l.strip(): continue
    d = json.loads(l)
    if d.get('operation') == 'Destroy' and d.get('result') == 'Success' and d.get('object_uid') == '${AUDIT_SYM_UID}':
        raise SystemExit(0)
raise SystemExit(1)
" 2>/dev/null; then
    destroy_seen=true
    break
  fi
  sleep 1
done

if [ "${destroy_seen}" != "true" ]; then
  echo "ERROR: the Destroy event for key ${AUDIT_SYM_UID} never reached PostgreSQL within 30s." >&2
  echo "       Exported so far:" >&2
  cat "${export_jsonl}" >&2
  echo "--- KMS server log (tail) ---" >&2
  tail -n 60 "${KMS_LOG_FILE}" >&2
  exit 1
fi

# Destroy landing proves the writer has caught up through it; the deliberate
# failing export issued right after it (still in flight when Destroy appeared)
# needs a short settle window of its own.
deadline=$((SECONDS + 10))
failure_seen=false
while [ "${SECONDS}" -lt "${deadline}" ]; do
  "${ckms_bin}" audit export \
    --audit-postgres-url "${KMS_AUDIT_POSTGRES_URL}" \
    --audit-instance-id "${INSTANCE_ID}" \
    >"${export_jsonl}" 2>/dev/null || true
  if python3 -c "
import json
for line in open('${export_jsonl}'):
    if not line.strip(): continue
    event = json.loads(line)
    result = event.get('result')
    if isinstance(result, dict) and 'Failure' in result and event.get('object_uid') == '${AUDIT_NONEXISTENT_UID}':
        raise SystemExit(0)
raise SystemExit(1)
" 2>/dev/null; then
    failure_seen=true
    break
  fi
  sleep 1
done

if [ "${failure_seen}" != "true" ]; then
  echo "ERROR: the deliberate Failure event never reached PostgreSQL within 10s of Destroy." >&2
  echo "       Exported so far:" >&2
  cat "${export_jsonl}" >&2
  exit 1
fi

events_seen=$(grep -c . "${export_jsonl}" || true)
echo "GUARD OK: ${events_seen} audit events reached PostgreSQL for instance_id=${INSTANCE_ID}."

audit_assert_events_jsonl "${export_jsonl}"
rm -f "${export_jsonl}"

# ── GUARD: ckms audit verify against the PostgreSQL backend ─────────────────

echo "==> Verifying the PostgreSQL audit chain (instance_id=${INSTANCE_ID})..."
verify_out=$("${ckms_bin}" audit verify \
  --audit-postgres-url "${KMS_AUDIT_POSTGRES_URL}" \
  --audit-instance-id "${INSTANCE_ID}")
echo "${verify_out}"
if ! echo "${verify_out}" | grep -q "chain OK: ${events_seen} events verified"; then
  echo "ERROR: verify's reported event count does not match the ${events_seen} exported events." >&2
  exit 1
fi
echo "GUARD OK: PostgreSQL audit chain verified for instance_id=${INSTANCE_ID}."

# ── GUARD: verify rejects an unknown instance_id (no vacuous success) ───────

echo "==> Verifying that an unknown instance_id is rejected, not vacuously verified..."
if "${ckms_bin}" audit verify \
  --audit-postgres-url "${KMS_AUDIT_POSTGRES_URL}" \
  --audit-instance-id "${INSTANCE_ID}-does-not-exist" >/dev/null 2>&1; then
  echo "ERROR: ckms audit verify succeeded for an instance_id that was never seeded." >&2
  exit 1
fi
echo "GUARD OK: unknown instance_id was rejected."

# ── GUARD: tamper → restart → seal-and-roll → verify across generations ─────
# Proves the real server's startup path (not just PgAuditSink in isolation) seals a
# corrupted generation and keeps serving on a fresh one, and that the CLI then reports
# the sealed generation as failed while the new one verifies clean.

echo "==> Stopping KMS and corrupting the last stored row of generation 0..."
kill "${KMS_PID}" 2>/dev/null || true
wait "${KMS_PID}" 2>/dev/null || true
KMS_PID=""

_repo_root="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
tamper_out=$(
  docker compose --project-directory "${_repo_root}" exec -T postgres-audit \
    psql -U kms_audit -d kms_audit -v ON_ERROR_STOP=1 <<SQL
ALTER TABLE kms_audit_events DISABLE TRIGGER kms_audit_no_update;
UPDATE kms_audit_events SET row_hash = decode(repeat('00', 32), 'hex')
 WHERE instance_id = '${INSTANCE_ID}' AND chain_generation = 0
   AND id = (SELECT max(id) FROM kms_audit_events
              WHERE instance_id = '${INSTANCE_ID}' AND chain_generation = 0);
ALTER TABLE kms_audit_events ENABLE TRIGGER kms_audit_no_update;
SQL
)
if ! echo "${tamper_out}" | grep -qx 'UPDATE 1'; then
  echo "ERROR: expected to tamper exactly one row, psql said: ${tamper_out}" >&2
  exit 1
fi

echo "==> Restarting KMS: it must seal generation 0 and start generation 1..."
kms_start_from_bin "${kms_bin}"

export_jsonl="$(mktemp -t audit-pg-e2e-roll-XXXXXX.jsonl)"
"${ckms_bin}" audit export \
  --audit-postgres-url "${KMS_AUDIT_POSTGRES_URL}" \
  --audit-instance-id "${INSTANCE_ID}" \
  >"${export_jsonl}"
if ! python3 -c "
import json
for l in open('${export_jsonl}'):
    if not l.strip(): continue
    d = json.loads(l)
    if d.get('operation') != 'audit:reanchor': continue
    det = d.get('details')
    det = json.loads(det) if isinstance(det, str) else (det or {})
    if det.get('reason') == 'hash_mismatch' and det.get('sealed_generation') == 0 and det.get('new_generation') == 1:
        raise SystemExit(0)
raise SystemExit(1)
"; then
  echo "ERROR: no audit:reanchor (hash_mismatch, generation 0 -> 1) event found after restart." >&2
  cat "${export_jsonl}" >&2
  exit 1
fi
rm -f "${export_jsonl}"
echo "GUARD OK: restart sealed generation 0 and recorded an audit:reanchor into generation 1."

echo "==> Verifying across generations (generation 0 must fail, generation 1 must pass)..."
set +e
verify_out=$("${ckms_bin}" audit verify \
  --audit-postgres-url "${KMS_AUDIT_POSTGRES_URL}" \
  --audit-instance-id "${INSTANCE_ID}" 2>&1)
verify_rc=$?
set -e
echo "${verify_out}"
if [ "${verify_rc}" -eq 0 ] ||
  ! echo "${verify_out}" | grep -q "1 of 2 generations failed verification" ||
  ! echo "${verify_out}" | grep -q "generation(s) 1 verified OK"; then
  echo "ERROR: verify must exit non-zero, flag generation 0 and verify generation 1 clean (rc=${verify_rc})." >&2
  exit 1
fi
echo "GUARD OK: verify flags the sealed generation 0 and verifies generation 1."

echo ""
echo "==========================================="
echo "PostgreSQL audit backend integration test PASSED"
echo "==========================================="
