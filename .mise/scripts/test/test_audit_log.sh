#!/usr/bin/env bash
# Audit log integration test.
#
# Proves tamper-evident JSONL single-writer log and HTTP audit middleware capture:
#
#   KMS audit middleware → JSONL file (ckms audit verify validates hash chain)
#
# Test flow:
#   1. Build KMS server + ckms CLI
#   2. Start KMS with audit logging enabled
#   3. Exercise KMIP operations: Create, Encrypt, Decrypt, Revoke, Destroy
#      (plus 1 deliberate Failure for result coverage) — .mise/lib/audit_e2e.sh
#   4. Assert event count, required fields, and Success/Failure coverage — same lib
#   5. Run `ckms audit verify --path` — exit 1 if chain broken
#   6. Mutate a copy of the audit log and assert `ckms audit verify` fails (tamper detection)
#   7. Print evidence for each event
#
# Usage:
#   bash .mise/scripts/test/test_audit_log.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"
source "${SCRIPT_DIR}/../../lib/audit_e2e.sh"

init_build_env "$@"
setup_test_logging

AUDIT_JSONL=""
TAMPERED_JSONL=""

cleanup() {
  kms_stop
  rm -f "${AUDIT_JSONL:-}" "${TAMPERED_JSONL:-}" 2>/dev/null || true
}
trap cleanup EXIT

echo "==========================================="
echo "Audit log integration test"
echo "Proves: tamper-evident JSONL hash chain + HTTP audit middleware capture"
echo "==========================================="

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building KMS server + ckms CLI..."
kms_build_all

kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

# ── Start KMS server with audit logging ───────────────────────────────────────

AUDIT_JSONL="$(mktemp -t kms-audit-XXXXXX.jsonl)"
KMS_PORT="$(kms_pick_free_port)"

echo "==> Starting KMS server on port ${KMS_PORT} with audit logging..."
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-audit-test-XXXXXX)"

cat >>"${KMS_CONFIG_FILE}" <<EOF

[audit]
enabled = true

[audit.file]
path = "${AUDIT_JSONL}"
EOF

kms_start_from_bin "${kms_bin}"
ckms_conf=$(kms_write_ckms_conf)

# ── Exercise KMIP operations ──────────────────────────────────────────────────

audit_exercise_kmip_ops

echo "==> Waiting for audit events to flush..."
sleep 2

# ── GUARD 1: audit file must have events, required fields, Success+Failure ───

audit_assert_events_jsonl "${AUDIT_JSONL}"
audit_lines=$(grep -c . "${AUDIT_JSONL}" || true)

# ── GUARD 2: hash chain must be valid ─────────────────────────────────────────

echo "==> Running ckms audit verify --path ${AUDIT_JSONL}..."
if ! "${ckms_bin}" audit verify --path "${AUDIT_JSONL}" 2>&1; then
  echo "ERROR: ckms audit verify failed — tamper-evident hash chain is broken." >&2
  echo "       Hash chain verification failed — chain is NOT intact." >&2
  exit 1
fi
echo "GUARD OK: hash chain verified (${audit_lines} rows, SHA-256 chain intact)."

# ── GUARD 2b: tamper detection (mutated log must fail verification) ───────────

echo "==> Testing tamper detection (mutating audit log copy)..."
TAMPERED_JSONL="$(mktemp -t audit-tampered-XXXXXX.jsonl)"
cp "${AUDIT_JSONL}" "${TAMPERED_JSONL}"

python3 -c "
import json
with open('${TAMPERED_JSONL}', 'r') as f:
    lines = [l for l in f if l.strip()]
d = json.loads(lines[1])
d['operation'] = d.get('operation', '') + '_tampered'
lines[1] = json.dumps(d) + '\n'
with open('${TAMPERED_JSONL}', 'w') as f:
    f.writelines(lines)
"

if "${ckms_bin}" audit verify --path "${TAMPERED_JSONL}" >/dev/null 2>&1; then
  echo "ERROR: ckms audit verify succeeded on tampered audit log — tampering was NOT detected!" >&2
  rm -f "${TAMPERED_JSONL}"
  exit 1
fi
rm -f "${TAMPERED_JSONL}"
TAMPERED_JSONL=""
echo "GUARD OK: tamper detection verified (ckms audit verify rejected mutated log)."

# ── Print evidence ────────────────────────────────────────────────────────────

echo ""
echo "==> Evidence — audit events sample:"
python3 -c "
import json
with open('${AUDIT_JSONL}') as f:
    for i, line in enumerate(f, 1):
        if not line.strip(): continue
        d = json.loads(line)
        result = d.get('result', '?')
        result_str = result if isinstance(result, str) else 'Failure:' + list(result.values())[0][:40]
        print(f'  [{i}] ts={d[\"timestamp\"][:19]} op={d[\"operation\"]:20s} user={d.get(\"user\",\"?\"):20s} result={result_str}')
"

echo ""
echo "Audit log integration test PASSED."
echo "Evidence: ${audit_lines} events written, hash chain verified (${audit_lines} rows)."
echo "Proves tamper-evident JSONL hash chain + HTTP audit middleware capture."
