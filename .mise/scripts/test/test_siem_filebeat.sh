#!/usr/bin/env bash
# Filebeat → Elasticsearch JSONL integration test.
#
# Validates the "Elasticsearch / OpenSearch" section of siems.md using
# official Elastic Docker images (Apache 2.0 / Elastic License 2.0).
#
# The test uses Elasticsearch 8.x with security disabled (xpack.security.enabled=false)
# so no TLS certificates or credentials are needed in CI.
#
# Test flow:
#   1. Build KMS server + ckms CLI
#   2. Ensure Elasticsearch is running (started by docker compose or locally)
#   3. Start KMS with audit logging enabled
#   4. Exercise KMIP operations to produce audit events
#   5. Start Filebeat (Docker) configured to tail the JSONL file
#   6. Wait for events to appear in Elasticsearch
#   7. Query the ES REST API and verify all required audit fields
#   8. Clean up
#
# Requires:
#   - Docker daemon running
#   - Elasticsearch container running (docker compose up -d elasticsearch)
#   - Filebeat image available: docker.elastic.co/beats/filebeat:8.17.0
#
# Environment variables:
#   ES_URL           Elasticsearch base URL (default: http://127.0.0.1:9200)
#   ES_INDEX         Index pattern to query (default: kms-audit)
#
# Usage:
#   docker compose up -d elasticsearch
#   bash .mise/scripts/test/test_siem_filebeat.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

HELPER="${SCRIPT_DIR}/siem_verify_fields.py"
AUDIT_JSONL=""
FILEBEAT_DIR=""
VENV_DIR=""
FILEBEAT_CONTAINER=""

# Elasticsearch endpoint — can be overridden by env
ES_URL="${ES_URL:-http://127.0.0.1:${KMS_SLOT_ES_PORT:-9200}}"
ES_INDEX="${ES_INDEX:-kms-audit}"
ELASTIC_VERSION="${ELASTIC_VERSION:-8.17.0}"

cleanup() {
  kms_stop
  if [ -n "${FILEBEAT_CONTAINER:-}" ]; then
    docker rm -f "${FILEBEAT_CONTAINER}" 2>/dev/null || true
    FILEBEAT_CONTAINER=""
  fi
  [ -n "${VENV_DIR:-}" ] && { rm -rf "${VENV_DIR}" || true; }
  [ -n "${FILEBEAT_DIR:-}" ] && { rm -rf "${FILEBEAT_DIR}" || true; }
  # Clean up ES resources created by this test
  curl -sf -X DELETE "${ES_URL}/${ES_INDEX}" -o /dev/null 2>/dev/null || true
  curl -sf -X DELETE "${ES_URL}/_ingest/pipeline/${PIPELINE_NAME:-kms-audit-normalize}" \
    -o /dev/null 2>/dev/null || true
}
trap cleanup EXIT

echo "==========================================="
echo "Filebeat → Elasticsearch integration test"
echo "Proves: siems.md 'Elasticsearch / OpenSearch' section"
echo "==========================================="

# ── Prerequisites ─────────────────────────────────────────────────────────────

if ! command -v docker &>/dev/null; then
  echo "ERROR: Docker is not available." >&2
  exit 1
fi
if ! docker info &>/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not running." >&2
  exit 1
fi

# Wait for Elasticsearch to be ready (it may be starting up via docker compose)
echo "==> Waiting for Elasticsearch at ${ES_URL}..."
waited=0
until curl -sf "${ES_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" \
  -o /dev/null 2>/dev/null; do
  if [ "${waited}" -ge 120 ]; then
    echo "ERROR: Elasticsearch did not become ready within 120s." >&2
    echo "Run: docker compose up -d elasticsearch" >&2
    exit 1
  fi
  echo "    Waiting for ES... (${waited}s elapsed)"
  sleep 5
  waited=$((waited + 5))
done
echo "    Elasticsearch is ready."

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building KMS server + ckms CLI..."
kms_build_all
kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

# ── Start KMS server with audit logging ───────────────────────────────────────

FILEBEAT_DIR="$(mktemp -d)"
AUDIT_JSONL="${FILEBEAT_DIR}/audit.jsonl"
touch "${AUDIT_JSONL}"

KMS_PORT="$(kms_pick_free_port)"
echo "==> Starting KMS server on port ${KMS_PORT} with audit logging..."
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-siem-es-XXXXXX)"

cat >>"${KMS_CONFIG_FILE}" <<EOF

[audit]
enabled = true

[audit.file]
path = "${AUDIT_JSONL}"
EOF

kms_start_from_bin "${kms_bin}"
ckms_conf=$(kms_write_ckms_conf)

# ── Exercise KMIP operations ──────────────────────────────────────────────────

echo "==> Exercising KMIP operations..."

ckms_json() {
  COSMIAN_KMS_CLI_FORMAT=json "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null
}
ckms_run() {
  "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null || true
}
extract_uid() {
  grep -o '"unique_identifier": *"[^"]*"' | head -1 | sed 's/"unique_identifier": *"//;s/"$//'
}

CREATE_OUT=$(ckms_json sym keys create --algorithm aes --number-of-bits 256)
SYM_UID=$(echo "${CREATE_OUT}" | extract_uid)
echo "    Created AES-256 key: ${SYM_UID}"

TMPDIR_ES="$(mktemp -d -t es-data-XXXXXX)"
PLAINTEXT="${TMPDIR_ES}/plaintext.txt"
ENCRYPTED="${TMPDIR_ES}/encrypted.bin"
echo "Hello, Filebeat ES test!" >"${PLAINTEXT}"
ckms_run sym encrypt "${PLAINTEXT}" --key-id "${SYM_UID}" --output "${ENCRYPTED}"
ckms_run sym decrypt "${ENCRYPTED}" --key-id "${SYM_UID}" --output "${TMPDIR_ES}/decrypted.txt"
ckms_run sym keys revoke --key-id "${SYM_UID}"
ckms_run sym keys destroy --key-id "${SYM_UID}"
rm -rf "${TMPDIR_ES}"

# Deliberately trigger a Failure event to prove the kms-audit-normalize pipeline
# handles BOTH result types (Success string and {"Failure":"..."} object).
# A Get on a non-existent UUID produces a Failure audit event.
echo "    Triggering a deliberate Failure event (non-existent key lookup)..."
ckms_run sym keys export --key-id "00000000-0000-0000-0000-000000000000" 2>/dev/null || true

echo "==> Waiting for audit events to flush..."
sleep 2

audit_lines=$(grep -c . "${AUDIT_JSONL}" 2>/dev/null || echo 0)
echo "    Audit file has ${audit_lines} event(s)."
if [ "${audit_lines}" -lt 3 ]; then
  echo "ERROR: expected at least 3 audit events, got ${audit_lines}" >&2
  cat "${AUDIT_JSONL}" >&2
  exit 1
fi

# ── Create Elasticsearch ingest pipeline ─────────────────────────────────────
#
# The KMS audit `result` field is a Rust enum that serializes as either:
#   - the string "Success"                        — for successful operations
#   - the object {"Failure": "error message"}     — for failed operations
#
# Elasticsearch cannot dynamically map a single field as both a string keyword
# and an object. Without normalization, the first "Success" event maps `result`
# as keyword, and every subsequent {"Failure": ...} event is DROPPED with a
# mapping conflict error.
#
# Solution: an ingest pipeline that splits `result` into two consistent fields:
#   - `result_status`  keyword — always "Success" or "Failure"
#   - `result_error`   text   — error message, present only on Failure events
#
# This pipeline must be created before the index and referenced in filebeat.yml
# via `output.elasticsearch.pipeline: kms-audit-normalize`.
PIPELINE_NAME="kms-audit-normalize"
echo "==> Creating ingest pipeline '${PIPELINE_NAME}'..."
curl -sf -X PUT "${ES_URL}/_ingest/pipeline/${PIPELINE_NAME}" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Normalize KMS audit result field (polymorphic Rust enum)",
    "processors": [
      {
        "script": {
          "lang": "painless",
          "source": "def r = ctx[\"result\"]; if (r instanceof String) { ctx[\"result_status\"] = r; } else if (r instanceof Map && r.containsKey(\"Failure\")) { ctx[\"result_status\"] = \"Failure\"; ctx[\"result_error\"] = r[\"Failure\"]; } else { ctx[\"result_status\"] = \"Unknown\"; } ctx.remove(\"result\");"
        }
      }
    ]
  }' -o /dev/null
echo "    Pipeline created."

# ── Create Elasticsearch index with correct mapping ──────────────────────────

echo "==> Creating Elasticsearch index '${ES_INDEX}' with field mapping..."
# Delete any previous run's index or data stream (best-effort)
curl -sf -X DELETE "${ES_URL}/${ES_INDEX}" -o /dev/null 2>/dev/null || true
curl -sf -X DELETE "${ES_URL}/_data_stream/${ES_INDEX}" -o /dev/null 2>/dev/null || true
# Remove any Filebeat-created index template that forces data stream mode
curl -sf -X DELETE "${ES_URL}/_index_template/${ES_INDEX}" -o /dev/null 2>/dev/null || true
# Create index with explicit mapping for all KMS audit fields.
# `result_status` and `result_error` are the normalized forms of the
# polymorphic `result` field, produced by the kms-audit-normalize pipeline.
curl -sf -X PUT "${ES_URL}/${ES_INDEX}" \
  -H "Content-Type: application/json" \
  -d '{
    "mappings": {
      "dynamic": true,
      "properties": {
        "id":            {"type": "long"},
        "timestamp":     {"type": "date"},
        "operation":     {"type": "keyword"},
        "user":          {"type": "keyword"},
        "result_status": {"type": "keyword"},
        "result_error":  {"type": "text"},
        "object_uid":    {"type": "keyword"},
        "algorithm":     {"type": "keyword"},
        "client_ip":     {"type": "ip"},
        "duration_ms":   {"type": "long"},
        "request_id":    {"type": "keyword"},
        "prev_hash":     {"type": "keyword", "index": false},
        "row_hash":      {"type": "keyword", "index": false}
      }
    }
  }' -o /dev/null
echo "    Index created."

# ── Write Filebeat config ─────────────────────────────────────────────────────

FB_CONFIG="${FILEBEAT_DIR}/filebeat.yml"

# This config demonstrates the JSONL file tailing pattern from siems.md.
# Key settings for Filebeat 8.x:
#   - type: filestream (replaces deprecated 'log' input in 8.x)
#   - setup.template.enabled: false — do NOT override our pre-created ES mapping
#   - setup.ilm.enabled: false — disable ILM to write to a plain index
#   - output.elasticsearch.index — explicit target index name
# The decode_json_fields processor is documented in siems.md.
cat >"${FB_CONFIG}" <<EOF
filebeat.inputs:
  - type: filestream
    id: kms-audit
    paths:
      - /audit/audit.jsonl
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
          add_error_key: false
    prospector.scanner.check_interval: 1s

processors:
  - drop_fields:
      fields: ["message", "log", "host", "agent", "ecs", "input", "event"]
      ignore_missing: true

output.elasticsearch:
  hosts: ["${ES_URL}"]
  index: "${ES_INDEX}"
  pipeline: "${PIPELINE_NAME}"

# Disable all automatic setup so Filebeat writes to our pre-created index
# without overriding its mapping or creating a data stream.
setup.template.enabled: false
setup.ilm.enabled: false
setup.kibana.enabled: false

logging.level: warning
EOF

# ── Run Filebeat container ────────────────────────────────────────────────────

echo "==> Running Filebeat ${ELASTIC_VERSION} container..."

# Detect host IP accessible from Docker
# On Linux: use host networking (--network host)
# On macOS: use host.docker.internal
if [[ "$(uname)" == "Linux" ]]; then
  NETWORK_ARGS=(--network host)
  # Rewrite ES_URL with localhost for container (host networking)
  FB_ES_URL="${ES_URL}"
else
  # macOS: replace 127.0.0.1/localhost with host.docker.internal
  FB_ES_URL="${ES_URL/127.0.0.1/host.docker.internal}"
  FB_ES_URL="${FB_ES_URL/localhost/host.docker.internal}"
  sed -i.bak "s|${ES_URL}|${FB_ES_URL}|g" "${FB_CONFIG}" || true
  NETWORK_ARGS=()
fi

FILEBEAT_CONTAINER="kms-siem-test-filebeat-$$"
docker run --rm --name "${FILEBEAT_CONTAINER}" \
  "${NETWORK_ARGS[@]}" \
  -v "${AUDIT_JSONL}:/audit/audit.jsonl:ro" \
  -v "${FB_CONFIG}:/usr/share/filebeat/filebeat.yml:ro" \
  --user root \
  "docker.elastic.co/beats/filebeat:${ELASTIC_VERSION}" \
  filebeat -e --strict.perms=false \
  2>/dev/null &

# ── Wait for events in Elasticsearch ─────────────────────────────────────────

echo "==> Waiting for events to appear in Elasticsearch (up to 60s)..."
waited=0
es_count=0
until [ "${es_count}" -ge "${audit_lines}" ]; do
  if [ "${waited}" -ge 60 ]; then
    # Hard fail — partial ingestion is not acceptable.
    echo "ERROR: only ${es_count}/${audit_lines} events indexed after 60s." >&2
    echo "       All audit events must be indexed — partial ingestion is not acceptable." >&2
    echo "       Filebeat may have dropped events due to a mapping conflict." >&2
    echo "       Check that the kms-audit-normalize ingest pipeline is in place." >&2
    docker rm -f "${FILEBEAT_CONTAINER}" 2>/dev/null || true
    FILEBEAT_CONTAINER=""
    exit 1
  fi
  sleep 3
  waited=$((waited + 3))
  es_count=$(curl -sf "${ES_URL}/${ES_INDEX}/_count" 2>/dev/null |
    grep -o '"count":[0-9]*' | cut -d: -f2 || echo 0)
  echo "    Indexed: ${es_count}/${audit_lines} events (${waited}s elapsed)"
done

# Stop Filebeat
docker rm -f "${FILEBEAT_CONTAINER}" 2>/dev/null || true
FILEBEAT_CONTAINER=""

# ── Verify indexed documents ──────────────────────────────────────────────────

echo "==> Querying Elasticsearch to verify field extraction..."

ES_DOCS=$(curl -sf "${ES_URL}/${ES_INDEX}/_search?size=100" \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}, "_source": true}' 2>/dev/null)

# Extract _source documents and write to a JSONL file for verification
VERIFY_JSONL="$(mktemp -t es-verify-XXXXXX.jsonl)"
echo "${ES_DOCS}" |
  python3 -c "
import json, sys
data = json.load(sys.stdin)
hits = data.get('hits', {}).get('hits', [])
for hit in hits:
    print(json.dumps(hit.get('_source', {})))
" >"${VERIFY_JSONL}"

# Python venv for the helper
VENV_DIR="$(mktemp -d -t siem-venv-XXXXXX)"
python3 -m venv "${VENV_DIR}"
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

indexed_count=$(grep -c . "${VERIFY_JSONL}" 2>/dev/null || echo 0)
echo "    Verifying ${indexed_count} indexed document(s)..."

# --exact: all audit events must be indexed (no partial success).
# verify_es_result_coverage: both Success AND Failure results must be present,
# which proves the ingest pipeline correctly handles the polymorphic result field.
python3 "${HELPER}" es "${VERIFY_JSONL}" --exact "${audit_lines}"
rm -f "${VERIFY_JSONL}"

echo ""
echo "Filebeat → Elasticsearch integration test PASSED."
echo "Verified: all ${audit_lines} KMS audit events indexed (Success + Failure)."
echo "Proves the 'Elasticsearch / OpenSearch' section of siems.md."
