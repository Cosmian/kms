#!/usr/bin/env bash
# Fluent Bit JSONL file-tailing integration test.
#
# Validates the "File tailing" integration model documented in siems.md
# using Fluent Bit — the lightweight, open-source (Apache 2.0) log shipper
# that covers the same pattern as Splunk UF, Datadog Agent, and Filebeat.
#
# Test flow:
#   1. Build KMS server + ckms CLI
#   2. Start KMS with audit logging enabled
#   3. Exercise KMIP operations to produce audit events
#   4. Run Fluent Bit (Docker) configured to tail the JSONL file and write
#      parsed events to an output JSON file
#   5. Verify that all KMS audit fields are correctly extracted by Fluent Bit
#
# Requires: Docker daemon running, docker pull access for fluent/fluent-bit:3
#
# Usage:
#   bash .mise/scripts/test/test_siem_fluent_bit.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

HELPER="${SCRIPT_DIR}/siem_verify_fields.py"
AUDIT_JSONL=""
FLUENT_OUTPUT=""
FLUENT_DIR=""
VENV_DIR=""
FLUENT_CONTAINER=""

cleanup() {
  kms_stop
  if [ -n "${FLUENT_CONTAINER:-}" ]; then
    docker rm -f "${FLUENT_CONTAINER}" 2>/dev/null || true
    FLUENT_CONTAINER=""
  fi
  [ -n "${VENV_DIR:-}" ] && { rm -rf "${VENV_DIR}" || true; }
  [ -n "${FLUENT_DIR:-}" ] && { rm -rf "${FLUENT_DIR}" || true; }
}
trap cleanup EXIT

echo "==========================================="
echo "Fluent Bit JSONL file-tailing test"
echo "Proves: siems.md 'File tailing' section"
echo "==========================================="

# ── Prerequisite: Docker ──────────────────────────────────────────────────────

if ! command -v docker &>/dev/null; then
  echo "ERROR: Docker is not available — skipping Fluent Bit test." >&2
  exit 1
fi
if ! docker info &>/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not running — skipping Fluent Bit test." >&2
  exit 1
fi

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building KMS server + ckms CLI..."
kms_build_all

kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

# ── Start KMS server with audit logging ───────────────────────────────────────

# Fluent Bit mounts the audit file and writes output into a shared directory.
# On macOS Docker Desktop only shares /private (which /tmp links to), not
# $TMPDIR (/var/folders/...).  Force the directory into /tmp so Docker can
# mount it on all platforms.
FLUENT_DIR="$(mktemp -d /tmp/kms-siem-fluent-XXXXXX)"
AUDIT_JSONL="${FLUENT_DIR}/audit.jsonl"
FLUENT_OUTPUT="${FLUENT_DIR}/output.log"
touch "${AUDIT_JSONL}" "${FLUENT_OUTPUT}"

KMS_PORT="$(kms_pick_free_port)"
echo "==> Starting KMS server on port ${KMS_PORT} with audit logging..."
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-siem-fluent-XXXXXX)"

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

TMPDIR_FB="$(mktemp -d -t fluent-data-XXXXXX)"
PLAINTEXT="${TMPDIR_FB}/plaintext.txt"
ENCRYPTED="${TMPDIR_FB}/encrypted.bin"
echo "Hello, Fluent Bit test!" >"${PLAINTEXT}"
ckms_run sym encrypt "${PLAINTEXT}" --key-id "${SYM_UID}" --output "${ENCRYPTED}"
ckms_run sym decrypt "${ENCRYPTED}" --key-id "${SYM_UID}" --output "${TMPDIR_FB}/decrypted.txt"
ckms_run sym keys revoke --key-id "${SYM_UID}"
ckms_run sym keys destroy --key-id "${SYM_UID}"
rm -rf "${TMPDIR_FB}"

echo "==> Waiting for audit events to flush..."
sleep 2

audit_lines=$(grep -c . "${AUDIT_JSONL}" 2>/dev/null || echo 0)
echo "    Audit file has ${audit_lines} event(s)."
if [ "${audit_lines}" -lt 3 ]; then
  echo "ERROR: expected at least 3 audit events, got ${audit_lines}" >&2
  cat "${AUDIT_JSONL}" >&2
  exit 1
fi

# ── Write Fluent Bit config ───────────────────────────────────────────────────

FB_CONFIG="${FLUENT_DIR}/fluent-bit.conf"
FB_PARSERS="${FLUENT_DIR}/parsers.conf"

cat >"${FB_PARSERS}" <<'EOF'
[PARSER]
    Name   kms_json
    Format json
    Time_Key timestamp
    Time_Format %Y-%m-%dT%H:%M:%S%.L%z
    Time_Keep On
EOF

# This Fluent Bit config mirrors the conceptual pattern from siems.md's
# "Generic file tailing" section (tail + JSON parse + forward output).
# stdout output is used so events flow to docker run stdout, which we capture
# to a file — simpler than the file output plugin which doesn't support
# json_lines format in Fluent Bit 4.x.
cat >"${FB_CONFIG}" <<EOF
[SERVICE]
    Flush         1
    Daemon        Off
    Log_Level     error
    Parsers_File  /fluent/parsers.conf

[INPUT]
    Name             tail
    Path             /audit/audit.jsonl
    Parser           kms_json
    Tag              kms_audit
    DB               /fluent/tail.db
    Refresh_Interval 1
    Read_from_Head   On

[OUTPUT]
    Name    stdout
    Match   kms_audit
    Format  json_lines
EOF

# ── Run Fluent Bit container ──────────────────────────────────────────────────

echo "==> Running Fluent Bit container to tail the audit JSONL file..."
echo "    fluent/fluent-bit:4.0 — official Docker image (Apache 2.0)"

# Capture Fluent Bit's stdout (which carries the json_lines output) to a file.
# stderr (banner + log messages) is suppressed — only JSON event lines reach stdout.
FLUENT_CONTAINER="kms-siem-test-fluent-$$"
docker run --rm --name "${FLUENT_CONTAINER}" \
  -v "${FLUENT_DIR}:/fluent:rw" \
  -v "${AUDIT_JSONL}:/audit/audit.jsonl:ro" \
  -v "${FB_CONFIG}:/fluent-bit/etc/fluent-bit.conf:ro" \
  fluent/fluent-bit:4.0 \
  /fluent-bit/bin/fluent-bit \
  -c /fluent-bit/etc/fluent-bit.conf \
  2>/dev/null >"${FLUENT_OUTPUT}" &

# Wait until the output file has exactly audit_lines lines or until timeout.
# Hard fail if timeout is reached without receiving all events.
echo "==> Waiting for Fluent Bit to process exactly ${audit_lines} event(s) (up to 30s)..."
waited=0
fb_lines=0
while [ "${waited}" -lt 30 ]; do
  if [ -f "${FLUENT_OUTPUT}" ]; then
    fb_lines=$(
      grep -c '^{' "${FLUENT_OUTPUT}" 2>/dev/null
      true
    )
    if [ "${fb_lines}" -ge "${audit_lines}" ]; then
      break
    fi
  fi
  sleep 2
  waited=$((waited + 2))
done

# Stop Fluent Bit container before checking count (avoid races)
docker rm -f "${FLUENT_CONTAINER}" 2>/dev/null || true
FLUENT_CONTAINER=""

# After container stops, do a final count (it may have flushed on shutdown)
fb_lines=$(
  grep -c '^{' "${FLUENT_OUTPUT}" 2>/dev/null
  true
)

# Guard: all audit events must be processed — no partial success.
if [ "${fb_lines}" -lt "${audit_lines}" ]; then
  echo "ERROR: Fluent Bit only produced ${fb_lines}/${audit_lines} events after 30s." >&2
  echo "       All audit events must be forwarded — partial ingestion is not acceptable." >&2
  echo "Fluent Bit output:" >&2
  cat "${FLUENT_OUTPUT}" >&2
  exit 1
fi

# ── Verify output ─────────────────────────────────────────────────────────────

echo "==> Verifying Fluent Bit parsed output..."

if [ ! -f "${FLUENT_OUTPUT}" ] || [ ! -s "${FLUENT_OUTPUT}" ]; then
  echo "ERROR: Fluent Bit produced no output at ${FLUENT_OUTPUT}" >&2
  exit 1
fi

# Python venv for the helper (no extra packages needed — stdlib only)
VENV_DIR="$(mktemp -d -t siem-venv-XXXXXX)"
python3 -m venv "${VENV_DIR}"
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

python3 "${HELPER}" fluent "${FLUENT_OUTPUT}" \
  --exact "${audit_lines}" \
  --source "${AUDIT_JSONL}"

echo ""
echo "Fluent Bit JSONL file-tailing test PASSED."
echo "Verified: KMS JSONL audit events are correctly parsed and forwarded by Fluent Bit."
