#!/usr/bin/env bash
# Generate a live KMS JSONL audit fixture (non-fips only — audit middleware feature gate)
# for the OpenSearch/Splunk SIEM compat checks, instead of relying on a static fixture.
#
# Drives Create -> Encrypt -> Decrypt -> Revoke -> Destroy (all expected to
# succeed) plus one deliberate Failure (export of a non-existent key), then
# hands off the resulting file at --output.
#
# Usage:
#   bash .mise/scripts/test/generate_live_audit_fixture.sh --output /path/to/audit.jsonl
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

OUTPUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o | --output)
      OUTPUT="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
[ -z "${OUTPUT}" ] && {
  echo "ERROR: --output <path> is required" >&2
  exit 1
}

kms_init_env "non-fips" "static"
setup_test_logging

cleanup() {
  kms_stop
}
trap cleanup EXIT

print_header "Generating a live KMS JSONL audit fixture"

echo "==> Building KMS server + ckms CLI..."
kms_build_all

kms_bin=$(get_kms_bin)
ckms_bin=$(get_ckms_bin)

KMS_PORT="$(kms_pick_free_port)"
kms_write_config "${KMS_PORT}" "$(mktemp -d /tmp/kms-audit-compat-live-XXXXXX)"

cat >>"${KMS_CONFIG_FILE}" <<EOF

[audit]
enabled = true

[audit.file]
path = "${OUTPUT}"
EOF

kms_start_from_bin "${kms_bin}"
ckms_conf=$(kms_write_ckms_conf)

ckms_json() {
  COSMIAN_KMS_CLI_FORMAT=json "${ckms_bin}" --conf-path "${ckms_conf}" "$@"
}
ckms_run() {
  "${ckms_bin}" --conf-path "${ckms_conf}" "$@" >/dev/null
}
extract_uid() {
  grep -o '"unique_identifier": *"[^"]*"' | head -1 | sed 's/"unique_identifier": *"//;s/"$//'
}

echo "==> Driving KMIP operations (Create, Encrypt, Decrypt, Revoke, Destroy, 1 deliberate Failure)..."
CREATE_OUT=$(ckms_json sym keys create --algorithm aes --number-of-bits 256)
SYM_UID=$(echo "${CREATE_OUT}" | extract_uid)

TMPDIR_DATA="$(mktemp -d -t audit-compat-live-XXXXXX)"
PLAINTEXT="${TMPDIR_DATA}/plaintext.txt"
ENCRYPTED="${TMPDIR_DATA}/encrypted.bin"
DECRYPTED="${TMPDIR_DATA}/decrypted.txt"
echo "Hello, live audit compat fixture!" >"${PLAINTEXT}"

# Every call below is expected to succeed (script exits on the first failure, see
# `set -e`), except the deliberate Failure at the end which is explicitly allowed to fail.
ckms_run sym encrypt "${PLAINTEXT}" --key-id "${SYM_UID}" --output-file "${ENCRYPTED}"
ckms_run sym decrypt "${ENCRYPTED}" --key-id "${SYM_UID}" --output-file "${DECRYPTED}"
# KMIP forbids destroying an Active key directly; it must be revoked first.
ckms_run sym keys revoke "audit fixture teardown" --key-id "${SYM_UID}"
ckms_run sym keys destroy --key-id "${SYM_UID}"
rm -rf "${TMPDIR_DATA}"

# Deliberate Failure: export a non-existent key to produce a Failure result event
ckms_run sym keys export --key-id "00000000-0000-0000-0000-000000000000" "$(mktemp -t audit-compat-export-XXXXXX)" || true

echo "==> Waiting for audit events to flush..."
previous_count=-1
for _ in $(seq 1 20); do
  current_count=$(grep -c . "${OUTPUT}" 2>/dev/null || echo 0)
  if [ "${current_count}" -gt 0 ] && [ "${current_count}" = "${previous_count}" ]; then
    break
  fi
  previous_count="${current_count}"
  sleep 0.5
done

if [ ! -s "${OUTPUT}" ]; then
  echo "ERROR: no audit events were written to ${OUTPUT}" >&2
  exit 1
fi

echo "==> Verifying hash chain integrity (ckms audit verify)..."
if ! "${ckms_bin}" audit verify --path "${OUTPUT}" 2>&1; then
  echo "ERROR: generated fixture failed hash-chain verification." >&2
  exit 1
fi

print_success "Live audit fixture written to ${OUTPUT} ($(grep -c . "${OUTPUT}") events)"
