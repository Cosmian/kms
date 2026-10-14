#!/usr/bin/env bash
# .mise/lib/audit_e2e.sh — Shared helpers for the file and PostgreSQL audit E2E scripts.
#
# Source this after `ckms_bin` and `ckms_conf` (see kms_server.sh's
# kms_write_ckms_conf) are set:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/audit_e2e.sh"
#
# Provides:
#   audit_ckms_json <args...>       — ckms with JSON output; exits (set -e) on failure
#   audit_ckms <args...>            — ckms; exits (set -e) on failure
#   audit_ckms_fail <args...>       — ckms; fails the script if it unexpectedly succeeds
#   audit_extract_uid               — pipe JSON output through this for unique_identifier
#   audit_exercise_kmip_ops         — Create/Encrypt/Decrypt/Revoke/Destroy + 1 deliberate
#                                      Failure; sets AUDIT_SYM_UID
#   audit_assert_events_jsonl <file> — event count, required fields, Success+Failure
#                                       coverage, and per-operation lifecycle coverage

[ -n "${_MISE_AUDIT_E2E_SH_LOADED:-}" ] && return 0
_MISE_AUDIT_E2E_SH_LOADED=1

_AUDIT_E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  # shellcheck source=.mise/lib/common.sh
  source "${_AUDIT_E2E_DIR}/common.sh"
fi

# Used by both audit_exercise_kmip_ops (to trigger the deliberate Failure) and
# audit_assert_events_jsonl (to confirm that specific failure landed) — an
# incidental Failure event (e.g. a startup readiness probe) must not be mistaken
# for it.
AUDIT_NONEXISTENT_UID="00000000-0000-0000-0000-000000000000"

# ── ckms invocation helpers ────────────────────────────────────────────────────
# Callers must set `ckms_bin` and `ckms_conf` before calling these.

audit_ckms_json() {
  COSMIAN_KMS_CLI_FORMAT=json "${ckms_bin}" --conf-path "${ckms_conf}" "$@"
}

audit_ckms() {
  "${ckms_bin}" --conf-path "${ckms_conf}" "$@"
}

audit_ckms_fail() {
  if "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null; then
    print_error "expected ckms command to fail: $*"
  fi
}

audit_extract_uid() {
  grep -o '"unique_identifier": *"[^"]*"' | head -1 | sed 's/"unique_identifier": *"//;s/"$//'
}

# ── KMIP operation sequence ────────────────────────────────────────────────────
# Create -> Encrypt -> Decrypt (with plaintext round-trip check) -> Revoke ->
# Destroy, plus one deliberate Failure (export of a nonexistent key). Sets
# AUDIT_SYM_UID. Every expected-success step exits the script on failure via
# audit_ckms/set -e — nothing here swallows an error.
audit_exercise_kmip_ops() {
  echo "==> Exercising KMIP operations..."

  local create_out
  create_out=$(audit_ckms_json sym keys create --algorithm aes --number-of-bits 256)
  AUDIT_SYM_UID=$(echo "${create_out}" | audit_extract_uid)
  echo "    Created AES-256 key: ${AUDIT_SYM_UID}"

  local tmpdir plaintext encrypted decrypted
  tmpdir="$(mktemp -d -t audit-e2e-data-XXXXXX)"
  plaintext="${tmpdir}/plaintext.txt"
  encrypted="${tmpdir}/encrypted.bin"
  decrypted="${tmpdir}/decrypted.txt"
  echo "Hello, audit E2E test!" >"${plaintext}"

  audit_ckms sym encrypt "${plaintext}" --key-id "${AUDIT_SYM_UID}" --output-file "${encrypted}"
  echo "    Encrypted."
  audit_ckms sym decrypt "${encrypted}" --key-id "${AUDIT_SYM_UID}" --output-file "${decrypted}"
  echo "    Decrypted."
  cmp -s "${plaintext}" "${decrypted}" || print_error "decrypted plaintext does not match the original"

  audit_ckms sym keys revoke "test cleanup" --key-id "${AUDIT_SYM_UID}"
  echo "    Revoked key."
  audit_ckms sym keys destroy --key-id "${AUDIT_SYM_UID}"
  echo "    Destroyed key."
  rm -rf "${tmpdir}"

  audit_ckms_fail sym keys export /dev/null --key-id "${AUDIT_NONEXISTENT_UID}"
  echo "    Triggered deliberate Failure event (non-existent key)."
}

# ── JSONL assertions ────────────────────────────────────────────────────────────
# GUARD: event count, required fields, Success+Failure coverage, and — when
# AUDIT_SYM_UID is set — one Success event per lifecycle operation on that key.
audit_assert_events_jsonl() {
  local jsonl_file="$1"

  local audit_lines
  audit_lines=$(grep -c . "${jsonl_file}" || true)
  echo "    Audit file has ${audit_lines} event(s)."
  if [ "${audit_lines}" -lt 4 ]; then
    print_error "expected at least 4 audit events, got ${audit_lines}"
  fi
  echo "GUARD OK: ${audit_lines} audit events written (>= 4 required)."

  local required_fields=("timestamp" "operation" "user" "result" "request_id" "client_ip")
  local missing_count=0 event_num=0 field line
  while IFS= read -r line; do
    [ -z "${line}" ] && continue
    event_num=$((event_num + 1))
    for field in "${required_fields[@]}"; do
      if ! echo "${line}" | python3 -c "import sys, json; d=json.loads(sys.stdin.read()); sys.exit(0 if '${field}' in d else 1)" 2>/dev/null; then
        echo "ERROR: event #${event_num} missing required field '${field}'." >&2
        echo "       Event: ${line}" >&2
        missing_count=$((missing_count + 1))
      fi
    done
  done <"${jsonl_file}"
  if [ "${missing_count}" -gt 0 ]; then
    print_error "${missing_count} field check(s) failed across ${event_num} audit events"
  fi
  echo "GUARD OK: all ${event_num} events have required fields: ${required_fields[*]}"

  local success_count failure_count
  success_count=$(python3 -c "
import json
lines = [l for l in open('${jsonl_file}') if l.strip()]
print(sum(1 for l in lines if json.loads(l).get('result') == 'Success'))
")
  failure_count=$(python3 -c "
import json
lines = [l for l in open('${jsonl_file}') if l.strip()]
print(sum(1 for l in lines if isinstance(json.loads(l).get('result'), dict) and 'Failure' in json.loads(l).get('result', {})))
")
  echo "    Result coverage: ${success_count} Success, ${failure_count} Failure events."
  if [ "${success_count}" -lt 1 ]; then
    print_error "no Success result events found — audit middleware may not be recording results"
  fi
  if [ "${failure_count}" -lt 1 ]; then
    print_error "no Failure result events found — deliberate failure was not captured"
  fi
  echo "GUARD OK: result coverage verified (${success_count} Success, ${failure_count} Failure)."

  # An incidental Failure (e.g. a startup readiness probe) could otherwise satisfy the
  # generic count check above without the deliberate failure ever having landed.
  if ! python3 -c "
import json
for l in open('${jsonl_file}'):
    if not l.strip(): continue
    d = json.loads(l)
    if isinstance(d.get('result'), dict) and d.get('object_uid') == '${AUDIT_NONEXISTENT_UID}':
        raise SystemExit(0)
raise SystemExit(1)
" 2>/dev/null; then
    print_error "the deliberate Failure event (export of ${AUDIT_NONEXISTENT_UID}) was not captured"
  fi
  echo "GUARD OK: the deliberate Failure event was captured."

  if [ -n "${AUDIT_SYM_UID:-}" ]; then
    local expected_ops=("Create" "Encrypt" "Decrypt" "Revoke" "Destroy")
    local op missing_ops=0
    for op in "${expected_ops[@]}"; do
      if ! python3 -c "
import json
found = False
for l in open('${jsonl_file}'):
    if not l.strip(): continue
    d = json.loads(l)
    if d.get('operation') == '${op}' and d.get('object_uid') == '${AUDIT_SYM_UID}' and d.get('result') == 'Success':
        found = True
        break
raise SystemExit(0 if found else 1)
" 2>/dev/null; then
        echo "ERROR: no Success event found for operation=${op} object_uid=${AUDIT_SYM_UID}." >&2
        missing_ops=$((missing_ops + 1))
      fi
    done
    if [ "${missing_ops}" -gt 0 ]; then
      print_error "${missing_ops} expected lifecycle event(s) missing for key ${AUDIT_SYM_UID}"
    fi
    echo "GUARD OK: Create/Encrypt/Decrypt/Revoke/Destroy all recorded for key ${AUDIT_SYM_UID}."
  fi
}
