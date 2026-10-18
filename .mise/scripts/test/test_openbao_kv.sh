#!/usr/bin/env bash
set -euo pipefail

# OpenBao `bao kv` client scenario against the KMS Vault KV v2-compatible store.
#
# Drives the real OpenBao CLI (container image, no host install) so the `/v1/<mount>` prefix,
# the KV v2 pre-flight and the PUT write path are exercised exactly as a user would hit them.
#
# Required environment:
#   BAO_ADDR      KMS base URL as seen from the container (e.g. https://localhost:9998)
#   BAO_TOKEN     token (X-Vault-Token) of the identity that owns the secrets
# Optional environment:
#   BAO_TOKEN_OTHER   token of a second identity with no grant: enables the 403 check
#   BAO_CACERT_HOST   PEM CA bundle on the host, mounted into the container
#   BAO_NETWORK       docker network mode (default: host on Linux, bridge + host-gateway elsewhere)
#   BAO_IMAGE         OpenBao image (default: ghcr.io/openbao/openbao:2.7.1)
#   KV_MOUNT          KV mount name (default: kv)
#   KV_TTL_WAIT_SECS  max seconds to wait for the TTL sweep (default: 30)

: "${BAO_ADDR:?BAO_ADDR must be set}"
: "${BAO_TOKEN:?BAO_TOKEN must be set}"
BAO_IMAGE="${BAO_IMAGE:-ghcr.io/openbao/openbao:2.7.1}"
KV_MOUNT="${KV_MOUNT:-kv}"
KV_TTL_WAIT_SECS="${KV_TTL_WAIT_SECS:-30}"
BAO_TOKEN_OTHER="${BAO_TOKEN_OTHER:-}"
BAO_CACERT_HOST="${BAO_CACERT_HOST:-}"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=.mise/lib/common.sh
source "${SCRIPT_DIR}/../../lib/common.sh"

require_cmd docker "Docker is required to run the OpenBao CLI."
require_cmd python3 "python3 is required to parse CLI JSON output."
require_cmd curl "curl is required for the TTL and authorization checks."

SECRET_PATH="openbao-ci/$$"
SECRET_NAME="$$"
FULL_PATH="${KV_MOUNT}/${SECRET_PATH}"
DATA_URI="/v1/${KV_MOUNT}/data/${SECRET_PATH}"

# Run the OpenBao CLI in a throw-away container. Token passed by name so it stays out of argv.
bao() {
  local args=(run --rm -i --entrypoint bao -e BAO_ADDR -e BAO_TOKEN)
  if [[ -n "${BAO_NETWORK:-}" ]]; then
    args+=(--network "${BAO_NETWORK}")
  elif [[ "$(uname -s)" == "Linux" ]]; then
    args+=(--network host)
  else
    args+=(--add-host host.docker.internal:host-gateway)
  fi
  if [[ -n "${BAO_CACERT_HOST}" ]]; then
    args+=(-v "${BAO_CACERT_HOST}:/ca.crt:ro" -e BAO_CACERT=/ca.crt)
  fi
  docker "${args[@]}" "${BAO_IMAGE}" "$@"
}

# Print a JSON field: json_field '<json>' '<python expression on d>'.
json_field() {
  printf '%s' "$1" | python3 -c "import sys, json; d = json.load(sys.stdin); print($2)"
}

# Fail with a message unless $1 == $2.
assert_eq() {
  [[ "$1" == "$2" ]] || print_error "$3: expected '$2', got '$1'"
  print_success "$3"
}

# Fail unless the command exits non-zero.
assert_fails() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    print_error "${label}: command unexpectedly succeeded"
  fi
  print_success "${label}"
}

# HTTP status of a KV call made with curl (the CLI hides status codes). Args: token method uri [body]
kv_status() {
  local token="$1" method="$2" uri="$3" body="${4:-}"
  local curl_args=(-s -o /dev/null -w '%{http_code}' -X "${method}" -H "X-Vault-Token: ${token}")
  [[ -n "${BAO_CACERT_HOST}" ]] && curl_args+=(--cacert "${BAO_CACERT_HOST}")
  [[ -n "${body}" ]] && curl_args+=(-H 'Content-Type: application/json' -d "${body}")
  curl "${curl_args[@]}" "$(curl_base_url)${uri}"
}

# The KMS URL reachable from the host (the container may use host.docker.internal instead).
curl_base_url() {
  echo "${BAO_ADDR/host.docker.internal/localhost}"
}

print_header "OpenBao kv scenario (${BAO_IMAGE}, mount '${KV_MOUNT}')"

print_status "bao version"
bao version

print_status "kv put (version 1) — exercises PUT + the KV v2 pre-flight"
bao kv put "${FULL_PATH}" api_key=first >/dev/null
print_success "kv put"

print_status "kv get returns the written value"
OUT=$(bao kv get -format=json "${FULL_PATH}")
assert_eq "$(json_field "${OUT}" "d['data']['data']['api_key']")" "first" "kv get value"
assert_eq "$(json_field "${OUT}" "d['data']['metadata']['version']")" "1" "kv get version"

print_status "kv put again creates version 2; version 1 stays readable"
bao kv put "${FULL_PATH}" api_key=second >/dev/null
OUT=$(bao kv get -format=json "${FULL_PATH}")
assert_eq "$(json_field "${OUT}" "d['data']['data']['api_key']")" "second" "latest value"
assert_eq "$(json_field "${OUT}" "d['data']['metadata']['version']")" "2" "latest version"
OUT=$(bao kv get -format=json -version=1 "${FULL_PATH}")
assert_eq "$(json_field "${OUT}" "d['data']['data']['api_key']")" "first" "version 1 value"

print_status "kv metadata get reports the version bookkeeping"
OUT=$(bao kv metadata get -format=json "${FULL_PATH}")
assert_eq "$(json_field "${OUT}" "d['data']['current_version']")" "2" "current_version"

print_status "kv list shows the secret under its prefix"
OUT=$(bao kv list -format=json "${KV_MOUNT}/openbao-ci")
assert_eq "$(json_field "${OUT}" "'${SECRET_NAME}' in d")" "True" "kv list contains the secret"

if [[ -n "${BAO_TOKEN_OTHER}" ]]; then
  print_status "a wrong token is rejected"
  BAO_TOKEN="not-a-valid-token" assert_fails "kv get with a bad token" bao kv get "${FULL_PATH}"

  print_status "a second identity without a grant gets 403"
  assert_eq "$(kv_status "${BAO_TOKEN_OTHER}" GET "${DATA_URI}")" "403" "non-owner read is forbidden"
else
  print_warning "BAO_TOKEN_OTHER not set — skipping the authentication and authorization checks"
fi

print_status "kv delete hides the latest version"
bao kv delete "${FULL_PATH}" >/dev/null
assert_fails "kv get after delete" bao kv get "${FULL_PATH}"

print_status "TTL: a secret written with options.ttl disappears after the sweep"
TTL_URI="${DATA_URI}-ttl"
assert_eq "$(kv_status "${BAO_TOKEN}" PUT "${TTL_URI}" '{"data":{"k":"v"},"options":{"ttl":"2s"}}')" "200" "write with ttl"
assert_eq "$(kv_status "${BAO_TOKEN}" GET "${TTL_URI}")" "200" "read before expiry"
expired=false
for _ in $(seq 1 "${KV_TTL_WAIT_SECS}"); do
  if [[ "$(kv_status "${BAO_TOKEN}" GET "${TTL_URI}")" == "404" ]]; then
    expired=true
    break
  fi
  sleep 1
done
[[ "${expired}" == "true" ]] || print_error "TTL secret still readable after ${KV_TTL_WAIT_SECS}s (is kv_ttl_check_interval_secs > 0?)"
print_success "TTL secret expired"

print_status "kv metadata delete removes every version"
bao kv put "${FULL_PATH}" api_key=again >/dev/null
bao kv metadata delete "${FULL_PATH}" >/dev/null
assert_fails "kv metadata get after metadata delete" bao kv metadata get "${FULL_PATH}"

print_success "OpenBao kv scenario passed"
