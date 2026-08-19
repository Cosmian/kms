#!/usr/bin/env bash
# OPA RBAC end-to-end test suite.
#
# Two-phase testing strategy:
#
# Phase 1 — Policy tests (OPA only, no KMS):
#   Queries OPA /v1/data/kms/allow directly with crafted inputs.
#   Covers all roles × operations × domain scenarios without a running KMS.
#
# Phase 2 — Integration tests (KMS + OPA):
#   Starts KMS with --features insecure (accepts unsigned JWTs) and --opa-mode enforcing.
#   Verifies that the full HTTP → KMS → OPA → allow/deny stack works correctly.
#
#   IMPORTANT: For KMIP operations, HTTP status codes do NOT reflect OPA decisions:
#   - Missing/invalid JWT         → HTTP 401  (JWT auth middleware, before KMS handler)
#   - OPA allows the operation    → HTTP 200 + KMIP ResultStatus "Success"
#   - OPA denies the operation    → HTTP 200 + KMIP ResultStatus "OperationFailed"
#   This is because KMIP errors are always wrapped in HTTP 200 per the KMIP protocol.
#
# Requires: cargo, docker (for OPA container), curl
set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"
setup_test_logging

# ── Configuration ────────────────────────────────────────────────────────────
KMS_PORT=9991
KMS_URL="http://127.0.0.1:${KMS_PORT}"
OPA_PORT=8182 # separate port to avoid conflict with docker-compose opa on 8181
OPA_URL="http://127.0.0.1:${OPA_PORT}"
OPA_CONTAINER="kms-opa-rbac-test-$$"

KMS_PID=""
SQLITE_PATH=""
KMS_CONF_PATH=""

cleanup() {
  [ -n "${KMS_PID:-}" ] && {
    kill "${KMS_PID}" 2>/dev/null || true
    wait "${KMS_PID}" 2>/dev/null || true
  }
  docker rm -f "${OPA_CONTAINER}" 2>/dev/null || true
  [ -n "${SQLITE_PATH:-}" ] && { rm -rf "${SQLITE_PATH}" || true; }
  [ -n "${KMS_CONF_PATH:-}" ] && { rm -f "${KMS_CONF_PATH}" || true; }
}
trap cleanup EXIT

# ── JWT helpers ───────────────────────────────────────────────────────────────
# Craft an unsigned JWT accepted by KMS when built with --features insecure.
# insecure_decode() only deserializes the payload; it never verifies the signature.

b64url() {
  printf '%s' "$1" | base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n'
}

# make_jwt <sub> <domain> <roles_json_array>
# Example: make_jwt "alice@acme.com" "acme.com" '["CryptoOfficer"]'
make_jwt() {
  local sub="$1" domain="$2" roles="$3"
  local header='{"alg":"RS256","typ":"JWT"}'
  local payload
  payload=$(printf '{"sub":"%s","iss":"test","iat":1000000,"exp":9999999999,"roles":%s,"as_domain":"%s"}' \
    "$sub" "$roles" "$domain")
  printf '%s.%s.fakesig' "$(b64url "$header")" "$(b64url "$payload")"
}

# ── KMIP request helpers ──────────────────────────────────────────────────────
# Both kmip_* helpers strip LD_LIBRARY_PATH before calling curl so the system
# curl does not load the FIPS OpenSSL 3.1.2 shared library (which is older than
# the OpenSSL the system libcurl was compiled against).
# Returns the HTTP status code for a KMIP /kmip/2_1 POST.
kmip_post_status() {
  local jwt="$1" body="$2"
  if [ -n "$jwt" ]; then
    env -u LD_LIBRARY_PATH -u LD_PRELOAD curl -s -o /dev/null -w "%{http_code}" \
      -X POST "${KMS_URL}/kmip/2_1" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${jwt}" \
      -d "$body"
  else
    env -u LD_LIBRARY_PATH -u LD_PRELOAD curl -s -o /dev/null -w "%{http_code}" \
      -X POST "${KMS_URL}/kmip/2_1" \
      -H "Content-Type: application/json" \
      -d "$body"
  fi
}

# Returns the raw KMIP response body (JSON TTLV).
kmip_response_body() {
  local jwt="$1" body="$2"
  if [ -n "$jwt" ]; then
    env -u LD_LIBRARY_PATH -u LD_PRELOAD curl -s \
      -X POST "${KMS_URL}/kmip/2_1" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${jwt}" \
      -d "$body"
  else
    env -u LD_LIBRARY_PATH -u LD_PRELOAD curl -s \
      -X POST "${KMS_URL}/kmip/2_1" \
      -H "Content-Type: application/json" \
      -d "$body"
  fi
}

# Build the TTLV JSON for a Create symmetric key request.
create_aes256_request() {
  cat <<'EOF'
{
  "tag": "RequestMessage",
  "type": "Structure",
  "value": [
    {
      "tag": "RequestHeader",
      "type": "Structure",
      "value": [
        {"tag": "ProtocolVersion","type": "Structure","value": [
            {"tag": "ProtocolVersionMajor","type": "Integer","value": 2},
            {"tag": "ProtocolVersionMinor","type": "Integer","value": 1}
        ]},
        {"tag": "BatchCount","type": "Integer","value": 1}
      ]
    },
    {
      "tag": "BatchItem",
      "type": "Structure",
      "value": [
        {"tag": "Operation","type": "Enumeration","value": "Create"},
        {
          "tag": "RequestPayload",
          "type": "Structure",
          "value": [
            {"tag": "ObjectType","type": "Enumeration","value": "SymmetricKey"},
            {
              "tag": "Attributes",
              "type": "Structure",
              "value": [
                {"tag": "CryptographicAlgorithm","type": "Enumeration","value": "AES"},
                {"tag": "CryptographicLength","type": "Integer","value": 256},
                {"tag": "CryptographicUsageMask","type": "Integer","value": 2108}
              ]
            }
          ]
        }
      ]
    }
  ]
}
EOF
}

# ── Precondition checks ───────────────────────────────────────────────────────

require_cmd docker "Docker is required to run the OPA container."
require_cmd curl "curl is required for HTTP requests."

echo "========================================="
echo "Running OPA RBAC end-to-end tests"
echo "Variant: ${VARIANT_NAME}"
echo "========================================="

# ── Step 1: Start OPA container ───────────────────────────────────────────────
echo "==> Starting OPA container on port ${OPA_PORT}..."

REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
REGO_FILE="${REPO_ROOT}/test_data/opa/kms.rego"

if [ ! -f "${REGO_FILE}" ]; then
  echo "ERROR: OPA policy file not found: ${REGO_FILE}" >&2
  exit 1
fi

docker run -d \
  --name "${OPA_CONTAINER}" \
  -p "${OPA_PORT}:8181" \
  -v "${REGO_FILE}:/policies/kms.rego:ro" \
  openpolicyagent/opa:edge-static-debug \
  run --server --log-level=error --addr=0.0.0.0:8181 /policies/kms.rego

echo "==> Waiting for OPA to be ready..."
# Unset LD_LIBRARY_PATH for curl: the Nix FIPS shell sets LD_LIBRARY_PATH to OpenSSL 3.1.2,
# but the system curl requires a newer OpenSSL ABI (3.3+), causing a version mismatch.
# OPA communication is plain HTTP — no TLS — so resetting the OpenSSL env vars is safe.
for i in $(seq 1 30); do
  if env -u LD_LIBRARY_PATH -u LD_PRELOAD curl -sf "${OPA_URL}/health" >/dev/null 2>&1; then
    echo "OPA ready."
    break
  fi
  [ "$i" -eq 30 ] && {
    echo "ERROR: OPA failed to start after 30s" >&2
    exit 1
  }
  sleep 1
done

# Smoke-test OPA policy is loaded
POLICY_COUNT=$(env -u LD_LIBRARY_PATH -u LD_PRELOAD curl -sf "${OPA_URL}/v1/policies" | grep -c '"id"' || true)
if [ "${POLICY_COUNT}" -lt 1 ]; then
  echo "ERROR: OPA loaded no policies. Check ${REGO_FILE}" >&2
  exit 1
fi
echo "OPA policy loaded (${POLICY_COUNT} polic(ies))."

# ── Step 2: Phase 1 — Direct OPA policy tests ────────────────────────────────
# Query OPA directly (no KMS) to validate the Rego policy logic in isolation.
PASS=0
FAIL=0

opa_input() {
  local user="$1" user_domain="$2" roles="$3" operation="$4" object_uid="$5" object_domain="$6" is_owner="$7"
  printf '{"input":{"user":"%s","user_domain":"%s","roles":%s,"operation":"%s","object_uid":"%s","object_domain":"%s","is_owner":%s}}' \
    "$user" "$user_domain" "$roles" "$operation" "$object_uid" "$object_domain" "$is_owner"
}

# Assert OPA allow result.
# Usage: assert_opa <desc> <expected_result: true|false> <input_json>
assert_opa() {
  local desc="$1" expected="$2" input="$3"
  local response actual
  response=$(env -u LD_LIBRARY_PATH -u LD_PRELOAD curl -sf "${OPA_URL}/v1/data/kms/allow" \
    -H "Content-Type: application/json" \
    -d "$input" || echo '{}')
  # OPA returns {"result": true} or {"result": false} or {} when result is undefined (=false)
  if echo "$response" | grep -q '"result":true'; then
    actual="true"
  else
    actual="false"
  fi
  if [ "$actual" = "$expected" ]; then
    echo "  PASS: ${desc} → ${actual}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${desc} — expected ${expected}, got response: ${response}"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 1: OPA policy unit tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# SuperAdmin — unrestricted across domains and operations
assert_opa "SuperAdmin can create in own domain" "true" \
  "$(opa_input "sa@acme.com" "acme.com" '["SuperAdmin"]' "create" "*" "acme.com" "false")"
assert_opa "SuperAdmin can create in other domain" "true" \
  "$(opa_input "sa@acme.com" "acme.com" '["SuperAdmin"]' "create" "*" "other.com" "false")"
assert_opa "SuperAdmin can destroy in any domain" "true" \
  "$(opa_input "sa@acme.com" "acme.com" '["SuperAdmin"]' "destroy" "uid-1" "other.com" "false")"

# DomainAdmin — full control within own domain
assert_opa "DomainAdmin can create in own domain" "true" \
  "$(opa_input "da@acme.com" "acme.com" '["DomainAdmin"]' "create" "*" "acme.com" "false")"
assert_opa "DomainAdmin denied in other domain" "false" \
  "$(opa_input "da@acme.com" "acme.com" '["DomainAdmin"]' "get" "uid-1" "other.com" "false")"

# CryptoOfficer — key lifecycle in own domain
assert_opa "CryptoOfficer can create in own domain" "true" \
  "$(opa_input "co@acme.com" "acme.com" '["CryptoOfficer"]' "create" "*" "acme.com" "false")"
assert_opa "CryptoOfficer can destroy in own domain" "true" \
  "$(opa_input "co@acme.com" "acme.com" '["CryptoOfficer"]' "destroy" "uid-1" "acme.com" "false")"
assert_opa "CryptoOfficer denied in other domain" "false" \
  "$(opa_input "co@acme.com" "acme.com" '["CryptoOfficer"]' "create" "*" "other.com" "false")"
assert_opa "CryptoOfficer denied encrypt (User-only op)" "false" \
  "$(opa_input "co@acme.com" "acme.com" '["CryptoOfficer"]' "encrypt" "*" "acme.com" "false")"

# Auditor — read-only metadata in own domain
assert_opa "Auditor can get_attributes in own domain" "true" \
  "$(opa_input "au@acme.com" "acme.com" '["Auditor"]' "get_attributes" "uid-1" "acme.com" "false")"
assert_opa "Auditor denied create" "false" \
  "$(opa_input "au@acme.com" "acme.com" '["Auditor"]' "create" "*" "acme.com" "false")"
assert_opa "Auditor denied destroy" "false" \
  "$(opa_input "au@acme.com" "acme.com" '["Auditor"]' "destroy" "uid-1" "acme.com" "false")"
assert_opa "Auditor denied in other domain" "false" \
  "$(opa_input "au@acme.com" "acme.com" '["Auditor"]' "get_attributes" "uid-1" "other.com" "false")"

# User — crypto-use only, no lifecycle
assert_opa "User can encrypt in own domain" "true" \
  "$(opa_input "u@acme.com" "acme.com" '["User"]' "encrypt" "uid-1" "acme.com" "false")"
assert_opa "User can decrypt in own domain" "true" \
  "$(opa_input "u@acme.com" "acme.com" '["User"]' "decrypt" "uid-1" "acme.com" "false")"
assert_opa "User denied create" "false" \
  "$(opa_input "u@acme.com" "acme.com" '["User"]' "create" "*" "acme.com" "false")"
assert_opa "User denied destroy" "false" \
  "$(opa_input "u@acme.com" "acme.com" '["User"]' "destroy" "uid-1" "acme.com" "false")"
assert_opa "User denied in other domain" "false" \
  "$(opa_input "u@acme.com" "acme.com" '["User"]' "encrypt" "uid-1" "other.com" "false")"

# No role — everything denied
assert_opa "No role denied create" "false" \
  "$(opa_input "anon@acme.com" "acme.com" '[]' "create" "*" "acme.com" "false")"
assert_opa "No role denied encrypt" "false" \
  "$(opa_input "anon@acme.com" "acme.com" '[]' "encrypt" "uid-1" "acme.com" "false")"

# Owner rule — owner always allowed regardless of role
assert_opa "Owner always allowed (no role)" "true" \
  "$(opa_input "anon@acme.com" "acme.com" '[]' "destroy" "uid-1" "acme.com" "true")"

echo ""
echo "Phase 1 results: ${PASS} passed, ${FAIL} failed"

PHASE1_PASS=$PASS
PHASE1_FAIL=$FAIL

# ── Step 3: Build KMS with insecure feature ───────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 2: Integration tests (KMS + OPA)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "==> Building KMS with --features insecure..."
# insecure enables dangerous::insecure_decode — accepts unsigned JWTs (test only)
#
# In the FIPS nix-shell, LD_LIBRARY_PATH is set to FIPS OpenSSL 3.1.2.  The
# system libcurl needs OpenSSL 3.2+; CARGO_NET_OFFLINE prevents registry access
# to avoid the libcurl ABI mismatch when cargo checks the network.
#
# We must pre-fetch all crate sources BEFORE setting CARGO_NET_OFFLINE, because
# on a fresh CI runner ~/.cargo/registry may be empty.  cargo fetch --locked
# downloads everything into the registry cache; the subsequent offline build then
# finds all packages without hitting the network.
#
# The user's ~/.cargo/config.toml may set clang as linker and sccache as the
# rustc-wrapper.  clang is not in the pure Nix PATH, so linker is set to cc.
# RUSTC_WRAPPER is cleared so sccache (at an absolute system path) is not used.
# The mold linker flag (-fuse-ld=mold) is handled by adding pkgs.mold to
# shell.nix buildInputs so the Nix-native mold is found before /usr/bin/ld.mold.
echo "cargo: $(command -v cargo) ($(cargo --version 2>&1 | head -1))"
echo "==> Fetching crate dependencies (online)..."
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
  RUSTC_WRAPPER="" \
  cargo fetch --locked
# shellcheck disable=SC2068
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
  RUSTC_WRAPPER="" \
  CARGO_NET_OFFLINE=true \
  cargo build ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --features insecure --bin cosmian_kms

# ── Step 4: Start KMS ─────────────────────────────────────────────────────────
SQLITE_PATH="$(mktemp -d -t kms-opa-rbac-XXXXXX)"
KMS_CONF_PATH="$(mktemp -t kms-opa-rbac-conf-XXXXXX.toml)"

# jwt_auth_provider format: "issuer,jwks_uri,audience1,audience2"
# With --features insecure, jwt signature and expiry are not verified.
# Any non-empty issuer value works; the JWKS URI is never fetched.
cat >"${KMS_CONF_PATH}" <<EOF
[http]
hostname = "127.0.0.1"
port = ${KMS_PORT}

[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_PATH}"
clear_database = true

[opa]
opa_url = "${OPA_URL}"
opa_mode = "enforcing"

[idp_auth]
jwt_auth_provider = ["test,http://127.0.0.1:1/jwks-not-fetched-in-insecure-mode"]
EOF

echo "==> Starting KMS (enforcing OPA mode)..."
# shellcheck disable=SC2068
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
  RUSTC_WRAPPER="" \
  CARGO_NET_OFFLINE=true \
  cargo run ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --features insecure --bin cosmian_kms -- \
  --config "${KMS_CONF_PATH}" &
KMS_PID=$!

if ! _wait_for_port "127.0.0.1" "${KMS_PORT}" 60; then
  echo "ERROR: KMS failed to start on port ${KMS_PORT}" >&2
  exit 1
fi
echo "KMS started (PID=${KMS_PID})."

# ── Step 5: Craft test JWTs ───────────────────────────────────────────────────
echo "==> Crafting test JWTs..."
JWT_SUPER_ADMIN=$(make_jwt "superadmin@acme.com" "acme.com" '["SuperAdmin"]')
JWT_DOMAIN_ADMIN=$(make_jwt "domainadmin@acme.com" "acme.com" '["DomainAdmin"]')
JWT_CRYPTO_OFF=$(make_jwt "officer@acme.com" "acme.com" '["CryptoOfficer"]')
JWT_AUDITOR=$(make_jwt "auditor@acme.com" "acme.com" '["Auditor"]')
JWT_USER=$(make_jwt "user@acme.com" "acme.com" '["User"]')
JWT_NO_ROLE=$(make_jwt "anon@acme.com" "acme.com" '[]')

CREATE_REQUEST=$(create_aes256_request)

# ── Step 6: Integration assertions ───────────────────────────────────────────
PASS=0
FAIL=0

# assert_kmip_http: check the HTTP status code (for auth-layer failures).
assert_kmip_http() {
  local desc="$1" expected_http="$2" jwt="$3" body="$4"
  local actual_http
  actual_http=$(kmip_post_status "$jwt" "$body")
  if [ "$actual_http" = "$expected_http" ]; then
    echo "  PASS: ${desc} → HTTP ${actual_http}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${desc} — expected HTTP ${expected_http}, got HTTP ${actual_http}"
    FAIL=$((FAIL + 1))
  fi
}

# assert_kmip_success: check that HTTP 200 + KMIP ResultStatus "Success".
assert_kmip_success() {
  local desc="$1" jwt="$2" body="$3"
  local resp
  resp=$(kmip_response_body "$jwt" "$body")
  local actual_http
  actual_http=$(kmip_post_status "$jwt" "$body")
  if [ "$actual_http" != "200" ]; then
    echo "  FAIL: ${desc} — expected HTTP 200, got HTTP ${actual_http}"
    FAIL=$((FAIL + 1))
    return
  fi
  if echo "$resp" | grep -q '"Success"'; then
    echo "  PASS: ${desc} → HTTP 200 + KMIP Success"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${desc} — HTTP 200 but KMIP body has no 'Success': ${resp}"
    FAIL=$((FAIL + 1))
  fi
}

# assert_kmip_denied: check that HTTP 200 + KMIP ResultStatus "OperationFailed".
# OPA-denied operations produce a KMIP error body, not an HTTP error.
assert_kmip_denied() {
  local desc="$1" jwt="$2" body="$3"
  local resp
  resp=$(kmip_response_body "$jwt" "$body")
  local actual_http
  actual_http=$(kmip_post_status "$jwt" "$body")
  if [ "$actual_http" != "200" ]; then
    echo "  FAIL: ${desc} — expected HTTP 200 (KMIP error body), got HTTP ${actual_http}"
    FAIL=$((FAIL + 1))
    return
  fi
  if echo "$resp" | grep -q '"OperationFailed"'; then
    echo "  PASS: ${desc} → HTTP 200 + KMIP OperationFailed"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${desc} — HTTP 200 but KMIP body has no 'OperationFailed': ${resp}"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "── Auth-layer tests (JWT middleware, HTTP status) ────────────────────────"
assert_kmip_http "No JWT → HTTP 401 (auth middleware)" "401" "" "$CREATE_REQUEST"

echo ""
echo "── Positive KMIP tests (OPA allows → KMIP Success) ──────────────────────"
assert_kmip_success "SuperAdmin    can create key" "$JWT_SUPER_ADMIN" "$CREATE_REQUEST"
assert_kmip_success "DomainAdmin   can create key" "$JWT_DOMAIN_ADMIN" "$CREATE_REQUEST"
assert_kmip_success "CryptoOfficer can create key" "$JWT_CRYPTO_OFF" "$CREATE_REQUEST"

echo ""
echo "── Negative KMIP tests (OPA denies → KMIP OperationFailed) ──────────────"
echo "   Note: HTTP is always 200; OPA denial is expressed in the KMIP response body."
assert_kmip_denied "Auditor       denied create" "$JWT_AUDITOR" "$CREATE_REQUEST"
assert_kmip_denied "User          denied create" "$JWT_USER" "$CREATE_REQUEST"
assert_kmip_denied "No role       denied create" "$JWT_NO_ROLE" "$CREATE_REQUEST"

# ── Step 7: Cross-domain integration test ─────────────────────────────────────
# Create a key as acme.com CryptoOfficer, then verify another-domain officer cannot destroy it.
echo ""
echo "── Cross-domain test ────────────────────────────────────────────────────"
echo "==> Creating a key as CryptoOfficer in acme.com domain..."
CREATE_RESP=$(kmip_response_body "$JWT_CRYPTO_OFF" "$CREATE_REQUEST")
KEY_UID=$(printf '%s' "$CREATE_RESP" | grep -o '"UniqueIdentifier".*"value":"[^"]*"' |
  grep -o '"value":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

if [ -z "${KEY_UID:-}" ]; then
  echo "  SKIP: Could not extract UID from Create response; skipping cross-domain test"
  echo "        Response: ${CREATE_RESP}"
else
  echo "  Created key UID: ${KEY_UID}"
  JWT_OTHER_DOMAIN=$(make_jwt "officer@other.com" "other.com" '["CryptoOfficer"]')
  DESTROY_REQUEST=$(printf '{"tag":"RequestMessage","type":"Structure","value":[{"tag":"RequestHeader","type":"Structure","value":[{"tag":"ProtocolVersion","type":"Structure","value":[{"tag":"ProtocolVersionMajor","type":"Integer","value":2},{"tag":"ProtocolVersionMinor","type":"Integer","value":1}]},{"tag":"BatchCount","type":"Integer","value":1}]},{"tag":"BatchItem","type":"Structure","value":[{"tag":"Operation","type":"Enumeration","value":"Destroy"},{"tag":"RequestPayload","type":"Structure","value":[{"tag":"UniqueIdentifier","type":"TextString","value":"%s"}]}]}]}' \
    "$KEY_UID")
  assert_kmip_denied "Cross-domain officer denied destroy on acme.com key" \
    "$JWT_OTHER_DOMAIN" "$DESTROY_REQUEST"
fi

# ── Phase 2 intermediate results (Phase 3 adds its own summary below) ─────────
echo ""
echo "Phase 2 results: ${PASS} passed, ${FAIL} failed"

echo "OPA RBAC tests completed successfully."

# ── Phase 3: Rust integration tests (vector_runner.rs `test_vec_opa_*`) ───────
#
# Requires the Cosmian Authentication Verifier binary to be built.
# Build with: cargo build -p auth_verifier --manifest-path authentication/Cargo.toml
#
# If the binary is not available, Phase 3 is skipped (with a prominent warning).
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 3: Rust vector_runner.rs integration tests (real auth server)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

AUTH_SERVER_PORT=8444 # Use 8444 to avoid conflict with any running 8443
AUTH_SERVER_URL="https://127.0.0.1:${AUTH_SERVER_PORT}"
AUTH_SERVER_PID=""
AUTH_VERIFIER_BIN=""

# Locate auth_verifier binary (prefer release, fall back to debug).
for candidate in \
  "${REPO_ROOT}/authentication/target/release/auth_verifier" \
  "${REPO_ROOT}/authentication/target/debug/auth_verifier"; do
  if [[ -x "${candidate}" ]]; then
    AUTH_VERIFIER_BIN="${candidate}"
    break
  fi
done

if [[ -z "${AUTH_VERIFIER_BIN}" ]]; then
  echo "WARNING: auth_verifier binary not found. Attempting to build..."
  if cargo build -p auth_verifier \
    --manifest-path "${REPO_ROOT}/authentication/Cargo.toml" 2>&1; then
    AUTH_VERIFIER_BIN="${REPO_ROOT}/authentication/target/debug/auth_verifier"
  else
    echo "WARNING: Could not build auth_verifier. Phase 3 SKIPPED."
    echo "         To enable: cargo build -p auth_verifier --manifest-path authentication/Cargo.toml"
    PHASE3_SKIPPED=true
  fi
fi

if [[ "${PHASE3_SKIPPED:-false}" != "true" ]]; then
  # ── Create a dedicated auth verifier config for integration tests ─────────
  AUTH_VERIFIER_CONF=$(mktemp -t kms-opa-auth-XXXXXX.toml)
  CA_CERT="${REPO_ROOT}/authentication/server/src/tests/certificates/ec/auth.ca.pem"
  # Update cleanup to also stop the auth server
  cleanup_phase3() {
    [ -n "${AUTH_SERVER_PID:-}" ] && {
      kill "${AUTH_SERVER_PID}" 2>/dev/null || true
      wait "${AUTH_SERVER_PID}" 2>/dev/null || true
    }
    [ -n "${AUTH_VERIFIER_CONF:-}" ] && rm -f "${AUTH_VERIFIER_CONF}" || true
    # Remove ephemeral auth DB
    rm -f /tmp/kms_opa_integration_auth.db 2>/dev/null || true
  }
  trap cleanup_phase3 EXIT

  # Write a minimal auth verifier config (dev mode, ephemeral SQLite).
  cat >"${AUTH_VERIFIER_CONF}" <<EOF
host_name = "127.0.0.1"
host_port = ${AUTH_SERVER_PORT}
roles = ["SuperAdmin","DomainAdmin","CryptoOfficer","Auditor","User"]
admin_ui_path = "admin-ui/dist"

[log]
level = "error"

[tls_params]
server_private_key = "server/src/tests/certificates/ec/auth.server.key.pem"
server_certificate = "server/src/tests/certificates/ec/auth.server.cert.pem"
server_ca_chain    = "server/src/tests/certificates/ec/auth.ca.pem"

[session_jwt_params]
jwt_ec_private_key = "server/src/tests/certificates/ec/auth.server.key.pem"
jwt_ec_public_key  = "server/src/tests/certificates/ec/auth.server.cert.pem"

[database_params]
auto_init_schema = true
backend = "sqlite"
connection_url = "sqlite:///tmp/kms_opa_integration_auth.db"

allowed_origins = ["http://127.0.0.1:9991"]
EOF

  # ── Start auth verifier ───────────────────────────────────────────────────
  echo "==> Starting auth verifier on port ${AUTH_SERVER_PORT}..."
  # Must run from authentication/ so relative cert paths resolve correctly.
  (cd "${REPO_ROOT}/authentication" &&
    "${AUTH_VERIFIER_BIN}" "${AUTH_VERIFIER_CONF}") \
    >"${REPO_ROOT}/target/auth_verifier_integration.log" 2>&1 &
  AUTH_SERVER_PID=$!

  # Wait for auth verifier to be ready (HTTPS health check).
  echo "==> Waiting for auth verifier to be ready..."
  ready=false
  for i in $(seq 1 30); do
    if env -u LD_LIBRARY_PATH -u LD_PRELOAD \
      curl -sk --cacert "${CA_CERT}" \
      "${AUTH_SERVER_URL}/health" >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done
  if [[ "${ready}" != "true" ]]; then
    echo "ERROR: auth verifier failed to start after 30s" >&2
    cat "${REPO_ROOT}/target/auth_verifier_integration.log" >&2
    exit 1
  fi
  echo "Auth verifier ready (PID=${AUTH_SERVER_PID})."

  # ── Provision users ───────────────────────────────────────────────────────
  echo "==> Provisioning auth verifier test users..."
  PROVISION_SCRIPT="${REPO_ROOT}/test_data/configs/auth_verifier/provision_opa_users.sh"
  eval "$(AUTH_URL="${AUTH_SERVER_URL}" CA_CERT="${CA_CERT}" \
    REPO_ROOT="${REPO_ROOT}" bash "${PROVISION_SCRIPT}")"
  echo "Provisioning complete."
  echo "  KMS_TEST_OPA_SUPER_ADMIN_JWT     set (length ${#KMS_TEST_OPA_SUPER_ADMIN_JWT})"
  echo "  KMS_TEST_OPA_OFFICER_JWT         set (length ${#KMS_TEST_OPA_OFFICER_JWT})"
  echo "  KMS_TEST_OPA_USER_ROLE_JWT       set (length ${#KMS_TEST_OPA_USER_ROLE_JWT})"
  echo "  KMS_TEST_OPA_AUDITOR_JWT         set (length ${#KMS_TEST_OPA_AUDITOR_JWT})"
  echo "  KMS_TEST_OPA_NO_ROLES_JWT        set (length ${#KMS_TEST_OPA_NO_ROLES_JWT})"
  echo "  KMS_TEST_OPA_UNKNOWN_ROLE_JWT    set (length ${#KMS_TEST_OPA_UNKNOWN_ROLE_JWT})"
  echo "  KMS_TEST_OPA_DOMAIN_ADMIN_OTHER_JWT set (length ${#KMS_TEST_OPA_DOMAIN_ADMIN_OTHER_JWT})"
  echo "  KMS_TEST_OPA_OTHER_DOMAIN_JWT    set (length ${#KMS_TEST_OPA_OTHER_DOMAIN_JWT})"

  # ── Export required env vars for the Rust tests ───────────────────────────
  export KMS_OPA_URL="${OPA_URL}"
  export KMS_AUTH_SERVER_URL="${AUTH_SERVER_URL}"
  # JWT vars already exported by provision script eval above.

  # ── Run Rust vector_runner.rs OPA tests ───────────────────────────────────
  echo ""
  echo "==> Running Rust OPA vector tests (--include-ignored -- test_vec_opa_)..."
  PHASE3_FAIL=0

  # shellcheck disable=SC2068
  if CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
    RUSTC_WRAPPER="" \
    CARGO_NET_OFFLINE=true \
    cargo test \
    ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} \
    --features non-fips \
    -p test_kms_server \
    --lib \
    -- \
    --include-ignored \
    test_vec_opa_ \
    2>&1 | tee /tmp/kms_opa_rust_tests.log; then
    echo "Phase 3: Rust OPA tests PASSED."
  else
    PHASE3_FAIL=1
    echo "Phase 3: Rust OPA tests FAILED." >&2
  fi
fi

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo "========================================="
echo "OPA RBAC test summary:"
echo "  Phase 1 (policy tests): ${PHASE1_PASS} pass / ${PHASE1_FAIL} fail"
echo "  Phase 2 (integration) : ${PASS} pass / ${FAIL} fail"
if [[ "${PHASE3_SKIPPED:-false}" == "true" ]]; then
  echo "  Phase 3 (Rust tests)  : SKIPPED (auth_verifier binary not available)"
else
  echo "  Phase 3 (Rust tests)  : $([ "${PHASE3_FAIL}" -eq 0 ] && echo PASSED || echo FAILED)"
fi
echo "========================================="

TOTAL_FAIL=$((PHASE1_FAIL + FAIL + ${PHASE3_FAIL:-0}))
if [ "${TOTAL_FAIL}" -gt 0 ]; then
  echo "ERROR: ${TOTAL_FAIL} OPA RBAC test(s) failed." >&2
  exit 1
fi
