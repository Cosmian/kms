#!/usr/bin/env bash
# =============================================================================
# Verify the RBAC stack: Keycloak (IdP) -> Cosmian KMS -> OPA.
#
# 1. Gets an access token for every sample user of the Keycloak realm `kms` and
#    checks the claims the KMS relies on (iss, aud, email, roles, as_rid).
# 2. Sends KMIP requests (JSON TTLV) to the KMS with those tokens. Every outcome
#    is compared with the expected decision of the documented role matrix and
#    with a direct query to OPA (POST /v1/data/kms/allow) carrying the input the
#    KMS sends.
#
# In `exclusive` mode OPA is the only authority: an allowed non-owner access can
# only come from the policy in test_data/opa/kms.rego. Create, Get, GetAttributes
# and Activate are checked end to end. Encrypt and Revoke on a key owned by someone
# else are authorized by the native KMS grants, not by OPA, so they are only checked
# against OPA (section 4).
#
# Usage:        ./verify.sh          (after `docker compose up -d --wait`)
# Requires:     bash 4+, curl, jq, base64
# Environment:  DEMO_USER_PASSWORD  password of the sample users (default: read from ./.env)
#               KEYCLOAK_URL, KMS_URL, OPA_URL  override the published endpoints (the expected
#               token issuer stays https://keycloak.localhost:8443/realms/kms: KC_HOSTNAME and the KMS fixture pin it)
# Exit status:  0 when everything agrees, 1 otherwise
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_FILE="${SCRIPT_DIR}/../../test_data/certificates/client_server/ca/ca.crt"
KEYCLOAK_URL="${KEYCLOAK_URL:-https://keycloak.localhost:8443}"
KMS_URL="${KMS_URL:-https://localhost:9998}"
OPA_URL="${OPA_URL:-http://localhost:8181}"
REALM="kms"
# Pinned by KC_HOSTNAME in docker-compose.yml and by jwt_auth_provider in the KMS fixture, whatever KEYCLOAK_URL is
ISSUER="https://keycloak.localhost:8443/realms/${REALM}"
CLIENT_ID="kms-demo"
AUDIENCE="cosmian-kms"
READY_RETRIES=60

# email|role (Keycloak group, "-" when the user has none)|domain (as_rid claim)
SAMPLE_USERS=(
  "superadmin@acme.com|SuperAdmin|acme.com"
  "admin@acme.com|DomainAdmin|acme.com"
  "officer@acme.com|CryptoOfficer|acme.com"
  "auditor@acme.com|Auditor|acme.com"
  "user@acme.com|User|acme.com"
  "norole@acme.com|-|acme.com"
  "officer@globex.com|CryptoOfficer|globex.com"
  "user@globex.com|User|globex.com"
)

OPERATIONS=(Create Get GetAttributes Activate)
POLICY_ONLY_OPERATIONS=(Encrypt Revoke)
declare -A OPA_OPERATION=(
  [Create]=create
  [Get]=get
  [GetAttributes]=get_attributes
  [Activate]=activate
  [Encrypt]=encrypt
  [Revoke]=revoke
)
# Roles allowed to run each operation on a key of their own domain they do not
# own. Mirrors test_data/opa/kms.rego; SuperAdmin is also allowed across domains.
# Auditor is deliberately absent from Get: it is read-only on metadata (GetAttributes,
# Locate) and must not be able to read key material.
declare -A ALLOWED_ROLES=(
  [Create]="SuperAdmin DomainAdmin CryptoOfficer"
  [Get]="SuperAdmin DomainAdmin CryptoOfficer"
  [GetAttributes]="SuperAdmin DomainAdmin CryptoOfficer Auditor User"
  [Activate]="SuperAdmin DomainAdmin CryptoOfficer"
  [Encrypt]="SuperAdmin DomainAdmin User"
  [Revoke]="SuperAdmin DomainAdmin CryptoOfficer"
)

declare -A ROLE DOMAIN TOKEN ACTIVATE_KEY
ACME_USERS=()
GLOBEX_USERS=()
FAILURES=()
CASES=0
KMS_STATUS="" KMS_REASON="" KMS_UID="" NEW_UID=""
KEY_BY_ADMIN="" KEY_BY_OFFICER="" KEY_GLOBEX=""

die() {
  echo "ERROR: $*" >&2
  exit 1
}

section() {
  printf '\n%s\n' "$*"
}

# Poll an HTTP endpoint with curl's own bounded retry (no fixed sleep).
wait_until_ready() { # name url [curl options...]
  local name=$1 url=$2
  shift 2
  echo "Waiting for ${name} (${url})"
  curl -fs -o /dev/null --max-time 5 --retry "$READY_RETRIES" --retry-delay 2 --retry-all-errors "$@" "$url" ||
    die "${name} is not ready at ${url} (is the stack up? does keycloak.localhost resolve to 127.0.0.1?)"
}

get_token() { # email
  # -j: no trailing newline, which would otherwise become part of the password.
  jq -jn --arg client "$CLIENT_ID" --arg user "$1" --arg pass "$DEMO_USER_PASSWORD" \
    '"grant_type=password&client_id=\($client | @uri)&username=\($user | @uri)&password=\($pass | @uri)"' |
    curl -fsS --cacert "$CA_FILE" --max-time 15 -X POST \
      "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" --data-binary @- |
    jq -r '.access_token'
}

decode_claims() { # jwt
  local payload=${1#*.}
  payload=${payload%%.*}
  payload=${payload//-/+}
  payload=${payload//_//}
  while ((${#payload} % 4 != 0)); do
    payload+="="
  done
  printf '%s' "$payload" | base64 -d
}

# KMIP request body for an operation; the payload mirrors .mise/scripts/test/test_opa_rbac.sh.
payload_for() { # operation uid
  jq -cn --arg op "$1" --arg uid "$2" '
    {tag: "UniqueIdentifier", type: "TextString", value: $uid} as $id
    | if $op == "Create" then
        [{tag: "ObjectType", type: "Enumeration", value: "SymmetricKey"},
         {tag: "Attributes", type: "Structure", value: [
           {tag: "CryptographicAlgorithm", type: "Enumeration", value: "AES"},
           {tag: "CryptographicLength", type: "Integer", value: 256},
           {tag: "CryptographicUsageMask", type: "Integer", value: 2108}]}]
      elif $op == "Encrypt" then
        [$id,
         {tag: "CryptographicParameters", type: "Structure", value: [
           {tag: "CryptographicAlgorithm", type: "Enumeration", value: "AES"},
           {tag: "BlockCipherMode", type: "Enumeration", value: "GCM"}]},
         {tag: "Data", type: "ByteString", value: "48656c6c6f"}]
      else [$id] end'
}

kmip_request() { # operation uid
  jq -cn --arg op "$1" --argjson payload "$(payload_for "$1" "$2")" '
    {tag: "RequestMessage", type: "Structure", value: [
      {tag: "RequestHeader", type: "Structure", value: [
        {tag: "ProtocolVersion", type: "Structure", value: [
          {tag: "ProtocolVersionMajor", type: "Integer", value: 2},
          {tag: "ProtocolVersionMinor", type: "Integer", value: 1}]},
        {tag: "BatchCount", type: "Integer", value: 1}]},
      {tag: "BatchItem", type: "Structure", value: [
        {tag: "Operation", type: "Enumeration", value: $op},
        {tag: "RequestPayload", type: "Structure", value: $payload}]}]}'
}

# Send one KMIP operation. Sets KMS_STATUS, KMS_REASON and KMS_UID. A policy denial is
# an HTTP 200 whose BatchItem has ResultStatus OperationFailed.
kmip_call() { # token operation uid
  local response
  response=$(kmip_request "$2" "$3" |
    curl -fsS --cacert "$CA_FILE" --max-time 30 -X POST "${KMS_URL}/kmip/2_1" \
      -H "Authorization: Bearer $1" -H 'Content-Type: application/json' --data-binary @-)
  KMS_STATUS=$(jq -r '[.. | objects | select(.tag == "ResultStatus") | .value][0] // "none"' <<<"$response")
  KMS_REASON=$(jq -r '[.. | objects | select(.tag == "ResultReason") | .value][0] // ""' <<<"$response")
  KMS_UID=$(jq -r '[.. | objects | select(.tag == "UniqueIdentifier") | .value][0] // ""' <<<"$response")
}

# Ask OPA directly, with the input document the KMS builds for the same request.
opa_decision() { # email operation uid object_domain is_owner
  # Object-less operations (Create) reach OPA with the wildcard UID "*".
  jq -cn --arg user "$1" --arg domain "${DOMAIN[$1]}" --arg role "${ROLE[$1]}" \
    --arg op "${OPA_OPERATION[$2]}" --arg uid "${3:-*}" --arg object_domain "$4" --argjson owner "$5" '
    {input: {user: $user, user_domain: $domain, roles: (if $role == "-" then [] else [$role] end),
             operation: $op, object_uid: $uid, object_domain: $object_domain, is_owner: $owner}}' |
    curl -fsS --max-time 10 -X POST "${OPA_URL}/v1/data/kms/allow" \
      -H 'Content-Type: application/json' --data-binary @- |
    jq -r 'if .result == true then "allow" else "deny" end'
}

expected_decision() { # role operation user_domain object_domain
  if [[ $3 != "$4" && $1 != SuperAdmin ]]; then
    echo deny
  elif [[ " ${ALLOWED_ROLES[$2]} " == *" $1 "* ]]; then
    echo allow
  else
    echo deny
  fi
}

create_key() { # email activate(true|false)
  kmip_call "${TOKEN[$1]}" Create ""
  [[ $KMS_STATUS == Success ]] || die "$1 could not create a key: ${KMS_STATUS} ${KMS_REASON}"
  NEW_UID=$KMS_UID
  if [[ $2 == true ]]; then
    # A new key is PreActive and Encrypt requires an Active key: its owner activates it.
    kmip_call "${TOKEN[$1]}" Activate "$NEW_UID"
    [[ $KMS_STATUS == Success ]] || die "$1 could not activate ${NEW_UID}: ${KMS_STATUS} ${KMS_REASON}"
  fi
}

# Keys used as targets are never owned by the caller, because an owner is always allowed.
key_owner_for() { # caller
  if [[ $1 == admin@acme.com ]]; then
    echo officer@acme.com
  else
    echo admin@acme.com
  fi
}

shared_key_for() { # caller
  if [[ $1 == admin@acme.com ]]; then
    echo "$KEY_BY_OFFICER"
  else
    echo "$KEY_BY_ADMIN"
  fi
}

# Run one operation and print the KMS decision, or MISMATCH when the KMS, the expected
# role matrix and OPA do not all agree.
run_case() { # email operation uid object_domain is_owner
  local email=$1 op=$2 uid=$3 object_domain=$4 owner=$5
  local expected kms=deny opa
  if [[ $owner == true ]]; then
    expected=allow
  else
    expected=$(expected_decision "${ROLE[$email]}" "$op" "${DOMAIN[$email]}" "$object_domain")
  fi
  kmip_call "${TOKEN[$email]}" "$op" "$uid"
  if [[ $KMS_STATUS == Success ]]; then
    kms=allow
  fi
  opa=$(opa_decision "$email" "$op" "$uid" "$object_domain" "$owner")
  CASES=$((CASES + 1))
  if [[ $kms == "$expected" && $opa == "$expected" ]]; then
    printf '%-15s' "$kms"
  else
    printf '%-15s' MISMATCH
    FAILURES+=("${email} ${op} on ${uid:-n/a}: expected=${expected} opa=${opa} kms=${kms} (${KMS_STATUS} ${KMS_REASON})")
  fi
}

# Compare OPA alone with the expected role matrix (no KMS involved).
policy_case() { # email operation object_domain
  local expected opa
  expected=$(expected_decision "${ROLE[$1]}" "$2" "${DOMAIN[$1]}" "$3")
  opa=$(opa_decision "$1" "$2" "$KEY_BY_ADMIN" "$3" false)
  CASES=$((CASES + 1))
  if [[ $opa == "$expected" ]]; then
    printf '%-15s' "$opa"
  else
    printf '%-15s' MISMATCH
    FAILURES+=("${1} ${2} (policy only): expected=${expected} opa=${opa}")
  fi
}

for tool in curl jq base64; do
  command -v "$tool" >/dev/null || die "${tool} is required"
done
[[ -f $CA_FILE ]] || die "missing ${CA_FILE}: run 'git submodule update --init test_data'"
if [[ -z ${DEMO_USER_PASSWORD:-} && -f "${SCRIPT_DIR}/.env" ]]; then
  DEMO_USER_PASSWORD="$(sed -n 's/^DEMO_USER_PASSWORD=//p' "${SCRIPT_DIR}/.env" | tail -n 1)"
fi
[[ -n ${DEMO_USER_PASSWORD:-} ]] || die "DEMO_USER_PASSWORD is not set (see .env.example)"

wait_until_ready Keycloak "${KEYCLOAK_URL}/realms/${REALM}/.well-known/openid-configuration" --cacert "$CA_FILE"
wait_until_ready OPA "${OPA_URL}/health"
wait_until_ready "Cosmian KMS" "${KMS_URL}/health" --cacert "$CA_FILE"

section "Sample users (claims decoded from the Keycloak access tokens)"
printf '  %-38s%-16s%-14s%s\n' USER ROLES AS_RID AUDIENCE
for entry in "${SAMPLE_USERS[@]}"; do
  IFS='|' read -r email role domain <<<"$entry"
  ROLE[$email]=$role
  DOMAIN[$email]=$domain
  TOKEN[$email]=$(get_token "$email") || die "no token for ${email} (wrong DEMO_USER_PASSWORD, or the realm was imported with another one: run 'docker compose down -v')"
  claims=$(decode_claims "${TOKEN[$email]}")
  claims_ok=$(jq -r --arg iss "$ISSUER" --arg email "$email" \
    --arg role "$role" --arg domain "$domain" --arg aud "$AUDIENCE" '
    [.iss == $iss, .email == $email, ((.aud | if type == "array" then . else [.] end) | index($aud) != null),
     ((.roles // ["-"]) == [$role]), .as_rid == $domain] | all' <<<"$claims")
  [[ $claims_ok == true ]] || die "unexpected claims for ${email}: ${claims}"
  printf '  %-38s%-16s%-14s%s\n' "$email" "$role" "$domain" "$AUDIENCE"
  if [[ $domain == acme.com ]]; then
    ACME_USERS+=("$email")
  else
    GLOBEX_USERS+=("$email")
  fi
done

echo
echo "Preparing the target keys"
create_key admin@acme.com true && KEY_BY_ADMIN=$NEW_UID
create_key officer@acme.com true && KEY_BY_OFFICER=$NEW_UID
create_key officer@globex.com true && KEY_GLOBEX=$NEW_UID
# One PreActive key per caller, so that every Activate case starts from the same state.
for email in "${ACME_USERS[@]}"; do
  create_key "$(key_owner_for "$email")" false
  ACTIVATE_KEY[$email]=$NEW_UID
done

section "1. Same domain: acme.com callers on a key owned by another acme.com user"
printf '  %-38s' USER
printf '%-15s' "${OPERATIONS[@]}"
echo
for email in "${ACME_USERS[@]}"; do
  printf '  %-38s' "${email} (${ROLE[$email]})"
  for op in "${OPERATIONS[@]}"; do
    uid=$(shared_key_for "$email")
    if [[ $op == Create ]]; then
      uid=""
    elif [[ $op == Activate ]]; then
      uid=${ACTIVATE_KEY[$email]}
    fi
    run_case "$email" "$op" "$uid" acme.com false
  done
  echo
done

section "2. Cross domain: only SuperAdmin may act on the other domain"
printf '  %-38s%-15s%-15s\n' "USER (target key)" Get GetAttributes
for email in "${ACME_USERS[@]}"; do
  printf '  %-38s' "${email} (globex.com key)"
  for op in Get GetAttributes; do
    run_case "$email" "$op" "$KEY_GLOBEX" globex.com false
  done
  echo
done
for email in "${GLOBEX_USERS[@]}"; do
  printf '  %-38s' "${email} (acme.com key)"
  for op in Get GetAttributes; do
    run_case "$email" "$op" "$KEY_BY_ADMIN" acme.com false
  done
  echo
done

section "3. Ownership: the owner of a key is always allowed, whatever its role"
printf '  %-38s' "officer@acme.com Encrypt (own key)"
run_case officer@acme.com Encrypt "$KEY_BY_OFFICER" acme.com true
echo " (Encrypt is not in the CryptoOfficer role: only ownership allows it)"

section "4. Policy only (OPA queried directly): the KMS authorizes these on keys of others with native grants"
printf '  %-38s' USER
printf '%-15s' "${POLICY_ONLY_OPERATIONS[@]}"
echo
for email in "${ACME_USERS[@]}"; do
  printf '  %-38s' "${email} (${ROLE[$email]})"
  for op in "${POLICY_ONLY_OPERATIONS[@]}"; do
    policy_case "$email" "$op" acme.com
  done
  echo
done

echo
if ((${#FAILURES[@]} == 0)); then
  echo "OK: ${CASES} checks, the KMS, the expected role matrix and OPA agree."
else
  echo "FAILED: ${#FAILURES[@]} of ${CASES} checks disagree:" >&2
  printf '  %s\n' "${FAILURES[@]}" >&2
  exit 1
fi
