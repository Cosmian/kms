#!/usr/bin/env bash
# SOPS interoperability tests for the KMS Vault Transit and OpenPGP sources.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../../common.sh"
REPO_ROOT="$(get_repo_root)"
source "${REPO_ROOT}/.mise/lib/kms_build.sh"
source "${REPO_ROOT}/.mise/lib/pkcs11_helpers.sh"
source "${REPO_ROOT}/.mise/lib/spire_test.sh"

init_build_env "$@"
setup_test_logging
require_cmd sops
require_cmd gpg
require_cmd gnupg-pkcs11-scd
require_cmd curl
require_cmd python3

TEST_DATA="${REPO_ROOT}/test_data/spire"
WORK_DIR="$(mktemp -d /tmp/kms-sops-XXXXXX)"
AUTH_PID=""
KMS_PID=""
GNUPGHOME="${WORK_DIR}/gnupg"
export GNUPGHOME
mkdir -m 700 "${GNUPGHOME}"

cleanup() {
  local rc=$?
  if [ "${rc}" -ne 0 ]; then
    [ -s "${WORK_DIR}/auth.log" ] && tail -n 40 "${WORK_DIR}/auth.log" >&2 || true
    [ -s "${WORK_DIR}/kms.log" ] && tail -n 40 "${WORK_DIR}/kms.log" >&2 || true
  fi
  [ -n "${KMS_PID}" ] && kill "${KMS_PID}" 2>/dev/null || true
  [ -n "${AUTH_PID}" ] && kill "${AUTH_PID}" 2>/dev/null || true
  rm -rf "${WORK_DIR}"
  exit "${rc}"
}
trap cleanup EXIT

spire_ensure_certs "${TEST_DATA}"
AUTH_BIN="$(spire_build_auth_verifier "${REPO_ROOT}")"
kms_build_server "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
kms_build_cli "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
kms_build_all

cp "${TEST_DATA}/config/auth_verifier.toml" "${WORK_DIR}/auth.toml"
cp "${TEST_DATA}/config/kms.toml" "${WORK_DIR}/kms.toml"
sed -i.bak \
  -e "s|sqlite:///tmp/auth-verifier-spire-test.db|sqlite://${WORK_DIR}/auth.db|" \
  "${WORK_DIR}/auth.toml"
sed -i.bak \
  -e "s|/tmp/kms-spire-test|${WORK_DIR}/kms-data|" \
  "${WORK_DIR}/kms.toml"
rm -f "${WORK_DIR}"/*.bak
mkdir -p "${WORK_DIR}/kms-data"

"${AUTH_BIN}" "${WORK_DIR}/auth.toml" >"${WORK_DIR}/auth.log" 2>&1 &
AUTH_PID=$!
wait_for_port 127.0.0.1 8443 60
"$(get_kms_bin)" --config "${WORK_DIR}/kms.toml" >"${WORK_DIR}/kms.log" 2>&1 &
KMS_PID=$!
wait_for_port 127.0.0.1 9998 120

CKMS_CONF="${WORK_DIR}/ckms.toml"
cp "${REPO_ROOT}/test_data/configs/client/default.toml" "${CKMS_CONF}"
sed -i.bak 's|http://localhost:9998|https://localhost:9998|' "${CKMS_CONF}"
rm -f "${CKMS_CONF}.bak"
ckms_approle() {
  "$(get_ckms_bin)" --conf-path "${CKMS_CONF}" vault approle "$@" \
    --auth-verifier-url "https://localhost:8443" \
    --admin-user admin --admin-password change_me --accept-invalid-certs
}

ROLE_NAME="sops-test"
ckms_approle create-role "${ROLE_NAME}" --token-ttl 3600 --token-policies default >/dev/null
ROLE_ID="$(ckms_approle get-role-id "${ROLE_NAME}" | tr -d '[:space:]')"
SECRET_ID="$(ckms_approle generate-secret-id "${ROLE_NAME}" | awk '/^secret_id:/{print $2}')"
LOGIN="$(curl -sf --insecure -X POST \
  -d "{\"role_id\":\"${ROLE_ID}\",\"secret_id\":\"${SECRET_ID}\"}" \
  https://localhost:9998/v1/auth/approle/login)"
VAULT_TOKEN="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["auth"]["client_token"])' "${LOGIN}")"
export VAULT_ADDR="https://localhost:9998" VAULT_TOKEN

kms_transit() {
  local method="$1" path="$2" body="${3:-}"
  curl -sf --insecure -X "${method}" -H "X-Vault-Token: ${VAULT_TOKEN}" \
    ${body:+-d "${body}"} "${VAULT_ADDR}/v1/transit/${path}"
}

print_header "SOPS Vault Transit source"
kms_transit POST "keys/sops-v1" '{"type":"aes256-gcm96"}' >/dev/null
kms_transit POST "keys/sops-v2" '{"type":"aes256-gcm96"}' >/dev/null
mkdir -p "${WORK_DIR}/transit"
cat >"${WORK_DIR}/transit/.sops.yaml" <<EOF
creation_rules:
  - path_regex: \\.yaml$
    hc_vault_transit_uri: https://localhost:9998/v1/transit/keys/sops-v1
EOF
printf 'database:\n  password: transit-secret\n' >"${WORK_DIR}/transit/secrets.yaml"
(
  cd "${WORK_DIR}/transit"
  SOPS_CONFIG="${PWD}/.sops.yaml" sops -e --in-place secrets.yaml
  grep -q 'sops:' secrets.yaml
  test "$(SOPS_CONFIG="${PWD}/.sops.yaml" sops -d secrets.yaml | grep 'password:' | tr -d '\r')" = '  password: transit-secret'
  cat >.sops.yaml <<EOF2
creation_rules:
  - path_regex: \\.yaml$
    hc_vault_transit_uri: https://localhost:9998/v1/transit/keys/sops-v2
EOF2
  SOPS_CONFIG="${PWD}/.sops.yaml" sops updatekeys --yes secrets.yaml
  test "$(SOPS_CONFIG="${PWD}/.sops.yaml" sops -d secrets.yaml | grep 'password:' | tr -d '\r')" = '  password: transit-secret'
)

print_header "SOPS OpenPGP source"
mkdir -p "${WORK_DIR}/pgp"
PKCS11_LIB="$(get_cosmian_pkcs11_lib)"
COSMIAN_KMS_CLI_CONF="${CKMS_CONF}"
export COSMIAN_KMS_CLI_CONF
PGP_RSA_JSON="$(
  COSMIAN_KMS_CLI_FORMAT=json "$(get_ckms_bin)" rsa keys create \
    --size_in_bits 2048 --tag gnupg-card
)"
PGP_PUBLIC_KEY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["public_key_unique_identifier"])' "${PGP_RSA_JSON}")"
"$(get_ckms_bin)" certificates certify \
  --public-key-id-to-certify "${PGP_PUBLIC_KEY_ID}" \
  --subject-name "CN=SOPS PKCS#11 CI" \
  --days 1095 \
  --tag gnupg-card >/dev/null
cat >"${GNUPGHOME}/gnupg-pkcs11-scd.conf" <<EOF
providers cosmian
provider-cosmian-library ${PKCS11_LIB}
provider-cosmian-allow-protected-auth
EOF
cat >"${GNUPGHOME}/gpg-agent.conf" <<EOF
scdaemon-program $(command -v gnupg-pkcs11-scd)
EOF
gpgconf --kill gpg-agent || true
gpg-connect-agent 'scd learn --force' /bye
gpg --card-status >/dev/null
cat >"${WORK_DIR}/pgp/master.batch" <<'EOF'
Key-Type: RSA
Key-Length: 2048
Key-Usage: cert
Name-Real: SOPS PKCS#11 CI
Name-Email: sops-pkcs11-ci@example.com
Expire-Date: 0
%no-protection
%commit
EOF
gpg --batch --generate-key "${WORK_DIR}/pgp/master.batch"
PGP_MASTER_FINGERPRINT="$(gpg --batch --with-colons --list-secret-keys sops-pkcs11-ci@example.com | awk -F: '$1 == "fpr" {print $10; exit}')"
gpg --batch --yes --edit-key "${PGP_MASTER_FINGERPRINT}" addcardkey 5
gpg --batch --list-secret-keys "${PGP_MASTER_FINGERPRINT}" | grep -q '>'
cat >"${WORK_DIR}/pgp/.sops.yaml" <<EOF
creation_rules:
  - path_regex: \\.yaml$
    pgp: ${PGP_MASTER_FINGERPRINT}
EOF
printf 'database:\n  password: pgp-secret\n' >"${WORK_DIR}/pgp/secrets.yaml"
(
  cd "${WORK_DIR}/pgp"
  SOPS_CONFIG="${PWD}/.sops.yaml" sops -e --in-place secrets.yaml
  grep -q 'sops:' secrets.yaml
  test "$(SOPS_CONFIG="${PWD}/.sops.yaml" sops -d secrets.yaml | grep 'password:' | tr -d '\r')" = '  password: pgp-secret'
  SOPS_CONFIG="${PWD}/.sops.yaml" sops updatekeys --yes secrets.yaml
  test "$(SOPS_CONFIG="${PWD}/.sops.yaml" sops -d secrets.yaml | grep 'password:' | tr -d '\r')" = '  password: pgp-secret'
)

print_success "SOPS Vault Transit and OpenPGP round-trips passed"
