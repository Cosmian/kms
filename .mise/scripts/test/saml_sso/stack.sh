#!/usr/bin/env bash
# Local SAML single sign-on stack for manually testing the KMS Web UI SAML login:
# Keycloak (IdP) + Auth Verifier SAML build (SP) + nginx (single public origin).
# The KMS itself runs on the host from the current checkout (see `up` output).
#
# Usage: stack.sh up|down|logs
#
# Env:
#   AUTH_VERIFIER_IMAGE  Auth Verifier SAML image (default: newest local cosmian-auth-verifier:*-saml)
#   KEYCLOAK_IMAGE       Keycloak image (default: quay.io/keycloak/keycloak:26.4)
#   NGINX_IMAGE          nginx image (default: nginx:1.27-alpine)
#   SAML_SSO_DIR         work dir for keys and configs (default: /tmp/kms-saml-sso)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
# shellcheck source=.mise/lib/common.sh
source "${REPO_ROOT}/.mise/lib/common.sh"

export SAML_SSO_DIR="${SAML_SSO_DIR:-/tmp/kms-saml-sso}"
export KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.4}"
export NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
PUBLIC_ORIGIN="https://localhost:8443"
SAML_REALM="kms-saml"
AV_URL="https://127.0.0.1:8444"
IDP_METADATA_URL="https://localhost:9443/realms/demo/protocol/saml/descriptor"
MARKER="${SAML_SSO_DIR}/.kms-saml-sso"

compose() {
  # `down` and `logs` do not need the real image; Compose only requires the variable to be set.
  AUTH_VERIFIER_IMAGE="${AUTH_VERIFIER_IMAGE:-cosmian-auth-verifier:unset}" \
    docker compose -p kms-saml-sso -f "${SCRIPT_DIR}/docker-compose.yml" "$@"
}

# Newest local Auth Verifier image built with the `saml` feature.
resolve_auth_verifier_image() {
  if [ -n "${AUTH_VERIFIER_IMAGE:-}" ]; then
    return
  fi
  AUTH_VERIFIER_IMAGE=$(docker images --format '{{.Repository}}:{{.Tag}}' cosmian-auth-verifier | grep -- '-saml$' | head -n1 || true)
  [ -n "${AUTH_VERIFIER_IMAGE}" ] ||
    print_error "No cosmian-auth-verifier:*-saml image found. Build it from the authentication repo (branch feat/saml-integration): 'mise run docker:load -- --variant saml', or set AUTH_VERIFIER_IMAGE."
  export AUTH_VERIFIER_IMAGE
}

# Fresh work dir with throw-away TLS and SAML SP keys (refuses to wipe a dir it did not create).
generate_keys() {
  if [ -d "${SAML_SSO_DIR}" ] && [ -n "$(ls -A "${SAML_SSO_DIR}")" ] && [ ! -f "${MARKER}" ]; then
    print_error "${SAML_SSO_DIR} is not empty and was not created by this script"
  fi
  rm -rf "${SAML_SSO_DIR}"
  mkdir -p "${SAML_SSO_DIR}"
  touch "${MARKER}"
  # EC P-256: the Auth Verifier also signs its session JWTs (ES256) with this TLS key.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 7 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:auth-verifier,IP:127.0.0.1" \
    -keyout "${SAML_SSO_DIR}/tls.key.pem" -out "${SAML_SSO_DIR}/tls.cert.pem" 2>/dev/null
  openssl req -x509 -newkey rsa:3072 -sha256 -days 7 -nodes -subj "/CN=kms-saml-sso SP" \
    -keyout "${SAML_SSO_DIR}/saml-sp.key.pem" -out "${SAML_SSO_DIR}/saml-sp.cert.pem" 2>/dev/null
}

# Auth Verifier, Keycloak realm and KMS configuration files.
write_configs() {
  cat >"${SAML_SSO_DIR}/auth_verifier.toml" <<TOML
host_name = "0.0.0.0"
host_port = 8444
admin_ui_path = "/srv/admin-ui"
roles = ["SuperAdmin", "DomainAdmin", "CryptoOfficer", "Auditor", "User"]

[tls_params]
server_private_key = "/conf/tls.key.pem"
server_certificate = "/conf/tls.cert.pem"
server_ca_chain = "/conf/tls.cert.pem"

[database_params]
backend = "sqlite"
connection_url = "sqlite::memory:"

[saml_sp_params]
saml_rsa_private_key = "/conf/saml-sp.key.pem"
saml_certificate = "/conf/saml-sp.cert.pem"
TOML

  SP_CERT=$(grep -v -- '-----' "${SAML_SSO_DIR}/saml-sp.cert.pem" | tr -d '\n') \
    PUBLIC_ORIGIN="${PUBLIC_ORIGIN}" SAML_REALM="${SAML_REALM}" \
    envsubst "\${PUBLIC_ORIGIN} \${SAML_REALM} \${SP_CERT}" \
    <"${SCRIPT_DIR}/keycloak-realm.json.tmpl" >"${SAML_SSO_DIR}/keycloak-realm.json"

  cat >"${SAML_SSO_DIR}/kms.toml" <<TOML
kms_public_url = "${PUBLIC_ORIGIN}"

[http]
port = 9998
hostname = "0.0.0.0"

[db]
database_type = "sqlite"
sqlite_path = "${SAML_SSO_DIR}/kms-data"

[auth_verifier]
auth_verifier_url = "${AV_URL}"
auth_verifier_saml_realm = "${SAML_REALM}"
auth_verifier_accept_invalid_certs = true   # self-signed local certificate, dev only

[ui_config]
ui_index_html_folder = "${REPO_ROOT}/ui/dist"
TOML
  # The containers run as uid 1000 and must read these throw-away files.
  chmod 755 "${SAML_SSO_DIR}"
  chmod 644 "${SAML_SSO_DIR}"/*.pem "${SAML_SSO_DIR}"/*.toml "${SAML_SSO_DIR}"/*.json
}

# Wait until an HTTPS endpoint answers successfully.
wait_for_url() {
  local name="$1" url="$2" tries="${3:-90}" i
  print_status "Waiting for ${name} (${url})..."
  for i in $(seq 1 "${tries}"); do
    if curl -ksf -o /dev/null "${url}"; then
      return 0
    fi
    sleep 2
  done
  compose logs --tail 50 >&2 || true
  print_error "${name} not ready after $((tries * 2)) s"
}

# Create the SAML realm on the Auth Verifier from the Keycloak metadata (dev super-admin admin/change_me).
seed_saml_realm() {
  local jar="${SAML_SSO_DIR}/admin.cookies" code
  curl -ksSf -o "${SAML_SSO_DIR}/idp-metadata.xml" "${IDP_METADATA_URL}"
  code=$(curl -ks -o /dev/null -w '%{http_code}' -c "${jar}" -X POST \
    -H "Authorization: Basic $(printf 'admin:change_me' | base64)" \
    -H "Content-Type: application/json" -d '{}' "${AV_URL}/login?realm=_")
  [ "${code}" = 200 ] || print_error "Auth Verifier admin login returned ${code}"

  jq -n --rawfile metadata "${SAML_SSO_DIR}/idp-metadata.xml" \
    --arg realm "${SAML_REALM}" --arg origin "${PUBLIC_ORIGIN}" '{
      id: $realm,
      auth_params: { saml_params: {
        metadata_xml: $metadata,
        sp_entity_id: "\($origin)/saml/\($realm)",
        sp_acs_url: "\($origin)/saml/\($realm)/acs",
        subject_attribute: "email",
        normalize_subject_case: true,
        role_attribute: "groups",
        allowed_return_origins: [$origin],
        default_return_url: "\($origin)/ui/locate"
      } },
      session_max_age_seconds: 900,
      session_max_stale_age_seconds: 900
    }' >"${SAML_SSO_DIR}/saml-realm.json"
  code=$(curl -ks -o "${SAML_SSO_DIR}/saml-realm.response" -w '%{http_code}' -b "${jar}" -X POST \
    -H "Content-Type: application/json" --data-binary "@${SAML_SSO_DIR}/saml-realm.json" \
    "${AV_URL}/admins/realms")
  case "${code}" in
    2*) print_status "Created Auth Verifier SAML realm '${SAML_REALM}'" ;;
    *) print_error "Creating realm '${SAML_REALM}' returned ${code}: $(cat "${SAML_SSO_DIR}/saml-realm.response")" ;;
  esac
}

up() {
  require_cmd docker
  require_cmd jq
  require_cmd openssl
  require_cmd envsubst
  resolve_auth_verifier_image
  compose down --remove-orphans >/dev/null 2>&1 || true
  generate_keys
  write_configs
  print_status "Starting Keycloak, Auth Verifier (${AUTH_VERIFIER_IMAGE}) and nginx"
  compose up -d
  wait_for_url "Auth Verifier" "${AV_URL}/public/version" 30
  wait_for_url "Keycloak" "${IDP_METADATA_URL}" 90
  seed_saml_realm
  print_success "SAML stack is up (work dir ${SAML_SSO_DIR})"
  print_info "Start the KMS:   cargo run --bin cosmian_kms -- -c ${SAML_SSO_DIR}/kms.toml"
  print_info "Then open:       ${PUBLIC_ORIGIN}/ui   (users: alice / alice-pw, bob / bob-pw)"
  print_info "Keycloak admin:  https://localhost:9443/admin   (admin / admin)"
}

down() {
  compose down --remove-orphans
  if [ -f "${MARKER}" ]; then
    rm -rf "${SAML_SSO_DIR}"
  fi
  print_success "SAML stack stopped"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  logs) compose logs --tail 200 ;;
  *) print_error "Usage: $0 up|down|logs" ;;
esac
