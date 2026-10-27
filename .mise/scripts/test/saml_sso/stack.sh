#!/usr/bin/env bash
# Local SAML single sign-on stack for manually testing the KMS Web UI SAML login:
# Keycloak (IdP) + nginx (single public origin) in Docker, and the Auth Verifier SAML build (SP)
# on the host with `cargo run -p auth_verifier --features saml` from the `authentication` submodule.
# The KMS itself runs on the host from the current checkout (see `up` output).
#
# Usage: stack.sh up|down|logs
#
# Env:
#   AUTH_VERIFIER_REPO   Authentication repo checkout (default: <repo>/authentication)
#   AUTH_VERIFIER_TIMEOUT  seconds to wait for the Auth Verifier to build and start (default: 1800)
#   KEYCLOAK_IMAGE       Keycloak image (default: docker.io/keycloak/keycloak:26.4.0)
#   NGINX_IMAGE          nginx image (default: nginx:1.27-alpine)
#   SAML_SSO_DIR         work dir for keys and configs (default: /tmp/kms-saml-sso)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
# shellcheck source=.mise/lib/common.sh
source "${REPO_ROOT}/.mise/lib/common.sh"

export SAML_SSO_DIR="${SAML_SSO_DIR:-/tmp/kms-saml-sso}"
export KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-docker.io/keycloak/keycloak:26.4.0}"
export NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
# Address the host-run Auth Verifier and KMS bind to. The nginx container reaches them through
# host.docker.internal: Docker Desktop (macOS) delivers that to host loopback, so loopback is enough;
# on Linux it is the docker bridge gateway. Never 0.0.0.0: the dev Auth Verifier has a default admin login.
bind_host() {
  if [ "$(uname -s)" = "Darwin" ]; then
    echo "127.0.0.1"
  else
    docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null ||
      print_error "cannot determine the docker bridge gateway address"
  fi
}

BIND_HOST="$(bind_host)" || exit 1
AV_URL="https://${BIND_HOST}:8444"
PUBLIC_ORIGIN="https://localhost:8443"
SAML_REALM="kms-saml"
IDP_METADATA_URL="https://localhost:9443/realms/demo/protocol/saml/descriptor"
MARKER="${SAML_SSO_DIR}/.kms-saml-sso"
AUTH_VERIFIER_REPO="${AUTH_VERIFIER_REPO:-${REPO_ROOT}/authentication}"
AV_PID_FILE="${SAML_SSO_DIR}/auth-verifier.pid"
AV_LOG="${SAML_SSO_DIR}/auth-verifier.log"

compose() {
  docker compose -p kms-saml-sso -f "${SCRIPT_DIR}/docker-compose.yml" "$@"
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
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${BIND_HOST}" \
    -keyout "${SAML_SSO_DIR}/tls.key.pem" -out "${SAML_SSO_DIR}/tls.cert.pem" 2>/dev/null
  openssl req -x509 -newkey rsa:3072 -sha256 -days 7 -nodes -subj "/CN=kms-saml-sso SP" \
    -keyout "${SAML_SSO_DIR}/saml-sp.key.pem" -out "${SAML_SSO_DIR}/saml-sp.cert.pem" 2>/dev/null
}

# Auth Verifier, Keycloak realm and KMS configuration files.
write_configs() {
  cat >"${SAML_SSO_DIR}/auth_verifier.toml" <<TOML
# Dev only: in-memory database, throw-away keys, torn down by \`stack.sh down\`.
host_name = "${BIND_HOST}"
host_port = 8444
roles = ["SuperAdmin", "DomainAdmin", "CryptoOfficer", "Auditor", "User"]

[tls_params]
server_private_key = "${SAML_SSO_DIR}/tls.key.pem"
server_certificate = "${SAML_SSO_DIR}/tls.cert.pem"
server_ca_chain = "${SAML_SSO_DIR}/tls.cert.pem"

[database_params]
backend = "sqlite"
connection_url = "sqlite::memory:"

[saml_sp_params]
saml_rsa_private_key = "${SAML_SSO_DIR}/saml-sp.key.pem"
saml_certificate = "${SAML_SSO_DIR}/saml-sp.cert.pem"
TOML

  SP_CERT=$(grep -v -- '-----' "${SAML_SSO_DIR}/saml-sp.cert.pem" | tr -d '\n') \
  PUBLIC_ORIGIN="${PUBLIC_ORIGIN}" SAML_REALM="${SAML_REALM}" \
    envsubst "\${PUBLIC_ORIGIN} \${SAML_REALM} \${SP_CERT}" \
    <"${SCRIPT_DIR}/keycloak-realm.json.tmpl" >"${SAML_SSO_DIR}/keycloak-realm.json"

  cat >"${SAML_SSO_DIR}/kms.toml" <<TOML
kms_public_url = "${PUBLIC_ORIGIN}"

[http]
port = 9998
hostname = "${BIND_HOST}"

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
  # The Keycloak and nginx containers run as non-root and must read these throw-away files.
  chmod 755 "${SAML_SSO_DIR}"
  chmod 644 "${SAML_SSO_DIR}"/*.pem "${SAML_SSO_DIR}"/*.toml "${SAML_SSO_DIR}"/*.json
}

# Wait until an HTTPS endpoint answers successfully.
wait_for_url() {
  local name="$1" url="$2" tries="${3:-90}"
  print_status "Waiting for ${name} (${url})..."
  for _ in $(seq 1 "${tries}"); do
    if curl -ksf -o /dev/null "${url}"; then
      return 0
    fi
    sleep 2
  done
  compose logs --tail 50 >&2 || true
  tail -50 "${AV_LOG}" >&2 || true
  print_error "${name} not ready after $((tries * 2)) s"
}

# Kill a process and all its descendants (nix-shell -> cargo -> auth_verifier).
kill_tree() {
  local pid="$1" child
  for child in $(pgrep -P "${pid}" 2>/dev/null || true); do
    kill_tree "${child}"
  done
  kill "${pid}" 2>/dev/null || true
}

stop_auth_verifier() {
  if [ -f "${AV_PID_FILE}" ]; then
    kill_tree "$(cat "${AV_PID_FILE}")"
    rm -f "${AV_PID_FILE}"
  fi
}

# Run the Auth Verifier SAML build on the host: `cargo run -p auth_verifier --features saml`.
# The `saml` feature links xmlsec/libxml2, which only the authentication repo's own nix-shell
# provides (it also pins a newer rustc than the KMS nix shell). The KMS shell's OpenSSL/FIPS
# and cargo variables are dropped so they do not leak into that build.
start_auth_verifier() {
  [ -f "${AUTH_VERIFIER_REPO}/server/auth_verifier.dev.toml" ] ||
    print_error "authentication submodule not found at '${AUTH_VERIFIER_REPO}'. Run: git submodule update --init authentication"
  if (exec 3<>"/dev/tcp/${BIND_HOST}/8444") 2>/dev/null; then
    print_error "something already listens on port 8444; stop it (or a previous Auth Verifier) first"
  fi
  print_status "Starting the Auth Verifier: cargo run -p auth_verifier --features saml (first build takes a while)"
  (
    cd "${AUTH_VERIFIER_REPO}"
    exec env -u IN_NIX_SHELL -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES -u OPENSSL_NO_VENDOR \
      -u OPENSSL_DIR -u OPENSSL_LIB_DIR -u OPENSSL_INCLUDE_DIR -u CARGO_TARGET_DIR -u RUSTFLAGS \
      nix-shell --run "exec cargo run -p auth_verifier --features saml -- '${SAML_SSO_DIR}/auth_verifier.toml'"
  ) >"${AV_LOG}" 2>&1 &
  echo $! >"${AV_PID_FILE}"
}

wait_for_auth_verifier() {
  local tries=$((${AUTH_VERIFIER_TIMEOUT:-1800} / 2)) pid
  pid="$(cat "${AV_PID_FILE}")"
  print_status "Waiting for the Auth Verifier (${AV_URL}/public/version)..."
  for _ in $(seq 1 "${tries}"); do
    if curl -ksf -o /dev/null "${AV_URL}/public/version"; then
      return 0
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
      tail -80 "${AV_LOG}" >&2 || true
      print_error "the Auth Verifier exited before becoming ready"
    fi
    sleep 2
  done
  tail -80 "${AV_LOG}" >&2 || true
  print_error "Auth Verifier not ready after ${AUTH_VERIFIER_TIMEOUT:-1800} s"
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
  require_cmd nix-shell "Nix is required to build the Auth Verifier SAML feature (xmlsec). Install Nix: https://nixos.org/download"
  compose down --remove-orphans >/dev/null 2>&1 || true
  stop_auth_verifier
  generate_keys
  write_configs
  start_auth_verifier
  print_status "Starting Keycloak and nginx"
  compose up -d
  wait_for_auth_verifier
  wait_for_url "Keycloak" "${IDP_METADATA_URL}" 90
  seed_saml_realm
  print_success "SAML stack is up (work dir ${SAML_SSO_DIR})"
  print_info "Start the KMS:   cargo run --bin cosmian_kms -- -c ${SAML_SSO_DIR}/kms.toml"
  print_info "Then open:       ${PUBLIC_ORIGIN}/ui   (users: alice / alice-pw, bob / bob-pw)"
  print_info "Keycloak admin:  https://localhost:9443/admin   (admin / admin)"
}

down() {
  compose down --remove-orphans
  stop_auth_verifier
  if [ -f "${MARKER}" ]; then
    rm -rf "${SAML_SSO_DIR}"
  fi
  print_success "SAML stack stopped"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  logs)
    compose logs --tail 200
    tail -200 "${AV_LOG}" 2>/dev/null || true
    ;;
  *) print_error "Usage: $0 up|down|logs" ;;
esac
