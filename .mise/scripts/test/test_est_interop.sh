#!/usr/bin/env bash
# EST (RFC 7030) interoperability test: globalsign `estclient` against a live KMS over TLS.
#
# Scenarios:
#   1. /cacerts            -> the EST CA certificate
#   2. /csrattrs           -> CsrAttrs (the server has a template configured)
#   3. /simpleenroll       -> certificate issued with HTTP Basic bootstrap credentials
#   4. /simpleenroll       -> wrong credentials and template violations are rejected
#   5. /simplereenroll     -> renewal over mutual TLS with the certificate being renewed
#   6. /simplereenroll     -> a different Subject is rejected (RFC 7030 §4.2.2)
#
# Client choice: the globalsign `estclient` (Go) is used instead of Cisco `libest`'s estclient
# because libest (autotools, OpenSSL 1.1-era API) was not built/validated for this test; the
# globalsign client exercises the same RFC 7030 endpoints including mTLS re-enrollment.
# Set ESTCLIENT_MODULE to test another Go EST client module.
#
# The CA is created first on a plain-HTTP instance, then the same database is served over
# TLS with `clients_ca_cert_file` = the EST CA, so the issued certificates are accepted as
# TLS client certificates for the re-enrollment.
#
# Usage: bash .mise/scripts/test/test_est_interop.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

ESTCLIENT_MODULE="${ESTCLIENT_MODULE:-github.com/globalsign/est/cmd/estclient@latest}"
CA_UID="est-ca"
BOOT_USER="bootstrap"
BOOT_PASS="bootstrap-secret"

require_cmd go "Go is required to install the estclient (github.com/globalsign/est)"
require_cmd openssl
require_cmd curl

print_header "Step 1: Build KMS server + ckms CLI (${VARIANT:-fips})"
kms_build_all

WORKDIR="$(mktemp -d /tmp/kms-est-interop-XXXXXX)"
CKMS_BIN="$(get_ckms_bin)"
EST_PID=""
# shellcheck disable=SC2329
cleanup() {
  kms_stop
  if [ -n "${EST_PID}" ]; then
    kill "${EST_PID}" 2>/dev/null || true
    wait "${EST_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

ckms() { "${CKMS_BIN}" --conf-path "${KMS_CKMS_CONF}" "$@"; }

print_header "Step 2: Install estclient"
GOBIN="${WORKDIR}/bin" go install "${ESTCLIENT_MODULE}"
ESTCLIENT="${WORKDIR}/bin/estclient"

print_header "Step 3: Create the EST CA on a plain-HTTP instance"
DB_DIR="${WORKDIR}/db"
port="$(kms_pick_free_port)"
kms_write_config "${port}" "${DB_DIR}"
kms_start_from_bin "$(get_kms_bin)"
kms_write_ckms_conf >/dev/null
cat >"${WORKDIR}/ca.ext" <<'EXT'
[ v3_ca ]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,crlSign,digitalSignature
EXT
ckms certificates certify --certificate-id "${CA_UID}" --generate-key-pair \
  --algorithm rsa2048 --subject-name "CN=EST Test CA,O=Cosmian Test,C=FR" \
  --days 3650 --certificate-extensions "${WORKDIR}/ca.ext" >/dev/null
ckms certificates export "${WORKDIR}/ca.crt" --certificate-id "${CA_UID}" --format pem >/dev/null
# Stop the instance but keep the database (kms_stop removes it, so work on a copy).
cp -R "${DB_DIR}" "${WORKDIR}/db-keep"
kms_stop

print_header "Step 4: Start the KMS over TLS with EST enabled"
# TLS server certificate (any CA: the estclient is given it as explicit trust anchor).
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=EST TLS CA" \
  -keyout "${WORKDIR}/tls-ca.key" -out "${WORKDIR}/tls-ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" \
  -keyout "${WORKDIR}/tls.key" -out "${WORKDIR}/tls.csr" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\n' >"${WORKDIR}/tls.ext"
openssl x509 -req -in "${WORKDIR}/tls.csr" -CA "${WORKDIR}/tls-ca.crt" -CAkey "${WORKDIR}/tls-ca.key" \
  -CAcreateserial -days 2 -extfile "${WORKDIR}/tls.ext" -out "${WORKDIR}/tls.crt" 2>/dev/null

EST_PORT="$(kms_pick_free_port)"
cat >"${WORKDIR}/kms-est.toml" <<TOML
default_username = "admin"

[db]
database_type = "sqlite"
sqlite_path = "${WORKDIR}/db-keep"
clear_database = false

[http]
hostname = "127.0.0.1"
port = ${EST_PORT}

[tls]
tls_cert_file = "${WORKDIR}/tls.crt"
tls_key_file = "${WORKDIR}/tls.key"
clients_ca_cert_file = "${WORKDIR}/ca.crt"

[logging]
rust_log = "info,cosmian_kms=info"
ansi_colors = false

[est]
est_enabled = true
est_ca_uid = "${CA_UID}"
est_require_client_cert = false
est_bootstrap_username = "${BOOT_USER}"
est_bootstrap_password = "${BOOT_PASS}"
est_template = "iot_device"

[templates.iot_device]
name = "iot_device"
min_rsa_key_bits = 2048
allowed_ekus = ["clientAuth"]
max_validity_days = 365
default_validity_days = 90
subject_cn_regex = "[a-z0-9-]+\\\\.iot\\\\.example"
TOML
"$(get_kms_bin)" --config "${WORKDIR}/kms-est.toml" >"${WORKDIR}/kms-est.log" 2>&1 &
EST_PID=$!
for _ in $(seq 1 120); do
  if curl -fsS --cacert "${WORKDIR}/tls-ca.crt" "https://127.0.0.1:${EST_PORT}/version" >/dev/null 2>&1; then
    break
  fi
  kill -0 "${EST_PID}" 2>/dev/null || {
    cat "${WORKDIR}/kms-est.log" >&2
    print_error "KMS exited during startup"
  }
  sleep 1
done
curl -fsS --cacert "${WORKDIR}/tls-ca.crt" "https://127.0.0.1:${EST_PORT}/version" >/dev/null ||
  print_error "KMS did not become ready over TLS"
SERVER="127.0.0.1:${EST_PORT}"
# est <command> [options...]: estclient expects the command first.
est() {
  local command="$1"
  shift
  "${ESTCLIENT}" "${command}" -server "${SERVER}" -explicit "${WORKDIR}/tls-ca.crt" "$@"
}

assert_contains() {
  if ! grep -Eqi "$2" <<<"$1"; then
    echo "----- unexpected output -----" >&2
    echo "$1" >&2
    echo "-----------------------------" >&2
    print_error "FAIL: $3 (expected to match: $2)"
  fi
  print_success "PASS: $3"
}

new_csr() { # <cn> <key-out> <csr-out>
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout "$2" -out "$3" 2>/dev/null
}

print_header "Scenario 1: /cacerts"
est cacerts -out "${WORKDIR}/cacerts.pem"
CA_FP=$(openssl x509 -in "${WORKDIR}/ca.crt" -noout -fingerprint -sha256)
GOT_FP=$(openssl x509 -in "${WORKDIR}/cacerts.pem" -noout -fingerprint -sha256)
[ "${CA_FP}" = "${GOT_FP}" ] || print_error "FAIL: /cacerts returned a different CA (${GOT_FP} != ${CA_FP})"
print_success "PASS: /cacerts returned the KMS CA certificate"

print_header "Scenario 2: /csrattrs"
OUT=$(est csrattrs 2>&1)
assert_contains "${OUT}" "." "/csrattrs answered"

print_header "Scenario 3: /simpleenroll with HTTP Basic bootstrap credentials"
new_csr device1.iot.example "${WORKDIR}/dev1.key" "${WORKDIR}/dev1.csr"
est enroll -user "${BOOT_USER}" -pass "${BOOT_PASS}" -csr "${WORKDIR}/dev1.csr" \
  -key "${WORKDIR}/dev1.key" -out "${WORKDIR}/dev1.crt"
openssl verify -CAfile "${WORKDIR}/ca.crt" "${WORKDIR}/dev1.crt"
EKU=$(openssl x509 -in "${WORKDIR}/dev1.crt" -noout -ext extendedKeyUsage)
assert_contains "${EKU}" "TLS Web Client Authentication" "template-injected clientAuth EKU"
SERIAL_1=$(openssl x509 -in "${WORKDIR}/dev1.crt" -noout -serial)
print_success "PASS: /simpleenroll issued a certificate verifying against the KMS CA"

print_header "Scenario 4: rejected enrollments"
if est enroll -user "${BOOT_USER}" -pass "wrong" -csr "${WORKDIR}/dev1.csr" \
  -key "${WORKDIR}/dev1.key" >/dev/null 2>&1; then
  print_error "FAIL: /simpleenroll must reject wrong credentials"
fi
print_success "PASS: wrong bootstrap password rejected"
new_csr evil.example.com "${WORKDIR}/evil.key" "${WORKDIR}/evil.csr"
RC=0
OUT=$(est enroll -user "${BOOT_USER}" -pass "${BOOT_PASS}" -csr "${WORKDIR}/evil.csr" \
  -key "${WORKDIR}/evil.key" 2>&1) || RC=$?
[ "${RC}" -ne 0 ] || print_error "FAIL: /simpleenroll must reject a CN outside the template"
assert_contains "${OUT}" "does not match|422|Unprocessable" "template violation reported to the client"

print_header "Scenario 5: /simplereenroll over mutual TLS"
new_csr device1.iot.example "${WORKDIR}/dev1-new.key" "${WORKDIR}/dev1-new.csr"
est reenroll -certs "${WORKDIR}/dev1.crt" -key "${WORKDIR}/dev1.key" \
  -csr "${WORKDIR}/dev1-new.csr" -out "${WORKDIR}/dev1-renewed.crt"
openssl verify -CAfile "${WORKDIR}/ca.crt" "${WORKDIR}/dev1-renewed.crt"
SERIAL_2=$(openssl x509 -in "${WORKDIR}/dev1-renewed.crt" -noout -serial)
[ "${SERIAL_1}" != "${SERIAL_2}" ] || print_error "FAIL: re-enrollment returned the same certificate"
print_success "PASS: /simplereenroll issued a new certificate (${SERIAL_1} -> ${SERIAL_2})"

print_header "Scenario 6: re-enrollment with another Subject is rejected"
new_csr device2.iot.example "${WORKDIR}/dev2.key" "${WORKDIR}/dev2.csr"
RC=0
OUT=$(est reenroll -certs "${WORKDIR}/dev1.crt" -key "${WORKDIR}/dev1.key" \
  -csr "${WORKDIR}/dev2.csr" 2>&1) || RC=$?
[ "${RC}" -ne 0 ] || print_error "FAIL: /simplereenroll must reject a different Subject"
assert_contains "${OUT}" "identical|400|Bad Request" "different Subject rejected"

print_success "All EST interoperability scenarios passed"
