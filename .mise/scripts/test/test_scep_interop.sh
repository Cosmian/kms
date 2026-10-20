#!/usr/bin/env bash
# SCEP (RFC 8894) interoperability test against the micromdm `scepclient`.
# The native Apple client is covered by test_scep_apple.sh (`mise run test:scep-apple`).
#
# Scenarios (all against a live KMS server, no internal API):
#   1. GetCACaps advertises exactly POSTPKIOperation / SHA-256 / AES / Renewal (no DES3, no SHA-1)
#   2. scepclient PKCSReq with the challenge password   -> certificate issued by the KMS CA
#   3. scepclient RenewalReq (existing cert) w/o challenge -> renewed certificate
#   4. scepclient PKCSReq with a wrong challenge        -> failInfo: badRequest
#
# Usage: bash .mise/scripts/test/test_scep_interop.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

SCEPCLIENT_VERSION="${SCEPCLIENT_VERSION:-v2.3.0}"
# Commit the tag above must resolve to: a moved or re-tagged upstream is refused.
SCEPCLIENT_COMMIT="${SCEPCLIENT_COMMIT:-8eb5412c850c98aaa83c3b96b2facae3710777d6}"
CHALLENGE="SecretChallenge123"
CA_UID="scep-ca"

require_cmd go "Go is required to install scepclient (github.com/micromdm/scep)"
require_cmd openssl
require_cmd curl

print_header "Step 1: Build KMS server + ckms CLI (${VARIANT:-fips})"
kms_build_all

WORKDIR="$(mktemp -d /tmp/kms-scep-interop-XXXXXX)"
CKMS_BIN="$(get_ckms_bin)"
# shellcheck disable=SC2329
cleanup() {
  kms_stop
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

ckms() { "${CKMS_BIN}" --conf-path "${KMS_CKMS_CONF}" "$@"; }

print_header "Step 2: Build scepclient ${SCEPCLIENT_VERSION} (AES-128-CBC)"
# The stock scepclient never reads GetCACaps and always encrypts the pkcsPKIEnvelope with
# single-DES-CBC (the default of the smallstep/pkcs7 library), which a FIPS 140-3 server must
# refuse (RFC 8894 §3.5.2: only advertised capabilities may be used). The same client library
# supports AES-128-CBC through one package variable, so one line is injected before building.
require_cmd git
retry git clone -q --depth 1 --branch "${SCEPCLIENT_VERSION}" https://github.com/micromdm/scep.git "${WORKDIR}/scep-src"
[ "$(git -C "${WORKDIR}/scep-src" rev-parse HEAD)" = "${SCEPCLIENT_COMMIT}" ] ||
  print_error "scepclient ${SCEPCLIENT_VERSION} does not resolve to the pinned commit ${SCEPCLIENT_COMMIT}"
(
  cd "${WORKDIR}/scep-src"
  perl -0pi -e 's|(\t"github.com/smallstep/scep"\n)|$1\t"github.com/smallstep/pkcs7"\n|; s|(\tflag.Parse\(\)\n)|\tpkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC\n$1|' \
    cmd/scepclient/scepclient.go
  # a silently unapplied patch would leave the single-DES client and fail the test misleadingly
  grep -q 'pkcs7.ContentEncryptionAlgorithm' cmd/scepclient/scepclient.go ||
    print_error "AES-128-CBC patch did not apply to scepclient ${SCEPCLIENT_VERSION}"
  retry go get github.com/smallstep/pkcs7@v0.1.1
  # Pin the fetched module: go.sum must hold exactly these hashes (also published at
  # https://sum.golang.org/lookup/github.com/smallstep/pkcs7@v0.1.1).
  for pinned in \
    "github.com/smallstep/pkcs7 v0.1.1 h1:x+rPdt2W088V9Vkjho4KtoggyktZJlMduZAtRHm68LU=" \
    "github.com/smallstep/pkcs7 v0.1.1/go.mod h1:dL6j5AIz9GHjVEBTXtW+QliALcgM19RtXaTeyxI+AfA="; do
    grep -qxF "${pinned}" go.sum || print_error "smallstep/pkcs7 v0.1.1 checksum differs from the pinned value: ${pinned}"
  done
  mkdir -p "${WORKDIR}/bin"
  retry go build -o "${WORKDIR}/bin/scepclient" ./cmd/scepclient
)
SCEPCLIENT="${WORKDIR}/bin/scepclient"

print_header "Step 3: Start a KMS server with SCEP enabled"
port="$(kms_pick_free_port)"
kms_write_config "${port}" "${WORKDIR}/db" \
  "[scep]" \
  "scep_enabled = true" \
  "scep_ca_uid = \"${CA_UID}\"" \
  "scep_challenge_password = \"${CHALLENGE}\"" \
  "scep_allow_renewal_without_challenge = true" \
  "scep_template = \"mdm_device\"" \
  "" \
  "[templates.mdm_device]" \
  "name = \"mdm_device\"" \
  "min_rsa_key_bits = 2048" \
  "allowed_ekus = [\"clientAuth\"]" \
  "max_validity_days = 365" \
  "default_validity_days = 90" \
  "subject_cn_regex = \"[a-z0-9.-]+\""
kms_start_from_bin "$(get_kms_bin)"
kms_write_ckms_conf >/dev/null
SCEP_URL="${KMS_URL}/scep"

cat >"${WORKDIR}/ca.ext" <<'EXT'
[ v3_ca ]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,crlSign,digitalSignature,keyEncipherment
EXT
ckms certificates certify --certificate-id "${CA_UID}" --generate-key-pair \
  --algorithm rsa2048 --subject-name "CN=SCEP Test CA,O=Cosmian Test,C=FR" \
  --days 3650 --certificate-extensions "${WORKDIR}/ca.ext" >/dev/null
ckms certificates export "${WORKDIR}/ca.crt" --certificate-id "${CA_UID}" --format pem >/dev/null
# Delegate the CA to the reserved enrollment identity: `certify` on the CA certificate and
# its private key (issuance fails closed without these grants).
ckms attributes get -i "${CA_UID}" -a LinkType -l private-key -o "${WORKDIR}/ca-links.json" >/dev/null
CA_SK_UID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["PrivateKeyLink"])' \
  "${WORKDIR}/ca-links.json")
ckms access-rights grant "[enrollment-service]" -i "${CA_UID}" certify >/dev/null
ckms access-rights grant "[enrollment-service]" -i "${CA_SK_UID}" certify >/dev/null

assert_contains() {
  if ! grep -Eqi "$2" <<<"$1"; then
    echo "----- unexpected output -----" >&2
    echo "$1" >&2
    echo "-----------------------------" >&2
    print_error "FAIL: $3 (expected to match: $2)"
  fi
  print_success "PASS: $3"
}

print_header "Scenario 1: GetCACaps"
CAPS=$(curl -fsS "${SCEP_URL}?operation=GetCACaps")
[ "${CAPS}" = "$(printf 'POSTPKIOperation\nSHA-256\nAES\nRenewal')" ] ||
  print_error "FAIL: unexpected GetCACaps: ${CAPS}"
if grep -Eqi "DES3|SHA-1" <<<"${CAPS}"; then
  print_error "FAIL: GetCACaps must not advertise DES3 / SHA-1"
fi
print_success "PASS: GetCACaps = POSTPKIOperation, SHA-256, AES, Renewal"

# scepclient keeps its CSR (csr.pem) next to the private key and reuses it on later runs,
# so every device gets its own directory.
mkdir -p "${WORKDIR}/dev1" "${WORKDIR}/bad"

# enroll <cn> <key> <cert> [extra scepclient args...]
enroll() {
  local cn="$1" key="$2" cert="$3"
  shift 3
  "${SCEPCLIENT}" -server-url "${SCEP_URL}" -cn "${cn}" -keySize 2048 \
    -private-key "${key}" -certificate "${cert}" "$@"
}

print_header "Scenario 2: PKCSReq with challenge password"
enroll device1.iot.example "${WORKDIR}/dev1/dev.key" "${WORKDIR}/dev1/dev.crt" -challenge "${CHALLENGE}"
[ -s "${WORKDIR}/dev1/dev.crt" ] || print_error "FAIL: scepclient did not write the certificate"
openssl verify -CAfile "${WORKDIR}/ca.crt" "${WORKDIR}/dev1/dev.crt"
SERIAL_1=$(openssl x509 -in "${WORKDIR}/dev1/dev.crt" -noout -serial)
EKU=$(openssl x509 -in "${WORKDIR}/dev1/dev.crt" -noout -ext extendedKeyUsage)
assert_contains "${EKU}" "TLS Web Client Authentication" "template-injected clientAuth EKU"
print_success "PASS: PKCSReq enrollment issued a certificate verifying against the KMS CA"

print_header "Scenario 3: RenewalReq without challenge password"
# Drop the CSR cached by scepclient (it still carries the challenge) so the renewal
# request is built without any challengePassword.
rm -f "${WORKDIR}/dev1/csr.pem"
enroll device1.iot.example "${WORKDIR}/dev1/dev.key" "${WORKDIR}/dev1/dev.crt"
openssl verify -CAfile "${WORKDIR}/ca.crt" "${WORKDIR}/dev1/dev.crt"
SERIAL_2=$(openssl x509 -in "${WORKDIR}/dev1/dev.crt" -noout -serial)
[ "${SERIAL_1}" != "${SERIAL_2}" ] || print_error "FAIL: renewal returned the same certificate"
print_success "PASS: challenge-less RenewalReq issued a new certificate (${SERIAL_1} -> ${SERIAL_2})"

print_header "Scenario 4: wrong challenge password is rejected"
RC=0
OUT=$(enroll device2.iot.example "${WORKDIR}/bad/bad.key" "${WORKDIR}/bad/bad.crt" -challenge "WrongSecret" 2>&1) || RC=$?
if [ "${RC}" -eq 0 ]; then
  echo "${OUT}" >&2
  print_error "FAIL: scepclient must fail with a wrong challenge"
fi
assert_contains "${OUT}" "failInfo: badRequest" "wrong challenge reports failInfo badRequest"
[ ! -e "${WORKDIR}/bad/bad.crt" ] || print_error "FAIL: no certificate must be written on failure"

print_success "All SCEP interoperability scenarios passed"
