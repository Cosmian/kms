#!/usr/bin/env bash
# SCEP (RFC 8894) interoperability test: micromdm `scepclient` + Apple SCEP profile.
#
# Scenarios (all against a live KMS server, no internal API):
#   1. GetCACaps advertises exactly POSTPKIOperation / SHA-256 / AES / Renewal (no DES3, no SHA-1)
#   2. scepclient PKCSReq with the challenge password   -> certificate issued by the KMS CA
#   3. scepclient RenewalReq (existing cert) w/o challenge -> renewed certificate
#   4. scepclient PKCSReq with a wrong challenge        -> failInfo: badRequest
#   5. (macOS) Apple `com.apple.security.scep` profile lints and drives an enrollment
#
# Usage: bash .mise/scripts/test/test_scep_interop.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

SCEPCLIENT_VERSION="${SCEPCLIENT_VERSION:-v2.3.0}"
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
git clone -q --depth 1 --branch "${SCEPCLIENT_VERSION}" https://github.com/micromdm/scep.git "${WORKDIR}/scep-src"
(
  cd "${WORKDIR}/scep-src"
  perl -0pi -e 's|(\t"github.com/smallstep/scep"\n)|$1\t"github.com/smallstep/pkcs7"\n|; s|(\tflag.Parse\(\)\n)|\tpkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC\n$1|' \
    cmd/scepclient/scepclient.go
  go get github.com/smallstep/pkcs7@v0.1.1
  mkdir -p "${WORKDIR}/bin"
  go build -o "${WORKDIR}/bin/scepclient" ./cmd/scepclient
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
mkdir -p "${WORKDIR}/dev1" "${WORKDIR}/bad" "${WORKDIR}/mac"

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

if [ "$(uname -s)" = "Darwin" ] && command -v plutil >/dev/null 2>&1; then
  print_header "Scenario 5: Apple com.apple.security.scep configuration profile"
  PROFILE="${WORKDIR}/scep.mobileconfig"
  cat >"${PROFILE}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.cosmian.kms.scep.profile</string>
  <key>PayloadUUID</key><string>5F0B6F2C-7A6B-4B52-8E55-0C1D4E9F2A11</string>
  <key>PayloadDisplayName</key><string>KMS SCEP test profile</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.security.scep</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.cosmian.kms.scep.test</string>
      <key>PayloadUUID</key><string>E5868B42-4581-42C4-82D5-5D9F0E177A19</string>
      <key>PayloadContent</key>
      <dict>
        <key>URL</key><string>${SCEP_URL}</string>
        <key>Name</key><string>KMS SCEP CA</string>
        <key>Subject</key><array><array><array><string>CN</string><string>mac-mdm-client.corp</string></array></array></array>
        <key>Challenge</key><string>${CHALLENGE}</string>
        <key>Keysize</key><integer>2048</integer>
        <key>Key Type</key><string>RSA</string>
        <key>Key Usage</key><integer>5</integer>
      </dict>
    </dict>
  </array>
</dict>
</plist>
PLIST
  plutil -lint "${PROFILE}"
  P_URL=$(plutil -extract PayloadContent.0.PayloadContent.URL raw "${PROFILE}")
  P_CN=$(plutil -extract PayloadContent.0.PayloadContent.Subject.0.0.1 raw "${PROFILE}")
  P_CHALLENGE=$(plutil -extract PayloadContent.0.PayloadContent.Challenge raw "${PROFILE}")
  P_KEYSIZE=$(plutil -extract PayloadContent.0.PayloadContent.Keysize raw "${PROFILE}")
  [ "${P_URL}" = "${SCEP_URL}" ] || print_error "FAIL: profile URL mismatch (${P_URL})"
  "${SCEPCLIENT}" -server-url "${P_URL}" -cn "${P_CN}" -keySize "${P_KEYSIZE}" -challenge "${P_CHALLENGE}" \
    -private-key "${WORKDIR}/mac/mac.key" -certificate "${WORKDIR}/mac/mac.crt"
  openssl verify -CAfile "${WORKDIR}/ca.crt" "${WORKDIR}/mac/mac.crt"
  rm -f "${WORKDIR}/mac/csr.pem"
  "${SCEPCLIENT}" -server-url "${P_URL}" -cn "${P_CN}" -keySize "${P_KEYSIZE}" \
    -private-key "${WORKDIR}/mac/mac.key" -certificate "${WORKDIR}/mac/mac.crt"
  openssl verify -CAfile "${WORKDIR}/ca.crt" "${WORKDIR}/mac/mac.crt"
  print_success "PASS: Apple SCEP profile parses; enrollment and renewal driven by its parameters succeed"
else
  echo "Skipping Apple profile scenario (needs macOS plutil)"
fi

print_success "All SCEP interoperability scenarios passed"
