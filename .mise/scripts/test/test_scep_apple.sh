#!/usr/bin/env bash
# Apple SCEP interoperability capture (macOS only, interactive).
#
# Drives the real macOS SCEP client (com.apple.security.scep profile payload) against a live KMS
# through a recording proxy, then stores the captured Apple request as a regression fixture under
# test_data/scep/apple/macos-<version>/ and replays its parsing with
# `cargo test -p cosmian_kms_server apple_scep`.
#
# Steps:
#   1. Start a KMS with SCEP + template, create and delegate an RSA-2048 CA, export it (test CA).
#   2. Install a profile with Challenge + CAFingerprint; the user approves it in System Settings.
#      Check: GetCACaps/GetCACert/PKIOperation(POST) sequence, issued certificate in a keychain,
#      chained to the CA with the template EKU; request uses SHA-256 and AES with an RSA-2048 key.
#   3. Opt-in (SCEP_APPLE_RENEW=1), inconclusive so far: the user runs
#      `sudo profiles renew -type configuration -identifier <id>`; what Apple sends is recorded,
#      not asserted. On macOS 26.6 it produced no SCEP traffic for a manually installed profile.
#
# Usage: bash .mise/scripts/test/test_scep_apple.sh [--variant fips|non-fips] [--link static|dynamic]
# Env:   SCEP_APPLE_WAIT_SECS (default 600) per wait, SCEP_APPLE_RENEW=1 (renewal step),
#        SCEP_APPLE_FP_ALG (sha256|sha1, default sha256) for CAFingerprint,
#        SCEP_APPLE_OVERWRITE=1 to replace an existing test_data/scep/apple/macos-<version> capture.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

[ "$(uname -s)" = "Darwin" ] || print_error "The Apple SCEP capture runs on macOS only"
require_cmd openssl
require_cmd curl
require_cmd python3
require_cmd plutil
require_cmd security
require_cmd uuidgen

WAIT_SECS="${SCEP_APPLE_WAIT_SECS:-600}"
FP_ALG="${SCEP_APPLE_FP_ALG:-sha256}"
# Same values as crate/server/src/tests/enrollment_tests.rs (apple_scep fixture test).
CHALLENGE="SecretChallenge123"
DEVICE_CN="mac-01.iot.example"
CA_UID="apple-scep-ca"
# Run-specific: never collides with (or removes) a profile installed by another run.
PROFILE_ID="com.cosmian.kms.scep.apple-interop.$(uuidgen | tr '[:upper:]' '[:lower:]')"
REPO_ROOT="$(get_repo_root)"
MACOS_VERSION="$(sw_vers -productVersion)"
FIXTURE_DIR="${REPO_ROOT}/test_data/scep/apple/macos-${MACOS_VERSION}"
# The capture is a committed regression fixture: never replace it silently.
[ ! -e "${FIXTURE_DIR}/pkcsreq.der" ] || [ "${SCEP_APPLE_OVERWRITE:-0}" = "1" ] ||
  print_error "${FIXTURE_DIR} already holds a capture; set SCEP_APPLE_OVERWRITE=1 to replace it"

print_header "Step 1: Build KMS server + ckms CLI (${VARIANT:-fips})"
kms_build_all

WORKDIR="$(mktemp -d /tmp/kms-scep-apple-XXXXXX)"
CAPTURE_DIR="${WORKDIR}/capture"
CKMS_BIN="$(get_ckms_bin)"
PROXY_PID=""
# shellcheck disable=SC2329
cleanup() {
  [ -z "${PROXY_PID}" ] || kill "${PROXY_PID}" 2>/dev/null || true
  kms_stop
  rm -rf "${WORKDIR}"
  # Listing system profiles needs root, so always remind once a profile has been offered.
  [ "${PROFILE_OPENED:-0}" != "1" ] ||
    print_warning "Remove the test profile (and its identity): sudo profiles remove -identifier ${PROFILE_ID}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

ckms() { "${CKMS_BIN}" --conf-path "${KMS_CKMS_CONF}" "$@"; }

print_header "Step 2: Start KMS (SCEP) and the recording proxy"
kms_write_config "$(kms_pick_free_port)" "${WORKDIR}/db" \
  "[scep]" \
  "scep_enabled = true" \
  "scep_ca_uid = \"${CA_UID}\"" \
  "scep_challenge_password = \"${CHALLENGE}\"" \
  "scep_allow_renewal_without_challenge = true" \
  "scep_template = \"iot_device\"" \
  "" \
  "[templates.iot_device]" \
  "name = \"iot_device\"" \
  "min_rsa_key_bits = 2048" \
  "allowed_ekus = [\"clientAuth\"]" \
  "max_validity_days = 365" \
  "default_validity_days = 90" \
  "subject_cn_regex = \"[a-z0-9-]+\\\\.iot\\\\.example\""
kms_start_from_bin "$(get_kms_bin)"
kms_write_ckms_conf >/dev/null

cat >"${WORKDIR}/ca.ext" <<'EXT'
[ v3_ca ]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,crlSign,digitalSignature,keyEncipherment
EXT
ckms certificates certify --certificate-id "${CA_UID}" --generate-key-pair \
  --algorithm rsa2048 --subject-name "CN=Apple SCEP Interop Test CA,O=Cosmian Test,C=FR" \
  --days 3650 --certificate-extensions "${WORKDIR}/ca.ext" >/dev/null
ckms certificates export "${WORKDIR}/ca.crt" --certificate-id "${CA_UID}" --format pem >/dev/null
ckms attributes get -i "${CA_UID}" -a LinkType -l private-key -o "${WORKDIR}/ca-links.json" >/dev/null
CA_SK_UID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["PrivateKeyLink"])' \
  "${WORKDIR}/ca-links.json")
# Test-only CA: its key is exported so the captured (CA-encrypted) request can be decrypted later.
ckms rsa keys export -k "${CA_SK_UID}" -f pkcs8-pem "${WORKDIR}/ca.key" >/dev/null
ckms access-rights grant "[enrollment-service]" -i "${CA_UID}" certify >/dev/null
ckms access-rights grant "[enrollment-service]" -i "${CA_SK_UID}" certify >/dev/null

PROXY_PORT="$(kms_pick_free_port)"
python3 "${SCRIPT_DIR}/scep_capture_proxy.py" "${PROXY_PORT}" "${KMS_URL}" "${CAPTURE_DIR}" \
  2>"${WORKDIR}/proxy.log" &
PROXY_PID=$!
wait_for_port 127.0.0.1 "${PROXY_PORT}" 15 || print_error "SCEP capture proxy did not start"
SCEP_URL="http://127.0.0.1:${PROXY_PORT}/scep"

CA_FP=$(openssl x509 -in "${WORKDIR}/ca.crt" -outform DER | openssl dgst "-${FP_ALG}" -binary | base64)

write_profile() {
  local file="$1"
  cat >"${file}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>${PROFILE_ID}</string>
  <key>PayloadUUID</key><string>$(uuidgen)</string>
  <key>PayloadDisplayName</key><string>KMS SCEP interop test</string>
  <key>PayloadScope</key><string>System</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.security.scep</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>${PROFILE_ID}.scep</string>
      <key>PayloadUUID</key><string>$(uuidgen)</string>
      <key>PayloadDisplayName</key><string>KMS SCEP identity</string>
      <key>PayloadContent</key>
      <dict>
        <key>URL</key><string>${SCEP_URL}</string>
        <key>Name</key><string>KMS SCEP CA</string>
        <key>Subject</key><array><array><array><string>CN</string><string>${DEVICE_CN}</string></array></array></array>
        <key>Challenge</key><string>${CHALLENGE}</string>
        <key>Keysize</key><integer>2048</integer>
        <key>Key Type</key><string>RSA</string>
        <key>Key Usage</key><integer>5</integer>
        <key>CAFingerprint</key><data>${CA_FP}</data>
      </dict>
    </dict>
  </array>
</dict>
</plist>
PLIST
  plutil -lint "${file}" >/dev/null
}

# wait_for_pkioperation <n>: wait until the n-th PKIOperation exchange has been captured.
wait_for_pkioperation() {
  local n="$1" waited=0
  print_info "Waiting up to ${WAIT_SECS}s for the Apple SCEP client (proxy log: ${CAPTURE_DIR}/exchanges.log)..."
  while [ "$(find "${CAPTURE_DIR}" -name '*-PKIOperation.resp' 2>/dev/null | wc -l | tr -d ' ')" -lt "${n}" ]; do
    [ "${waited}" -lt "${WAIT_SECS}" ] || return 1
    sleep 2
    waited=$((waited + 2))
  done
}

# nth_pkioperation <n> <ext>: path of the n-th captured PKIOperation request/response.
nth_pkioperation() { find "${CAPTURE_DIR}" -name "*-PKIOperation.$2" | sort | sed -n "$1p"; }

print_header "Scenario 1: Apple PKCSReq enrollment (challenge + CAFingerprint/${FP_ALG})"
write_profile "${WORKDIR}/enroll.mobileconfig"
open "${WORKDIR}/enroll.mobileconfig"
PROFILE_OPENED=1
print_info "Approve the profile: System Settings > General > Device Management > 'KMS SCEP interop test' > Install."
wait_for_pkioperation 1 ||
  print_error "FAIL: no PKIOperation received from the Apple SCEP client within ${WAIT_SECS}s"
cat "${CAPTURE_DIR}/exchanges.log"
grep -q -- "-GET-GetCACaps " "${CAPTURE_DIR}/exchanges.log" || print_error "FAIL: Apple client did not query GetCACaps"
grep -q -- "-GET-GetCACert " "${CAPTURE_DIR}/exchanges.log" || print_error "FAIL: Apple client did not query GetCACert"
grep -q -- "-POST-PKIOperation " "${CAPTURE_DIR}/exchanges.log" ||
  print_error "FAIL: Apple client did not use POST for PKIOperation despite POSTPKIOperation"
print_success "PASS: Apple client queried GetCACert and GetCACaps, then POSTed PKIOperation"

REQ="$(nth_pkioperation 1 req)"
openssl cms -verify -noverify -binary -inform DER -in "${REQ}" -out "${WORKDIR}/envelope.der" 2>/dev/null ||
  print_error "FAIL: Apple pkiMessage signature does not verify"
SIGNED_PRINT=$(openssl cms -cmsout -print -inform DER -in "${REQ}")
grep -q "digestAlgorithm:.*sha256\|algorithm: sha256" <<<"${SIGNED_PRINT}" ||
  print_error "FAIL: Apple pkiMessage is not signed with SHA-256"
ENV_PRINT=$(openssl cms -cmsout -print -inform DER -in "${WORKDIR}/envelope.der")
ENC_ALG=$(grep -A1 "contentEncryptionAlgorithm:" <<<"${ENV_PRINT}" | grep -o "aes-[0-9]*-cbc\|des-ede3-cbc\|des-cbc" | head -1)
case "${ENC_ALG}" in aes-*) ;; *) print_error "FAIL: Apple envelope uses '${ENC_ALG:-unknown}', expected AES" ;; esac
openssl cms -decrypt -binary -inform DER -in "${WORKDIR}/envelope.der" \
  -recip "${WORKDIR}/ca.crt" -inkey "${WORKDIR}/ca.key" -out "${WORKDIR}/csr.der"
CSR_TEXT=$(openssl req -inform DER -in "${WORKDIR}/csr.der" -noout -text -verify 2>&1)
grep -q "Public-Key: (2048 bit)" <<<"${CSR_TEXT}" || print_error "FAIL: Apple CSR is not RSA-2048"
grep -q "challengePassword" <<<"${CSR_TEXT}" || print_error "FAIL: Apple CSR carries no challengePassword"
print_success "PASS: Apple request: SHA-256 signature, ${ENC_ALG} envelope, RSA-2048 CSR with challenge"

grep -q "rejected" "${KMS_LOG_FILE}" && {
  grep "SCEP" "${KMS_LOG_FILE}" >&2
  print_error "FAIL: KMS rejected the Apple request"
}
ISSUED=""
for keychain in /Library/Keychains/System.keychain "${HOME}/Library/Keychains/login.keychain-db"; do
  ISSUED=$(security find-certificate -a -c "${DEVICE_CN}" -p "${keychain}" 2>/dev/null || true)
  [ -z "${ISSUED}" ] || break
done
[ -n "${ISSUED}" ] || print_error "FAIL: issued certificate ${DEVICE_CN} not found in the System or login keychain"
# Keep the most recent one if several remain from earlier runs.
awk '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{last=c} END{printf "%s", last}' <<<"${ISSUED}" >"${WORKDIR}/issued.pem"
openssl verify -CAfile "${WORKDIR}/ca.crt" "${WORKDIR}/issued.pem" >/dev/null ||
  print_error "FAIL: keychain certificate is not issued by the KMS CA"
ISSUED_TEXT=$(openssl x509 -in "${WORKDIR}/issued.pem" -noout -text) ||
  print_error "FAIL: cannot parse the keychain certificate"
grep -q "TLS Web Client Authentication" <<<"${ISSUED_TEXT}" || print_error "FAIL: template clientAuth EKU missing"
print_success "PASS: macOS installed the KMS-issued identity (template EKU applied)"

mkdir -p "${FIXTURE_DIR}"
cp "${WORKDIR}/ca.crt" "${FIXTURE_DIR}/ca.crt"
cp "${WORKDIR}/ca.key" "${FIXTURE_DIR}/ca.key"
cp "${REQ}" "${FIXTURE_DIR}/pkcsreq.der"
cp "${WORKDIR}/enroll.mobileconfig" "${FIXTURE_DIR}/enroll.mobileconfig"

RENEWAL_NOTE="not run (set SCEP_APPLE_RENEW=1)"
if [ "${SCEP_APPLE_RENEW:-0}" = "1" ]; then
  print_header "Scenario 2: macOS certificate renewal (observed only)"
  print_info "In another terminal run: sudo profiles renew -type configuration -identifier ${PROFILE_ID}"
  if wait_for_pkioperation 2; then
    cp "$(nth_pkioperation 2 req)" "${FIXTURE_DIR}/renewal.der"
    SCEP_LINE=$(grep "SCEP PKIOperation" "${KMS_LOG_FILE}" | tail -1)
    if grep -q "messageType=17" <<<"${SCEP_LINE}"; then
      RENEWAL_NOTE="Apple sent RenewalReq (17)"
    else
      RENEWAL_NOTE="Apple sent ${SCEP_LINE##*messageType=}"
    fi
    if grep -q "rejected" "${KMS_LOG_FILE}"; then
      RENEWAL_NOTE="${RENEWAL_NOTE}; KMS rejected it: $(grep rejected "${KMS_LOG_FILE}" | tail -1 | sed 's/.*rejected //')"
    else
      RENEWAL_NOTE="${RENEWAL_NOTE}; KMS issued a certificate"
    fi
    print_info "Renewal observation: ${RENEWAL_NOTE}"
  else
    RENEWAL_NOTE="no PKIOperation received within ${WAIT_SECS}s (renew not run, or failed before SCEP)"
    print_warning "${RENEWAL_NOTE}"
  fi
fi

cat >"${FIXTURE_DIR}/README.md" <<EOF
# Apple SCEP capture: macOS ${MACOS_VERSION} ($(sw_vers -buildVersion))

Captured on $(date -u +%Y-%m-%d) by \`mise run test:scep-apple\` from the native macOS SCEP client
(\`com.apple.security.scep\` payload, see \`enroll.mobileconfig\`).

- \`ca.crt\`, \`ca.key\`: throwaway test CA the requests are encrypted to. Test-only, never trust it.
- \`pkcsreq.der\`: signed \`pkiMessage\` (\`PKCSReq\`, challenge \`${CHALLENGE}\`, CN \`${DEVICE_CN}\`).
- \`renewal.der\` (if present): what Apple sends on \`profiles renew -type configuration\`.
- CAFingerprint algorithm: ${FP_ALG}; content encryption: ${ENC_ALG}.
- Renewal observation: ${RENEWAL_NOTE}.

Parsed by \`apple_scep_fixtures_parse\` in \`crate/server/src/tests/enrollment_tests.rs\`.
EOF
print_success "Fixture written to ${FIXTURE_DIR}"

print_header "Step 3: Replay fixture parsing"
cargo test -p cosmian_kms_server ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} --lib apple_scep -- --nocapture

print_success "Apple SCEP interoperability capture completed"
