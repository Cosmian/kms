#!/usr/bin/env bash
# Fill a running KMS with every kind of object and call every KMIP operation reachable through
# `ckms` (plus curl for the operations `ckms` cannot send), then re-check it later.
#
#   populate_db.sh populate --ckms BIN --url URL --state-dir DIR [--prefix pop] [--variant fips|non-fips]
#                           [--lenient] [--kek-wrapped] [--migrated-state DIR]
#   populate_db.sh verify   --ckms BIN --url URL --state-dir DIR [--legacy-state] [--legacy-locate] [--legacy-nested-wrap]
#
# populate writes DIR/{artifacts.tsv,ops.tsv,ids.env}; verify replays artifacts.tsv against a server
# holding a (possibly migrated) copy of the database. --lenient records unsupported operations as SKIP
# instead of aborting (used against old releases). --legacy-state (verify) accepts the State drift of
# releases before 5.13.0 (stored JSON PreActive/Deactivated vs enforced column Active/Destroyed) and Locate
# entries whose stored record lacks the tag (5.12.x Redis stale Findex index). --legacy-locate (verify) accepts
# only that Locate drift, for Redis releases before 5.29.0 whose re-certified certificates lost the tag.
# --kek-wrapped (populate) is for a server configured with a key encryption key: every server version refuses to
# export a wrapped private key in a requested format, so those Get/Export operations are recorded as SKIP.
# --legacy-nested-wrap (verify) skips the decrypt check of keys wrapped by a user key on a server configured with a
# key encryption key: releases before 5.29.0 cannot unwrap them after a restart (Incompatible_Cryptographic_Usage_Mask).
set -euo pipefail

MISE_CONFIG_ROOT="${MISE_CONFIG_ROOT:-$(git rev-parse --show-toplevel)}"
# shellcheck source=.mise/lib/common.sh
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
require_cmd jq
require_cmd curl
require_cmd cmp
# Client configs hold repo-root-relative certificate paths.
cd "$(get_repo_root "${MISE_CONFIG_ROOT}")"

MODE="${1:-}"
[ "$#" -eq 0 ] || shift
CKMS="" URL="" STATE="" P="pop" VARIANT="fips" LENIENT=0 LEGACY_STATE=0 LEGACY_LOCATE=0 KEK_WRAPPED=0 LEGACY_NESTED=0 MIGRATED=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --ckms) CKMS="$2" ;;
    --url) URL="$2" ;;
    --state-dir) STATE="$2" ;;
    --prefix) P="$2" ;;
    --variant) VARIANT="$2" ;;
    --migrated-state) MIGRATED="$2" ;;
    --lenient | --legacy-state | --legacy-locate | --kek-wrapped | --legacy-nested-wrap)
      case "$1" in --lenient) LENIENT=1 ;; --legacy-state) LEGACY_STATE=1 ;; --kek-wrapped) KEK_WRAPPED=1 ;; --legacy-nested-wrap) LEGACY_NESTED=1 ;; *) LEGACY_LOCATE=1 ;; esac
      shift
      continue
      ;;
    *) print_error "Unknown argument: $1" ;;
  esac
  shift 2
done
case "${MODE}" in populate | verify) ;; *) print_error "Usage: populate_db.sh populate|verify --ckms BIN --url URL --state-dir DIR" ;; esac
[ -n "${CKMS}" ] || print_error "--ckms is required"
[ -n "${URL}" ] || print_error "--url is required"
[ -n "${STATE}" ] || print_error "--state-dir is required"
mkdir -p "${STATE}/raw"
STATE="$(cd "${STATE}" && pwd)"
PORT="${URL##*:}"
CERTS="test_data/certificates/client_server"
LAST=""

owner_ckms() {
  COSMIAN_KMS_CLI_FORMAT=json "${CKMS}" -c test_data/configs/client/cert_owner.toml --url "${URL}" "$@" 2>>"${STATE}/ckms.log" </dev/null
}
user_ckms() {
  COSMIAN_KMS_CLI_FORMAT=json "${CKMS}" -c test_data/configs/client/cert_user.toml --url "${URL}" "$@" 2>>"${STATE}/ckms.log" </dev/null
}

# kmip_raw OP JSON_FILE: POST a raw KMIP 2.1 JSON-TTLV request; succeed only on the matching response tag.
kmip_raw() {
  local op="$1" file="$2" body
  body="$(curl -sS --max-time 30 --cacert "${CERTS}/ca/ca.crt" \
    --cert "${CERTS}/owner/owner.client.acme.com.crt" --key "${CERTS}/owner/owner.client.acme.com.key" \
    --resolve "kmserver.acme.com:${PORT}:127.0.0.1" -H 'Content-Type: application/json' \
    --data @"${file}" "https://kmserver.acme.com:${PORT}/kmip/2_1")" || return 1
  printf '%s' "${body}"
  jq -e --arg t "${op}Response" '.tag == $t' <<<"${body}" >/dev/null || {
    printf '%s\n' "${body}" >&2
    return 1
  }
}

# op NAME CMD...: run CMD, capture stdout in LAST, record PASS/SKIP; strict mode aborts on failure.
op() {
  local name="$1" err
  shift
  if LAST="$("$@" 2>"${STATE}/last.err")"; then
    printf '%s\tPASS\n' "${name}" >>"${STATE}/ops.tsv"
    return 0
  fi
  err="$(tail -n 3 "${STATE}/last.err" | tr '\t\n' '  ')"
  [ -n "${err// /}" ] || err="$(tail -n 3 "${STATE}/ckms.log" | tr '\t\n' '  ')" # owner_ckms/user_ckms send stderr to ckms.log
  if [ "${LENIENT}" = 1 ] || { [ "${KEK_WRAPPED}" = 1 ] && [[ "${err}" == *"wrapped key with a requested Key Format Type"* ]]; }; then
    printf '%s\tSKIP\t%s\n' "${name}" "${err:0:200}" >>"${STATE}/ops.tsv"
    return 1
  fi
  echo "populate_db.sh: operation ${name} failed: ${err}" >&2
  exit 1
}

record() { (
  IFS=$'\t'
  printf '%s\n' "$*" >>"${STATE}/artifacts.tsv"
); }
jf() { jq -er ".$1 // empty" <<<"${LAST}"; }

# state_of UID: the KMIP State attribute (not exposed by `ckms attributes get`, so use raw GetAttributes).
state_of() {
  local f="${STATE}/raw/state.json"
  jq -nc --arg u "$1" '{tag:"GetAttributes",value:[{tag:"UniqueIdentifier",type:"TextString",value:$u}]}' >"${f}"
  kmip_raw GetAttributes "${f}" 2>/dev/null | jq -er '.value[]|select(.tag=="Attributes").value[]|select(.tag=="State").value'
}

# has_tag UID TAG: true when the object's stored tags contain TAG (raw GetAttributes with the cosmian `tag` reference).
has_tag() {
  local f="${STATE}/raw/tags.json"
  jq -nc --arg u "$1" '{tag:"GetAttributes",value:[{tag:"UniqueIdentifier",type:"TextString",value:$u},
    {tag:"AttributeReference",value:[{tag:"VendorIdentification",type:"TextString",value:"cosmian"},{tag:"AttributeName",type:"TextString",value:"tag"}]}]}' >"${f}"
  kmip_raw GetAttributes "${f}" 2>/dev/null | jq -e --arg t "$2" \
    '[.. | objects | select(.tag=="AttributeValue") | .value | strings | (try fromjson catch [])[]?] | index($t) != null' >/dev/null
}

# rec_obj UID [full|exists]: queue an object; states are read once everything ran (finalize).
rec_obj() {
  [ -n "$1" ] || return 1
  printf '%s\t%s\n' "$1" "${2:-full}" >>"${STATE}/pending.tsv"
}

# finalize: record each queued object with its final state; unreadable objects are an error (SKIP when lenient).
finalize() {
  local uid mode s
  while IFS=$'\t' read -r uid mode; do
    if s="$(state_of "${uid}")"; then
      [ "${mode}" = full ] || s="-" # read -r with a tab IFS would collapse an empty field
      record object "${uid}" "${s}" "${mode}"
    elif [ "${LENIENT}" != 1 ]; then
      echo "populate_db.sh: cannot read the state of ${uid}" >&2
      exit 1
    fi
  done <"${STATE}/pending.tsv"
}

raw_file() {
  printf '%s\n' "$2" >"${STATE}/raw/$1.json"
  echo "${STATE}/raw/$1.json"
}
# raw_tpl NAME TEMPLATE KEY VALUE: copy a test-vector request replacing {{KEY}}.
raw_tpl() {
  sed "s|{{$3}}|$4|g" "test_data/vectors/fips/kmip_operations/$2" >"${STATE}/raw/$1.json"
  echo "${STATE}/raw/$1.json"
}

# export_by KIND UID FORMAT FILE: re-export an object (used by digest records). Symmetric and secret keys are
# unwrapped: a server with a key encryption key stores them wrapped, and the 6.0 row-binding re-wrap changes those bytes.
export_by() {
  case "$1" in
    sym) owner_ckms sym keys export --key-id "$2" --key-format "$3" --unwrap "$4" ;;
    secret) owner_ckms secret-data export --key-id "$2" --key-format "$3" --unwrap "$4" ;;
    rsa) owner_ckms rsa keys export --key-id "$2" --key-format "$3" "$4" ;;
    ec) owner_ckms ec keys export --key-id "$2" --key-format "$3" "$4" ;;
    cert) owner_ckms certificates export --certificate-id "$2" --format "$3" "$4" ;;
  esac
}

# digest_rec KIND UID FORMAT: export and record the sha256 of the exported bytes.
digest_rec() {
  local f="${STATE}/digest.$1.$2.tmp"
  op "Get:$1:$2" export_by "$1" "$2" "$3" "${f}" || return 1
  record digest "$1" "$2" "$3" "$(compute_sha256 "${f}")"
}

cipher_sym() {
  local k="$1"
  op "Encrypt:sym:${k}" owner_ckms sym encrypt --key-id "${k}" --output-file "${STATE}/${k}.enc" "${STATE}/plain.txt" &&
    op "Decrypt:sym:${k}" owner_ckms sym decrypt --key-id "${k}" --output-file "${STATE}/${k}.dec" "${STATE}/${k}.enc" &&
    op "Decrypt-check:sym:${k}" cmp -s "${STATE}/plain.txt" "${STATE}/${k}.dec" &&
    record cipher sym "${k}" "${k}.enc" owner
}

# make_ids FILE: write ids.env first line.
populate() {
  : >"${STATE}/ops.tsv"
  : >"${STATE}/artifacts.tsv"
  : >"${STATE}/pending.tsv"
  : >"${STATE}/ckms.log"
  printf 'populate-%s' "${P}" >"${STATE}/plain.txt"
  printf 'prefix=%s\n' "${P}" >"${STATE}/ids.env"
  local hex=706f70756c617465 u1 u2 s1 s2 s3 pub priv

  # Core-op gate
  op "Create:aes_256" owner_ckms sym keys create --number-of-bits 256 --algorithm aes --tag "${P}" "${P}_aes_256" || {
    echo "populate_db.sh: cannot create a basic AES key on ${URL} (connectivity or ckms/server wire incompatibility)" >&2
    exit 1
  }
  rec_obj "${P}_aes_256"

  # 1. Server
  op "DiscoverVersions" owner_ckms server discover-versions || true
  op "Query" owner_ckms server query || true
  op "Hash" owner_ckms hash --algorithm sha256 --data "${hex}" || true
  op "RNGRetrieve" owner_ckms rng retrieve --length 32 || true
  op "RNGSeed" owner_ckms rng seed --data "$(printf '%064d' 0 | tr 0 a)" || true
  op "Ping" kmip_raw Ping "$(raw_file ping '{"tag":"Ping","value":[]}')" || true
  op "Log" kmip_raw Log "$(raw_file log '{"tag":"Log","value":[{"tag":"LogMessage","type":"TextString","value":"populate_db"}]}')" || true
  op "GetConstraints" kmip_raw GetConstraints "$(raw_file constraints '{"tag":"GetConstraints","value":[]}')" || true
  {
    op "Login" kmip_raw Login "$(raw_file login '{"tag":"Login","value":[]}')" &&
      op "Logout" kmip_raw Logout "$(raw_file logout "$(jq -c '{tag:"Logout",value:[.value[]?|select(.tag=="Ticket")]}' <<<"${LAST}")")"
  } || true

  # 2. Symmetric
  op "Create:aes_128" owner_ckms sym keys create --number-of-bits 128 --tag "${P}" "${P}_aes_128" && rec_obj "${P}_aes_128" || true
  op "Create:aes_wrapped" owner_ckms sym keys create --wrapping-key-id "${P}_aes_256" --tag "${P}" "${P}_aes_wrapped" && rec_obj "${P}_aes_wrapped" || true
  op "Create:aes_rotating" owner_ckms sym keys create --rotation-interval 86400 --tag "${P}" "${P}_aes_rotating" && rec_obj "${P}_aes_rotating" || true
  local k
  for k in aes_split aes_rekey upg_aes aes_revoked upg_revoked aes_destroyed aes_removed; do
    op "Create:${k}" owner_ckms sym keys create --tag "${P}" "${P}_${k}" || true
  done
  cipher_sym "${P}_aes_256" || true
  cipher_sym "${P}_aes_wrapped" || true
  { op "Get:sym" export_by sym "${P}_aes_256" raw "${STATE}/aes_256.raw" &&
    record digest sym "${P}_aes_256" raw "$(compute_sha256 "${STATE}/aes_256.raw")"; } || true
  {
    op "Export:wrapped" owner_ckms sym keys export --key-id "${P}_aes_128" --key-format json-ttlv --wrap-key-id "${P}_aes_256" "${STATE}/aes_128.wrapped.json" &&
      op "Import:wrapped" owner_ckms sym keys import --key-format json-ttlv --tag "${P}" "${STATE}/aes_128.wrapped.json" "${P}_aes_imported_wrapped" &&
      rec_obj "${P}_aes_imported_wrapped"
  } || true
  {
    op "Create:mac_key" owner_ckms sym keys create --tag "${P}" "${P}_mac_key" &&
      op "SetAttribute:key-usage" owner_ckms attributes set --id "${P}_mac_key" --key-usage mac-generate --key-usage mac-verify &&
      rec_obj "${P}_mac_key" &&
      op "MAC" owner_ckms mac compute --mac-key-id "${P}_mac_key" --mode hmac --algorithm sha256 --data "${hex}" &&
      local mac &&
      mac="$(jf str_out | grep -Eo '[0-9a-fA-F]{32,}' | head -n1)" &&
      op "MACVerify" owner_ckms mac verify --mac-key-id "${P}_mac_key" --mode hmac --algorithm sha256 --data "${hex}" --mac "${mac}" &&
      record mac "${P}_mac_key" "${hex}" "${mac}"
  } || true
  op "DeriveKey" owner_ckms derive-key --password populate-pw --derivation-method pbkdf2 --salt 00112233445566778899aabbccddeeff --iteration-count 10000 --length 256 --derived-key-id "${P}_derived" && rec_obj "${P}_derived" || true
  {
    op "CreateSplitKey" owner_ckms sym keys create-split-key --key-id "${P}_aes_split" --total-parts 3 --method xor &&
      s1="$(jq -er '.unique_identifiers[0]' <<<"${LAST}")" && s2="$(jq -er '.unique_identifiers[1]' <<<"${LAST}")" && s3="$(jq -er '.unique_identifiers[2]' <<<"${LAST}")" &&
      rec_obj "${s1}" exists && rec_obj "${s2}" exists && rec_obj "${s3}" exists &&
      op "JoinSplitKey" owner_ckms sym keys join-split-key "${s1}" "${s2}" "${s3}" &&
      rec_obj "$(jf str_out | grep -Eo '[0-9a-f]{8}-[0-9a-f-]{27}' | tail -n1)" exists
  } || true
  op "ReKey:sym" owner_ckms sym keys re-key --key-id "${P}_aes_rekey" && rec_obj "$(jf unique_identifier)" exists || true
  rec_obj "${P}_upg_aes" exists || true
  op "Revoke:aes_revoked" owner_ckms sym keys revoke --key-id "${P}_aes_revoked" "populate revoke" && rec_obj "${P}_aes_revoked" || true
  op "Revoke:upg_revoked" owner_ckms sym keys revoke --key-id "${P}_upg_revoked" "populate revoke" && rec_obj "${P}_upg_revoked" exists || true
  {
    op "Revoke:aes_destroyed" owner_ckms sym keys revoke --key-id "${P}_aes_destroyed" "populate revoke" &&
      op "Destroy" owner_ckms sym keys destroy --key-id "${P}_aes_destroyed" && rec_obj "${P}_aes_destroyed"
  } || true
  {
    op "Revoke:aes_removed" owner_ckms sym keys revoke --key-id "${P}_aes_removed" "populate revoke" &&
      op "Destroy:remove" owner_ckms sym keys destroy --key-id "${P}_aes_removed" --remove &&
      record object "${P}_aes_removed" - absent
  } || true
  op "Get:revoked" owner_ckms sym keys export --key-id "${P}_aes_revoked" --allow-revoked --key-format raw "${STATE}/revoked.raw" || true

  # 3. Secret data and opaque objects
  op "Create:secret_seed" owner_ckms secret-data create --tag "${P}" "${P}_secret_seed" && rec_obj "${P}_secret_seed" || true
  op "Create:secret_pw" owner_ckms secret-data create --type password --value populate-secret --tag "${P}" "${P}_secret_pw" && rec_obj "${P}_secret_pw" &&
    digest_rec secret "${P}_secret_pw" raw || true
  op "Create:secret_wrapped" owner_ckms secret-data create --wrapping-key-id "${P}_aes_256" --tag "${P}" "${P}_secret_wrapped" && rec_obj "${P}_secret_wrapped" || true
  op "Create:opaque" owner_ckms opaque-object create --data "populate opaque" --id "${P}_opaque" --tag "${P}" && rec_obj "${P}_opaque" || true
  local reg
  reg="$(jq -nc --arg t "${P}" '{tag:"Register",value:[
    {tag:"ObjectType",type:"Enumeration",value:"SecretData"},
    {tag:"Attributes",value:[
      {tag:"ObjectType",type:"Enumeration",value:"SecretData"},
      {tag:"CryptographicUsageMask",type:"Integer",value:2},
      {tag:"Attribute",value:[
        {tag:"VendorIdentification",type:"TextString",value:"cosmian"},
        {tag:"AttributeName",type:"TextString",value:"tag"},
        {tag:"AttributeValue",type:"TextString",value:([$t]|tojson)}]}]},
    {tag:"SecretData",value:[
      {tag:"SecretDataType",type:"Enumeration",value:"Password"},
      {tag:"KeyBlock",value:[
        {tag:"KeyFormatType",type:"Enumeration",value:"Opaque"},
        {tag:"KeyValue",value:[{tag:"KeyMaterial",type:"ByteString",value:"DEADBEEFCAFE0123456789ABCDEF"}]}]}]}]}')"
  {
    op "Register" kmip_raw Register "$(raw_file register1 "${reg}")" &&
      u1="$(jq -er '.value[]|select(.tag=="UniqueIdentifier").value' <<<"${LAST}")" &&
      printf 'REGISTERED_UID=%s\n' "${u1}" >>"${STATE}/ids.env" &&
      op "Activate" owner_ckms secret-data activate --key-id "${u1}" && rec_obj "${u1}" exists
  } || true
  {
    op "Register:preactive" kmip_raw Register "$(raw_file register2 "${reg}")" &&
      u2="$(jq -er '.value[]|select(.tag=="UniqueIdentifier").value' <<<"${LAST}")" &&
      printf 'PREACTIVE_UID=%s\n' "${u2}" >>"${STATE}/ids.env" && rec_obj "${u2}" exists
  } || true

  # 4. RSA and EC
  local rk
  for rk in rsa rsa_wrapped rsa_rekey upg_rsa; do
    local wrap=()
    [ "${rk}" != rsa_wrapped ] || wrap=(--wrapping-key-id "${P}_aes_256")
    if op "Create:${rk}" owner_ckms rsa keys create --size_in_bits 2048 --tag "${P}" "${wrap[@]}" "${P}_${rk}"; then
      priv="$(jf private_key_unique_identifier)"
      pub="$(jf public_key_unique_identifier)"
      printf '%s=%s\n' "${rk}_PUB" "${pub}" >>"${STATE}/ids.env"
      if [ "${rk}" = upg_rsa ]; then
        rec_obj "${priv}" exists
        rec_obj "${pub}" exists
      elif [ "${rk}" != rsa_rekey ]; then
        rec_obj "${priv}"
        rec_obj "${pub}"
      else rec_obj "${priv}" exists; fi
    fi
  done
  RSA_PUB="$(sed -n 's/^rsa_PUB=//p' "${STATE}/ids.env")"
  {
    op "Sign:rsa" owner_ckms rsa sign --key-id "${P}_rsa" --output-file "${STATE}/rsa.sig" "${STATE}/plain.txt" &&
      op "SignatureVerify:rsa" owner_ckms rsa sign-verify --key-id "${RSA_PUB}" "${STATE}/plain.txt" "${STATE}/rsa.sig" &&
      record sig rsa "${RSA_PUB}" rsa.sig
  } || true
  {
    op "Encrypt:rsa" owner_ckms rsa encrypt --key-id "${RSA_PUB}" --encryption-algorithm ckm-rsa-pkcs-oaep --hashing-algorithm sha256 --output-file "${STATE}/rsa.enc" "${STATE}/plain.txt" &&
      op "Decrypt:rsa" owner_ckms rsa decrypt --key-id "${P}_rsa" --encryption-algorithm ckm-rsa-pkcs-oaep --hashing-algorithm sha256 --output-file "${STATE}/rsa.dec" "${STATE}/rsa.enc" &&
      op "Decrypt-check:rsa" cmp -s "${STATE}/plain.txt" "${STATE}/rsa.dec" &&
      record cipher rsa "${P}_rsa" rsa.enc owner
  } || true
  local curve
  for curve in p256 p384; do
    if op "Create:ec_${curve}" owner_ckms ec keys create --curve "nist-${curve}" --tag "${P}" "${P}_ec_${curve}"; then
      rec_obj "$(jf private_key_unique_identifier)"
      rec_obj "$(jf public_key_unique_identifier)"
      [ "${curve}" != p256 ] || printf 'ec_PUB=%s\n' "$(jf public_key_unique_identifier)" >>"${STATE}/ids.env"
    fi
  done
  EC_PUB="$(sed -n 's/^ec_PUB=//p' "${STATE}/ids.env")"
  {
    op "Sign:ec" owner_ckms ec sign --key-id "${P}_ec_p256" --output-file "${STATE}/ec.sig" "${STATE}/plain.txt" &&
      op "SignatureVerify:ec" owner_ckms ec sign-verify --key-id "${EC_PUB}" "${STATE}/plain.txt" "${STATE}/ec.sig" &&
      record sig ec "${EC_PUB}" ec.sig
  } || true
  op "ReKeyKeyPair" owner_ckms rsa keys re-key --key-id "${P}_rsa_rekey" && {
    rec_obj "$(jq -er '.private_key_unique_identifier // .unique_identifier' <<<"${LAST}")" exists || true
  } || true
  digest_rec rsa "${P}_rsa" pkcs8-der || true
  {
    op "Export:ec" owner_ckms ec keys export --key-id "${P}_ec_p256" --key-format pkcs8-pem "${STATE}/ec.pem" &&
      op "Import:ec" owner_ckms ec keys import --key-format pem --tag "${P}" "${STATE}/ec.pem" "${P}_ec_imported" &&
      rec_obj "${P}_ec_imported"
  } || true
  if [ "${VARIANT}" = non-fips ]; then
    op "Create:ed25519" owner_ckms ec keys create --curve ed25519 --tag "${P}" "${P}_ed25519" && rec_obj "$(jf private_key_unique_identifier)" && rec_obj "$(jf public_key_unique_identifier)" || true
    op "Create:mlkem" owner_ckms pqc keys create --algorithm ml-kem-768 --tag "${P}" && rec_obj "$(jf private_key_unique_identifier)" && rec_obj "$(jf public_key_unique_identifier)" || true
    if op "Create:mldsa" owner_ckms pqc keys create --algorithm ml-dsa-65 --tag "${P}"; then
      local mlpub mlpriv
      mlpriv="$(jf private_key_unique_identifier)"
      rec_obj "${mlpriv}"
      mlpub="$(jf public_key_unique_identifier)"
      rec_obj "${mlpub}"
      {
        op "Sign:pqc" owner_ckms pqc sign --key-id "${mlpriv}" --output-file "${STATE}/pqc.sig" "${STATE}/plain.txt" &&
          op "SignatureVerify:pqc" owner_ckms pqc sign-verify --key-id "${mlpub}" "${STATE}/plain.txt" "${STATE}/pqc.sig" &&
          record sig pqc "${mlpub}" pqc.sig
      } || true
    fi
  fi

  # 5. Certificates
  printf '[ v3_ca ]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,crlSign\n' >"${STATE}/v3_ca.ext"
  op "Certify:ca" owner_ckms certificates certify --generate-key-pair --algorithm rsa2048 --subject-name "CN=Populate Root CA" --certificate-extensions "${STATE}/v3_ca.ext" --certificate-id "${P}_ca" --tag "${P}" && rec_obj "${P}_ca" || true
  local lf
  for lf in leaf leaf_revoked; do
    op "Certify:${lf}" owner_ckms certificates certify --generate-key-pair --algorithm nist-p256 --subject-name "CN=Populate ${lf}" --issuer-certificate-id "${P}_ca" --certificate-id "${P}_${lf}" --tag "${P}" && rec_obj "${P}_${lf}" || true
  done
  op "Certify:public-key" owner_ckms certificates certify --public-key-id-to-certify "${RSA_PUB}" --subject-name "CN=Populate RSA" --issuer-certificate-id "${P}_ca" --certificate-id "${P}_rsa_cert" --tag "${P}" && rec_obj "${P}_rsa_cert" || true
  op "ReCertify" kmip_raw ReCertify "$(raw_tpl recertify recertify_old_cert_stays_active/step3_recertify.json old_cert_id "${P}_leaf")" &&
    rec_obj "$(jq -er '.value[]|select(.tag=="UniqueIdentifier").value' <<<"${LAST}")" exists || true
  op "Certify:renew" owner_ckms certificates certify --certificate-id-to-re-certify "${P}_rsa_cert" || true
  op "Validate" owner_ckms certificates validate --certificate-id "${P}_ca" || true
  op "Import:cert" owner_ckms certificates import --format pem --tag "${P}" "${CERTS}/server/kmserver.acme.com.crt" "${P}_imported_cert" && rec_obj "${P}_imported_cert" || true
  digest_rec cert "${P}_ca" pem || true
  if [ "${VARIANT}" = non-fips ]; then
    # FIPS builds can neither read nor write PKCS#12 (PKCS12KDF is not approved).
    local leaf_priv
    leaf_priv="$(owner_ckms attributes get --id "${P}_leaf_revoked" --attribute LinkType | jq -er '.attributes.PrivateKeyLink')" &&
      op "Export:pkcs12" owner_ckms certificates export --certificate-id "${leaf_priv}" --format pkcs12 --pkcs12-password populate "${STATE}/leaf.p12" || true
    op "Import:pkcs12" owner_ckms certificates import --format pkcs12 --pkcs12-password password --tag "${P}" "${CERTS}/server/kmserver.acme.com.p12" "${P}_p12" && rec_obj "${P}_p12" exists || true
  fi
  op "Revoke:cert" owner_ckms certificates revoke --certificate-id "${P}_leaf_revoked" "populate" && rec_obj "${P}_leaf_revoked" || true
  op "GenerateCRL" owner_ckms certificates generate-crl --certificate-id "${P}_ca" --output-file "${STATE}/ca.crl" || true

  # 6. Attributes
  op "SetAttribute:name" owner_ckms attributes set --id "${P}_aes_128" --name populate-name || true
  op "SetAttribute:vendor" owner_ckms attributes set --id "${P}_aes_128" --vendor-identification cosmian --attribute-name populate_attr --attribute-value 01020304 || true
  op "SetAttribute:link" owner_ckms attributes set --id "${P}_aes_128" --parent-id "${P}_aes_256" || true
  op "ModifyAttribute" owner_ckms attributes modify --id "${P}_aes_128" --name populate-name-modified || true
  op "DeleteAttribute" owner_ckms attributes delete --id "${P}_aes_128" --parent-id "${P}_aes_256" || true
  op "GetAttributes" owner_ckms attributes get --id "${P}_aes_128" || true
  op "AddAttribute" kmip_raw AddAttribute "$(raw_tpl addattr attribute_management/step06_add_attribute.json key_id "${P}_aes_128")" || true
  op "GetAttributeList" kmip_raw GetAttributeList "$(raw_tpl attrlist attribute_management/step03_get_attribute_list.json key_id "${P}_aes_128")" || true
  op "Check" kmip_raw Check "$(raw_tpl check check/step2_check.json key_id "${P}_aes_128")" || true

  # 7. Access rights
  {
    op "Grant" owner_ckms access-rights grant user.client@acme.com --object-uid "${P}_aes_256" encrypt decrypt get &&
      op "ListAccess" owner_ckms access-rights list "${P}_aes_256" &&
      record access "${P}_aes_256" "$(jq -c '.accesses | sort_by(.user_id)' <<<"${LAST}")" &&
      op "Encrypt:grantee" user_ckms sym encrypt --key-id "${P}_aes_256" --output-file "${STATE}/grantee.enc" "${STATE}/plain.txt" &&
      record cipher sym "${P}_aes_256" grantee.enc grantee
  } || true
  if ! user_ckms sym keys export --key-id "${P}_aes_128" --key-format raw "${STATE}/denied.raw" >/dev/null 2>&1; then
    printf 'Deny:grantee\tPASS\n' >>"${STATE}/ops.tsv"
    record deny "${P}_aes_128"
  else
    echo "populate_db.sh: grantee unexpectedly exported ${P}_aes_128" >&2
    exit 1
  fi

  # 8. Locate (last)
  if op "Locate" owner_ckms locate --tag "${P}"; then
    jq -r '.unique_identifiers[]' <<<"${LAST}" | sort >"${STATE}/locate.txt"
    record locate "${P}" locate.txt
  fi

  finalize
  [ -z "${MIGRATED}" ] || migrated_usage
}

# Exercise objects migrated from the old release (only those present in the old state).
migrated_usage() {
  local old_p
  old_p="$(sed -n 's/^prefix=//p' "${MIGRATED}/ids.env" | head -n1)"
  has_old() { cut -f2 "${MIGRATED}/artifacts.tsv" | grep -qx "${old_p}_$1"; }
  na() { printf '%s\tN/A\n' "$1" >>"${STATE}/ops.tsv"; }
  if has_old upg_aes; then
    op "Migrated:ReKey:sym" owner_ckms sym keys re-key --key-id "${old_p}_upg_aes" &&
      local nk && nk="$(jf unique_identifier)" &&
      op "Migrated:Encrypt" owner_ckms sym encrypt --key-id "${nk}" --output-file "${STATE}/mig.enc" "${STATE}/plain.txt" &&
      op "Migrated:Decrypt" owner_ckms sym decrypt --key-id "${nk}" --output-file "${STATE}/mig.dec" "${STATE}/mig.enc" || true
  else na "Migrated:ReKey:sym"; fi
  if has_old upg_rsa; then op "Migrated:ReKey:rsa" owner_ckms rsa keys re-key --key-id "${old_p}_upg_rsa" || true; else na "Migrated:ReKey:rsa"; fi
  local pre
  pre="$(sed -n 's/^PREACTIVE_UID=//p' "${MIGRATED}/ids.env" | head -n1)"
  if [ -n "${pre}" ]; then op "Migrated:Activate" owner_ckms secret-data activate --key-id "${pre}" || true; else na "Migrated:Activate"; fi
  if has_old upg_revoked; then op "Migrated:Destroy" owner_ckms sym keys destroy --key-id "${old_p}_upg_revoked" || true; else na "Migrated:Destroy"; fi
  if has_old aes_256; then op "Migrated:SetAttribute" owner_ckms attributes set --id "${old_p}_aes_256" --name migrated-name || true; else na "Migrated:SetAttribute"; fi
  if has_old ca; then
    op "Migrated:Certify" owner_ckms certificates certify --generate-key-pair --algorithm nist-p256 --subject-name "CN=Post-upgrade leaf" --issuer-certificate-id "${old_p}_ca" --certificate-id "${P}_leaf_from_migrated_ca" || true
  else na "Migrated:Certify"; fi
}

verify() {
  [ -f "${STATE}/artifacts.tsv" ] || print_error "missing ${STATE}/artifacts.tsv"
  local fails=0 kind a b c d actual out
  fail() {
    echo "VERIFY FAIL $1 $2: expected=$3 actual=$4" >&2
    fails=$((fails + 1))
  }
  while IFS=$'\t' read -r kind a b c d <&3; do
    case "${kind}" in
      object)
        case "${c}" in
          full)
            actual="$(state_of "${a}" 2>/dev/null || echo UNREADABLE)"
            if [ "${LEGACY_STATE}" = 1 ]; then # shortcut: maps both sides, so a real PreActive->Active bug on old objects is masked
              b="${b/PreActive/Active}" actual="${actual/PreActive/Active}"
              b="${b/Deactivated/Destroyed}" actual="${actual/Deactivated/Destroyed}"
            fi
            [ "${actual}" = "${b}" ] || fail object "${a}" "${b}" "${actual}"
            ;;
          exists) state_of "${a}" >/dev/null 2>&1 || fail object "${a}" present missing ;;
          absent) ! state_of "${a}" >/dev/null 2>&1 || fail object "${a}" absent present ;;
        esac
        ;;
      digest)
        out="${STATE}/verify.digest.tmp"
        rm -f "${out}"
        if export_by "${a}" "${b}" "${c}" "${out}" >/dev/null 2>&1; then
          actual="$(compute_sha256 "${out}")"
        else actual=EXPORT_FAILED; fi
        [ "${actual}" = "${d}" ] || fail digest "${b}" "${d}" "${actual}"
        ;;
      cipher)
        [ "${LEGACY_NESTED}" = 1 ] && [[ "${b}" == *_wrapped ]] && continue
        out="${STATE}/verify.dec.tmp"
        rm -f "${out}"
        if [ "${a}" = rsa ]; then
          owner_ckms rsa decrypt --key-id "${b}" --encryption-algorithm ckm-rsa-pkcs-oaep --hashing-algorithm sha256 --output-file "${out}" "${STATE}/${c}" >/dev/null 2>&1 || true
        elif [ "${d}" = grantee ]; then
          user_ckms sym decrypt --key-id "${b}" --output-file "${out}" "${STATE}/${c}" >/dev/null 2>&1 || true
        else
          owner_ckms sym decrypt --key-id "${b}" --output-file "${out}" "${STATE}/${c}" >/dev/null 2>&1 || true
        fi
        cmp -s "${out}" "${STATE}/plain.txt" || fail cipher "${b}" "plaintext" "decrypt mismatch (${c})"
        ;;
      sig) owner_ckms "${a}" sign-verify --key-id "${b}" "${STATE}/plain.txt" "${STATE}/${c}" >/dev/null 2>&1 || fail sig "${b}" valid invalid ;;
      mac) owner_ckms mac verify --mac-key-id "${a}" --mode hmac --algorithm sha256 --data "${b}" --mac "${c}" >/dev/null 2>&1 || fail mac "${a}" valid invalid ;;
      access)
        actual="$(owner_ckms access-rights list "${a}" 2>/dev/null | jq -c '.accesses | sort_by(.user_id)' 2>/dev/null || echo ERR)"
        [ "${actual}" = "${b}" ] || fail access "${a}" "${b}" "${actual}"
        ;;
      deny) ! user_ckms sym keys export --key-id "${a}" --key-format raw "${STATE}/verify.deny.tmp" >/dev/null 2>&1 || fail deny "${a}" refused exported ;;
      locate)
        local absent cur
        absent="$(awk -F'\t' '$1=="object" && $4=="absent" {print $2}' "${STATE}/artifacts.tsv" | sort)"
        cur="$(owner_ckms locate --tag "${a}" 2>/dev/null | jq -r '.unique_identifiers[]?' | sort)" || true
        actual=""
        local m
        # Destroyed objects legitimately leave Locate results (e.g. destroyed by the post-upgrade usage step).
        # Pre-5.13 Redis: ReCertify dropped the user tags from the stored record but left them in the Findex index,
        # so Locate found the object; the upgrade re-indexes it from the record. Tolerated when the record lacks the tag.
        for m in $(comm -23 <(comm -23 <(sort "${STATE}/${b}") <(printf '%s\n' "${absent}")) <(printf '%s\n' "${cur}")); do
          [ "$(state_of "${m}" 2>/dev/null || true)" = Destroyed ] && continue
          { [ "${LEGACY_STATE}" = 1 ] || [ "${LEGACY_LOCATE}" = 1 ]; } && ! has_tag "${m}" "${a}" && continue
          actual+="${m} "
        done
        [ -z "${actual}" ] || fail locate "${a}" "all located objects" "missing ${actual}"
        ;;
    esac
  done 3<"${STATE}/artifacts.tsv"
  [ "${fails}" -eq 0 ] || exit 1
  echo "populate_db.sh: verify OK (${STATE})"
}

"${MODE}"
