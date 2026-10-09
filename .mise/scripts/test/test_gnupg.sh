#!/usr/bin/env bash
# GnuPG <-> Cosmian KMS OpenPGP interoperability tests.
#
# Runs both the Rust battle-testing suite (pgp_gnupg_tests) and the
# end-to-end CLI <-> gpg integration scenario against a running KMS server.
#
# Usage:
#   mise test:gnupg
#   bash .mise/scripts/test/test_gnupg.sh --variant non-fips
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/pkcs11_helpers.sh"
source "${SCRIPT_DIR}/../../lib/kms_server.sh"

init_build_env "$@"
setup_test_logging

if ! has_cmd gpg; then
  echo "GnuPG interoperability tests: gpg not in PATH."
  echo "Install gnupg and re-run to enable these tests."
  exit 1
fi

echo "========================================="
echo "Running GnuPG OpenPGP Interop Suite"
echo "========================================="
gpg --version | head -1

# OpenPGP support only compiles with the non-fips feature.
export VARIANT="non-fips"
kms_build_all

echo "── Part 1: Rust GnuPG interoperability tests ──"
cargo test -p test_kms_server --features non-fips -- pgp_gnupg --nocapture --test-threads=1
cargo test -p ckms --features non-fips test_gpg_key_import_export_accepts_armored_and_binary_keys -- --nocapture

echo "── Part 2: CLI <-> GnuPG end-to-end integration ──"

KMS_PORT=$(kms_pick_free_port)
SQLITE_DIR=$(mktemp -d "/tmp/kms-pgp-sqlite-XXXXXX")
kms_write_config "${KMS_PORT}" "${SQLITE_DIR}"
kms_start_from_bin "$(get_kms_bin)"
kms_write_ckms_conf

GNUPGHOME=$(mktemp -d "/tmp/kms-gnupg-XXXXXX")
chmod 700 "${GNUPGHOME}"
export GNUPGHOME

TEST_WORK_DIR=$(mktemp -d "/tmp/kms-pgp-work-XXXXXX")

cleanup() {
  kms_stop
  rm -rf "${GNUPGHOME}" "${TEST_WORK_DIR}" "${SQLITE_DIR}"
}
trap cleanup EXIT

CKMS_BIN="$(get_ckms_bin)"
GPG_OPTS=(--batch --yes --no-tty --pinentry-mode loopback --passphrase "")

cd "${TEST_WORK_DIR}"
echo "Hello, OpenPGP CLI interop world!" >data.txt

echo ">>> Subtest 2.1: KMS -> GnuPG (Ed25519)"
# 1. Create key in KMS via ckms pgp
"${CKMS_BIN}" --url "${KMS_URL}" pgp keys create --algorithm ed25519 --user-id "CI <ci@example.com>" --tag pgp-ci

# 2. Export the secret key in both GnuPG encodings and import both into GnuPG.
"${CKMS_BIN}" --url "${KMS_URL}" pgp export --tag pgp-ci --key-format pgp-secret sec.asc
"${CKMS_BIN}" --url "${KMS_URL}" pgp export --tag pgp-ci --key-format pgp-secret-binary sec.pgp
gpg "${GPG_OPTS[@]}" --import sec.asc
gpg "${GPG_OPTS[@]}" --import sec.pgp
# 3. KMS signs, gpg verifies
"${CKMS_BIN}" --url "${KMS_URL}" pgp sign --tag pgp-ci -o data.sig data.txt
gpg "${GPG_OPTS[@]}" --verify data.sig data.txt

# 4. KMS encrypts, gpg decrypts
"${CKMS_BIN}" --url "${KMS_URL}" pgp encrypt --tag pgp-ci -o msg.bin data.txt
gpg "${GPG_OPTS[@]}" --decrypt msg.bin >out_kms.txt
diff -u data.txt out_kms.txt

# 5. KMS encrypts to the default <FILE>.gpg, then KMS decrypts that .gpg file.
# The .gpg file must be a binary OpenPGP message (gpg can list its packets).
echo ">>> Subtest 2.1.5: KMS encrypt -> KMS decrypt of the .gpg file"
"${CKMS_BIN}" --url "${KMS_URL}" pgp encrypt --tag pgp-ci data.txt
test -s data.gpg
gpg "${GPG_OPTS[@]}" --list-packets data.gpg >/dev/null
"${CKMS_BIN}" --url "${KMS_URL}" pgp decrypt --tag pgp-ci -o out_kms_roundtrip.txt data.gpg
diff -u data.txt out_kms_roundtrip.txt

echo ">>> Subtest 2.2: GnuPG -> KMS"
# 1. Generate key in gpg with encryption subkey and explicit preferences
cat <<'EOF' | gpg "${GPG_OPTS[@]}" --generate-key
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign,cert
Subkey-Type: ecdh
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Preferences: AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed
Name-Real: GPG User
Name-Email: gpg@example.com
Expire-Date: 0
%no-protection
%commit
EOF

# 2. Export secret key and import into KMS
gpg "${GPG_OPTS[@]}" --armor --export-secret-keys "gpg@example.com" >gpg-sec.asc
"${CKMS_BIN}" --url "${KMS_URL}" pgp import --key-format pgp gpg-sec.asc gpg-imported
gpg --export-secret-keys "gpg@example.com" >gpg-sec.pgp
"${CKMS_BIN}" --url "${KMS_URL}" pgp import --key-format pgp gpg-sec.pgp gpg-imported-binary

for key_uid in gpg-imported gpg-imported-binary; do
  for encoding in armored binary; do
    if [ "${encoding}" = "armored" ]; then
      key_format=pgp-secret
      extension=asc
    else
      key_format=pgp-secret-binary
      extension=pgp
    fi
    output_file="${key_uid}-${encoding}.${extension}"
    "${CKMS_BIN}" --url "${KMS_URL}" pgp export -k "${key_uid}" --key-format "${key_format}" "${output_file}"
    gpg "${GPG_OPTS[@]}" --import "${output_file}"
  done
done

gpg "${GPG_OPTS[@]}" --armor --export "gpg@example.com" >gpg-pub.asc
gpg "${GPG_OPTS[@]}" --export "gpg@example.com" >gpg-pub.pgp
for input_encoding in armored binary; do
  if [ "${input_encoding}" = "armored" ]; then
    key_file=gpg-pub.asc
  else
    key_file=gpg-pub.pgp
  fi
  key_uid="gpg-public-${input_encoding}"
  "${CKMS_BIN}" --url "${KMS_URL}" pgp import --key-format pgp "${key_file}" "${key_uid}"
  for output_encoding in armored binary; do
    if [ "${output_encoding}" = "armored" ]; then
      key_format=pgp-public
      extension=asc
    else
      key_format=pgp-public-binary
      extension=pgp
    fi
    output_file="${key_uid}-${output_encoding}.${extension}"
    "${CKMS_BIN}" --url "${KMS_URL}" pgp export -k "${key_uid}" --key-format "${key_format}" "${output_file}"
    gpg "${GPG_OPTS[@]}" --import "${output_file}"
  done
done

# 3. gpg encrypts, KMS decrypts
echo ">>> Subtest 2.2.3: encrypt/decrypt"
gpg "${GPG_OPTS[@]}" --trust-model always --recipient "gpg@example.com" --output msg.gpg --encrypt data.txt
"${CKMS_BIN}" --url "${KMS_URL}" pgp decrypt -k gpg-imported -o out.txt msg.gpg
diff -u data.txt out.txt

# 3b. KMS encrypts with the imported key to a .gpg file, KMS and gpg both decrypt it
echo ">>> Subtest 2.2.3b: KMS encrypt -> KMS and gpg decrypt of the .gpg file"
"${CKMS_BIN}" --url "${KMS_URL}" pgp encrypt -k gpg-imported -o imported.gpg data.txt
gpg "${GPG_OPTS[@]}" --list-packets imported.gpg >/dev/null
"${CKMS_BIN}" --url "${KMS_URL}" pgp decrypt -k gpg-imported -o out_imported_kms.txt imported.gpg
diff -u data.txt out_imported_kms.txt
gpg "${GPG_OPTS[@]}" --decrypt imported.gpg >out_imported_gpg.txt
diff -u data.txt out_imported_gpg.txt

# 4. gpg signs (binary detached), KMS verifies
echo ">>> Subtest 2.2.4: sign-verify binary"
gpg "${GPG_OPTS[@]}" --local-user "gpg@example.com" --detach-sign --output gpg.sig data.txt
VERIFY_OUT=$("${CKMS_BIN}" --url "${KMS_URL}" pgp sign-verify -k gpg-imported data.txt gpg.sig)
echo "${VERIFY_OUT}"
echo "${VERIFY_OUT}" | grep -q "is Valid"

# 5. gpg signs (ASCII armor detached), KMS verifies
echo ">>> Subtest 2.2.5: sign-verify armor"
gpg "${GPG_OPTS[@]}" --local-user "gpg@example.com" --armor --detach-sign --output gpg.asc data.txt
VERIFY_ARM_OUT=$("${CKMS_BIN}" --url "${KMS_URL}" pgp sign-verify -k gpg-imported data.txt gpg.asc)
echo "${VERIFY_ARM_OUT}"
echo "${VERIFY_ARM_OUT}" | grep -q "is Valid"

echo "GnuPG OpenPGP interoperability tests passed."
