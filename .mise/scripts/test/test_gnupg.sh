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

echo "── Part 1: Rust battle-testing interop matrix ──"
cargo test -p test_kms_server --features non-fips -- pgp_gnupg --nocapture --test-threads=1

echo "── Part 2: CLI <-> GnuPG end-to-end integration ──"
kms_build_all

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

# 2. Export secret key and import into gpg (so gpg can decrypt messages encrypted to this key)
"${CKMS_BIN}" --url "${KMS_URL}" pgp export --tag pgp-ci --key-format pgp-secret sec.asc
gpg "${GPG_OPTS[@]}" --import sec.asc
# 3. KMS signs, gpg verifies
"${CKMS_BIN}" --url "${KMS_URL}" pgp sign --tag pgp-ci -o data.sig data.txt
gpg "${GPG_OPTS[@]}" --verify data.sig data.txt

# 4. KMS encrypts, gpg decrypts
"${CKMS_BIN}" --url "${KMS_URL}" pgp encrypt --tag pgp-ci -o msg.bin data.txt
gpg "${GPG_OPTS[@]}" --decrypt msg.bin >out_kms.txt
diff -u data.txt out_kms.txt

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

# 3. gpg encrypts, KMS decrypts
echo ">>> Subtest 2.2.3: encrypt/decrypt"
gpg "${GPG_OPTS[@]}" --trust-model always --recipient "gpg@example.com" --output msg.gpg --encrypt data.txt
"${CKMS_BIN}" --url "${KMS_URL}" pgp decrypt -k gpg-imported -o out.txt msg.gpg
diff -u data.txt out.txt

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
