#!/usr/bin/env bash
# GnuPG <-> Cosmian KMS OpenPGP interoperability tests.
#
# Drives crate/test_kms_server/src/pgp_gnupg_tests.rs, which starts an in-process KMS
# server (start_default_test_kms_server) and shells out to gpg in an isolated GNUPGHOME.
#
# Usage:
#   mise test:gnupg
#   bash .mise/scripts/test/test_gnupg.sh --variant non-fips
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"
setup_test_logging

if ! command -v gpg >/dev/null 2>&1; then
  echo "Skipping GnuPG interoperability tests: gpg not in PATH."
  echo "Install gnupg and re-run to enable these tests."
  exit 0
fi

gpg --version | head -1

# OpenPGP support only compiles with the non-fips feature.
cargo test -p test_kms_server --features non-fips -- pgp_gnupg --nocapture --test-threads=1

echo "GnuPG OpenPGP interoperability tests passed."
