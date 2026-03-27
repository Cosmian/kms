#!/usr/bin/env bash
# LUKS + Cosmian KMS PKCS#11 integration tests
#
# This script validates the libcosmian_pkcs11 library as a PKCS#11 provider
# for LUKS disk-encryption key management in two phases:
#
#   Part 1 — Rust unit tests (always executed):
#     test_kms_client_and_backend  — verifies certificate and private key
#                                    discovery for the 'disk-encryption' tag
#     test_generate_key_encrypt_decrypt — verifies AES symmetric key discovery
#                                         and AES-CBC encryption/decryption via
#                                         the full PKCS#11 C_FindObjects path
#
#   Part 2 — Shell integration test:
#     Starts a local KMS server, generates a fresh RSA self-signed certificate,
#     imports it as PKCS#12 tagged 'disk-encryption', and imports two AES-128
#     volume keys also tagged 'disk-encryption'.
#
#     On Linux with pkcs11-tool (OpenSC) available, the PKCS#11 library is
#     queried directly to confirm certificates and secret keys are visible.
#     On macOS (no pkcs11-tool), the round-trip is verified by checking ckms
#     can retrieve the objects and the library initialises without errors.
#
# Usage:
#   bash .github/scripts/nix.sh test luks
#   bash .github/scripts/nix.sh --variant non-fips test luks
#   bash .github/scripts/test_luks.sh
set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging

echo "============================================="
echo "Running LUKS PKCS#11 KMS integration tests"
echo "============================================="

# The LUKS tests must always use non-fips because the test module in
# crate/clients/pkcs11/provider/src/lib.rs is gated with
#   #[cfg(feature = "non-fips")]
# AES-128 CBC and RSA-2048 keys used for LUKS are FIPS-approved algorithms,
# but the in-process test server helpers only compile under non-fips.
if [ "${VARIANT}" != "non-fips" ]; then
  echo "Note: LUKS PKCS#11 tests require non-fips (test helpers only compile with non-fips feature)."
fi
VARIANT="non-fips"
FEATURES_FLAG=(--features non-fips)

# ── Part 1: Rust unit tests ──────────────────────────────────────────────────
echo "============================================="
echo "Part 1: LUKS disk-encryption Rust unit tests"
echo "============================================="

# Build the ckms CLI first so test executables that call `Command::cargo_bin("ckms")`
# find a compiled binary with matching feature flags.
cargo build -p ckms "${FEATURES_FLAG[@]}"

# Run the LUKS-related unit tests. The Rust test harness accepts a single
# substring filter; run them separately to keep output clean.
cargo test \
  -p cosmian_pkcs11 \
  "${FEATURES_FLAG[@]}" \
  -- test_kms_client_and_backend \
  --nocapture

cargo test \
  -p cosmian_pkcs11 \
  "${FEATURES_FLAG[@]}" \
  -- test_generate_key_encrypt_decrypt \
  --nocapture

echo "LUKS disk-encryption Rust unit tests passed."

# ── Part 2: Shell integration test ──────────────────────────────────────────
echo "============================================="
echo "Part 2: Shell integration test"
echo "============================================="

# Require openssl to generate a self-signed certificate.
if ! command -v openssl >/dev/null 2>&1; then
  echo "Skipping shell integration test: openssl not in PATH."
  echo "All LUKS PKCS#11 tests passed (Rust unit tests only)."
  exit 0
fi

# Build PKCS#11 library, KMS server, and ckms CLI.
cargo build \
  -p cosmian_pkcs11 \
  -p cosmian_kms_server \
  -p ckms \
  "${FEATURES_FLAG[@]}"

cargo_target_dir="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
kms_bin="$cargo_target_dir/debug/cosmian_kms"
ckms_bin="$cargo_target_dir/debug/ckms"

# Platform-specific PKCS#11 library extension.
if [ "$(uname)" = "Darwin" ]; then
  pkcs11_lib="$cargo_target_dir/debug/libcosmian_pkcs11.dylib"
else
  pkcs11_lib="$cargo_target_dir/debug/libcosmian_pkcs11.so"
fi

if [ ! -f "$pkcs11_lib" ]; then
  echo "ERROR: PKCS#11 library not found: $pkcs11_lib" >&2
  exit 1
fi
echo "Using PKCS#11 library: $pkcs11_lib"

# ── Start a dedicated KMS server ─────────────────────────────────────────────
tmp_dir=$(mktemp -d)
kms_pid=""

_cleanup_luks_test() {
  [ -n "${kms_pid:-}" ] && {
    kill "$kms_pid" 2>/dev/null || true
    wait "$kms_pid" 2>/dev/null || true
  }
  rm -rf "${tmp_dir:-}"
}
trap _cleanup_luks_test EXIT

# Use a dedicated port to avoid collisions with the Rust test-server (9998),
# the SoftHSM2 test (19998), and the OpenSSH test (19997).
kms_port=19996
sqlite_path="$tmp_dir/kms-data"

# Force an explicit config to avoid host defaults and ensure deterministic
# startup behavior in CI and local nix-shell runs.
kms_conf="$tmp_dir/kms.toml"
cat >"$kms_conf" <<EOF
default_username = "admin"

[http]
hostname = "127.0.0.1"
port = ${kms_port}

[db]
database_type = "sqlite"
sqlite_path = "${sqlite_path}"
clear_database = true

[logging]
rust_log = "info,cosmian_kms=info"
ansi_colors = false
EOF

"$kms_bin" \
  --config "$kms_conf" \
  >"$tmp_dir/kms.log" 2>&1 &
kms_pid=$!

kms_wait_ready "http://127.0.0.1:${kms_port}/" "$kms_pid" "$tmp_dir/kms.log" 120

ckms_args=(--url "http://127.0.0.1:${kms_port}")

# ── Generate a fresh self-signed RSA certificate ─────────────────────────────
p12_password="cosmian_luks_test"
echo "Generating RSA-2048 self-signed certificate for LUKS enrollment..."
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 \
  -out "$tmp_dir/private_key.pem" 2>/dev/null

openssl req -new -x509 \
  -key "$tmp_dir/private_key.pem" \
  -out "$tmp_dir/cert.pem" \
  -days 1 \
  -subj "/CN=luks-test/O=Cosmian/C=FR" 2>/dev/null

openssl pkcs12 \
  -export \
  -out "$tmp_dir/certificate.p12" \
  -inkey "$tmp_dir/private_key.pem" \
  -in "$tmp_dir/cert.pem" \
  -passout "pass:$p12_password" 2>/dev/null

echo "Generated PKCS#12 at $tmp_dir/certificate.p12"

# ── Import PKCS#12 with disk-encryption tag ──────────────────────────────────
echo "Importing PKCS#12 into KMS with tag 'disk-encryption'..."
p12_import_output=$(
  "$ckms_bin" "${ckms_args[@]}" certificates import \
    --format pkcs12 \
    --pkcs12-password "$p12_password" \
    --tag disk-encryption \
    --tag luks_volume \
    "$tmp_dir/certificate.p12" 2>&1
)
echo "$p12_import_output"

# The private key ID is printed as "The private key in the PKCS12 file was
# imported with id: <UUID>". Extract it to confirm the import succeeded.
p12_privkey_id=$(echo "$p12_import_output" | grep -o '[0-9a-f-]\{36\}' | head -1 || true)
if [ -z "${p12_privkey_id:-}" ]; then
  # Try alternate single-line output format
  p12_privkey_id=$(echo "$p12_import_output" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1 || true)
fi
if [ -z "${p12_privkey_id:-}" ]; then
  echo "ERROR: could not extract private key ID from PKCS#12 import output." >&2
  echo "Import output: $p12_import_output" >&2
  exit 1
fi
echo "Imported PKCS#12 private key with id: $p12_privkey_id"

# ── Import two AES-128 symmetric volume keys ─────────────────────────────────
echo "Creating AES-128 symmetric keys tagged 'disk-encryption' for vol1 and vol2..."
vol1_id=$("$ckms_bin" "${ckms_args[@]}" sym keys create \
  --algorithm aes \
  --number-of-bits 128 \
  --tag disk-encryption \
  --tag vol1 2>&1 | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
echo "vol1 key id: $vol1_id"

vol2_id=$("$ckms_bin" "${ckms_args[@]}" sym keys create \
  --algorithm aes \
  --number-of-bits 128 \
  --tag disk-encryption \
  --tag vol2 2>&1 | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
echo "vol2 key id: $vol2_id"

# ── Write PKCS#11 client config ────────────────────────────────────────────────
ckms_conf="$tmp_dir/ckms.toml"
cat >"$ckms_conf" <<EOF
[http_config]
server_url = "http://127.0.0.1:${kms_port}"
EOF
echo "Wrote PKCS#11 config: $ckms_conf"

# ── Verify via pkcs11-tool (Linux only) ──────────────────────────────────────
if command -v pkcs11-tool >/dev/null 2>&1; then
  echo "============================================="
  echo "pkcs11-tool: listing objects from KMS token"
  echo "============================================="

  set +x
  pkcs11_output=$(
    CKMS_CONF="$ckms_conf" \
      COSMIAN_PKCS11_LOGGING_LEVEL="warn" \
      pkcs11-tool \
        --module "$pkcs11_lib" \
        --login --login-type so \
        --list-objects 2>&1 || true
  )
  set -x

  echo "--- pkcs11-tool --list-objects output ---"
  echo "$pkcs11_output"
  echo "-----------------------------------------"

  # Expect at least: 1 certificate, 1 private key, 2 secret keys.
  cert_count=$(echo "$pkcs11_output" | grep -ic "Certificate Object" || true)
  privkey_count=$(echo "$pkcs11_output" | grep -ic "Private Key Object" || true)
  seckey_count=$(echo "$pkcs11_output" | grep -ic "Secret Key Object" || true)

  if [ "$cert_count" -lt 1 ]; then
    echo "ERROR: expected at least 1 certificate in PKCS#11 output, got $cert_count." >&2
    exit 1
  fi
  if [ "$privkey_count" -lt 1 ]; then
    echo "ERROR: expected at least 1 private key in PKCS#11 output, got $privkey_count." >&2
    exit 1
  fi
  if [ "$seckey_count" -lt 2 ]; then
    echo "ERROR: expected at least 2 secret keys (vol1, vol2) in PKCS#11 output, got $seckey_count." >&2
    exit 1
  fi

  echo "OK: pkcs11-tool found $cert_count certificate(s), $privkey_count private key(s), $seckey_count secret key(s)."
else
  echo "pkcs11-tool not available (macOS or pkcs11-tool not installed); skipping object listing via pkcs11-tool."

  # ── Verify via ckms locate commands ──────────────────────────────────────
  # Confirm that objects are correctly stored by listing them through ckms locate.
  echo "Verifying objects via ckms locate..."

  all_disk_ids=$(
    "$ckms_bin" "${ckms_args[@]}" locate --tag disk-encryption 2>&1 || true
  )
  echo "Objects with tag 'disk-encryption': $all_disk_ids"

  # Check ckms locate returns at least the 2 vol IDs we created.
  if ! echo "$all_disk_ids" | grep -q "${vol1_id:-NONE}"; then
    echo "ERROR: vol1 key ($vol1_id) not found by 'ckms locate --tag disk-encryption'." >&2
    exit 1
  fi
  if ! echo "$all_disk_ids" | grep -q "${vol2_id:-NONE}"; then
    echo "ERROR: vol2 key ($vol2_id) not found by 'ckms locate --tag disk-encryption'." >&2
    exit 1
  fi
  echo "OK: vol1 and vol2 disk-encryption symmetric keys confirmed via ckms."

  # Verify the PKCS#11 library initialises and can list objects without crashing.
  # Use C_Initialize + C_Finalize via a minimal test binary if available; otherwise
  # use the Rust test suite as the functional test.
  echo "Verifying PKCS#11 library enumerates disk-encryption objects..."
  set +x
  lib_output=$(
    CKMS_CONF="$ckms_conf" \
      COSMIAN_PKCS11_LOGGING_LEVEL="info" \
      COSMIAN_PKCS11_DISK_ENCRYPTION_TAG="disk-encryption" \
      cargo test \
        -p cosmian_pkcs11 \
        "${FEATURES_FLAG[@]}" \
        -- test_kms_client_and_backend \
        --nocapture 2>&1
  )
  set -x
  echo "$lib_output"
  echo "OK: PKCS#11 library enumeration test passed."
fi

# Cleanup via the EXIT trap.
echo "============================================="
echo "LUKS PKCS#11 KMS integration tests passed!"
echo "============================================="
