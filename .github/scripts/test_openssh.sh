#!/usr/bin/env bash
# OpenSSH + Cosmian KMS PKCS#11 integration tests
#
# This script validates the libcosmian_pkcs11 library as a PKCS#11 provider
# for OpenSSH key operations in two phases:
#
#   Part 1 — Rust unit tests (always executed):
#     test_ssh_rsa_sign, test_ssh_ecdsa_p256_sign, test_ssh_key_discovery
#
#   Part 2 — Shell integration test (requires ssh-keygen):
#     Starts a local KMS server, creates SSH keypairs tagged with "ssh-auth",
#     then calls `ssh-keygen -D <lib>` to exercise the full PKCS#11 path that
#     OpenSSH uses to enumerate public keys.
#
# Usage:
#   bash .github/scripts/nix.sh --variant non-fips test openssh
#   bash .github/scripts/test_openssh.sh [--variant non-fips]
set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running OpenSSH PKCS#11 integration tests"
echo "========================================="

# OpenSSH tests force non-FIPS to cover the full algorithm set
# (EdDSA / Ed25519 is only available in non-FIPS mode).
# RSA and EC P-256/P-384 also work in FIPS mode, but standardising on
# non-FIPS keeps the test matrix simple.
if [ "${VARIANT}" != "non-fips" ]; then
  echo "Note: OpenSSH PKCS#11 tests force non-FIPS variant (EdDSA requires non-FIPS)."
fi
VARIANT="non-fips"
FEATURES_FLAG=(--features non-fips)

# ── Part 1: Rust unit tests ──────────────────────────────────────────────────
echo "========================================="
echo "Part 1: SSH signing Rust unit tests"
echo "========================================="

# Build the ckms CLI binary first so that `Command::cargo_bin("ckms")` inside
# lib tests finds a binary compiled with the matching feature flags.
cargo build -p ckms "${FEATURES_FLAG[@]}"

cargo test \
  -p cosmian_pkcs11 \
  "${FEATURES_FLAG[@]}" \
  -- test_ssh \
  --nocapture

echo "SSH Rust unit tests passed."

# ── Part 2: Shell integration test (ssh-keygen -D) ──────────────────────────
echo "========================================="
echo "Part 2: Shell integration test (ssh-keygen -D)"
echo "========================================="

# ssh-keygen is part of openssh-client; skip gracefully if not present.
if ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "Skipping ssh-keygen integration test: ssh-keygen not in PATH."
  echo "Install openssh-client and re-run to enable this test."
  echo "All OpenSSH PKCS#11 tests passed (Rust unit tests only)."
  exit 0
fi

# Build PKCS#11 library, KMS server and ckms CLI.
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

# ── Start a dedicated KMS server for the integration test ───────────────────
tmp_dir=$(mktemp -d)
kms_pid=""

_cleanup_openssh_test() {
  [ -n "${kms_pid:-}" ] && {
    kill "$kms_pid" 2>/dev/null || true
    wait "$kms_pid" 2>/dev/null || true
  }
  rm -rf "${tmp_dir:-}"
}
trap _cleanup_openssh_test EXIT

# Use a dedicated port to avoid collisions with the Rust test-server (9998)
# and the SoftHSM2 integration test (19998).
kms_port=19997
sqlite_path="$tmp_dir/kms-data"

"$kms_bin" \
  --database-type sqlite \
  --sqlite-path "$sqlite_path" \
  --port "$kms_port" \
  --hostname "127.0.0.1" \
  >"$tmp_dir/kms.log" 2>&1 &
kms_pid=$!

kms_wait_ready "http://127.0.0.1:${kms_port}/kmip/2_1" "$kms_pid" "$tmp_dir/kms.log" 120

ckms_args=(--url "http://127.0.0.1:${kms_port}")

# Create SSH keypairs tagged with "ssh-auth" so the PKCS#11 library discovers them.
"$ckms_bin" "${ckms_args[@]}" ec keys create --curve nist-p256 --tag ssh-auth
"$ckms_bin" "${ckms_args[@]}" rsa keys create --size_in_bits 2048 --tag ssh-auth

echo "Created EC P-256 and RSA-2048 SSH keypairs with tag 'ssh-auth'."

# Write a ckms.toml pointing to the running server.
# The PKCS#11 library loads this file at C_Initialize time via CKMS_CONF.
ckms_conf="$tmp_dir/ckms.toml"
cat >"$ckms_conf" <<EOF
[http_config]
server_url = "http://127.0.0.1:${kms_port}"
EOF

# ── ssh-keygen -D ────────────────────────────────────────────────────────────
# This invokes the complete OpenSSH PKCS#11 stack:
#   1. ssh-keygen calls C_Initialize + C_GetSlotList/C_OpenSession
#   2. C_FindObjects with a public-key template
#   3. Each public key is serialised as an OpenSSH public key string
#
# On macOS, DYLD_INSERT_LIBRARIES / DYLD_LIBRARY_PATH are restricted for
# system binaries under SIP; our dylib only depends on system frameworks
# (Security.framework, CoreFoundation) so no extra LD paths are needed here.
echo "Running: CKMS_CONF=$ckms_conf ssh-keygen -D $pkcs11_lib"
set +x
ssh_keygen_output=$(
  CKMS_CONF="$ckms_conf" \
    COSMIAN_PKCS11_LOGGING_LEVEL="warn" \
    ssh-keygen -D "$pkcs11_lib" 2>&1 || true
)
set -x

echo "--- ssh-keygen -D output ---"
echo "$ssh_keygen_output"
echo "----------------------------"

# Verify at least 2 OpenSSH public keys are printed (EC P-256 + RSA-2048).
key_count=$(echo "$ssh_keygen_output" | grep -cE '^(ecdsa-sha2-|ssh-rsa |ssh-ed25519 )' || true)

if [ "${key_count}" -lt 2 ]; then
  echo "ERROR: expected at least 2 public keys from ssh-keygen -D, got ${key_count}." >&2
  echo "Full ssh-keygen output repeated for diagnosis:" >&2
  echo "$ssh_keygen_output" >&2
  exit 1
fi

echo "OK: ssh-keygen -D returned ${key_count} SSH public key(s)."

# Cleanup via the EXIT trap.
echo "========================================="
echo "OpenSSH PKCS#11 integration tests passed!"
echo "========================================="
