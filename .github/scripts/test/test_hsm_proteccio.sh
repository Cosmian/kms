#!/usr/bin/env bash
set -eo pipefail
set -x

# Proteccio-only tests (Linux only)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging

echo "========================================="
echo "Running Proteccio HSM tests"
echo "========================================="

# Proteccio tests require external credentials/configuration. In CI/Nix environments
# these are often not provided; skip with success rather than failing under `set -u`.
if [[ -z "${PROTECCIO_PASSWORD-}" || -z "${PROTECCIO_SLOT-}" ]]; then
  echo "Skipping Proteccio HSM tests (missing PROTECCIO_PASSWORD and/or PROTECCIO_SLOT)."
  exit 0
fi

[ ! -f /etc/lsb-release ] && [ ! -f /etc/os-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

# Disable trace to avoid leaking password in logs
set +x
export HSM_USER_PASSWORD="${PROTECCIO_PASSWORD}"
HSM_SLOT_ID_VALUE="${PROTECCIO_SLOT}"
set -x

# Setup Proteccio HSM client tools
if ! source "$REPO_ROOT/.github/reusable_scripts/prepare_proteccio.sh"; then
  echo "Warning: Failed to source prepare_proteccio.sh, nethsmstatus may be failing. with return code $?."
fi

# PROTECCIO integration test (KMS)
# Unset Nix OpenSSL environment to use system libraries for Proteccio HSM
env -u LD_PRELOAD -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  PATH="$PATH" \
  HSM_MODEL="proteccio" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  RUST_LOG="cosmian_kms_server=trace" \
  HSM_SLOT_ID="$HSM_SLOT_ID_VALUE" \
  cargo test \
  -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  -- tests::hsm::test_hsm_all --ignored --exact

set +x
env -u LD_PRELOAD -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
  PATH="$PATH" \
  HSM_MODEL="proteccio" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="$HSM_SLOT_ID_VALUE" \
  RUST_LOG="cosmian_kms_server=trace" \
  cargo test \
  -p proteccio_pkcs11_loader \
  --features proteccio \
  -- tests::test_hsm_proteccio_all --ignored --exact
set -x

# ─── pkcs11-tool warning check ────────────────────────────────────────────────
# Spin up a KMS server, create AES and RSA keys via ckms, then run
# pkcs11-tool --list-objects to confirm no warnings appear.
# This is the integration-level regression test for issue #745
# (KMS was not setting CKA_ID on HSM-created keys).
test_pkcs11tool_no_warnings() {
  if ! command -v pkcs11-tool >/dev/null 2>&1; then
    echo "Skipping pkcs11-tool warning test: pkcs11-tool not in PATH."
    return 0
  fi

  echo "========================================="
  echo "pkcs11-tool: checking KMS-created HSM keys for warnings (Proteccio)"
  echo "========================================="

  # Build server + CLI binaries (reuses any already-built artifacts)
  local -a build_args=(-p cosmian_kms_server -p ckms)
  if [ ${#FEATURES_FLAG[@]} -gt 0 ]; then
    build_args+=("${FEATURES_FLAG[@]}")
  fi
  env -u LD_PRELOAD -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    cargo build "${build_args[@]}"

  local cargo_target_dir
  cargo_target_dir="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
  local kms_bin="$cargo_target_dir/debug/cosmian_kms"
  local ckms_bin="$cargo_target_dir/debug/ckms"

  # Proteccio PKCS11 module is always at /lib/libnethsm.so (installed by prepare_proteccio.sh)
  local proteccio_lib="/lib/libnethsm.so"

  local tmp_dir
  tmp_dir=$(mktemp -d)
  local kms_pid=""

  _cleanup_pkcs11_test() {
    [ -n "${kms_pid:-}" ] && {
      kill "$kms_pid" 2>/dev/null || true
      wait "$kms_pid" 2>/dev/null || true
    }
    rm -rf "${tmp_dir:-}"
  }
  trap _cleanup_pkcs11_test EXIT

  local kms_port=19998
  local sqlite_path="$tmp_dir/kms-data"
  local ts
  ts=$(date +%s)
  local aes_label="pkcs11tool_aes_${ts}"
  local rsa_label="pkcs11tool_rsa_${ts}"
  local aes_uid="hsm::${HSM_SLOT_ID_VALUE}::${aes_label}"
  local rsa_uid="hsm::${HSM_SLOT_ID_VALUE}::${rsa_label}"

  # The KMS server environment has two conflicting constraints:
  #
  # 1. LD_LIBRARY_PATH must be stripped: the Nix FIPS shell prepends OpenSSL 3.1.2
  #    to LD_LIBRARY_PATH.  libnethsm.so has OpenSSL statically embedded (CRYPTOGAMS
  #    assembly), reads OPENSSL_CONF/OPENSSL_MODULES itself, and the Nix FIPS module
  #    is binary-incompatible with libnethsm's embedded OpenSSL → C_Initialize = 6.
  #
  # 2. cosmian_kms (FIPS build) calls Provider::load("fips") at startup, which
  #    requires [fips_sect] config data (the HMAC integrity hash from fipsmodule.cnf).
  #    Stripping OPENSSL_CONF makes cosmian_kms fall back to its compiled-in
  #    OPENSSLDIR (/usr/local/cosmian/lib/ssl/) which does not exist on CI runners.
  #
  # Solution: write a custom openssl.cnf that:
  #   a. Includes [fips_sect] + .include fipsmodule.cnf  →  Provider::load("fips") works
  #   b. Sets activate = 0 for fips                       →  libnethsm's embedded OpenSSL
  #                                                           will NOT auto-load the FIPS
  #                                                           module (avoids binary incompat)
  #   c. Sets activate = 1 for default                    →  non-FIPS operations still work
  local kms_openssl_cnf="$tmp_dir/kms-openssl.cnf"
  local fipsmodule_cnf
  fipsmodule_cnf="$(dirname "${OPENSSL_CONF:-/dev/null}")/fipsmodule.cnf"
  if [ -f "$fipsmodule_cnf" ]; then
    # FIPS env: provide [fips_sect] config data but do not auto-activate FIPS
    cat >"$kms_openssl_cnf" <<OPENSSL_CNF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
fips = fips_sect
default = default_sect

[fips_sect]
activate = 0
.include $fipsmodule_cnf

[default_sect]
activate = 1
OPENSSL_CNF
  else
    # Non-FIPS / no fipsmodule.cnf: just load the built-in default provider
    printf '[openssl_conf]\nopenssl_conf = openssl_init\n\n[openssl_init]\nproviders = provider_sect\n\n[provider_sect]\ndefault = default_sect\n\n[default_sect]\nactivate = 1\n' \
      >"$kms_openssl_cnf"
  fi

  # Write a temp config so that /etc/cosmian/kms.toml (if present on the host)
  # does not interfere: when --config is supplied explicitly, the server never
  # falls back to the default path.
  local kms_conf="$tmp_dir/kms.toml"
  cat >"$kms_conf" <<KMS_CONF_EOF
hsm_model = "proteccio"
hsm_admin = ["admin"]
hsm_slot = [${HSM_SLOT_ID_VALUE}]
hsm_password = ["${HSM_USER_PASSWORD}"]

[db]
database_type = "sqlite"
sqlite_path = "${sqlite_path}"

[http]
hostname = "127.0.0.1"
port = ${kms_port}
KMS_CONF_EOF

  env -u LD_PRELOAD -u LD_LIBRARY_PATH \
    PATH="$PATH" \
    OPENSSL_CONF="$kms_openssl_cnf" \
    "$kms_bin" \
    --config "$kms_conf" \
    >"$tmp_dir/kms.log" 2>&1 &
  kms_pid=$!

  local probe_url="http://127.0.0.1:${kms_port}/kmip/2_1"
  kms_wait_ready "$probe_url" "$kms_pid" "$tmp_dir/kms.log" 60

  local base_args=(--url "http://127.0.0.1:${kms_port}")

  # Create AES-256 and RSA-2048 keys on the Proteccio HSM.
  # Keys are intentionally NOT created with --sensitive so that pkcs11-tool can
  # read CKA_VALUE without receiving CKR_ATTRIBUTE_SENSITIVE, keeping the
  # pkcs11-tool output clean for the warning check below.
  env -u LD_PRELOAD PATH="$PATH" \
    "$ckms_bin" "${base_args[@]}" sym keys create \
    --algorithm aes \
    --number-of-bits 256 \
    "$aes_uid"

  env -u LD_PRELOAD PATH="$PATH" \
    "$ckms_bin" "${base_args[@]}" rsa keys create \
    --size_in_bits 2048 \
    "$rsa_uid"

  kill "$kms_pid" 2>/dev/null || true
  wait "$kms_pid" 2>/dev/null || true
  kms_pid=""

  # Run pkcs11-tool --list-objects without any Nix OpenSSL override so it uses
  # system libraries (pkcs11-tool from the OS is linked against the system OpenSSL)
  local pkcs11_output pkcs11_rc=0
  set +x
  pkcs11_output=$(
    env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
      pkcs11-tool \
      --module "$proteccio_lib" \
      --login --pin "$HSM_USER_PASSWORD" \
      --slot "$HSM_SLOT_ID_VALUE" \
      --list-objects 2>&1
  ) || pkcs11_rc=$?
  set -x
  if [ "$pkcs11_rc" -ne 0 ]; then
    echo "WARNING: pkcs11-tool exited with code $pkcs11_rc" >&2
  fi
  echo "--- pkcs11-tool --list-objects output ---"
  echo "$pkcs11_output"
  echo "-----------------------------------------"

  # Proteccio does not implement CKA_VERIFY_RECOVER at all: both
  # C_GetAttributeValue and C_SetAttributeValue return CKR_ATTRIBUTE_TYPE_INVALID
  # for it.  pkcs11-tool always probes this attribute on RSA public keys, so the
  # warning is an inherent Proteccio library limitation, not a KMS bug.
  pkcs11_check_warnings "$pkcs11_output" "VERIFY_RECOVER" || exit 1

  echo "OK: no pkcs11-tool warnings on KMS-created HSM keys."

  # Clean up test keys from the HSM
  set +x
  env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    pkcs11-tool --module "$proteccio_lib" --login --pin "$HSM_USER_PASSWORD" \
    --slot "$HSM_SLOT_ID_VALUE" --delete-object --type secrkey \
    --label "$aes_label" 2>/dev/null || true
  env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    pkcs11-tool --module "$proteccio_lib" --login --pin "$HSM_USER_PASSWORD" \
    --slot "$HSM_SLOT_ID_VALUE" --delete-object --type privkey \
    --label "$rsa_label" 2>/dev/null || true
  env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    pkcs11-tool --module "$proteccio_lib" --login --pin "$HSM_USER_PASSWORD" \
    --slot "$HSM_SLOT_ID_VALUE" --delete-object --type pubkey \
    --label "${rsa_label}_pk" 2>/dev/null || true
  set -x

  trap - EXIT
  rm -rf "$tmp_dir"
  echo "pkcs11-tool warning test passed."
}

test_pkcs11tool_no_warnings

echo "Proteccio HSM tests completed successfully."
