#!/usr/bin/env bash
set -euo pipefail
set -x

# Utimaco-only tests (Linux only)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env
setup_test_logging

echo "========================================="
echo "Running Utimaco HSM tests"
echo "========================================="

[ ! -f /etc/lsb-release ] && {
  echo "Error: HSM tests are only supported on Linux (Ubuntu/Debian)" >&2
  exit 1
}

export HSM_USER_PASSWORD="12345678"

# Ensure OpenSSL runtime is available for tests needing libcrypto
if [ -n "${NIX_OPENSSL_OUT:-}" ] && [ -d "${NIX_OPENSSL_OUT}/lib" ]; then
  export LD_LIBRARY_PATH="${NIX_OPENSSL_OUT}/lib:${LD_LIBRARY_PATH:-}"
fi
if [ -z "${DYN_OPENSSL_LIB:-}" ]; then
  DYN_OPENSSL_LIB="$(dirname "$(ls /nix/store/*-openssl-3.*/lib/libcrypto.so.3 2>/dev/null | head -n1)" 2>/dev/null || true)"
fi
if [ -n "${DYN_OPENSSL_LIB:-}" ] && [ -d "$DYN_OPENSSL_LIB" ]; then
  export LD_LIBRARY_PATH="$DYN_OPENSSL_LIB:${LD_LIBRARY_PATH:-}"
fi

# Setup Utimaco HSM simulator
pushd "$REPO_ROOT" >/dev/null
__LDP_SAVE__="${LD_LIBRARY_PATH-}"
unset LD_LIBRARY_PATH || true
source "$REPO_ROOT/.github/reusable_scripts/test_utimaco.sh"
if [ "${__LDP_SAVE__+set}" = set ]; then
  export LD_LIBRARY_PATH="$__LDP_SAVE__"
  unset __LDP_SAVE__
fi
popd >/dev/null

: "${UTIMACO_PKCS11_LIB:?UTIMACO_PKCS11_LIB not set}"
: "${CS_PKCS11_R3_CFG:?CS_PKCS11_R3_CFG not set}"
UTIMACO_LIB_DIR="$(dirname "$UTIMACO_PKCS11_LIB")"

# Utimaco integration test (KMS)
SYS_LD_PATHS=""
CXX_LIB_PATH="$(gcc -print-file-name=libstdc++.so.6 2>/dev/null || true)"
if [ -n "$CXX_LIB_PATH" ] && [ -f "$CXX_LIB_PATH" ]; then
  SYS_LD_PATHS="$(dirname "$CXX_LIB_PATH"):${SYS_LD_PATHS}"
fi

env \
  PATH="$PATH" \
  LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${SYS_LD_PATHS}${DYN_OPENSSL_LIB:+$DYN_OPENSSL_LIB:}${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
  HSM_MODEL="utimaco" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="0" \
  UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" \
  CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" \
  cargo test \
  "${FEATURES_FLAG[@]}" \
  $RELEASE_FLAG \
  -- tests::hsm::test_hsm_all --ignored

# Utimaco loader test (no system lib dirs, scoped runtime)
SYS_LD_PATHS=""
CXX_LIB_PATH="$(gcc -print-file-name=libstdc++.so.6 2>/dev/null || true)"
if [ -n "$CXX_LIB_PATH" ] && [ -f "$CXX_LIB_PATH" ]; then
  SYS_LD_PATHS="$(dirname "$CXX_LIB_PATH"):${SYS_LD_PATHS}"
fi

env \
  PATH="$PATH" \
  LD_LIBRARY_PATH="${UTIMACO_LIB_DIR}:${SYS_LD_PATHS}${DYN_OPENSSL_LIB:+$DYN_OPENSSL_LIB:}${NIX_OPENSSL_OUT:+$NIX_OPENSSL_OUT/lib:}${LD_LIBRARY_PATH:-}" \
  HSM_MODEL="utimaco" \
  HSM_USER_PASSWORD="$HSM_USER_PASSWORD" \
  HSM_SLOT_ID="0" \
  UTIMACO_PKCS11_LIB="$UTIMACO_PKCS11_LIB" \
  CS_PKCS11_R3_CFG="$CS_PKCS11_R3_CFG" \
  cargo test \
  -p utimaco_pkcs11_loader \
  $RELEASE_FLAG \
  --features utimaco \
  -- tests::test_hsm_utimaco_all --ignored

echo "Utimaco HSM tests completed successfully."
